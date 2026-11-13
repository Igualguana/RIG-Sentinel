"""Genesis B2-M2-C1-H1: hardening after the Gemini review (findings H1-01 to H1-04).

Each test distinguishes the actual behaviour of the standard library and of M1/P2 from the
assumptions in the findings. Pure; synthetic values only.
"""

import hashlib
import hmac
import json
import re

import pytest
from audit_fixtures import AUTH_MATERIAL, REF_MATERIAL, auth_key, ref_key
from policy_fixtures import baseline_engine, make_request
from test_audit_c1_chain import (
    APPROVAL,
    CHAIN_ID,
    CHAIN_MATERIAL,
    NOW,
    Chain,
    chain_key,
    codes,
    loaded,
    rechain,
    validated,
    verify,
)

from rig_sentinel.audit import AuditKey, KeyPurpose, ProjectionEpoch, derive_engine_ref_key
from rig_sentinel.audit import bounded_json as bj
from rig_sentinel.audit import records as rec
from rig_sentinel.audit.chainverify import (
    DEFAULT_MAX_RECORDS,
    ChainIssue,
    ChainReport,
    ChainStatus,
    verify_chain,
)
from rig_sentinel.audit.records import StorageError, StorageErrorCode
from rig_sentinel.policy.canonical import canonical_json

NUL = bytes(1)
HIGH, LOW, HIGH2 = chr(0xD83D), chr(0xDE00), chr(0xD800)


def esc(hex4):
    """One JSON \\uXXXX escape as bytes (built without a literal backslash-u in this file)."""
    return b"\\" + b"u" + hex4


def code_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value.code


@pytest.fixture
def no_json_loads(monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append(1)
        raise AssertionError("json.loads must not be called")

    monkeypatch.setattr(bj.json, "loads", spy)
    return calls


# --- H1-01: Unicode surrogates -------------------------------------------------------------------


def test_the_standard_library_really_accepts_unpaired_surrogates():
    # The finding's premise, checked rather than assumed: json.loads does NOT reject them, and
    # canonical_json is not injective over strings that contain them.
    assert json.loads(b'"' + esc(b"d800") + b'"') == HIGH2
    assert json.loads(b'"' + esc(b"dc00") + esc(b"d800") + b'"') == chr(0xDC00) + HIGH2
    assert canonical_json([HIGH + HIGH + LOW]) == canonical_json([HIGH + chr(0x1F600)])
    with pytest.raises(UnicodeEncodeError):
        HIGH2.encode("utf-8")


@pytest.mark.parametrize("char", [chr(0x1F600), chr(0x10000), chr(0x10FFFF), chr(0x1D11E)],
                         ids=["emoji", "first-supplementary", "last-code-point", "musical-symbol"])
def test_valid_supplementary_characters_round_trip(char):
    data = canonical_json({"s": "a" + char + "b"})
    assert data.count(b"\\" + b"u") == 2  # one canonical (lowercase) surrogate pair
    value = bj.strict_canonical_loads(data, max_bytes=20_480)
    assert value == {"s": "a" + char + "b"} and value["s"].encode("utf-8")


@pytest.mark.parametrize(
    "inside",
    [
        esc(b"d83d"),
        esc(b"de00"),
        esc(b"de00") + esc(b"d83d"),
        esc(b"d83d") + b"a",
        esc(b"d83d") + b"a" + esc(b"de00"),
        esc(b"d83d") + b"\\n",
        esc(b"d83d") + esc(b"0041"),
        esc(b"d83d") + esc(b"d83d") + esc(b"de00"),
        b"a" + esc(b"dfff"),
        esc(b"dbff"),
        esc(b"D83D"),
    ],
    ids=["lone-high", "lone-low", "reversed", "high-then-ascii", "high-ascii-low", "high-then-simple-escape", "high-then-bmp-escape",
         "two-highs-then-low", "low-after-ascii", "last-high", "uppercase-lone-high"],
)
def test_unpaired_or_misordered_surrogates_are_rejected_before_json_loads(inside, no_json_loads):
    data = b'["' + inside + b'"]'
    assert code_of(bj.strict_canonical_loads, data, max_bytes=20_480) is StorageErrorCode.SURROGATE_INVALID
    assert code_of(bj.prescan, data, max_bytes=20_480) is StorageErrorCode.SURROGATE_INVALID
    assert no_json_loads == []


@pytest.mark.parametrize("text", [HIGH, LOW, LOW + HIGH, HIGH + "x", HIGH + HIGH + LOW, "ok" + LOW],
                         ids=["high", "low", "reversed", "high-x", "high-high-low", "trailing-low"])
def test_what_canonical_json_emits_for_unpaired_surrogates_is_rejected(text):
    assert code_of(bj.strict_canonical_loads, canonical_json([text]), max_bytes=20_480) is (
        StorageErrorCode.SURROGATE_INVALID)


def test_layers_are_distinguished_for_surrogate_escapes():
    upper_pair = b'["' + esc(b"D83D") + esc(b"DE00") + b'"]'
    bj.prescan(upper_pair, max_bytes=20_480)  # lexically a valid pair
    assert code_of(bj.strict_canonical_loads, upper_pair, max_bytes=20_480) is StorageErrorCode.NON_CANONICAL


@pytest.mark.parametrize(
    "inside, expected",
    [
        (b"\\\\" + b"ud800", None),  # escaped backslash followed by the text "ud800": not an escape
        (b"\\\\" + esc(b"d83d") + esc(b"de00"), None),
        (b"\\\\" + esc(b"d83d"), StorageErrorCode.SURROGATE_INVALID),
        (esc(b"d80"), StorageErrorCode.BAD_ESCAPE),
        (esc(b"d80g"), StorageErrorCode.BAD_ESCAPE),
        (esc(b"d83d") + b"\\" + b"x", StorageErrorCode.SURROGATE_INVALID),
    ],
    ids=["escaped-backslash-text", "escaped-backslash-then-pair", "escaped-backslash-then-lone",
         "short-escape", "non-hex", "high-then-bad-escape"],
)
def test_backslash_and_malformed_escape_cases(inside, expected):
    data = b'["' + inside + b'"]'
    if expected is None:
        bj.prescan(data, max_bytes=20_480)
    else:
        assert code_of(bj.prescan, data, max_bytes=20_480) is expected


def test_string_length_counts_raw_escape_bytes_at_the_boundary():
    pair = esc(b"d83d") + esc(b"de00")  # 12 raw bytes, one character
    exact = b'"' + pair * 341 + b"abcd" + b'"'  # 341 * 12 + 4 = 4,096 raw bytes
    assert len(bj.strict_canonical_loads(exact, max_bytes=20_480)) == 345
    over = b'"' + pair * 341 + b"abcde" + b'"'
    assert code_of(bj.strict_canonical_loads, over, max_bytes=20_480) is StorageErrorCode.STRING_TOO_LONG
    split = b'"' + b"a" * 4_090 + pair + b'"'  # the low half crosses the limit
    assert code_of(bj.strict_canonical_loads, split, max_bytes=20_480) is StorageErrorCode.STRING_TOO_LONG


def test_m1_and_p2_never_emit_surrogate_escapes_in_persisted_bytes():
    # Compatibility: strict pairing rejects nothing M1 or P2 produce. Requests carrying surrogates
    # are reduced to digests or refused by M1, and projections contain no \u escapes at all.
    for overrides in ({"resource": HIGH2}, {"agent": LOW}, {"labels": [HIGH + "x"]}, {}, APPROVAL):
        request = make_request(**overrides)
        baseline_engine().evaluate(request)
    lines = Chain().event().event(**APPROVAL).event(resource="db:" + HIGH2).lines
    for line in lines:
        assert (b"\\" + b"u") not in line
        rec.parse_record(line)


def test_records_with_an_unpaired_surrogate_are_rejected_at_parse():
    line = Chain().event().lines[1]
    tampered = line.replace(b'"engine_version":"', b'"engine_version":"' + esc(b"d800"), 1)
    assert tampered != line
    assert code_of(rec.parse_record, tampered) is StorageErrorCode.SURROGATE_INVALID
    report = verify([Chain().lines[0], tampered])
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.SURROGATE_INVALID]


def test_anchor_and_checkpoint_with_surrogates_are_rejected():
    keys = {chain_key().key_id: chain_key()}
    anchor = rec.build_anchor(chain_id=CHAIN_ID, segment=0, seq=1, record_digest="ab" * 32,
                              auth_key_id=auth_key().key_id, generation=1, chain_key=chain_key())
    bad = anchor.replace(b'"anchor_schema":"', b'"anchor_schema":"' + esc(b"dc00"), 1)
    assert code_of(rec.verify_anchor, bad, keys) is StorageErrorCode.SURROGATE_INVALID


# --- H1-02: verifier resources ---------------------------------------------------------------------


def test_record_budget_is_enforced_before_any_work(monkeypatch):
    lines = Chain().event().event().lines
    monkeypatch.setattr(rec, "parse_record", lambda *_: pytest.fail("parsed despite budget"))
    with pytest.raises(StorageError) as info:
        verify_chain(lines, chain_keys={}, auth_keys={}, max_records=2)
    assert info.value.code is StorageErrorCode.RECORD_BUDGET_EXCEEDED and info.value.__context__ is None


def test_record_budget_boundary_and_default():
    lines = Chain().event().event().lines
    assert verify(lines, max_records=3).status is ChainStatus.CHAIN_VALID
    assert DEFAULT_MAX_RECORDS == 1_000_000
    assert verify(lines).status is ChainStatus.CHAIN_VALID


@pytest.mark.parametrize("bad", [0, -1, True, 10_000_001, 1.5, None], ids=["zero", "neg", "bool", "above-cap",
                                                                          "float", "none"])
def test_record_budget_must_be_a_bounded_int(bad):
    with pytest.raises(StorageError) as info:
        verify(Chain().lines, max_records=bad)
    assert info.value.code is StorageErrorCode.INPUT_TYPE_INVALID


@pytest.mark.parametrize("make", [lambda lines: iter(lines), lambda lines: (x for x in lines),
                                  lambda lines: type("L", (list,), {})(lines), lambda lines: set(lines),
                                  lambda lines: {i: x for i, x in enumerate(lines)}],
                         ids=["iterator", "generator", "list-subclass", "set", "dict"])
def test_only_materialized_lists_or_tuples_are_accepted(make):
    with pytest.raises(StorageError) as info:
        verify(make(Chain().lines))
    assert info.value.code is StorageErrorCode.INPUT_TYPE_INVALID


def test_self_referencing_list_terminates_with_a_typed_issue():
    lines = list(Chain().lines)
    lines.append(lines)  # a list that contains itself
    report = verify(lines)
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.INPUT_TYPE_INVALID]


def test_garbage_flood_is_bounded_by_the_issue_cap():
    lines = Chain().lines + [b"[" * 100 + b"\n"] * 5_000 + [b"x" * 30_000 + b"\n"] * 100
    report = verify(lines, max_issues=50)
    assert len(report.issues) == 51 and report.issues[-1].code is StorageErrorCode.TOO_MANY_ISSUES


def test_segment_numbers_never_loop_back():
    # Segments are compared by number only and must increase; a "back reference" is just a
    # structurally invalid record, so no visited-segment set is needed.
    records = loaded(Chain().event().close().open(rec.OpenReason.ROTATION).event().lines)
    records[3]["chain"]["segment"] = 0
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED


# --- H1-03: K_chain / K_auth versus K_ref and the derived K_eref -----------------------------------


EREF_MATERIAL = hmac.new(REF_MATERIAL, b"rig.audit-key-derive/v1" + NUL + b"engine-ref", hashlib.sha256).digest()


def test_eref_material_is_the_unchanged_p2_derivation():
    eref = derive_engine_ref_key(ref_key())
    assert eref.key_id == hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"engine-ref" + NUL
                                         + EREF_MATERIAL).hexdigest()[:32]
    assert ProjectionEpoch.keyed(ref_key()).engine_ref_key_id == eref.key_id


@pytest.mark.parametrize("material", [EREF_MATERIAL, REF_MATERIAL, AUTH_MATERIAL], ids=["eref", "ref", "auth"])
def test_require_independent_keys_refuses_shared_chain_material(material):
    chain = AuditKey.from_bytes(KeyPurpose.CHAIN, material)
    assert code_of(rec.require_independent_keys, chain, auth_key(), ref_key()) is StorageErrorCode.KEYS_NOT_INDEPENDENT


def test_require_independent_keys_refuses_auth_equal_to_eref():
    auth = AuditKey.from_bytes(KeyPurpose.AUTH, EREF_MATERIAL)
    assert code_of(rec.require_independent_keys, chain_key(), auth, ref_key()) is StorageErrorCode.KEYS_NOT_INDEPENDENT


@pytest.mark.parametrize("material", [EREF_MATERIAL, REF_MATERIAL], ids=["eref", "ref"])
def test_builders_detect_shared_material_from_the_epoch_alone(material):
    shared = AuditKey.from_bytes(KeyPurpose.CHAIN, material)
    keyed = ProjectionEpoch.keyed(ref_key())
    assert rec.key_matches_epoch(shared, keyed) and not rec.key_matches_epoch(chain_key(), keyed)
    assert code_of(rec.build_segment_open, position=rec.ChainPosition(CHAIN_ID, 0, 0, None), created_at=NOW,
                   reason=rec.OpenReason.GENESIS, auth_key_id=auth_key().key_id, chain_key=shared, epoch=keyed,
                   previous_segment=None, recovery=None, writer_version="0.1.0") is StorageErrorCode.KEYS_NOT_INDEPENDENT
    v = validated()
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=keyed,
                   position=rec.ChainPosition(CHAIN_ID, 0, 1, "ab" * 32), chain_key=shared) is (
        StorageErrorCode.KEYS_NOT_INDEPENDENT)


def test_event_builder_refuses_auth_equal_to_eref():
    auth = AuditKey.from_bytes(KeyPurpose.AUTH, EREF_MATERIAL)
    v = validated(auth=auth)  # P2 itself still allows this pairing (P2 semantics unchanged)
    assert code_of(rec.build_event_record, v, auth_key=auth, epoch=ProjectionEpoch.keyed(ref_key()),
                   position=rec.ChainPosition(CHAIN_ID, 0, 1, "ab" * 32), chain_key=chain_key()) is (
        StorageErrorCode.KEYS_NOT_INDEPENDENT)


def test_unlinked_epoch_names_no_ref_key_and_is_not_matched():
    shared = AuditKey.from_bytes(KeyPurpose.CHAIN, EREF_MATERIAL)
    assert not rec.key_matches_epoch(shared, ProjectionEpoch.unlinked())


def test_verifier_flags_a_stored_chain_whose_k_chain_is_k_eref():
    records = loaded(Chain().event().lines)
    lines = rechain(records, EREF_MATERIAL)  # an attacker or misconfigured writer used K_eref
    shared = AuditKey.from_bytes(KeyPurpose.CHAIN, EREF_MATERIAL)
    report = verify(lines, shared)
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.KEYS_NOT_INDEPENDENT in codes(report)


def test_independence_errors_never_contain_material_or_ids():
    shared = AuditKey.from_bytes(KeyPurpose.CHAIN, EREF_MATERIAL)
    with pytest.raises(StorageError) as info:
        rec.require_independent_keys(shared, auth_key(), ref_key())
    text = str(info.value) + repr(info.value) + repr(info.value.args)
    for secret in (EREF_MATERIAL.hex(), REF_MATERIAL.hex(), shared.key_id, ref_key().key_id):
        assert secret not in text


# --- H1-04: privacy of verification output -------------------------------------------------------


_ALLOWED_ERROR_TEXT = re.compile(r"[a-z_]+(: [a-z_.:0-9]+)?")


def test_report_fields_are_codes_positions_counts_and_one_digest():
    assert [f for f in ChainReport.__dataclass_fields__] == [
        "status", "issues", "records", "segments", "last_seq", "last_record_digest", "authenticated"]
    assert [f for f in ChainIssue.__dataclass_fields__] == ["index", "seq", "code", "severity"]


def test_report_never_contains_content_tags_or_key_ids():
    chain = Chain().event(**APPROVAL).event()
    lines = list(chain.lines)
    lines[2] = lines[2].replace(b'"seq":2', b'"seq":3')
    for keys in ((), (chain_key(),)):
        report = verify(lines, *keys) if keys else verify_chain(lines, chain_keys={}, auth_keys={})
        text = repr(report)
        for line in chain.lines:
            data = json.loads(line)
            for secret in (data["chain_auth"]["mac"], data["chain_auth"]["key_id"]):
                assert secret not in text
            if data["envelope"] is not None:
                for secret in (data["envelope"]["auth"]["mac"], data["envelope"]["projection_digest"],
                               data["envelope"]["projection"]["audit"]["event_id"], data["envelope_digest"]):
                    assert secret not in text
        for secret in ("helpdesk", "database_write", CHAIN_MATERIAL.hex(), AUTH_MATERIAL.hex(), auth_key().key_id):
            assert secret not in text


def test_structure_only_report_marks_its_digest_unauthenticated():
    report = verify_chain(Chain().event().lines, chain_keys={}, auth_keys={})
    assert report.status is ChainStatus.UNVERIFIABLE and report.authenticated is False
    assert report.last_record_digest is not None  # present, but documented as unauthenticated input


def test_parsed_record_repr_hides_content_and_tags():
    line = Chain().event(**APPROVAL).lines[1]
    parsed = rec.parse_record(line)
    text = repr(parsed) + str(parsed)
    data = json.loads(line)
    assert parsed.envelope_bytes is not None and parsed.envelope_bytes.decode() not in text
    for secret in (data["chain_auth"]["mac"], data["envelope"]["auth"]["mac"], "helpdesk", "event_id"):
        assert secret not in text
    genesis = rec.parse_record(Chain().lines[0])
    assert "previous_segment" not in repr(genesis) and "writer" not in repr(genesis)


@pytest.mark.parametrize(
    "call",
    [
        lambda: bj.strict_canonical_loads(b'{"zq-canary":1,"zq-canary":2}', max_bytes=100),
        lambda: rec.parse_record(b'{"zq-canary":' + esc(b"d800") + b"}\n"),
        lambda: rec.verify_anchor(b'{"zq-canary":1}\n', {chain_key().key_id: chain_key()}),
        lambda: verify_chain([], chain_keys={"zq-canary": chain_key()}, auth_keys={}),
        lambda: verify_chain([b"x"], chain_keys={}, auth_keys={}, max_records="zq-canary"),
    ],
    ids=["parser", "record", "anchor", "keyring", "budget"],
)
def test_error_text_is_a_code_and_a_fixed_path(call):
    with pytest.raises(StorageError) as info:
        call()
    assert _ALLOWED_ERROR_TEXT.fullmatch(str(info.value)) and "zq-canary" not in repr(info.value)
    assert info.value.__context__ is None and info.value.__cause__ is None
