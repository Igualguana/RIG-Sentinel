"""Genesis B2-M2-C1: independent chain key, rig.audit-record/v2 records, anchors and checkpoints.

Pure: no file is read or written. Every ValidatedProjection is treated as an untrusted carrier:
the record builder re-applies the P2 gate to its exact bytes. Synthetic values only.
"""

import dataclasses
import hashlib
import hmac
import itertools
import json

import pytest
from audit_fixtures import AUTH_MATERIAL, FIXED_AUDIT_NOW, REF_MATERIAL, auth_key, both_keys, ref_key
from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA_V3,
    AuditEventBuilder,
    AuditKey,
    AuditKeys,
    KeyPurpose,
    ProjectionEpoch,
    ProjectionProfile,
    ValidatedProjection,
    check_projection_persistable,
    keyring,
    project,
)
from rig_sentinel.audit import records as rec
from rig_sentinel.audit.records import StorageError, StorageErrorCode
from rig_sentinel.policy.canonical import canonical_json

NUL = bytes(1)
CHAIN_MATERIAL = bytes(range(200, 232))
OTHER_CHAIN_MATERIAL = bytes(range(160, 192))
CHAIN_ID = "c1" * 16
NOW = "2026-11-12T12:00:00.000000Z"
APPROVAL = dict(tool="mcp://helpdesk/tickets.update", operation="database_write", resource="db:helpdesk/tickets")


def chain_key(material=CHAIN_MATERIAL):
    return AuditKey.from_bytes(KeyPurpose.CHAIN, material)


def code_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value.code


def validated(keys=None, unlinked=False, **overrides):
    request = make_request(**overrides)
    record = baseline_engine().evaluate(request)
    keys = (AuditKeys(auth=auth_key()) if unlinked else both_keys()) if keys is None else keys
    ids = itertools.count(1)
    builder = AuditEventBuilder(keys, clock=lambda: FIXED_AUDIT_NOW, id_factory=lambda: f"{next(ids):032x}",
                                event_schema=AUDIT_EVENT_SCHEMA_V3)
    profile = ProjectionProfile.UNLINKED if unlinked else ProjectionProfile.KEYED
    envelope = project(builder.build_envelope(record, request), keys, profile=profile)
    epoch = ProjectionEpoch.unlinked() if unlinked else ProjectionEpoch.keyed(ref_key())
    result = check_projection_persistable(envelope, keyring([auth_key()]), expected_epoch=epoch)
    assert result.ok and type(result.validated) is ValidatedProjection
    return result.validated, epoch


def position(seq=1, segment=0, prev="ab" * 32, chain_id=CHAIN_ID):
    return rec.ChainPosition(chain_id=chain_id, segment=segment, seq=seq, prev_record_digest=prev)


def event_line(v=None, epoch=None, **pos):
    if v is None:
        v, epoch = validated()
    return rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(**pos), chain_key=chain_key())


def genesis_line(key=None, epoch=None):
    return rec.build_segment_open(
        position=rec.ChainPosition(CHAIN_ID, 0, 0, None), created_at=NOW, reason=rec.OpenReason.GENESIS,
        auth_key_id=auth_key().key_id, chain_key=key or chain_key(), epoch=epoch or ProjectionEpoch.keyed(ref_key()),
        previous_segment=None, recovery=None, writer_version="0.1.0")


# --- Independent chain key ---------------------------------------------------------------------


def test_chain_key_is_an_independent_purpose_with_its_own_key_id():
    key = chain_key()
    assert key.purpose is KeyPurpose.CHAIN and KeyPurpose.CHAIN.value == "chain"
    expected = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"chain" + NUL + CHAIN_MATERIAL).hexdigest()[:32]
    assert key.key_id == expected
    generated = AuditKey.generate(KeyPurpose.CHAIN)
    assert generated.purpose is KeyPurpose.CHAIN and generated.key_id != key.key_id


def test_chain_key_is_not_derived_from_auth_or_ref():
    derived = hmac.new(AUTH_MATERIAL, b"rig.audit-key-derive/v1" + NUL + b"chain", hashlib.sha256).digest()
    assert rec.require_chain_key(chain_key()) is not None
    assert chain_key().key_id != AuditKey.from_bytes(KeyPurpose.CHAIN, derived).key_id


@pytest.mark.parametrize("material", [AUTH_MATERIAL, REF_MATERIAL], ids=["same-as-auth", "same-as-ref"])
def test_duplicate_key_material_is_refused(material):
    duplicate = AuditKey.from_bytes(KeyPurpose.CHAIN, material)
    assert code_of(rec.require_independent_keys, duplicate, auth_key(), ref_key()) is (
        StorageErrorCode.KEYS_NOT_INDEPENDENT)
    rec.require_independent_keys(chain_key(), auth_key(), ref_key())
    rec.require_independent_keys(chain_key(), auth_key(), None)


@pytest.mark.parametrize(
    "bad", [auth_key(), ref_key(), None, CHAIN_MATERIAL, "chain", type("K", (), {"purpose": KeyPurpose.CHAIN})()],
    ids=["auth", "ref", "none", "bytes", "str", "look-alike"],
)
def test_require_chain_key_rejects_everything_else(bad):
    assert code_of(rec.require_chain_key, bad) in (StorageErrorCode.KEY_INVALID, StorageErrorCode.KEY_PURPOSE_MISMATCH)


@pytest.mark.parametrize("material", [b"", bytes(31), bytes(33), bytes(32), "x" * 32, None],
                         ids=["empty", "short", "long", "all-zero", "str", "none"])
def test_chain_key_material_is_strictly_validated(material):
    with pytest.raises(Exception):  # noqa: B017 - AuditKey raises AuditError for every invalid material
        AuditKey.from_bytes(KeyPurpose.CHAIN, material)


def test_chain_key_never_reveals_material():
    key = chain_key()
    assert CHAIN_MATERIAL.hex() not in repr(key) + str(key)
    with pytest.raises(TypeError):
        import pickle

        pickle.dumps(key)


def test_existing_key_behaviour_is_unchanged():
    with pytest.raises(Exception):  # noqa: B017
        AuditKeys(ref=chain_key())
    with pytest.raises(Exception):  # noqa: B017
        AuditKeys(auth=chain_key())
    with pytest.raises(Exception):  # noqa: B017
        keyring([chain_key()])


# --- Event records: P2 boundary and exact bytes -------------------------------------------------


def test_event_record_carries_the_exact_validated_bytes_without_reserialization():
    v, epoch = validated(**APPROVAL)
    line = rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    assert line.endswith(b"\n") and line.count(b"\n") == 1 and line.isascii()
    assert line.count(v.canonical) == 1
    body = line[:-1]
    assert canonical_json(json.loads(body)) == body
    parsed = rec.parse_record(line)
    assert parsed.envelope_bytes == v.canonical
    assert parsed.envelope_digest == hashlib.sha256(b"rig.audit-envelope-in-record/v2" + NUL + v.canonical).hexdigest()


def test_record_digest_and_mac_match_an_independent_computation():
    v, epoch = validated()
    line = rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(seq=5, segment=2),
                                  chain_key=chain_key())
    data = json.loads(line)
    preimage = {k: val for k, val in data.items() if k not in ("record_digest", "chain_auth")}
    expected_digest = hashlib.sha256(b"rig.audit-record/v2" + NUL + canonical_json(preimage)).hexdigest()
    assert data["record_digest"] == expected_digest
    key_id = chain_key().key_id
    expected_mac = hmac.new(CHAIN_MATERIAL, b"rig.audit-chain-mac/v2" + NUL + key_id.encode() + NUL
                            + expected_digest.encode(), hashlib.sha256).hexdigest()
    assert data["chain_auth"] == {"algorithm": "HMAC-SHA256", "key_id": key_id, "mac": expected_mac}
    assert data["record_schema"] == "rig.audit-record/v2" and data["kind"] == "event" and data["body"] is None
    assert data["chain"] == {"chain_id": CHAIN_ID, "prev_record_digest": "ab" * 32, "segment": 2, "seq": 5}


def test_mutated_carrier_bytes_are_refused():
    v, epoch = validated()
    object.__setattr__(v, "canonical", v.canonical.replace(b'"decision":"ALLOW"', b'"decision":"DENY"'))
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=epoch, position=position(),
                   chain_key=chain_key()) in (StorageErrorCode.PROJECTION_REJECTED, StorageErrorCode.SCHEMA_INVALID)


def test_mutated_carrier_metadata_is_ignored():
    v, epoch = validated()
    object.__setattr__(v, "event_id", "f" * 32)
    object.__setattr__(v, "projection_digest", "0" * 64)
    line = rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    assert b"f" * 32 not in line and b"0" * 64 not in line


@pytest.mark.parametrize(
    "inject",
    [b'"request_digest":"' + b"a1" * 32 + b'",', b'"eligible_approvers":["oncall-lead"],'],
    ids=["raw-request-digest", "raw-approver-ids"],
)
def test_privacy_violations_injected_into_carrier_bytes_are_refused(inject):
    v, epoch = validated(**APPROVAL)
    tampered = v.canonical.replace(b'"engine":{', b'"engine":{' + inject, 1)
    object.__setattr__(v, "canonical", tampered)
    code = code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=epoch, position=position(),
                   chain_key=chain_key())
    assert code in (StorageErrorCode.PROJECTION_REJECTED, StorageErrorCode.SCHEMA_INVALID)


def test_disallowed_64_hex_identifier_is_refused_even_when_resealed():
    from rig_sentinel.audit import ProjectionEnvelope

    v, epoch = validated()
    from rig_sentinel.audit import projection_envelope_from_dict

    env = projection_envelope_from_dict(json.loads(v.canonical))
    engine = dataclasses.replace(env.projection.engine, policy_id="a1" * 32)
    forged = ProjectionEnvelope.seal(dataclasses.replace(env.projection, engine=engine), auth_key())
    object.__setattr__(v, "canonical", forged.canonical_bytes())
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=epoch, position=position(),
                   chain_key=chain_key()) is StorageErrorCode.PROJECTION_REJECTED


def test_wrong_auth_key_or_epoch_is_refused():
    v, epoch = validated()
    other_auth = AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(110, 142)))
    assert code_of(rec.build_event_record, v, auth_key=other_auth, epoch=epoch, position=position(),
                   chain_key=chain_key()) is StorageErrorCode.PROJECTION_REJECTED
    other_epoch = ProjectionEpoch.keyed(AuditKey.from_bytes(KeyPurpose.REF, bytes(range(70, 102))))
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=other_epoch, position=position(),
                   chain_key=chain_key()) is StorageErrorCode.PROJECTION_REJECTED
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=ProjectionEpoch.unlinked(),
                   position=position(), chain_key=chain_key()) is StorageErrorCode.PROJECTION_REJECTED


def test_unlinked_projection_needs_the_unlinked_epoch():
    v, epoch = validated(unlinked=True)
    assert epoch == ProjectionEpoch.unlinked()
    line = rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    assert rec.parse_record(line).envelope_bytes == v.canonical


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (dict(auth_key=None), StorageErrorCode.KEY_INVALID),
        (dict(chain_key=None), StorageErrorCode.KEY_INVALID),
        (dict(chain_key=auth_key()), StorageErrorCode.KEY_PURPOSE_MISMATCH),
        (dict(auth_key=chain_key()), StorageErrorCode.KEY_PURPOSE_MISMATCH),
        (dict(chain_key=AuditKey.from_bytes(KeyPurpose.CHAIN, AUTH_MATERIAL)), StorageErrorCode.KEYS_NOT_INDEPENDENT),
        (dict(epoch="keyed"), StorageErrorCode.INPUT_TYPE_INVALID),
        (dict(position=(CHAIN_ID, 0, 1, "ab" * 32)), StorageErrorCode.INPUT_TYPE_INVALID),
    ],
    ids=["no-auth", "no-chain", "auth-as-chain", "chain-as-auth", "dependent-chain", "epoch-str", "position-tuple"],
)
def test_builder_rejects_invalid_keys_and_inputs(kwargs, expected):
    v, epoch = validated()
    args = dict(auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    args.update(kwargs)
    assert code_of(rec.build_event_record, v, **args) is expected


@pytest.mark.parametrize("bad", [None, {}, b"{}", "validated"], ids=["none", "dict", "bytes", "str"])
def test_builder_accepts_only_validated_projections(bad):
    _v, epoch = validated()
    assert code_of(rec.build_event_record, bad, auth_key=auth_key(), epoch=epoch, position=position(),
                   chain_key=chain_key()) is StorageErrorCode.NOT_VALIDATED


@pytest.mark.parametrize(
    "pos",
    [dict(chain_id="C1" * 16), dict(chain_id="c1" * 15), dict(segment=-1), dict(seq=-1), dict(seq=2 ** 53),
     dict(prev="AB" * 32), dict(seq=0, prev="ab" * 32), dict(seq=1, prev=None), dict(segment=True),
     dict(segment=2, seq=1)],
    ids=["upper-chain-id", "short-chain-id", "neg-segment", "neg-seq", "seq-too-big", "upper-prev",
         "seq0-with-prev", "seq1-without-prev", "bool-segment", "segment-above-seq"],
)
def test_chain_positions_are_strictly_validated(pos):
    args = dict(chain_id=CHAIN_ID, segment=0, seq=1, prev="ab" * 32)
    args.update(pos)
    assert code_of(rec.ChainPosition, args["chain_id"], args["segment"], args["seq"], args["prev"]) in (
        StorageErrorCode.SCHEMA_INVALID, StorageErrorCode.INPUT_TYPE_INVALID)


def test_new_chain_id_is_random_128_bit_hex():
    a, b = rec.new_chain_id(), rec.new_chain_id()
    assert a != b and len(a) == 32 and int(a, 16) >= 0 and a == a.lower()


def test_events_never_take_the_genesis_position():
    v, epoch = validated()
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=epoch,
                   position=rec.ChainPosition(CHAIN_ID, 0, 0, None), chain_key=chain_key()) is (
        StorageErrorCode.SCHEMA_INVALID)


@pytest.mark.parametrize("shift", [0, 1], ids=["extra-byte", "wrong-offset"])
def test_splice_proof_refuses_a_corrupted_splice(monkeypatch, shift):
    real = rec._splice

    def corrupted(template, raw):
        text, offset = real(template, raw)
        if raw is None or offset < 0:
            return text, offset
        if shift:
            return text, offset + shift
        return text[:offset] + raw + b" " + text[offset + len(raw):], offset

    v, epoch = validated()
    monkeypatch.setattr(rec, "_splice", corrupted)
    assert code_of(rec.build_event_record, v, auth_key=auth_key(), epoch=epoch, position=position(),
                   chain_key=chain_key()) is StorageErrorCode.INTERNAL_INVARIANT


def test_gate_output_must_equal_the_captured_bytes(monkeypatch):
    # Defence in depth: even if the gate returned a different (valid) projection, nothing is built.
    v, epoch = validated()
    other, _ = validated(**APPROVAL)
    real = rec.check_projection_persistable

    def swapped(envelope, keys, **kwargs):
        from rig_sentinel.audit import projection_envelope_from_dict

        return real(projection_envelope_from_dict(json.loads(other.canonical)), keys, **kwargs)

    monkeypatch.setattr(rec, "check_projection_persistable", swapped)
    with pytest.raises(StorageError) as info:
        rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    assert info.value.code is StorageErrorCode.PROJECTION_REJECTED and info.value.path == "bytes"


def test_envelope_digest_is_checked_even_when_the_record_digest_is_recomputed():
    data = json.loads(event_line())
    data["envelope_digest"] = "cd" * 32
    preimage = {k: v for k, v in data.items() if k not in ("record_digest", "chain_auth")}
    data["record_digest"] = hashlib.sha256(b"rig.audit-record/v2" + NUL + canonical_json(preimage)).hexdigest()
    assert code_of(rec.parse_record, canonical_json(data) + b"\n") is StorageErrorCode.DIGEST_MISMATCH


@pytest.mark.parametrize(
    "line, expected",
    [
        (b"{" + b"a" * 20_480, StorageErrorCode.LINE_TOO_LONG),
        (b"{" + b"a" * 20_478 + b"\n", StorageErrorCode.UNTERMINATED),  # in the size limit: scanned
        (b"{" + b"a" * 20_479 + b"\n", StorageErrorCode.LINE_TOO_LONG),
    ],
    ids=["oversized-without-newline", "exactly-20480", "exactly-20481"],
)
def test_record_line_limit_is_checked_first_and_is_inclusive(line, expected):
    assert code_of(rec.parse_record, line) is expected


def test_record_mac_is_bound_to_the_named_key_id():
    parsed = rec.parse_record(event_line())
    assert rec.verify_record_mac(parsed, chain_key())
    renamed = dataclasses.replace(parsed, chain_key_id=chain_key(OTHER_CHAIN_MATERIAL).key_id)
    assert not rec.verify_record_mac(renamed, chain_key())
    with pytest.raises(StorageError):
        rec.verify_record_mac(json.loads(event_line()), chain_key())


# --- Control records ---------------------------------------------------------------------------


def test_genesis_segment_open_is_canonical_and_parses():
    line = genesis_line()
    parsed = rec.parse_record(line)
    assert parsed.kind is rec.RecordKind.SEGMENT_OPEN and parsed.seq == 0 and parsed.prev_record_digest is None
    body = parsed.body
    assert body["reason"] == "genesis" and body["auth_key_id"] == auth_key().key_id
    assert body["chain_key_id"] == chain_key().key_id
    assert body["epoch"] == {"engine_ref_mode": "keyed", "ref_key_id": ref_key().key_id,
                             "engine_ref_key_id": ProjectionEpoch.keyed(ref_key()).engine_ref_key_id}
    assert body["writer"] == {"record_schema": "rig.audit-record/v2", "rig_sentinel_version": "0.1.0"}
    assert rec.verify_record_mac(parsed, chain_key())


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (dict(reason=rec.OpenReason.GENESIS, position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32)),
         StorageErrorCode.SCHEMA_INVALID),
        (dict(reason=rec.OpenReason.ROTATION, previous_segment=None,
              position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32)), StorageErrorCode.SCHEMA_INVALID),
        (dict(reason=rec.OpenReason.RECOVERY, recovery=None,
              previous_segment=rec.PreviousSegment(0, 4, "ab" * 32),
              position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32)), StorageErrorCode.SCHEMA_INVALID),
        (dict(reason=rec.OpenReason.ROTATION, previous_segment=rec.PreviousSegment(0, 3, "ab" * 32),
              position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32)), StorageErrorCode.SCHEMA_INVALID),
        (dict(reason=rec.OpenReason.ROTATION, previous_segment=rec.PreviousSegment(0, 4, "cd" * 32),
              position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32)), StorageErrorCode.SCHEMA_INVALID),
        (dict(created_at="2026-11-12 12:00:00"), StorageErrorCode.SCHEMA_INVALID),
        (dict(created_at="2026-13-40T12:00:00.000000Z"), StorageErrorCode.SCHEMA_INVALID),
        (dict(auth_key_id="A" * 32), StorageErrorCode.SCHEMA_INVALID),
        (dict(writer_version="0.1.0; rm -rf"), StorageErrorCode.SCHEMA_INVALID),
        (dict(reason="genesis"), StorageErrorCode.INPUT_TYPE_INVALID),
    ],
    ids=["genesis-not-at-start", "rotation-without-previous", "recovery-without-body", "previous-seq-wrong",
         "previous-digest-wrong", "bad-timestamp", "impossible-date", "bad-auth-key-id", "bad-writer-version", "reason-str"],
)
def test_segment_open_contract(kwargs, expected):
    args = dict(position=rec.ChainPosition(CHAIN_ID, 0, 0, None), created_at=NOW, reason=rec.OpenReason.GENESIS,
                auth_key_id=auth_key().key_id, chain_key=chain_key(), epoch=ProjectionEpoch.keyed(ref_key()),
                previous_segment=None, recovery=None, writer_version="0.1.0")
    args.update(kwargs)
    assert code_of(rec.build_segment_open, **args) is expected


def test_recovery_body_is_closed_and_bounded():
    recovery = rec.RecoveryInfo(damaged_segment=0, damage_kind=rec.DamageKind.PARTIAL_LINE, last_valid_seq=4,
                                last_valid_record_digest="ab" * 32, discarded_bytes=17, invalid_lines=0,
                                unconfirmed_seqs=())
    line = rec.build_segment_open(
        position=rec.ChainPosition(CHAIN_ID, 1, 5, "ab" * 32), created_at=NOW, reason=rec.OpenReason.RECOVERY,
        auth_key_id=auth_key().key_id, chain_key=chain_key(), epoch=ProjectionEpoch.keyed(ref_key()),
        previous_segment=rec.PreviousSegment(0, 4, "ab" * 32), recovery=recovery, writer_version="0.1.0")
    assert rec.parse_record(line).body["recovery"]["damage_kind"] == "partial_line"
    with pytest.raises(StorageError):
        rec.RecoveryInfo(damaged_segment=0, damage_kind=rec.DamageKind.PARTIAL_LINE, last_valid_seq=4,
                         last_valid_record_digest="ab" * 32, discarded_bytes=-1, invalid_lines=0, unconfirmed_seqs=())
    with pytest.raises(StorageError):
        rec.RecoveryInfo(damaged_segment=0, damage_kind=rec.DamageKind.UNCONFIRMED, last_valid_seq=4,
                         last_valid_record_digest="ab" * 32, discarded_bytes=0, invalid_lines=0,
                         unconfirmed_seqs=tuple(range(1000)))


@pytest.mark.parametrize("count", [0, 1, 11, True], ids=["zero", "one", "above-seq", "bool"])
def test_segment_close_count_bounds(count):
    assert code_of(rec.build_segment_close, position=position(seq=9), chain_key=chain_key(), record_count=count,
                   reason=rec.CloseReason.SIZE) is StorageErrorCode.SCHEMA_INVALID


def test_segment_close_and_checkpoint_marker():
    close = rec.build_segment_close(position=position(seq=9), chain_key=chain_key(), record_count=10,
                                    reason=rec.CloseReason.SIZE)
    parsed = rec.parse_record(close)
    assert parsed.kind is rec.RecordKind.SEGMENT_CLOSE
    assert parsed.body == {"last_seq": 8, "reason": "size", "record_count": 10, "segment": 0}
    marker = rec.build_checkpoint_marker(position=position(seq=10), chain_key=chain_key(), checkpoint_seq=9,
                                         checkpoint_record_digest="cd" * 32)
    assert rec.parse_record(marker).body == {"checkpoint_record_digest": "cd" * 32, "checkpoint_seq": 9}
    assert code_of(rec.build_checkpoint_marker, position=position(seq=10), chain_key=chain_key(), checkpoint_seq=10,
                   checkpoint_record_digest="cd" * 32) is StorageErrorCode.SCHEMA_INVALID


# --- Parsing stored records --------------------------------------------------------------------


def _mutate(line, old, new):
    assert line.count(old) >= 1
    return line.replace(old, new, 1)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda line: line[:-1], StorageErrorCode.PARTIAL_LINE),
        (lambda line: line + b"\n", StorageErrorCode.BYTE_NOT_ALLOWED),
        (lambda line: line[:-1] + b"\r\n", StorageErrorCode.BYTE_NOT_ALLOWED),
        (lambda line: _mutate(line, b'"kind":"event"', b'"kind":"evil"'), StorageErrorCode.SCHEMA_INVALID),
        (lambda line: _mutate(line, b'"record_schema":"rig.audit-record/v2"', b'"record_schema":"rig.audit-record/v1"'),
         StorageErrorCode.SCHEMA_INVALID),
        (lambda line: _mutate(line, b'"kind":"event"', b'"extra":1,"kind":"event"'), StorageErrorCode.SCHEMA_INVALID),
        (lambda line: _mutate(line, b'"seq":1', b'"seq":2'), StorageErrorCode.DIGEST_MISMATCH),
        (lambda line: _mutate(line, b'"decision":', b'"decision" :'), StorageErrorCode.TOKEN_INVALID),
    ],
    ids=["no-newline", "two-newlines", "crlf", "bad-kind", "old-schema", "extra-field", "seq-changed",
         "non-canonical"],
)
def test_parse_record_rejects_structural_damage(mutation, expected):
    line = event_line()
    assert code_of(rec.parse_record, mutation(line)) is expected


def test_parse_record_does_not_authenticate():
    line = event_line()
    parsed = rec.parse_record(line)
    assert not rec.verify_record_mac(parsed, chain_key(OTHER_CHAIN_MATERIAL))
    forged = json.loads(line)
    forged["chain_auth"]["mac"] = "0" * 64
    forged_line = canonical_json(forged) + b"\n"
    assert not rec.verify_record_mac(rec.parse_record(forged_line), chain_key())


def test_oversized_lines_are_rejected_before_parsing():
    assert code_of(rec.parse_record, b"{" + b" " * 20_480 + b"}\n") is StorageErrorCode.LINE_TOO_LONG


# --- Anchors -----------------------------------------------------------------------------------


def anchor(**changes):
    args = dict(chain_id=CHAIN_ID, segment=2, seq=41, record_digest="ab" * 32, auth_key_id=auth_key().key_id,
                generation=7, chain_key=chain_key())
    args.update(changes)
    return rec.build_anchor(**args)


def test_anchor_is_canonical_bounded_and_authenticated():
    data = anchor()
    assert data.endswith(b"\n") and len(data) <= 1_024 and data.isascii()
    parsed = rec.verify_anchor(data, {chain_key().key_id: chain_key()})
    assert (parsed.chain_id, parsed.segment, parsed.seq, parsed.generation) == (CHAIN_ID, 2, 41, 7)
    body = json.loads(data)
    mac = body.pop("mac")
    key_id = chain_key().key_id
    expected = hmac.new(CHAIN_MATERIAL, b"rig.audit-anchor/v1" + NUL + key_id.encode() + NUL + canonical_json(body),
                        hashlib.sha256).hexdigest()
    assert mac == expected and body["anchor_schema"] == "rig.audit-anchor/v1"


@pytest.mark.parametrize(
    "field, value",
    [("seq", 40), ("generation", 6), ("segment", 1), ("chain_id", "c2" * 16), ("record_digest", "cd" * 32),
     ("auth_key_id", "0" * 32), ("mac", "0" * 64)],
)
def test_tampered_anchor_fields_fail_authentication(field, value):
    body = json.loads(anchor())
    body[field] = value
    data = canonical_json(body) + b"\n"
    assert code_of(rec.verify_anchor, data, {chain_key().key_id: chain_key()}) is StorageErrorCode.MAC_INVALID


def test_anchor_under_wrong_or_unknown_chain_key():
    data = anchor()
    other = chain_key(OTHER_CHAIN_MATERIAL)
    assert code_of(rec.verify_anchor, data, {other.key_id: other}) is StorageErrorCode.UNKNOWN_KEY
    assert code_of(rec.verify_anchor, data, {chain_key().key_id: other}) is StorageErrorCode.KEYRING_INVALID
    assert code_of(rec.verify_anchor, data, {chain_key().key_id: auth_key()}) is StorageErrorCode.KEYRING_INVALID
    assert code_of(rec.verify_anchor, data, None) is StorageErrorCode.KEYRING_INVALID


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"", StorageErrorCode.PARTIAL_LINE),
        (b"{}\n", StorageErrorCode.SCHEMA_INVALID),
        (b"[" * 40 + b"]" * 40 + b"\n", StorageErrorCode.DEPTH_EXCEEDED),
        (b"x" * 2_000 + b"\n", StorageErrorCode.LINE_TOO_LONG),
    ],
    ids=["empty", "empty-object", "deep", "oversized"],
)
def test_malformed_anchors_are_rejected(data, expected):
    assert code_of(rec.verify_anchor, data, {chain_key().key_id: chain_key()}) is expected


@pytest.mark.parametrize(
    "changes",
    [dict(generation=-1), dict(generation=True), dict(seq=2 ** 53), dict(chain_id="xyz"), dict(record_digest="ab")],
    ids=["neg-generation", "bool-generation", "huge-seq", "bad-chain-id", "short-digest"],
)
def test_anchor_builder_validates_fields(changes):
    assert code_of(anchor, **changes) in (StorageErrorCode.SCHEMA_INVALID, StorageErrorCode.INPUT_TYPE_INVALID)


# --- Checkpoints (content-free, bound to the anchor generation) ---------------------------------


def checkpoint(**changes):
    args = dict(chain_id=CHAIN_ID, segment=2, seq=41, record_digest="ab" * 32, created_at=NOW,
                auth_key_id=auth_key().key_id, anchor_generation=7, chain_key=chain_key())
    args.update(changes)
    return rec.build_checkpoint(**args)


def test_checkpoint_is_content_free_bounded_and_authenticated():
    data = checkpoint()
    assert len(data) <= 2_048 and data.endswith(b"\n")
    body = json.loads(data)
    assert set(body) == {"checkpoint_schema", "chain_id", "segment", "seq", "record_digest", "created_at",
                         "chain_key_id", "auth_key_id", "anchor_generation", "mac"}
    assert body["checkpoint_schema"] == "rig.audit-checkpoint/v2" and body["anchor_generation"] == 7
    parsed = rec.verify_checkpoint(data, {chain_key().key_id: chain_key()})
    assert parsed.anchor_generation == 7 and parsed.seq == 41


@pytest.mark.parametrize("field, value", [("anchor_generation", 8), ("seq", 42), ("record_digest", "cd" * 32)])
def test_tampered_checkpoint_fails_authentication(field, value):
    body = json.loads(checkpoint())
    body[field] = value
    assert code_of(rec.verify_checkpoint, canonical_json(body) + b"\n", {chain_key().key_id: chain_key()}) is (
        StorageErrorCode.MAC_INVALID)


def test_domains_are_separated_between_anchor_checkpoint_and_records():
    anchor_body = json.loads(anchor())
    anchor_mac = anchor_body.pop("mac")
    key_id = chain_key().key_id.encode()
    as_checkpoint = hmac.new(CHAIN_MATERIAL, b"rig.audit-checkpoint/v2" + NUL + key_id + NUL
                             + canonical_json(anchor_body), hashlib.sha256).hexdigest()
    assert anchor_mac != as_checkpoint
    assert len({rec.RECORD_DIGEST_DOMAIN, rec.CHAIN_MAC_DOMAIN, rec.ANCHOR_MAC_DOMAIN, rec.CHECKPOINT_MAC_DOMAIN,
                rec.ENVELOPE_IN_RECORD_DOMAIN}) == 5


# --- Known-answer vectors (independent stdlib computation, pinned) -----------------------------


def test_known_answer_vectors_for_control_records():
    line = genesis_line()
    data = json.loads(line)
    preimage = {k: v for k, v in data.items() if k not in ("record_digest", "chain_auth")}
    digest = hashlib.sha256(b"rig.audit-record/v2" + NUL + canonical_json(preimage)).hexdigest()
    key_id = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"chain" + NUL + CHAIN_MATERIAL).hexdigest()[:32]
    mac = hmac.new(CHAIN_MATERIAL, b"rig.audit-chain-mac/v2" + NUL + key_id.encode() + NUL + digest.encode(),
                   hashlib.sha256).hexdigest()
    assert (data["record_digest"], data["chain_auth"]["mac"], data["chain_auth"]["key_id"]) == (digest, mac, key_id)
    assert key_id == KAT_CHAIN_KEY_ID
    assert digest == KAT_GENESIS_RECORD_DIGEST and mac == KAT_GENESIS_MAC
    assert hashlib.sha256(line).hexdigest() == KAT_GENESIS_LINE_SHA256
    assert json.loads(anchor())["mac"] == KAT_ANCHOR_MAC
    assert json.loads(checkpoint())["mac"] == KAT_CHECKPOINT_MAC


# Pinned from an independent standard-library computation (c1_vectors.py in the audit package),
# which never imports rig_sentinel.
KAT_CHAIN_KEY_ID = "86eb5a681c45a46a6b01304532e23dda"
KAT_GENESIS_RECORD_DIGEST = "31e54a3e40446da5c49410113b28f2e23c494461df96083cddfb9ba4fcd3f786"
KAT_GENESIS_MAC = "15fe6a18078fc033aa7fc65c8317cb98fe657b3284543853b7799c9edf6587b9"
KAT_GENESIS_LINE_SHA256 = "723e7f3915c6d8cb5b79cd4f760ffa62161af43fda9f92221954a3a0e10d8309"
KAT_ANCHOR_MAC = "8f708b344a7c692db1cd69a4288fd201dd027e113161e890134546d0ae3c6206"
KAT_CHECKPOINT_MAC = "da8c0534b107a39f75ee1a31bb4c5703244e3555afb1fe5007cfdbc43237ec18"


# --- Privacy of errors -------------------------------------------------------------------------


def test_errors_never_echo_values_or_keys():
    v, epoch = validated()
    object.__setattr__(v, "canonical", v.canonical.replace(b'"engine":{', b'"engine":{"zq-canary-c1":1,', 1))
    with pytest.raises(StorageError) as info:
        rec.build_event_record(v, auth_key=auth_key(), epoch=epoch, position=position(), chain_key=chain_key())
    text = str(info.value) + repr(info.value) + repr(info.value.args)
    assert "zq-canary-c1" not in text and CHAIN_MATERIAL.hex() not in text and AUTH_MATERIAL.hex() not in text
