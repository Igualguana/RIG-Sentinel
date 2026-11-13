"""Genesis B2-M2-C1: pure chain verification over in-memory record lines.

Covers linking, segments, rotations, key-compromise simulations, privacy damage, structure-only
mode and limits. No file is read or written; synthetic values only.
"""

import builtins
import copy
import hashlib
import hmac
import io
import itertools
import json
import pathlib
import socket

import pytest
from audit_fixtures import AUTH_MATERIAL, FIXED_AUDIT_NOW, auth_key, ref_key
from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA_V3,
    AuditEventBuilder,
    AuditKey,
    AuditKeys,
    KeyPurpose,
    ProjectionEpoch,
    ProjectionProfile,
    check_projection_persistable,
    project,
)
from rig_sentinel.audit import records as rec
from rig_sentinel.audit.chainverify import ChainStatus, verify_chain
from rig_sentinel.audit.records import StorageError, StorageErrorCode
from rig_sentinel.policy.canonical import canonical_json

NUL = bytes(1)
CHAIN_MATERIAL = bytes(range(200, 232))
NEW_CHAIN_MATERIAL = bytes(range(160, 192))
ATTACKER_CHAIN_MATERIAL = bytes(range(120, 152))
AUTH2_MATERIAL = bytes(range(70, 102))
CHAIN_ID = "c1" * 16
NOW = "2026-11-12T12:00:00.000000Z"
APPROVAL = dict(tool="mcp://helpdesk/tickets.update", operation="database_write", resource="db:helpdesk/tickets")
_IDS = itertools.count(1)


def chain_key(material=CHAIN_MATERIAL):
    return AuditKey.from_bytes(KeyPurpose.CHAIN, material)


def auth2():
    return AuditKey.from_bytes(KeyPurpose.AUTH, AUTH2_MATERIAL)


KEYED = ProjectionEpoch.keyed(ref_key())


def validated(auth=None, unlinked=False, **overrides):
    auth = auth or auth_key()
    request = make_request(**overrides)
    record = baseline_engine().evaluate(request)
    keys = AuditKeys(auth=auth) if unlinked else AuditKeys(ref=ref_key(), auth=auth)
    builder = AuditEventBuilder(keys, clock=lambda: FIXED_AUDIT_NOW, id_factory=lambda: f"{next(_IDS):032x}",
                                event_schema=AUDIT_EVENT_SCHEMA_V3)
    profile = ProjectionProfile.UNLINKED if unlinked else ProjectionProfile.KEYED
    envelope = project(builder.build_envelope(record, request), keys, profile=profile)
    epoch = ProjectionEpoch.unlinked() if unlinked else KEYED
    result = check_projection_persistable(envelope, {auth.key_id: auth}, expected_epoch=epoch)
    assert result.ok
    return result.validated


class Chain:
    """Builds a chain with the pure C1 builders (what a future sink would write)."""

    def __init__(self, key=None, auth=None, epoch=KEYED):
        self.lines = []
        self.key = key or chain_key()
        self.auth = auth or auth_key()
        self.epoch = epoch
        self.segment = 0
        self.first_seq = 0
        self.open(rec.OpenReason.GENESIS)

    @property
    def seq(self):
        return len(self.lines)

    @property
    def prev(self):
        return json.loads(self.lines[-1])["record_digest"] if self.lines else None

    def position(self):
        return rec.ChainPosition(CHAIN_ID, self.segment, self.seq, self.prev)

    def open(self, reason, *, recovery=None, segment=None):
        previous = None
        if reason is not rec.OpenReason.GENESIS:
            previous = rec.PreviousSegment(self.segment, self.seq - 1, self.prev)
            self.segment = self.segment + 1 if segment is None else segment
        self.first_seq = self.seq
        self.lines.append(rec.build_segment_open(
            position=self.position(), created_at=NOW, reason=reason, auth_key_id=self.auth.key_id, chain_key=self.key,
            epoch=self.epoch, previous_segment=previous, recovery=recovery, writer_version="0.1.0"))
        return self

    def event(self, v=None, **overrides):
        v = v or validated(auth=self.auth, unlinked=self.epoch.engine_ref_mode is ProjectionProfile.UNLINKED,
                           **overrides)
        self.lines.append(rec.build_event_record(v, auth_key=self.auth, epoch=self.epoch, position=self.position(),
                                                 chain_key=self.key))
        return self

    def close(self, reason=rec.CloseReason.SIZE):
        count = self.seq - self.first_seq + 1
        self.lines.append(rec.build_segment_close(position=self.position(), chain_key=self.key, record_count=count,
                                                  reason=reason))
        return self

    def marker(self):
        last = json.loads(self.lines[-1])
        self.lines.append(rec.build_checkpoint_marker(position=self.position(), chain_key=self.key,
                                                      checkpoint_seq=last["chain"]["seq"],
                                                      checkpoint_record_digest=last["record_digest"]))
        return self


def rings(*chain_keys, auths=None):
    chain = {k.key_id: k for k in (chain_keys or (chain_key(),))}
    auth = {k.key_id: k for k in (auths if auths is not None else (auth_key(),))}
    return dict(chain_keys=chain, auth_keys=auth)


def verify(lines, *chain_keys, auths=None, **kwargs):
    return verify_chain(lines, **rings(*chain_keys, auths=auths), **kwargs)


def codes(report):
    return [issue.code for issue in report.issues]


# --- Forgery helpers: an attacker holding a given K_chain (stdlib + canonical_json only) ---------


def reseal(record, material):
    record = copy.deepcopy(record)
    if record["envelope"] is not None:
        raw = canonical_json(record["envelope"])
        record["envelope_digest"] = hashlib.sha256(b"rig.audit-envelope-in-record/v2" + NUL + raw).hexdigest()
    pre = {k: v for k, v in record.items() if k not in ("record_digest", "chain_auth")}
    digest = hashlib.sha256(b"rig.audit-record/v2" + NUL + canonical_json(pre)).hexdigest()
    key_id = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"chain" + NUL + material).hexdigest()[:32]
    mac = hmac.new(material, b"rig.audit-chain-mac/v2" + NUL + key_id.encode() + NUL + digest.encode(),
                   hashlib.sha256).hexdigest()
    record["record_digest"] = digest
    record["chain_auth"] = {"algorithm": "HMAC-SHA256", "key_id": key_id, "mac": mac}
    return canonical_json(record) + b"\n"


def rechain(records, material):
    """Renumber and relink a single-segment chain and re-MAC every record."""
    out, prev = [], None
    for seq, record in enumerate(records):
        record = copy.deepcopy(record)
        record["chain"]["seq"], record["chain"]["prev_record_digest"] = seq, prev
        if record["kind"] == "segment_open" and seq == 0:
            key_id = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"chain" + NUL + material).hexdigest()[:32]
            record["body"]["chain_key_id"] = key_id
        line = reseal(record, material)
        prev = json.loads(line)["record_digest"]
        out.append(line)
    return out


def loaded(lines):
    return [json.loads(line) for line in lines]


# --- Valid chains ------------------------------------------------------------------------------


def test_a_well_formed_chain_is_valid_and_authenticated():
    chain = Chain().event().event(**APPROVAL).event().marker().close().open(rec.OpenReason.ROTATION).event()
    report = verify(chain.lines)
    assert report.status is ChainStatus.CHAIN_VALID and report.issues == ()
    assert report.authenticated and report.records == 8 and report.segments == 2
    assert report.last_seq == 7 and report.last_record_digest == json.loads(chain.lines[-1])["record_digest"]
    assert verify(chain.lines, expected_chain_id=CHAIN_ID).status is ChainStatus.CHAIN_VALID


def test_unlinked_epoch_segments_verify_with_the_explicit_unlinked_epoch():
    chain = Chain(epoch=ProjectionEpoch.unlinked()).event().event()
    assert verify(chain.lines).status is ChainStatus.CHAIN_VALID


def test_only_the_genesis_record_is_valid():
    assert verify(Chain().lines).status is ChainStatus.CHAIN_VALID


def test_tail_truncation_is_not_detectable_from_the_lines_alone():
    # Documented limitation: without the anchor (C3/C4) or an external checkpoint, a chain cut
    # after any record still verifies. verify_chain never claims more than CHAIN_VALID.
    chain = Chain().event().event().event()
    truncated = chain.lines[:2]
    report = verify(truncated)
    assert report.status is ChainStatus.CHAIN_VALID
    assert report.last_seq == 1 != json.loads(chain.lines[-1])["chain"]["seq"]


# --- Structure-only and missing keys (F9) -------------------------------------------------------


def test_structure_only_mode_is_never_valid():
    chain = Chain().event().event()
    report = verify_chain(chain.lines, chain_keys={}, auth_keys={})
    assert report.status is ChainStatus.UNVERIFIABLE and not report.authenticated


@pytest.mark.parametrize("missing", ["chain", "auth"])
def test_a_missing_key_makes_the_chain_unverifiable(missing):
    chain = Chain().event()
    kwargs = rings()
    kwargs["chain_keys" if missing == "chain" else "auth_keys"] = {}
    report = verify_chain(chain.lines, **kwargs)
    assert report.status is ChainStatus.UNVERIFIABLE and not report.authenticated


def test_structure_damage_still_wins_over_missing_keys():
    lines = Chain().event().event().lines
    report = verify_chain([lines[0], lines[2]], chain_keys={}, auth_keys={})
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEQUENCE_GAP in codes(report)


def test_empty_input_is_unverifiable():
    report = verify([])
    assert report.status is ChainStatus.UNVERIFIABLE and codes(report) == [StorageErrorCode.EMPTY_CHAIN]


# --- Manipulation of stored lines ----------------------------------------------------------------


def test_deleted_middle_record_is_detected():
    lines = Chain().event().event().event().lines
    report = verify(lines[:2] + lines[3:])
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.SEQUENCE_GAP]


def test_reordered_records_are_detected():
    lines = Chain().event().event().event().lines
    report = verify([lines[0], lines[2], lines[1], lines[3]])
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEQUENCE_GAP in codes(report)


def test_replayed_record_is_detected():
    lines = Chain().event().event().lines
    report = verify(lines + [lines[-1]])
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEQUENCE_GAP in codes(report)


def test_record_from_another_chain_position_breaks_the_link():
    a = Chain().event().event().lines
    b = Chain().event(**APPROVAL).event().lines
    report = verify(a[:2] + b[2:])
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.LINK_BROKEN in codes(report)


@pytest.mark.parametrize(
    "damage, expected",
    [
        (lambda line: line[:-1], StorageErrorCode.PARTIAL_LINE),
        (lambda line: line[:40] + b"\n", StorageErrorCode.UNTERMINATED),
        (lambda line: b"\n", StorageErrorCode.MALFORMED_JSON),
        (lambda line: b"[" * 64 + b"]" * 64 + b"\n", StorageErrorCode.DEPTH_EXCEEDED),
        (lambda line: line.replace(b'"seq":2', b'"seq":3'), StorageErrorCode.DIGEST_MISMATCH),
        (lambda line: line.replace(b'"kind":"event"', b'"kind":"evnt"'), StorageErrorCode.SCHEMA_INVALID),
    ],
    ids=["partial", "cut", "empty-line", "deep", "seq-edit", "kind-edit"],
)
def test_damaged_lines_are_reported_with_their_own_code(damage, expected):
    lines = Chain().event().event().event().lines
    lines[2] = damage(lines[2])
    report = verify(lines)
    assert report.status is ChainStatus.DAMAGED and report.issues[0].code is expected and report.issues[0].index == 2


def test_wrong_chain_mac_is_mac_invalid_not_malformed():
    lines = Chain().event().event().lines
    record = json.loads(lines[1])
    record["chain_auth"]["mac"] = "0" * 64
    lines[1] = canonical_json(record) + b"\n"
    report = verify(lines)
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.MAC_INVALID]


def test_expected_chain_id_mismatch():
    report = verify(Chain().event().lines, expected_chain_id="d2" * 16)
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.CHAIN_ID_MISMATCH in codes(report)


def test_chain_id_switch_inside_a_chain_is_detected():
    records = loaded(Chain().event().event().lines)
    records[2]["chain"]["chain_id"] = "d2" * 16
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.CHAIN_ID_MISMATCH]


@pytest.mark.parametrize("field, value", [("segment", 3), ("writer", {"record_schema": "rig.audit-record/v1",
                                                                       "rig_sentinel_version": "0.1.0"})])
def test_header_body_must_match_its_position_and_schema(field, value):
    records = loaded(Chain().event().lines)
    records[0]["body"][field] = value
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and report.issues[0].code is StorageErrorCode.SCHEMA_INVALID


def test_first_record_must_be_genesis():
    lines = Chain().event().event().lines
    report = verify(lines[1:])
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.GENESIS_INVALID in codes(report)


# --- Key-compromise simulations (Arch. section 2.5) ------------------------------------------------


def test_k_auth_only_attacker_cannot_insert_records():
    # Holds K_auth (can make gate-compliant projections) but not K_chain: any record it appends
    # or inserts carries a chain MAC under a key the verifier doesn't trust for this segment.
    chain = Chain().event()
    forged_v = validated()
    attacker = Chain(key=chain_key(ATTACKER_CHAIN_MATERIAL))
    attacker.lines = list(chain.lines)
    attacker.event(forged_v)
    report = verify(attacker.lines)
    assert report.status is ChainStatus.DAMAGED
    assert StorageErrorCode.KEY_CHANGE_INVALID in codes(report)
    report_with_attacker_key = verify(attacker.lines, chain_key(), chain_key(ATTACKER_CHAIN_MATERIAL))
    assert report_with_attacker_key.status is ChainStatus.DAMAGED


def test_k_auth_only_attacker_cannot_rewrite_a_stored_record():
    lines = Chain().event().event().lines
    record = json.loads(lines[1])
    record["envelope"]["projection"]["engine"]["matched_rule_count"] += 1
    lines[1] = canonical_json(record) + b"\n"  # stale digests and MAC
    assert verify(lines).status is ChainStatus.DAMAGED


def test_k_chain_only_attacker_can_delete_and_rechain_but_not_change_content():
    original = Chain().event().event().event()
    records = loaded(original.lines)
    shortened = rechain(records[:2] + records[3:], CHAIN_MATERIAL)
    report = verify(shortened)
    # Local verification passes: documented. Only a prior external checkpoint reveals it (C4).
    assert report.status is ChainStatus.CHAIN_VALID
    checkpoint = rec.verify_checkpoint(
        rec.build_checkpoint(chain_id=CHAIN_ID, segment=0, seq=3, record_digest=records[3]["record_digest"],
                             created_at=NOW, auth_key_id=auth_key().key_id, anchor_generation=3,
                             chain_key=chain_key()),
        {chain_key().key_id: chain_key()})
    assert (report.last_seq, report.last_record_digest) != (checkpoint.seq, checkpoint.record_digest)

    # Changing projection content needs K_auth: the P2 MAC fails even after re-chaining.
    tampered = copy.deepcopy(records)
    tampered[1]["envelope"]["projection"]["engine"]["matched_rule_count"] += 1  # schema-valid change
    report = verify(rechain(tampered, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.PROJECTION_AUTH_FAILED in codes(report)


def test_attacker_with_k_chain_cannot_smuggle_privacy_violations():
    records = loaded(Chain().event(**APPROVAL).lines)
    for injected in ({"request_digest": "a1" * 32}, {"eligible_approvers": ["oncall-lead"]}):
        tampered = copy.deepcopy(records)
        tampered[1]["envelope"]["projection"]["engine"].update(injected)
        report = verify(rechain(tampered, CHAIN_MATERIAL))
        assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.PRIVACY_DAMAGE]


def test_gate_privacy_refusal_after_the_closed_schema_is_privacy_damage():
    # A schema-valid identifier field carrying a 64-hex value passes the closed P2 schema but is
    # refused by the gate's deep privacy scan (FORBIDDEN_FIELD), before any MAC check.
    records = loaded(Chain().event().lines)
    records[1]["envelope"]["projection"]["engine"]["policy_id"] = "a1" * 32
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.PRIVACY_DAMAGE]


def test_readable_label_restriction_is_privacy_damage():
    lines = Chain().event(labels=["untrusted_content_present"]).lines
    assert verify(lines).status is ChainStatus.CHAIN_VALID
    report = verify(lines, readable_labels=frozenset())
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.PRIVACY_DAMAGE]


def test_epoch_swap_in_the_header_is_detected():
    records = loaded(Chain().event().lines)
    records[0]["body"]["epoch"] = {"engine_ref_key_id": None, "engine_ref_mode": "unlinked", "ref_key_id": None}
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.EPOCH_MISMATCH in codes(report)


def test_header_naming_another_auth_key_is_detected():
    records = loaded(Chain().event().lines)
    records[0]["body"]["auth_key_id"] = auth2().key_id
    lines = rechain(records, CHAIN_MATERIAL)
    assert verify(lines).status is ChainStatus.UNVERIFIABLE  # that K_auth isn't configured
    report = verify(lines, auths=(auth_key(), auth2()))
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.KEY_CHANGE_INVALID in codes(report)


# --- Segments and rotation -----------------------------------------------------------------------


def test_chain_key_rotation_across_segments():
    chain = Chain().event().close(rec.CloseReason.CHAIN_KEY_ROTATION)
    chain.key = chain_key(NEW_CHAIN_MATERIAL)
    chain.open(rec.OpenReason.CHAIN_KEY_ROTATION).event()
    both = (chain_key(), chain_key(NEW_CHAIN_MATERIAL))
    assert verify(chain.lines, *both).status is ChainStatus.CHAIN_VALID
    retired_missing = verify(chain.lines, chain_key(NEW_CHAIN_MATERIAL))
    assert retired_missing.status is ChainStatus.UNVERIFIABLE
    assert StorageErrorCode.UNKNOWN_KEY in codes(retired_missing)


def test_auth_key_rotation_across_segments():
    chain = Chain().event().close(rec.CloseReason.KEY_ROTATION)
    chain.auth = auth2()
    chain.open(rec.OpenReason.KEY_ROTATION).event()
    assert verify(chain.lines, auths=(auth_key(), auth2())).status is ChainStatus.CHAIN_VALID
    assert verify(chain.lines).status is ChainStatus.UNVERIFIABLE


def test_epoch_rotation_across_segments():
    chain = Chain().event().close(rec.CloseReason.EPOCH_ROTATION)
    chain.epoch = ProjectionEpoch.unlinked()
    chain.open(rec.OpenReason.EPOCH_ROTATION).event()
    assert verify(chain.lines).status is ChainStatus.CHAIN_VALID


@pytest.mark.parametrize(
    "close_reason, open_reason, change",
    [
        (rec.CloseReason.SIZE, rec.OpenReason.ROTATION, "chain"),
        (rec.CloseReason.KEY_ROTATION, rec.OpenReason.KEY_ROTATION, "chain"),
        (rec.CloseReason.SIZE, rec.OpenReason.ROTATION, "epoch"),
        (rec.CloseReason.SIZE, rec.OpenReason.KEY_ROTATION, "auth"),
    ],
    ids=["chain-key-on-plain-rotation", "chain-key-on-auth-rotation", "epoch-on-plain-rotation",
         "reason-mismatch"],
)
def test_key_or_epoch_changes_need_the_matching_rotation(close_reason, open_reason, change):
    chain = Chain().event().close(close_reason)
    if change == "chain":
        chain.key = chain_key(NEW_CHAIN_MATERIAL)
    elif change == "epoch":
        chain.epoch = ProjectionEpoch.unlinked()
    else:
        chain.auth = auth2()
    chain.open(open_reason).event()
    report = verify(chain.lines, chain_key(), chain_key(NEW_CHAIN_MATERIAL), auths=(auth_key(), auth2()))
    assert report.status is ChainStatus.DAMAGED
    assert {StorageErrorCode.KEY_CHANGE_INVALID, StorageErrorCode.SEGMENT_INVALID} & set(codes(report))


def test_records_after_a_segment_close_are_rejected():
    chain = Chain().event().close()
    chain.event()
    report = verify(chain.lines)
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEGMENT_INVALID in codes(report)


def test_rotation_without_a_close_is_rejected():
    chain = Chain().event().open(rec.OpenReason.ROTATION).event()
    report = verify(chain.lines)
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEGMENT_INVALID in codes(report)


def test_wrong_close_count_is_rejected():
    records = loaded(Chain().event().close().lines)
    records[2]["body"]["record_count"] = 2
    report = verify(rechain(records, CHAIN_MATERIAL))
    assert report.status is ChainStatus.DAMAGED and StorageErrorCode.SEGMENT_INVALID in codes(report)


def _recovery(chain, kind=rec.DamageKind.PARTIAL_LINE):
    return rec.RecoveryInfo(damaged_segment=chain.segment, damage_kind=kind, last_valid_seq=chain.seq - 1,
                            last_valid_record_digest=chain.prev, discarded_bytes=17, invalid_lines=0,
                            unconfirmed_seqs=())


def test_recovery_segment_is_discontinuous():
    chain = Chain().event()
    chain.open(rec.OpenReason.RECOVERY, recovery=_recovery(chain)).event()
    report = verify(chain.lines)
    assert report.status is ChainStatus.DISCONTINUOUS and codes(report) == [StorageErrorCode.RECOVERY_RECORDED]


def test_recovery_may_skip_an_incomplete_segment_header():
    chain = Chain().event()
    chain.open(rec.OpenReason.RECOVERY, recovery=_recovery(chain, rec.DamageKind.HEADER_INCOMPLETE), segment=2)
    assert verify(chain.lines).status is ChainStatus.DISCONTINUOUS


def test_anchor_reinitialization_is_discontinuous_never_valid():
    chain = Chain().event()
    chain.open(rec.OpenReason.ANCHOR_REINITIALIZED, recovery=_recovery(chain, rec.DamageKind.ANCHOR_MISSING)).event()
    report = verify(chain.lines)
    assert report.status is ChainStatus.DISCONTINUOUS
    assert codes(report) == [StorageErrorCode.ANCHOR_REINITIALIZED]


def test_duplicate_event_id_within_a_segment_is_rejected():
    v = validated()
    chain = Chain().event(v).event(v)
    report = verify(chain.lines)
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.DUPLICATE_EVENT_ID]


def test_same_event_id_in_a_later_segment_is_not_reported_here():
    v = validated()
    chain = Chain().event(v).close().open(rec.OpenReason.ROTATION).event(v)
    assert verify(chain.lines).status is ChainStatus.CHAIN_VALID  # cross-segment duplicates: C3/C4


# --- Bounds and configuration ------------------------------------------------------------------


def test_issue_count_is_bounded():
    lines = Chain().lines + [b"x\n"] * 50
    report = verify(lines, max_issues=10)
    assert len(report.issues) == 11 and report.issues[-1].code is StorageErrorCode.TOO_MANY_ISSUES
    assert report.status is ChainStatus.DAMAGED


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (dict(chain_keys=None), StorageErrorCode.KEYRING_INVALID),
        (dict(chain_keys={"x": chain_key()}), StorageErrorCode.KEYRING_INVALID),
        (dict(chain_keys={auth_key().key_id: auth_key()}), StorageErrorCode.KEYRING_INVALID),
        (dict(auth_keys={chain_key().key_id: chain_key()}), StorageErrorCode.KEYRING_INVALID),
        (dict(auth_keys=[auth_key()]), StorageErrorCode.KEYRING_INVALID),
        (dict(chain_keys={(k := AuditKey.from_bytes(KeyPurpose.CHAIN, AUTH_MATERIAL)).key_id: k}),
         StorageErrorCode.KEYS_NOT_INDEPENDENT),
        (dict(max_issues=0), StorageErrorCode.INPUT_TYPE_INVALID),
        (dict(max_issues=True), StorageErrorCode.INPUT_TYPE_INVALID),
        (dict(expected_chain_id="C1" * 16), StorageErrorCode.INPUT_TYPE_INVALID),
        (dict(readable_labels=["x"]), StorageErrorCode.INPUT_TYPE_INVALID),
    ],
    ids=["chain-none", "chain-wrong-id", "chain-auth-purpose", "auth-chain-purpose", "auth-list", "dependent",
         "zero-issues", "bool-issues", "upper-chain-id", "labels-list"],
)
def test_configuration_errors_raise(kwargs, expected):
    args = rings()
    args.update(kwargs)
    with pytest.raises(StorageError) as info:
        verify_chain(Chain().lines, **args)
    assert info.value.code is expected and info.value.__context__ is None


def test_lines_must_be_a_list_or_tuple():
    lines = Chain().lines
    with pytest.raises(StorageError) as info:
        verify_chain(iter(lines), **rings())
    assert info.value.code is StorageErrorCode.INPUT_TYPE_INVALID
    assert verify_chain(tuple(lines), **rings()).status is ChainStatus.CHAIN_VALID


def test_non_bytes_line_is_reported_not_raised():
    lines = Chain().event().lines
    report = verify([lines[0], lines[1].decode("ascii")])
    assert report.status is ChainStatus.DAMAGED and codes(report) == [StorageErrorCode.INPUT_TYPE_INVALID]


# --- Privacy and purity ---------------------------------------------------------------------------


def test_reports_contain_no_content_or_key_material():
    chain = Chain().event(**APPROVAL).event()
    lines = list(chain.lines)
    lines[2] = lines[2][:-1]
    report = verify(lines)
    text = repr(report)
    for secret in (CHAIN_MATERIAL.hex(), AUTH_MATERIAL.hex(), "helpdesk", "oncall", "database_write"):
        assert secret not in text
    envelope = json.loads(chain.lines[1])["envelope"]
    assert envelope["projection_digest"] not in text and envelope["auth"]["mac"] not in text


def test_building_and_verifying_perform_no_file_or_network_io(monkeypatch):
    v = validated(**APPROVAL)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("I/O attempted")

    for target, name in ((builtins, "open"), (io, "open"), (pathlib.Path, "open"), (socket, "socket"),
                         (socket, "create_connection")):
        monkeypatch.setattr(target, name, forbidden)
    chain = Chain().event(v).marker().close().open(rec.OpenReason.ROTATION)
    anchor = rec.build_anchor(chain_id=CHAIN_ID, segment=1, seq=chain.seq - 1, record_digest=chain.prev,
                              auth_key_id=auth_key().key_id, generation=1, chain_key=chain_key())
    rec.verify_anchor(anchor, {chain_key().key_id: chain_key()})
    assert verify(chain.lines).status is ChainStatus.CHAIN_VALID


def test_event_lines_carry_validated_bytes_verbatim_across_the_whole_chain():
    vs = [validated(**APPROVAL), validated(), validated(unlinked=False)]
    chain = Chain()
    for v in vs:
        chain.event(v)
    for v, line in zip(vs, chain.lines[1:], strict=True):
        parsed = rec.parse_record(line)
        assert parsed.envelope_bytes == v.canonical and line.count(v.canonical) == 1
