"""M2-B event and envelope models: closed schema, immutability, limits, tampering."""

import copy
import dataclasses
import json

import pytest
from audit_fixtures import auth_key, both_keys, builder, evaluated, ref_key

from rig_sentinel.audit import (
    AUDIT_ENVELOPE_SCHEMA,
    AUDIT_EVENT_SCHEMA,
    MAX_EVENT_BYTES,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEvent,
    AuditKeys,
    AuthStatus,
    envelope_from_dict,
    event_from_dict,
    keyring,
    verify_envelope_dict,
)
from rig_sentinel.audit.events import AuditSection, EngineSection, RedactionMode

RING = keyring([auth_key()])


def _envelope(keys=None, **request):
    req, record = evaluated(**request)
    return builder(keys).build_envelope(record, req)


def _as_dict(envelope):
    return json.loads(envelope.canonical_bytes())


# --- Round trip and schema versions ---------------------------------------------------


def test_round_trip_through_json_is_exact():
    envelope = _envelope()
    data = _as_dict(envelope)
    assert data["envelope_schema"] == AUDIT_ENVELOPE_SCHEMA
    assert data["event"]["schema_version"] == AUDIT_EVENT_SCHEMA
    rebuilt = envelope_from_dict(data)
    assert rebuilt == envelope
    assert rebuilt.canonical_bytes() == envelope.canonical_bytes()
    assert rebuilt.verify(RING) is AuthStatus.AUTHENTIC


def test_canonical_bytes_are_ascii_sorted_and_compact():
    raw = _envelope().canonical_bytes()
    raw.decode("ascii")
    assert b" " not in raw and b"\n" not in raw
    assert raw == json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.mark.parametrize("version", ["rig.audit-event/v1", "rig.audit-event/v3", "", None, 2])
def test_unsupported_event_schema_versions_are_rejected(version):
    data = _as_dict(_envelope())["event"]
    data["schema_version"] = version
    with pytest.raises(AuditError) as info:
        event_from_dict(data)
    assert info.value.code is AuditErrorCode.UNSUPPORTED_SCHEMA


def test_unsupported_envelope_schema_is_rejected():
    data = _as_dict(_envelope())
    data["envelope_schema"] = "rig.audit-envelope/v9"
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code is AuditErrorCode.UNSUPPORTED_SCHEMA


# --- Closed schema: unknown, missing and mistyped fields ------------------------------

SECTIONS = [(), ("event",), ("event", "audit"), ("event", "engine"), ("event", "caller"),
            ("event", "caller", "resource"), ("auth",)]


def _section(data, path):
    for key in path:
        data = data[key]
    return data


@pytest.mark.parametrize("path", SECTIONS, ids=lambda p: ".".join(p) or "envelope")
def test_unknown_fields_are_rejected_at_every_level(path):
    data = _as_dict(_envelope())
    _section(data, path)["raw_request"] = {"token": "x"}
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code is AuditErrorCode.UNKNOWN_FIELD


@pytest.mark.parametrize("path", SECTIONS, ids=lambda p: ".".join(p) or "envelope")
def test_missing_fields_are_rejected_at_every_level(path):
    data = _as_dict(_envelope())
    section = _section(data, path)
    section.pop(sorted(section)[0])
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code is AuditErrorCode.MISSING_FIELD


BAD_VALUES = {
    ("event", "audit", "event_id"): ["XYZ", "0" * 31, "0" * 33, "G" * 32, 1, None],
    ("event", "audit", "recorded_at"): ["2026-11-10 12:00:00", "2026-11-10T12:00:00Z", None],
    ("event", "audit", "redaction_mode"): ["full", "SCOPED", None],
    ("event", "engine", "decision"): ["allow", "PERMIT", None],
    ("event", "engine", "reason_code"): ["NOT_A_CODE", None],
    ("event", "engine", "enforced"): [True, 0, "false", None],
    ("event", "engine", "protected"): [1, "true", None],
    ("event", "engine", "decision_ref"): ["0" * 63, "Z" * 64, None],
    ("event", "engine", "deciding_rule_count"): [-1, True, 1.5, 10**9],
    ("event", "engine", "matched_rule_ids"): ["read-tickets", [1], ["B-Rule"], ["b", "a"], ["a", "a"]],
    ("event", "engine", "error_class"): ["bad name", "x" * 65, 7],
    ("event", "caller", "agent_id"): ["Support-Bot", "a b", "", 5],
    ("event", "caller", "consistency"): ["verified", None],
    ("event", "caller", "redacted_fields"): [-1, 65, None],
    ("auth",): ["x", 1],
}


@pytest.mark.parametrize(
    ("path", "value"),
    [(path, value) for path, values in BAD_VALUES.items() for value in values],
    ids=lambda x: repr(x)[:40],
)
def test_invalid_field_values_are_rejected(path, value):
    data = _as_dict(_envelope())
    parent = _section(data, path[:-1])
    parent[path[-1]] = value
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code in {
        AuditErrorCode.INVALID_FIELD, AuditErrorCode.LIMIT_EXCEEDED, AuditErrorCode.INCONSISTENT_EVENT
    }


def test_enforced_true_cannot_be_constructed():
    engine = _envelope().event.engine
    with pytest.raises(AuditError) as info:
        dataclasses.replace(engine, enforced=True)
    assert info.value.path == "engine.enforced"


def test_verified_is_not_a_consistency_value():
    data = _as_dict(_envelope())
    data["event"]["caller"]["consistency"] = "verified"
    with pytest.raises(AuditError):
        envelope_from_dict(data)


# --- Cross-field invariants ----------------------------------------------------------


def test_no_ref_key_mode_forbids_keyed_references():
    event = _envelope().event
    with pytest.raises(AuditError) as info:
        dataclasses.replace(
            event, audit=dataclasses.replace(event.audit, redaction_mode=RedactionMode.NO_REF_KEY, ref_key_id=None)
        )
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_claims_require_consistent_binding():
    event = _envelope(resource="fs:/a/../b").event  # invalid request: no claims recorded
    assert event.caller.consistency.value == "invalid_request"
    with pytest.raises(AuditError) as info:
        dataclasses.replace(event.caller, agent_id="support-bot")
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


# --- Immutability ------------------------------------------------------------------


def test_models_are_frozen():
    envelope = _envelope()
    for obj, field in ((envelope, "event_digest"), (envelope.event, "audit"),
                       (envelope.event.engine, "decision"), (envelope.event.caller, "agent_id")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, field, None)
    assert copy.deepcopy(envelope) == envelope


# --- Tampering ---------------------------------------------------------------------

MUTATIONS = [
    (("event", "engine", "decision"), "ALLOW", "DENY"),
    (("event", "engine", "reason_code"), "RULE_ALLOW", "RULE_DENY"),
    (("event", "engine", "policy_id"), "acme-support-agents", "other-policy"),
    (("event", "caller", "agent_id"), "support-bot", "ops-bot"),
    (("event", "audit", "recorded_at"), None, "2030-01-01T00:00:00.000000Z"),
    (("event", "caller", "redacted_fields"), 0, 1),
]


@pytest.mark.parametrize(("path", "expected", "new"), MUTATIONS, ids=lambda x: str(x)[:30])
def test_any_event_change_invalidates_digest_and_mac(path, expected, new):
    data = _as_dict(_envelope())
    parent = _section(data, path[:-1])
    if expected is not None:
        assert parent[path[-1]] == expected
    parent[path[-1]] = new
    assert verify_envelope_dict(data, RING) is AuthStatus.DIGEST_MISMATCH
    data["event_digest"] = AuditEvent.digest.fget(event_from_dict(data["event"]))  # attacker fixes the digest
    assert verify_envelope_dict(data, RING) is AuthStatus.MAC_MISMATCH


def test_tag_and_key_tampering_is_detected():
    data = _as_dict(_envelope())
    tampered_mac = dict(data, auth=dict(data["auth"], mac="0" * 64))
    assert verify_envelope_dict(tampered_mac, RING) is AuthStatus.MAC_MISMATCH
    unknown_key = dict(data, auth=dict(data["auth"], key_id="f" * 32))
    assert verify_envelope_dict(unknown_key, RING) is AuthStatus.UNKNOWN_KEY
    stripped = dict(data, auth=None)
    assert verify_envelope_dict(stripped, RING) is AuthStatus.UNAUTHENTICATED
    assert verify_envelope_dict({"not": "an envelope"}, RING) is AuthStatus.SCHEMA_INVALID


def test_wrong_auth_key_cannot_verify():
    other = AuditKeys(ref=ref_key(), auth=None)
    from rig_sentinel.audit import AuditKey, KeyPurpose

    wrong = AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(201, 233)))
    envelope = _envelope()
    forged = dict(_as_dict(envelope), auth=dict(_as_dict(envelope)["auth"], key_id=wrong.key_id))
    assert verify_envelope_dict(forged, {wrong.key_id: wrong}) is AuthStatus.MAC_MISMATCH
    assert _envelope(keys=other).auth is None  # no K_auth: unauthenticated by construction


def test_unauthenticated_envelope_verifies_only_as_unauthenticated():
    envelope = _envelope(keys=AuditKeys(ref=ref_key()))
    assert envelope.auth is None
    assert envelope.verify(RING) is AuthStatus.UNAUTHENTICATED


# --- Size and list limits ------------------------------------------------------------


def test_maximal_lists_fit_and_oversize_is_rejected():
    event = _envelope(operation="database_write", tool="mcp://helpdesk/tickets.update").event
    ids = tuple(sorted(f"rule-{i:03d}-" + "x" * 115 for i in range(32)))
    engine = dataclasses.replace(
        event.engine, deciding_rule_ids=ids, deciding_rule_count=1000, matched_rule_ids=ids,
        matched_rule_count=1000,
        approval=dataclasses.replace(event.engine.approval, eligible_approvers=ids, eligible_approver_count=100),
    )
    big = dataclasses.replace(event, engine=engine)
    assert len(big.canonical_bytes()) <= MAX_EVENT_BYTES
    assert AuditEnvelope.seal(big, auth_key()).verify(RING) is AuthStatus.AUTHENTIC
    with pytest.raises(AuditError) as info:
        dataclasses.replace(engine, matched_rule_ids=ids + ("zzz",))
    assert info.value.code is AuditErrorCode.LIMIT_EXCEEDED


def test_counts_cannot_understate_lists():
    engine = _envelope().event.engine
    with pytest.raises(AuditError) as info:
        dataclasses.replace(engine, matched_rule_count=0)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_event_has_no_persistence_or_enforcement_claims():
    flat = json.dumps(_as_dict(_envelope())).lower()
    for word in ("stored", "persisted", "saved", "durab", "executed", "blocked", "verified"):
        assert word not in flat
    assert _as_dict(_envelope())["event"]["engine"]["enforced"] is False


def test_sections_reject_wrong_types():
    event = _envelope().event
    with pytest.raises(AuditError):
        AuditEvent(audit=event.engine, engine=event.engine, caller=event.caller)
    with pytest.raises(AuditError):
        AuditSection(event_id="0" * 32, correlation_id="0" * 32, recorded_at="x",
                     redaction_mode=RedactionMode.SCOPED, ref_key_id="0" * 32)
    assert isinstance(event.engine, EngineSection)
    assert both_keys().auth is not None
