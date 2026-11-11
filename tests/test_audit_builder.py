"""M2-B builder: provenance, consistency, privacy minimization, canaries, M1 invariance."""

import dataclasses
import json
from collections.abc import Mapping

import pytest
from audit_fixtures import (
    CANARY,
    FIXED_AUDIT_NOW,
    auth_key,
    both_keys,
    builder,
    counter_ids,
    evaluated,
    ref_key,
)
from policy_fixtures import BASELINE_POLICY, baseline_engine, fixed_clock, make_request

from rig_sentinel.audit import (
    AuditError,
    AuditErrorCode,
    AuditEventBuilder,
    AuditKeys,
    RedactionMode,
    RequestConsistency,
)
from rig_sentinel.audit.chain import pseudonym
from rig_sentinel.policy import Decision, PolicyEngine, ReasonCode, load_policy_text
from rig_sentinel.policy.decision import FALLBACK_DENY

ESC = chr(0x1B)
RLO = chr(0x202E)
ZWSP = chr(0x200B)


def _all_text(envelope, *extra):
    parts = [envelope.canonical_bytes().decode("ascii"), repr(envelope), str(envelope)]
    parts.extend(repr(item) for item in extra)
    return "\n".join(parts)


# --- Provenance and consistency --------------------------------------------------


def test_consistent_request_records_engine_and_caller_sections():
    request, record = evaluated()
    event = builder().build(record, request)
    assert event.engine.decision is Decision.ALLOW
    assert event.engine.reason_code is ReasonCode.RULE_ALLOW
    assert event.engine.decision_ref == record.decision_digest
    assert event.engine.policy_sha256 == record.policy_sha256
    assert event.engine.enforced is False
    assert event.caller.consistency is RequestConsistency.CONSISTENT
    assert event.caller.agent_id == "support-bot"
    assert event.caller.assurance_claim.value == "authenticated"  # a claim, not a verification
    assert event.caller.tool_id == "mcp://helpdesk/tickets.get"
    assert event.audit.recorded_at == "2026-11-10T12:00:00.123456Z"
    assert event.audit.event_id == f"{1:032x}" and event.audit.correlation_id == f"{2:032x}"


def test_invalid_request_records_no_caller_claims():
    request, record = evaluated(resource="fs:/srv/../etc/" + CANARY)
    event = builder().build(record, request)
    assert record.reason_code is ReasonCode.INVALID_RESOURCE
    assert event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert event.caller.resource is None and event.caller.agent_id is None


def test_policy_unavailable_is_not_applicable():
    request = make_request()
    record = PolicyEngine(None, clock=fixed_clock).evaluate(request)
    event = builder().build(record, request)
    assert event.caller.consistency is RequestConsistency.NOT_APPLICABLE
    assert event.engine.policy_id is None and event.caller.agent_id is None


def test_request_changed_after_evaluation_is_a_mismatch():
    request, record = evaluated()
    changed = dict(request, operation="write")
    event = builder().build(record, changed)
    assert event.caller.consistency is RequestConsistency.MISMATCH
    assert event.caller.agent_id is None and event.caller.resource is None


def test_hostile_mapping_that_changes_between_reads_is_a_mismatch():
    request, record = evaluated()

    class Shifting(Mapping):
        def __init__(self):
            self.reads = 0
            self.base = request

        def __getitem__(self, key):
            self.reads += 1
            if key == "resource":
                return "db:helpdesk/other"
            return self.base[key]

        def __iter__(self):
            return iter(self.base)

        def __len__(self):
            return len(self.base)

    event = builder().build(record, Shifting())
    assert event.caller.consistency is RequestConsistency.MISMATCH


def test_hostile_request_exceptions_do_not_leak():
    hostile = type("Leak" + chr(10) + CANARY + ESC + "[31m", (Exception,), {})

    class Raising(Mapping):
        def __getitem__(self, key):
            raise hostile(CANARY)

        def __iter__(self):
            raise hostile(CANARY)

        def __len__(self):
            return 5

    request = Raising()
    record = baseline_engine().evaluate(request)
    envelope = builder().build_envelope(record, request)
    assert envelope.event.engine.error_class == "UnlistedError"
    assert envelope.event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert CANARY not in _all_text(envelope)


def test_base_exceptions_from_the_request_propagate():
    class Interrupting(Mapping):
        def __getitem__(self, key):
            raise KeyboardInterrupt

        def __iter__(self):
            raise KeyboardInterrupt

        def __len__(self):
            return 5

    _, record = evaluated()
    with pytest.raises(KeyboardInterrupt):
        builder().build(record, Interrupting())


# --- Records: only genuine, internally consistent M1 records ---------------------------


def test_forged_record_with_wrong_digest_is_rejected():
    request, record = evaluated()
    forged = dataclasses.replace(record, decision=Decision.DENY)  # digest no longer matches
    with pytest.raises(AuditError) as info:
        builder().build(forged, request)
    assert info.value.code is AuditErrorCode.RECORD_INCONSISTENT


def test_record_claiming_enforcement_is_rejected():
    request, record = evaluated()
    object.__setattr__(record, "enforced", True)
    with pytest.raises(AuditError):
        builder().build(record, request)


@pytest.mark.parametrize("bad", [None, {}, "record", 1])
def test_non_record_inputs_are_rejected(bad):
    with pytest.raises(AuditError) as info:
        builder().build(bad, make_request())
    assert info.value.code is AuditErrorCode.INVALID_RECORD


@pytest.mark.parametrize(
    "error_type",
    ["Leak" + chr(10) + CANARY, CANARY, "NotABuiltinError", "ValueError" + CANARY, "x" * 80],
    ids=["newline+canary", "canary", "custom", "builtin+suffix", "long"],
)
def test_self_consistent_record_with_hostile_error_type_is_mapped(error_type):
    # A record built outside the engine can carry any error_type and still have a
    # matching decision_digest; the builder must not trust it.
    from rig_sentinel.policy.decision import make_record

    forged = make_record(
        decision=Decision.DENY, reason_code=ReasonCode.EVALUATION_ERROR,
        deciding_rule_ids=(), matched_rule_ids=(), policy_id=None, policy_version=None,
        policy_sha256=None, request_digest=None, evaluated_at=None, protected=True,
        error_type=error_type,
    )
    envelope = builder().build_envelope(forged, make_request())
    assert envelope.event.engine.error_class == "UnlistedError"
    assert CANARY not in _all_text(envelope)


def test_fallback_record_is_accepted_with_internal_error_class():
    event = builder().build(FALLBACK_DENY, make_request())
    assert event.engine.error_class == "InternalError"
    assert event.engine.evaluated_at is None


def test_long_rule_lists_are_truncated_with_counts():
    rules = "\n".join(
        f'[[rules]]\nid = "r{i:04d}"\neffect = "allow"\nagents = ["support-bot"]\n'
        f'tools = ["mcp://helpdesk/tickets.get"]\noperations = ["read"]\nresources = ["db:helpdesk/tickets"]\n'
        for i in range(40)
    )
    policy_text = BASELINE_POLICY + "\n" + rules
    engine = PolicyEngine(load_policy_text(policy_text), clock=fixed_clock)
    request = make_request()
    record = engine.evaluate(request)
    event = builder().build(record, request)
    assert len(record.matched_rule_ids) > 32
    assert event.engine.matched_rule_count == len(record.matched_rule_ids)
    assert event.engine.matched_rule_ids == tuple(record.matched_rule_ids)[:32]


# --- Privacy: scoped vs no-ref-key ----------------------------------------------------


def test_scoped_mode_pseudonymizes_resource_and_ids():
    request, record = evaluated(session_id="s-1", request_id="r-1")
    event = builder().build(record, request)
    key = ref_key()
    assert event.audit.redaction_mode is RedactionMode.SCOPED
    assert event.audit.ref_key_id == key.key_id
    resource = event.caller.resource
    assert resource.kind.value == "db" and resource.depth == 1
    assert resource.authority_ref == pseudonym(key, "authority/db", "helpdesk")
    assert resource.resource_ref == pseudonym(key, "resource/db", "db:helpdesk/tickets")
    assert event.caller.session_ref == pseudonym(key, "session", "s-1")
    assert event.caller.request_ref == pseudonym(key, "request", "r-1")
    text = event.canonical_bytes().decode()
    # The tool id (policy vocabulary) may contain these words; the resource itself must not appear.
    for raw in ("db:helpdesk/tickets", "db:helpdesk", '"s-1"', '"r-1"'):
        assert raw not in text


def test_ids_that_already_look_like_pseudonyms_are_still_pseudonymized():
    raw_session, raw_request = "ab" * 16, "cd" * 16  # 32 hex chars: valid identifiers and valid hex32
    request, record = evaluated(session_id=raw_session, request_id=raw_request)
    event = builder().build(record, request)
    assert event.caller.session_ref == pseudonym(ref_key(), "session", raw_session) != raw_session
    assert event.caller.request_ref == pseudonym(ref_key(), "request", raw_request) != raw_request
    text = event.canonical_bytes().decode()
    assert raw_session not in text and raw_request not in text


def test_missing_ref_key_minimizes_safely():
    request, record = evaluated(session_id="s-1", request_id="r-1")
    event = builder(AuditKeys(auth=auth_key())).build(record, request)
    assert event.audit.redaction_mode is RedactionMode.NO_REF_KEY and event.audit.ref_key_id is None
    resource = event.caller.resource
    assert resource.authority_ref is None and resource.resource_ref is None
    assert resource.kind.value == "db" and resource.depth == 1
    assert event.caller.session_ref is None and event.caller.request_ref is None


def test_no_keys_at_all_still_produces_minimized_unauthenticated_events():
    request, record = evaluated()
    envelope = AuditEventBuilder(clock=lambda: FIXED_AUDIT_NOW, id_factory=counter_ids()).build_envelope(record, request)
    assert envelope.auth is None
    assert envelope.event.audit.redaction_mode is RedactionMode.NO_REF_KEY


def test_pseudonyms_are_stable_per_key_and_differ_across_keys():
    request, record = evaluated(session_id="s-1")
    first = builder().build(record, request).caller.session_ref
    again = builder().build(record, request).caller.session_ref
    other_keys = AuditKeys(
        ref=type(ref_key()).from_bytes(ref_key().purpose, bytes(range(150, 182))), auth=auth_key()
    )
    other = builder(other_keys).build(record, request).caller.session_ref
    assert first == again and first != other


# --- Synthetic-secret canaries ---------------------------------------------------------

CANARY_REQUESTS = {
    "session id": {"session_id": CANARY},
    "request id": {"request_id": CANARY},
    "url path token": {"resource": "url:https://app.example.com/reset/" + CANARY},
    "fs path": {"resource": "fs:/home/" + CANARY + "/notes.txt"},
    "secret name": {"resource": "secret:kv/" + CANARY},
    "label": {"labels": [CANARY]},
    "agent id": {"agent": CANARY},
}


@pytest.mark.parametrize("overrides", CANARY_REQUESTS.values(), ids=CANARY_REQUESTS.keys())
@pytest.mark.parametrize("keys", ["both", "auth-only"])
def test_canaries_never_appear_in_events_or_receipts(overrides, keys):
    from rig_sentinel.audit import MemorySink, keyring

    request, record = evaluated(**overrides)
    audit_keys = both_keys() if keys == "both" else AuditKeys(auth=auth_key())
    envelope = builder(audit_keys).build_envelope(record, request)
    sink = MemorySink(verify_keys=keyring([audit_keys.auth]))
    receipt = sink.append(envelope)
    assert receipt.stored
    assert CANARY not in _all_text(envelope, receipt, sink, sink.canonical_records(), sink.envelopes())
    assert CANARY.split("-")[-1] not in _all_text(envelope)


def test_credential_like_agent_ids_and_labels_are_dropped_and_counted():
    request, record = evaluated(agent="xoxb-1234-5678-abcd", labels=["reviewed", "sk-live-0000"])
    event = builder().build(record, request)
    assert event.caller.consistency is RequestConsistency.CONSISTENT
    assert event.caller.agent_id is None
    assert event.caller.labels == ("reviewed",)
    assert event.caller.redacted_fields == 2


# --- Hostile strings and Unicode ----------------------------------------------------

HOSTILE_VALUES = [
    "a" + chr(10) + "b", "a" + chr(13) + "b", "x" + ESC + "[2J", "bidi" + RLO + "evil", "zw" + ZWSP + "sp",
    "caf" + chr(0xE9), "nul" + chr(0) + "byte", '{"inject": true}', "a" * 5000, "x" + chr(0x2028) + "y",
]


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=lambda v: ascii(v)[:24])
@pytest.mark.parametrize("field", ["agent", "session_id", "resource", "labels"])
def test_hostile_strings_never_reach_events(field, value):
    overrides = {"labels": [value]} if field == "labels" else {field: value}
    if field == "resource":
        overrides = {"resource": "fs:/srv/" + value}
    request, record = evaluated(**overrides)
    envelope = builder().build_envelope(record, request)
    raw = envelope.canonical_bytes()
    raw.decode("ascii")  # pure ASCII, one line
    assert b"\n" not in raw and b"\r" not in raw
    assert value not in raw.decode("ascii")
    parsed = json.loads(raw)
    assert parsed["event"]["caller"]["consistency"] in {"invalid_request", "consistent"}


# --- Clocks and ids -------------------------------------------------------------------


@pytest.mark.parametrize(
    "clock",
    [lambda: "2026-11-10", lambda: FIXED_AUDIT_NOW.replace(tzinfo=None), lambda: (_ for _ in ()).throw(RuntimeError(CANARY))],
    ids=["string", "naive", "raises"],
)
def test_bad_audit_clocks_are_rejected_without_leaking(clock):
    request, record = evaluated()
    with pytest.raises(AuditError) as info:
        AuditEventBuilder(both_keys(), clock=clock).build(record, request)
    assert info.value.code is AuditErrorCode.INVALID_CLOCK
    assert CANARY not in str(info.value)


@pytest.mark.parametrize("bad_id", ["", "0" * 31, "Z" * 32, CANARY, 7, None])
def test_malformed_generated_ids_are_rejected(bad_id):
    request, record = evaluated()
    with pytest.raises(AuditError) as info:
        AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW, id_factory=lambda: bad_id).build(record, request)
    assert info.value.code is AuditErrorCode.INVALID_ID


def test_default_ids_are_random_hex():
    request, record = evaluated()
    events = [AuditEventBuilder(both_keys()).build(record, request) for _ in range(20)]
    ids = {event.audit.event_id for event in events}
    assert len(ids) == 20 and all(len(i) == 32 for i in ids)


def test_explicit_correlation_id_is_validated():
    request, record = evaluated()
    event = builder().build(record, request, correlation_id="c" * 32)
    assert event.audit.correlation_id == "c" * 32
    with pytest.raises(AuditError):
        builder().build(record, request, correlation_id="not-hex")


# --- M1 invariance -----------------------------------------------------------------------


REQUESTS = [
    {}, {"resource": "db:helpdesk/users"}, {"resource": "fs:/a/../b"},
    {"operation": "database_write", "tool": "mcp://helpdesk/tickets.update"},
    {"environment": "prod"}, {"tool": "mcp://helpdesk/tickets.delete"}, {"agent": None},
]


@pytest.mark.parametrize("overrides", REQUESTS, ids=lambda o: ",".join(o) or "default")
def test_auditing_does_not_change_m1_records(overrides):
    request = make_request(**overrides)
    plain = baseline_engine().evaluate(request)
    record = baseline_engine().evaluate(request)
    before = record.to_dict()
    builder().build_envelope(record, request)
    assert record.to_dict() == before == plain.to_dict()
    assert record.enforced is False


def test_builder_repr_never_shows_keys():
    text = repr(builder())
    assert "ref" in text or "scoped" in text
    for material in (bytes(range(1, 33)).hex(), bytes(range(33, 65)).hex()):
        assert material not in text
