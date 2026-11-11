"""M2-B remediation of Gemini findings H-1 (snapshot consistency) and H-2 (exception
boundaries), plus the redacted_fields bound. Synthetic values only."""

import traceback
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest
from audit_fixtures import CANARY, FIXED_AUDIT_NOW, both_keys, builder, counter_ids, evaluated
from policy_fixtures import make_request

from rig_sentinel.audit import AuditError, AuditErrorCode, AuditEventBuilder, RequestConsistency
from rig_sentinel.audit import builder as builder_module
from rig_sentinel.audit.validation import MAX_REDACTED_FIELDS
from rig_sentinel.policy import Decision, ReasonCode
from rig_sentinel.policy.canonical import DECISION_DIGEST_DOMAIN, digest
from rig_sentinel.policy.decision import make_record
from rig_sentinel.policy.model import MAX_REQUEST_LABELS


def _assert_clean_error(error, code):
    assert isinstance(error, AuditError)
    assert error.code is code
    assert error.__cause__ is None and error.__context__ is None  # no attacker exception attached
    rendered = "".join(traceback.format_exception(error)) + str(error) + repr(error)
    assert CANARY not in rendered


def _raises_clean(code, fn):
    with pytest.raises(AuditError) as info:
        fn()
    _assert_clean_error(info.value, code)


class _Trap:
    """Any use of this object fails loudly: it must never be read."""

    def __getattr__(self, name):
        raise AssertionError("record attribute was read after the snapshot")

    def __iter__(self):
        raise AssertionError("record attribute was iterated after the snapshot")

    def __eq__(self, other):
        raise AssertionError("record attribute was compared after the snapshot")

    __hash__ = None


def _with_snapshot(record, snapshot_factory):
    """Give a genuine record an instance-level to_dict (a hostile record object)."""
    calls = []

    def to_dict():
        calls.append(1)
        return snapshot_factory()

    object.__setattr__(record, "to_dict", to_dict)
    return calls


def _approval_record():
    request, record = evaluated(operation="database_write", tool="mcp://helpdesk/tickets.update")
    assert record.decision is Decision.REQUIRE_APPROVAL
    return request, record


def _redigest(body):
    body = dict(body)
    body.pop("decision_digest", None)
    body["decision_digest"] = digest(DECISION_DIGEST_DOMAIN, body)
    return body


# --- H-1: one snapshot, digest-checked, is the only source of engine data ---------------


def test_event_engine_data_comes_only_from_the_verified_snapshot():
    request, record = _approval_record()
    genuine = record.to_dict()
    calls = _with_snapshot(record, lambda: genuine)
    for field in ("decision", "reason_code", "deciding_rule_ids", "matched_rule_ids", "policy_id",
                  "policy_version", "policy_sha256", "request_digest", "evaluated_at", "protected",
                  "approval", "error_type", "engine_version", "record_schema", "decision_digest"):
        object.__setattr__(record, field, _Trap())
    event = builder().build(record, request)
    assert calls == [1]  # exactly one snapshot
    assert event.engine.decision.value == genuine["decision"]
    assert list(event.engine.approval.eligible_approvers) == genuine["approval"]["eligible_approvers"]
    assert event.engine.decision_ref == genuine["decision_digest"]
    assert event.caller.consistency is RequestConsistency.CONSISTENT


def test_fake_approver_attributes_cannot_enter_the_event():
    request, record = _approval_record()
    genuine = record.to_dict()
    _with_snapshot(record, lambda: genuine)

    class FakeApproval:
        eligible_approvers = ("attacker-approver",)
        request_binding_sha256 = "f" * 64
        ttl_seconds = 3600

    object.__setattr__(record, "approval", FakeApproval())
    event = builder().build(record, request)
    assert event.engine.approval.eligible_approvers == tuple(genuine["approval"]["eligible_approvers"])
    assert "attacker-approver" not in event.canonical_bytes().decode()


def test_conflicting_decision_attribute_is_ignored_in_favor_of_snapshot():
    request, record = evaluated()
    genuine = record.to_dict()  # ALLOW
    deny = _redigest(dict(genuine, decision="DENY", reason_code="RULE_DENY", deciding_rule_ids=[]))
    _with_snapshot(record, lambda: deny)
    event = builder().build(record, request)
    assert record.decision is Decision.ALLOW  # attribute says ALLOW...
    assert event.engine.decision is Decision.DENY  # ...the event follows the verified snapshot
    assert event.engine.decision_ref == deny["decision_digest"]


def test_snapshot_is_detached_from_mutable_nested_containers():
    request, record = _approval_record()
    genuine = record.to_dict()
    shared_approvers = list(genuine["approval"]["eligible_approvers"])
    snapshot = dict(genuine, approval=dict(genuine["approval"], eligible_approvers=shared_approvers))
    _with_snapshot(record, lambda: snapshot)
    event = builder().build(record, request)
    shared_approvers.append("late-approver")  # mutate after the build
    snapshot["decision"] = "ALLOW"
    assert "late-approver" not in event.engine.approval.eligible_approvers
    assert event.engine.decision is Decision.REQUIRE_APPROVAL


def test_dict_subclass_with_shifting_items_is_read_once():
    request, record = evaluated()
    genuine = record.to_dict()

    class Shifting(dict):
        reads = 0

        def items(self):
            Shifting.reads += 1
            if Shifting.reads > 1:
                return dict(self, decision="DENY").items()
            return super().items()

    _with_snapshot(record, lambda: Shifting(genuine))
    event = builder().build(record, request)
    assert event.engine.decision is Decision.ALLOW
    assert event.engine.decision_ref == genuine["decision_digest"]


def test_snapshot_digest_mismatch_is_rejected():
    request, record = evaluated()
    tampered = dict(record.to_dict(), decision="DENY")  # digest not recomputed
    _with_snapshot(record, lambda: tampered)
    _raises_clean(AuditErrorCode.RECORD_INCONSISTENT, lambda: builder().build(record, request))


MALFORMED = {
    "not a dict": lambda g: ["decision", "ALLOW"],
    "none": lambda g: None,
    "missing key": lambda g: _redigest({k: v for k, v in g.items() if k != "policy_id"}),
    "extra key": lambda g: _redigest(dict(g, raw_request={"token": CANARY})),
    "unknown decision": lambda g: _redigest(dict(g, decision="MAYBE")),
    "decision as int": lambda g: _redigest(dict(g, decision=1)),
    "rule ids not strings": lambda g: _redigest(dict(g, matched_rule_ids=[1, 2])),
    "rule ids not a list": lambda g: _redigest(dict(g, matched_rule_ids="read-tickets")),
    "enforced true": lambda g: _redigest(dict(g, enforced=True)),
    "protected as string": lambda g: _redigest(dict(g, protected="true")),
    "wrong record schema": lambda g: _redigest(dict(g, record_schema="rig.decision/v9")),
    "approval not a dict": lambda g: _redigest(dict(g, approval=["x"])),
    "canary in policy id": lambda g: _redigest(dict(g, policy_id="Bad Id " + CANARY)),
    "nan value": lambda g: dict(g, protected=float("nan")),
    "unserializable object": lambda g: dict(g, approval=object()),
    "decision digest not a string": lambda g: dict(g, decision_digest=12345),
}


@pytest.mark.parametrize("make", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_snapshots_are_rejected_with_closed_codes(make):
    request, record = evaluated()
    bad = make(record.to_dict())
    _with_snapshot(record, lambda: bad)
    with pytest.raises(AuditError) as info:
        builder().build(record, request)
    assert info.value.code in {AuditErrorCode.INVALID_RECORD, AuditErrorCode.RECORD_INCONSISTENT}
    _assert_clean_error(info.value, info.value.code)


def test_hostile_record_accessor_exception_is_closed():
    request, record = evaluated()
    hostile = type("Leak" + chr(10) + CANARY, (Exception,), {})

    def explode():
        raise hostile(CANARY)

    object.__setattr__(record, "to_dict", explode)
    _raises_clean(AuditErrorCode.INVALID_RECORD, lambda: builder().build(record, request))


def test_genuine_m1_records_still_build_unchanged():
    request, record = _approval_record()
    event = builder().build(record, request)
    assert event.engine.decision_ref == record.decision_digest
    assert event.engine.approval.eligible_approvers == record.approval.eligible_approvers
    assert event.engine.matched_rule_ids == record.matched_rule_ids


# --- H-2: exception boundaries for clocks, ids and unexpected failures -------------------


class _RaisingOffset(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("offset " + CANARY)

    def dst(self, dt):
        return timedelta(0)


class _BadOffsetType(tzinfo):
    def utcoffset(self, dt):
        return CANARY  # not a timedelta

    def dst(self, dt):
        return None


class _HostileDatetime(datetime):
    def astimezone(self, tz=None):
        raise RuntimeError("astimezone " + CANARY)

    def strftime(self, fmt):
        return CANARY


CLOCKS = {
    "tzinfo utcoffset raises": lambda: datetime(2026, 1, 1, tzinfo=_RaisingOffset()),
    "tzinfo returns a non-timedelta": lambda: datetime(2026, 1, 1, tzinfo=_BadOffsetType()),
    "hostile datetime subclass": lambda: _HostileDatetime(2026, 1, 1, tzinfo=UTC),
    "conversion overflows": lambda: datetime(9999, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=-12))),
    "naive datetime": lambda: datetime(2026, 1, 1),
    "not a datetime": lambda: CANARY,
    "custom exception class": lambda: (_ for _ in ()).throw(type("Clock" + CANARY, (Exception,), {})(CANARY)),
}


@pytest.mark.parametrize("clock", CLOCKS.values(), ids=CLOCKS.keys())
def test_clock_and_time_conversion_failures_are_invalid_clock(clock):
    request, record = evaluated()
    build = AuditEventBuilder(both_keys(), clock=clock, id_factory=counter_ids())
    _raises_clean(AuditErrorCode.INVALID_CLOCK, lambda: build.build(record, request))


def test_year_formatting_edge_never_escapes_the_boundary():
    request, record = evaluated()
    build = AuditEventBuilder(both_keys(), clock=lambda: datetime(1, 1, 1, tzinfo=UTC), id_factory=counter_ids())
    try:
        event = build.build(record, request)
    except AuditError as error:
        _assert_clean_error(error, AuditErrorCode.INVALID_CLOCK)
    else:
        assert event.audit.recorded_at.startswith("0001-")


IDS = {
    "raises": lambda: (_ for _ in ()).throw(RuntimeError(CANARY)),
    "str subclass": lambda: type("S", (str,), {})("a" * 32),
    "uppercase hex": lambda: "A" * 32,
    "canary": lambda: CANARY,
    "bytes": lambda: b"a" * 32,
}


@pytest.mark.parametrize("factory", IDS.values(), ids=IDS.keys())
def test_malformed_id_factories_are_invalid_id(factory):
    request, record = evaluated()
    build = AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW, id_factory=factory)
    _raises_clean(AuditErrorCode.INVALID_ID, lambda: build.build(record, request))


def test_unexpected_internal_failures_become_build_failed(monkeypatch):
    request, record = evaluated()

    def explode(*_args, **_kwargs):
        raise RuntimeError("internal " + CANARY)

    monkeypatch.setattr(builder_module.redaction, "minimize_resource", explode)
    _raises_clean(AuditErrorCode.BUILD_FAILED, lambda: builder().build(record, request))


def test_base_exceptions_still_propagate_from_clocks():
    request, record = evaluated()

    def interrupt():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        AuditEventBuilder(both_keys(), clock=interrupt).build(record, request)


# --- redacted_fields: reachable maximum and bound ---------------------------------------


def test_redaction_bound_covers_every_reachable_count():
    # agent_id (1) + tool_id (1) + at most MAX_REQUEST_LABELS unique labels.
    assert 2 + MAX_REQUEST_LABELS <= MAX_REDACTED_FIELDS


def test_maximum_reachable_redactions_are_counted_exactly():
    labels = [f"xoxb-{i:02d}-label" for i in range(MAX_REQUEST_LABELS)]
    request = make_request(agent="xoxb-agent-0001", tool="mcp://xoxb-server/tool", labels=labels)
    from policy_fixtures import baseline_engine

    record = baseline_engine().evaluate(request)
    assert record.reason_code is ReasonCode.UNKNOWN_TOOL and record.request_digest is not None
    event = builder().build(record, request)
    assert event.caller.consistency is RequestConsistency.CONSISTENT
    assert event.caller.redacted_fields == 2 + MAX_REQUEST_LABELS
    assert event.caller.agent_id is None and event.caller.tool_id is None and event.caller.labels == ()


def test_requests_above_the_m1_label_limit_never_reach_the_counter():
    labels = [f"xoxb-{i:02d}-label" for i in range(MAX_REQUEST_LABELS + 1)]
    request, record = evaluated(labels=labels)
    assert record.reason_code is ReasonCode.INVALID_REQUEST
    event = builder().build(record, request)
    assert event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert event.caller.redacted_fields == 0
