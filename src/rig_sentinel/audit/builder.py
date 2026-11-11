"""Build audit events from M1 decision records (M2-B).

:class:`AuditEventBuilder` never calls the policy engine and never changes the
record or the request.

**Record (H-1).** The builder calls ``record.to_dict()`` exactly once,
serializes that snapshot to canonical JSON once, and parses it back into
plain JSON values. That detached snapshot is the only source of engine data:

* its ``decision_digest`` must recompute from the snapshot itself;
* every engine field in the event (decision, rules, approval, policy
  identity, ``request_digest``, ...) is taken from the snapshot;
* no record attribute is read again.

So the event can never contain engine data that differs from what the digest
covers. A matching digest proves internal consistency only; it does not prove
that ``PolicyEngine`` produced the record (the digest is unkeyed).

**Request.** The request object that was passed to
``PolicyEngine.evaluate()`` is untrusted. It is re-parsed with M1's own
parser, and caller fields are recorded only when the result reproduces the
snapshot's ``request_digest`` (``consistent``). That proves the fields match
what was evaluated; it does not prove who the caller is. Re-parsing runs the
code of a hostile request object a second time (see docs/AUDIT.md).

**Exception boundary (H-2).** Every call into caller-supplied code (record,
request, clock, id factory) happens inside an ``except Exception`` boundary.
Failures become closed :class:`AuditError` codes (``INVALID_RECORD``,
``INVALID_CLOCK``, ``INVALID_ID``, or ``BUILD_FAILED`` for anything
unexpected), raised *outside* the handler so no attacker-controlled exception
is attached as ``__cause__`` or ``__context__``. ``BaseException``
(``KeyboardInterrupt``, ``SystemExit``) propagates, as in M1.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from rig_sentinel.audit import redaction
from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.audit.events import (
    ApprovalSection,
    AuditEnvelope,
    AuditEvent,
    AuditSection,
    CallerSection,
    EngineSection,
    RedactionMode,
    RequestConsistency,
)
from rig_sentinel.audit.keys import AuditKeys
from rig_sentinel.audit.validation import (
    MAX_COUNT,
    MAX_LIST_ITEMS,
    require_hex32,
    require_identifier,
    require_timestamp,
)
from rig_sentinel.policy.canonical import (
    DECISION_DIGEST_DOMAIN,
    REQUEST_DIGEST_DOMAIN,
    canonical_json,
    digest,
)
from rig_sentinel.policy.decision import DECISION_RECORD_SCHEMA, DecisionRecord
from rig_sentinel.policy.engine import coerce_request
from rig_sentinel.policy.model import AuthorizationRequest, Decision
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.schema import SCHEMA_VERSION

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_RECORD_FIELDS = frozenset(
    {
        "record_schema", "decision", "reason_code", "deciding_rule_ids", "matched_rule_ids",
        "policy_id", "policy_version", "policy_sha256", "schema_version", "engine_version",
        "request_digest", "evaluated_at", "protected", "approval", "error_type", "enforced",
        "decision_digest",
    }
)
_APPROVAL_FIELDS = frozenset({"eligible_approvers", "request_binding_sha256", "ttl_seconds"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return secrets.token_hex(16)


def _invalid_record(path: str = "record") -> AuditError:
    return AuditError(AuditErrorCode.INVALID_RECORD, path)


def _record_snapshot(record: object) -> dict[str, Any]:
    """Read ``record`` once and return a detached, digest-checked snapshot."""
    if type(record) is not DecisionRecord:
        raise _invalid_record()
    data: object = None
    failed = False
    try:
        raw = canonical_json(record.to_dict())  # the only read of the record
        data = json.loads(raw)  # detached: plain dict, list, str, int, bool, None
    except Exception:
        failed = True
    if failed:
        raise _invalid_record()
    if type(data) is not dict or set(data) != _RECORD_FIELDS:
        raise _invalid_record()
    claimed = data["decision_digest"]
    body = {key: value for key, value in data.items() if key != "decision_digest"}
    if type(claimed) is not str or claimed != digest(DECISION_DIGEST_DOMAIN, body):
        raise AuditError(AuditErrorCode.RECORD_INCONSISTENT, "engine.decision_ref")
    return data


def _enum_from(enum_type: Any, value: object, path: str) -> Any:
    if type(value) is not str:
        raise _invalid_record(path)
    try:
        return enum_type(value)
    except ValueError:
        pass
    raise _invalid_record(path)


def _identifier_list(value: object, path: str) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_COUNT:
        raise _invalid_record(path)
    items = tuple(value)
    for item in items:
        require_identifier(item, path)
    if list(items) != sorted(set(items)):
        raise _invalid_record(path)
    return items


def _engine_section(data: dict[str, Any]) -> EngineSection:
    """Build the engine section from the verified snapshot only."""
    if data["record_schema"] != DECISION_RECORD_SCHEMA or type(data["record_schema"]) is not str:
        raise _invalid_record("engine.record_schema")
    if data["schema_version"] != SCHEMA_VERSION or type(data["schema_version"]) is not str:
        raise _invalid_record("record.schema_version")
    deciding = _identifier_list(data["deciding_rule_ids"], "engine.deciding_rule_ids")
    matched = _identifier_list(data["matched_rule_ids"], "engine.matched_rule_ids")

    approval = None
    raw_approval = data["approval"]
    if raw_approval is not None:
        if type(raw_approval) is not dict or set(raw_approval) != _APPROVAL_FIELDS:
            raise _invalid_record("engine.approval")
        approvers = _identifier_list(raw_approval["eligible_approvers"], "engine.approval.eligible_approvers")
        approval = ApprovalSection(
            eligible_approvers=approvers[:MAX_LIST_ITEMS],
            eligible_approver_count=len(approvers),
            request_binding_sha256=raw_approval["request_binding_sha256"],
            ttl_seconds=raw_approval["ttl_seconds"],
        )

    error_type = data["error_type"]
    if error_type is not None and type(error_type) is not str:
        raise _invalid_record("engine.error_class")

    return EngineSection(
        decision=_enum_from(Decision, data["decision"], "engine.decision"),
        reason_code=_enum_from(ReasonCode, data["reason_code"], "engine.reason_code"),
        decision_ref=data["decision_digest"],
        protected=data["protected"],
        enforced=data["enforced"],
        record_schema=data["record_schema"],
        engine_version=data["engine_version"],
        evaluated_at=data["evaluated_at"],
        policy_id=data["policy_id"],
        policy_version=data["policy_version"],
        policy_sha256=data["policy_sha256"],
        deciding_rule_ids=deciding[:MAX_LIST_ITEMS],
        deciding_rule_count=len(deciding),
        matched_rule_ids=matched[:MAX_LIST_ITEMS],
        matched_rule_count=len(matched),
        approval=approval,
        error_class=redaction.safe_error_class(error_type),
        request_digest=data["request_digest"],
    )


def _checked_engine_section(data: dict[str, Any]) -> EngineSection:
    """Any validation failure of snapshot content is a malformed record."""
    path = ""
    try:
        return _engine_section(data)
    except AuditError as exc:
        if exc.code is AuditErrorCode.INVALID_RECORD:
            raise
        path = exc.path
    raise _invalid_record(path or "record")


class AuditEventBuilder:
    """Turn ``(DecisionRecord, request)`` into an :class:`AuditEvent` or envelope."""

    def __init__(
        self,
        keys: AuditKeys | None = None,
        *,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        if keys is None:
            keys = AuditKeys()
        if type(keys) is not AuditKeys:
            raise AuditError(AuditErrorCode.KEY_INVALID, "keys")
        self._keys = keys
        self._clock: Clock = clock if clock is not None else _utc_now
        self._new_id: IdFactory = id_factory if id_factory is not None else _new_id

    def __repr__(self) -> str:
        mode = RedactionMode.SCOPED if self._keys.ref is not None else RedactionMode.NO_REF_KEY
        return f"AuditEventBuilder(redaction_mode={mode.value!r}, authenticated={self._keys.auth is not None})"

    # -- public API -----------------------------------------------------------------

    def build(
        self,
        record: DecisionRecord,
        request: object,
        *,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        failed = False
        try:
            return self._build(record, request, correlation_id)
        except AuditError:
            raise
        except Exception:
            failed = True
        if failed:
            raise AuditError(AuditErrorCode.BUILD_FAILED, "event")
        raise AssertionError("unreachable")  # pragma: no cover

    def build_envelope(
        self,
        record: DecisionRecord,
        request: object,
        *,
        correlation_id: str | None = None,
    ) -> AuditEnvelope:
        """Build and seal; authenticated only when the builder has K_auth."""
        event = self.build(record, request, correlation_id=correlation_id)
        failed = False
        try:
            return AuditEnvelope.seal(event, self._keys.auth)
        except AuditError:
            raise
        except Exception:
            failed = True
        if failed:
            raise AuditError(AuditErrorCode.BUILD_FAILED, "envelope")
        raise AssertionError("unreachable")  # pragma: no cover

    # -- internals ------------------------------------------------------------------

    def _build(self, record: object, request: object, correlation_id: str | None) -> AuditEvent:
        data = _record_snapshot(record)
        engine = _checked_engine_section(data)
        caller = self._caller_section(data["request_digest"], request)
        ref_key = self._keys.ref
        event_id = self._fresh_id("audit.event_id")  # generated first, as before the fix
        if correlation_id is None:
            correlation = self._fresh_id("audit.correlation_id")
        else:
            correlation = require_hex32(correlation_id, "audit.correlation_id")
        audit = AuditSection(
            event_id=event_id,
            correlation_id=correlation,
            recorded_at=self._now(),
            redaction_mode=RedactionMode.SCOPED if ref_key is not None else RedactionMode.NO_REF_KEY,
            ref_key_id=None if ref_key is None else ref_key.key_id,
        )
        return AuditEvent(audit=audit, engine=engine, caller=caller)

    def _fresh_id(self, path: str) -> str:
        value: object = None
        failed = False
        try:
            value = self._new_id()
        except Exception:
            failed = True
        if failed or type(value) is not str:
            raise AuditError(AuditErrorCode.INVALID_ID, path)
        valid = True
        try:
            require_hex32(value, path)
        except AuditError:
            valid = False
        if not valid:
            raise AuditError(AuditErrorCode.INVALID_ID, path)
        return value  # type: ignore[return-value]

    def _now(self) -> str:
        """Call the clock and format its value inside one exception boundary."""
        text: object = None
        failed = False
        try:
            value = self._clock()
            if type(value) is datetime and value.tzinfo is not None:
                text = value.astimezone(UTC).strftime(_TIME_FORMAT)
                require_timestamp(text, "audit.recorded_at")
            else:
                failed = True
        except Exception:
            failed = True
        if failed or type(text) is not str:
            raise AuditError(AuditErrorCode.INVALID_CLOCK, "audit.recorded_at")
        return text  # type: ignore[return-value]

    def _caller_section(self, request_digest: str | None, request: object) -> CallerSection:
        consistency, parsed = self._consistency(request_digest, request)
        if consistency is not RequestConsistency.CONSISTENT or parsed is None:
            return CallerSection(
                consistency=consistency,
                agent_id=None,
                assurance_claim=None,
                tool_id=None,
                manifest_sha256=None,
                operation=None,
                environment=None,
                labels=None,
                resource=None,
                session_ref=None,
                request_ref=None,
                redacted_fields=0,
            )

        # Bound: at most 1 (agent) + 1 (tool) + MAX_REQUEST_LABELS (32) unique labels = 34,
        # below MAX_REDACTED_FIELDS (64); parse_request rejects more labels.
        redacted = 0
        agent = parsed.agent
        agent_id = None if agent is None else agent.agent_id
        if agent_id is not None and redaction.looks_like_credential(agent_id):
            agent_id, redacted = None, redacted + 1
        tool_id: str | None = parsed.tool.tool_id
        if redaction.tool_id_looks_like_credential(tool_id):
            tool_id, redacted = None, redacted + 1
        labels = []
        for label in parsed.context.labels:
            if redaction.looks_like_credential(label):
                redacted += 1
            else:
                labels.append(label)

        ref_key = self._keys.ref
        return CallerSection(
            consistency=consistency,
            agent_id=agent_id,
            assurance_claim=None if agent is None else agent.assurance,
            tool_id=tool_id,
            manifest_sha256=parsed.tool.manifest_sha256,
            operation=parsed.operation,
            environment=parsed.context.environment,
            labels=tuple(sorted(set(labels))[:MAX_LIST_ITEMS]),
            resource=redaction.minimize_resource(parsed.resource, ref_key),
            session_ref=redaction.reference(ref_key, "session", parsed.context.session_id),
            request_ref=redaction.reference(ref_key, "request", parsed.context.request_id),
            redacted_fields=redacted,
        )

    @staticmethod
    def _consistency(
        request_digest: str | None, request: object
    ) -> tuple[RequestConsistency, AuthorizationRequest | None]:
        parsed: AuthorizationRequest | None = None
        parsed_digest: str | None = None
        try:
            parsed = coerce_request(request)  # M1's own parser; the request is untrusted
            parsed_digest = digest(REQUEST_DIGEST_DOMAIN, parsed.to_dict())
        except Exception:
            parsed, parsed_digest = None, None
        if request_digest is None:
            if parsed is None:
                return RequestConsistency.INVALID_REQUEST, None
            return RequestConsistency.NOT_APPLICABLE, None
        if parsed is None or parsed_digest != request_digest:
            return RequestConsistency.MISMATCH, None
        return RequestConsistency.CONSISTENT, parsed
