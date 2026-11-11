"""Closed-schema validation for audit events and envelopes (M2-B).

Two layers:

* Field checks (``require_*``) used by the frozen models in ``events.py`` on
  construction, so an invalid event object cannot be created through the
  public constructors.
* Parsers (:func:`event_from_dict`, :func:`envelope_from_dict`) that rebuild
  models from untrusted dictionaries (for example ``json.loads`` output) and
  reject unknown fields, missing fields, wrong types and oversized input.

Errors are :class:`~rig_sentinel.audit.errors.AuditError` with a code and a
fixed field path; values are never echoed.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, TypeVar

from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.policy.identifiers import is_identifier, is_sha256_hex, is_tool_id

MAX_LIST_ITEMS = 32
MAX_COUNT = 100_000
MAX_DEPTH = 1024
MAX_REDACTED_FIELDS = 64
MAX_EVENT_BYTES = 16 * 1024
MAX_ENVELOPE_BYTES = 17 * 1024
MIN_APPROVAL_TTL = 30
MAX_APPROVAL_TTL = 3600

_HEX32_RE = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_ERROR_CLASS_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_POLICY_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_ENGINE_VERSION_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SCHEMA_TAG_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,31}/v[0-9]{1,3}")

E = TypeVar("E", bound=Enum)


def _fail(code: AuditErrorCode, path: str) -> AuditError:
    return AuditError(code, path)


# --- Field checks -------------------------------------------------------------------


def require_hex32(value: object, path: str) -> str:
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_sha256(value: object, path: str) -> str:
    if not is_sha256_hex(value):
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value  # type: ignore[return-value]


def require_identifier(value: object, path: str) -> str:
    if not is_identifier(value):
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value  # type: ignore[return-value]


def require_tool_id(value: object, path: str) -> str:
    if not is_tool_id(value):
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value  # type: ignore[return-value]


def require_timestamp(value: object, path: str) -> str:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_error_class(value: object, path: str) -> str:
    if type(value) is not str or _ERROR_CLASS_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_policy_version(value: object, path: str) -> str:
    if type(value) is not str or _POLICY_VERSION_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_engine_version(value: object, path: str) -> str:
    if type(value) is not str or _ENGINE_VERSION_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_schema_tag(value: object, path: str) -> str:
    if type(value) is not str or _SCHEMA_TAG_RE.fullmatch(value) is None:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_int(value: object, path: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value


def require_enum(value: object, enum_type: type[E], path: str) -> E:
    if type(value) is not enum_type:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    return value  # type: ignore[return-value]


def require_identifier_tuple(value: object, path: str, *, max_items: int = MAX_LIST_ITEMS) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    if len(value) > max_items:
        raise _fail(AuditErrorCode.LIMIT_EXCEEDED, path)
    for item in value:
        require_identifier(item, path)
    if list(value) != sorted(set(value)):
        raise _fail(AuditErrorCode.INVALID_FIELD, path)  # must be sorted and unique
    return value


def optional(check: Any, value: object, path: str, *args: Any) -> Any:
    return None if value is None else check(value, path, *args)


# --- Parsing untrusted dictionaries ----------------------------------------------------


def _table(data: object, fields: frozenset[str], path: str) -> dict[str, Any]:
    if type(data) is not dict:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    if not all(type(key) is str for key in data):
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    unknown = set(data) - fields
    if unknown:
        raise _fail(AuditErrorCode.UNKNOWN_FIELD, path)
    missing = fields - set(data)
    if missing:
        raise _fail(AuditErrorCode.MISSING_FIELD, path)
    return data


def _enum(enum_type: type[E], value: object, path: str) -> E:
    if type(value) is not str:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    try:
        return enum_type(value)
    except ValueError:
        raise _fail(AuditErrorCode.INVALID_FIELD, path) from None


def _optional_enum(enum_type: type[E], value: object, path: str) -> E | None:
    return None if value is None else _enum(enum_type, value, path)


def _id_tuple(value: object, path: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise _fail(AuditErrorCode.INVALID_FIELD, path)
    if len(value) > MAX_LIST_ITEMS:
        raise _fail(AuditErrorCode.LIMIT_EXCEEDED, path)
    return tuple(value)


def event_from_dict(data: object) -> Any:
    """Rebuild an :class:`~rig_sentinel.audit.events.AuditEvent` from untrusted data."""
    from rig_sentinel.audit import events as ev
    from rig_sentinel.policy.model import Assurance, Decision, Environment, OperationClass
    from rig_sentinel.policy.reasons import ReasonCode
    from rig_sentinel.policy.resources import ResourceKind

    top = _table(data, ev.EVENT_FIELDS, "")
    if top["schema_version"] != ev.AUDIT_EVENT_SCHEMA:
        raise _fail(AuditErrorCode.UNSUPPORTED_SCHEMA, "schema_version")

    a = _table(top["audit"], ev.AUDIT_FIELDS, "audit")
    audit = ev.AuditSection(
        event_id=a["event_id"],
        correlation_id=a["correlation_id"],
        recorded_at=a["recorded_at"],
        redaction_mode=_enum(ev.RedactionMode, a["redaction_mode"], "audit.redaction_mode"),
        ref_key_id=a["ref_key_id"],
    )

    e = _table(top["engine"], ev.ENGINE_FIELDS, "engine")
    approval = None
    if e["approval"] is not None:
        p = _table(e["approval"], ev.APPROVAL_FIELDS, "engine.approval")
        approval = ev.ApprovalSection(
            eligible_approvers=_id_tuple(p["eligible_approvers"], "engine.approval.eligible_approvers"),
            eligible_approver_count=p["eligible_approver_count"],
            request_binding_sha256=p["request_binding_sha256"],
            ttl_seconds=p["ttl_seconds"],
        )
    engine = ev.EngineSection(
        decision=_enum(Decision, e["decision"], "engine.decision"),
        reason_code=_enum(ReasonCode, e["reason_code"], "engine.reason_code"),
        decision_ref=e["decision_ref"],
        protected=e["protected"],
        enforced=e["enforced"],
        record_schema=e["record_schema"],
        engine_version=e["engine_version"],
        evaluated_at=e["evaluated_at"],
        policy_id=e["policy_id"],
        policy_version=e["policy_version"],
        policy_sha256=e["policy_sha256"],
        deciding_rule_ids=_id_tuple(e["deciding_rule_ids"], "engine.deciding_rule_ids"),
        deciding_rule_count=e["deciding_rule_count"],
        matched_rule_ids=_id_tuple(e["matched_rule_ids"], "engine.matched_rule_ids"),
        matched_rule_count=e["matched_rule_count"],
        approval=approval,
        error_class=e["error_class"],
        request_digest=e["request_digest"],
    )

    c = _table(top["caller"], ev.CALLER_FIELDS, "caller")
    resource = None
    if c["resource"] is not None:
        r = _table(c["resource"], ev.RESOURCE_FIELDS, "caller.resource")
        resource = ev.ResourceSection(
            kind=_enum(ResourceKind, r["kind"], "caller.resource.kind"),
            depth=r["depth"],
            authority_ref=r["authority_ref"],
            resource_ref=r["resource_ref"],
        )
    labels = None if c["labels"] is None else _id_tuple(c["labels"], "caller.labels")
    caller = ev.CallerSection(
        consistency=_enum(ev.RequestConsistency, c["consistency"], "caller.consistency"),
        agent_id=c["agent_id"],
        assurance_claim=_optional_enum(Assurance, c["assurance_claim"], "caller.assurance_claim"),
        tool_id=c["tool_id"],
        manifest_sha256=c["manifest_sha256"],
        operation=_optional_enum(OperationClass, c["operation"], "caller.operation"),
        environment=_optional_enum(Environment, c["environment"], "caller.environment"),
        labels=labels,
        resource=resource,
        session_ref=c["session_ref"],
        request_ref=c["request_ref"],
        redacted_fields=c["redacted_fields"],
    )
    return ev.AuditEvent(audit=audit, engine=engine, caller=caller)


def envelope_from_dict(data: object) -> Any:
    """Rebuild an :class:`~rig_sentinel.audit.events.AuditEnvelope` from untrusted data.

    Only the structure is checked here; whether ``event_digest`` and the MAC
    match is decided by :meth:`AuditEnvelope.verify`.
    """
    from rig_sentinel.audit import events as ev

    top = _table(data, ev.ENVELOPE_FIELDS, "")
    if top["envelope_schema"] != ev.AUDIT_ENVELOPE_SCHEMA:
        raise _fail(AuditErrorCode.UNSUPPORTED_SCHEMA, "envelope_schema")
    auth = None
    if top["auth"] is not None:
        t = _table(top["auth"], ev.AUTH_FIELDS, "auth")
        auth = ev.AuthTag(algorithm=t["algorithm"], key_id=t["key_id"], mac=t["mac"])
    return ev.AuditEnvelope(
        event=event_from_dict(top["event"]),
        event_digest=top["event_digest"],
        auth=auth,
    )
