"""Privacy-safe audit projection (Genesis B2-P2-B1). Pure, in memory, no I/O.

A projection is the only representation intended for future persistent storage. It
is produced from an already sealed ``rig.audit-event/v3`` envelope by :func:`project`,
which first verifies the source (exact types, digest and MAC under K_auth, closed-schema
re-parse, readable-label allowlist) and only then transforms it:

* M1's unkeyed ``request_digest``, ``decision_digest`` (``decision_ref``) and approval
  ``request_binding_sha256`` become HMAC references under a derived engine-reference key
  K_eref, each in its own domain (``rig.audit-engine-ref/v1/<kind>``);
* raw ``eligible_approvers`` become keyed references under K_ref (``approver`` namespace);
* the v3 ``event_digest`` and MAC are never copied.

The result, ``rig.audit-projection/v1``, is sealed in ``rig.audit-envelope/v2`` with its
own digest and MAC domains. Verifying a projection needs only K_auth.

What a projection does **not** prove: that ``PolicyEngine`` made the decision, that a tool
ran or was blocked, or who sealed it among K_auth holders. References are linkable within
one K_ref epoch, and any K_ref holder can confirm guesses.

B2-P2-C adds :func:`check_projection_persistable` (the pure persistence gate a future sink
must apply; it performs no I/O and stores nothing) and :func:`verify_projection_fidelity`
(optional comparison with an original M1 ``DecisionRecord``). Persistent storage itself is
M2-C and is not implemented here.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rig_sentinel.audit import validation as v
from rig_sentinel.audit.chain import MAC_ALGORITHM, AuthStatus, macs_equal, pseudonym
from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.audit.events import (
    APPROVED_READABLE_LABELS,
    AUDIT_EVENT_SCHEMA_V3,
    AUTH_FIELDS,
    AuditEnvelope,
    AuditEventV3,
    AuditSection,
    AuthTag,
    CallerSectionV3,
    IdentityMode,
    RedactionMode,
    RequestConsistency,
)
from rig_sentinel.audit.keys import AuditKey, AuditKeys, KeyPurpose, derive_engine_ref_key
from rig_sentinel.audit.redaction import check_persistable
from rig_sentinel.policy.canonical import canonical_json, digest
from rig_sentinel.policy.model import Decision
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.schema import MAX_APPROVERS

AUDIT_PROJECTION_SCHEMA = "rig.audit-projection/v1"
AUDIT_ENVELOPE_SCHEMA_V2 = "rig.audit-envelope/v2"
PROJECTOR_VERSION = "genesis-b2-p2"
PROJECTION_DIGEST_DOMAIN = "rig.audit-projection/v1"
PROJECTION_MAC_DOMAIN = "rig.audit-projection-mac/v1"
ENGINE_REF_DOMAIN = "rig.audit-engine-ref/v1"
ENGINE_REF_KINDS = frozenset({"request-digest", "decision-digest", "approval-binding"})
APPROVER_NAMESPACE = "approver"
_SEPARATOR = bytes(1)

PROJECTION_FIELDS = frozenset({"schema_version", "audit", "engine", "caller", "projection"})
PROJECTION_ENGINE_FIELDS = frozenset(
    {
        "decision", "reason_code", "protected", "enforced", "record_schema", "engine_version",
        "evaluated_at", "policy_id", "policy_version", "policy_sha256", "deciding_rule_ids",
        "deciding_rule_count", "matched_rule_ids", "matched_rule_count", "approval", "error_class",
        "request_ref", "decision_ref_keyed", "engine_ref_key_id",
    }
)
PROJECTION_APPROVAL_FIELDS = frozenset(
    {"eligible_approver_refs", "eligible_approver_count", "binding_ref", "ttl_seconds"}
)
PROJECTION_META_FIELDS = frozenset({"projector_version", "source_schema", "engine_ref_mode"})
ENVELOPE_V2_FIELDS = frozenset({"envelope_schema", "projection", "projection_digest", "auth"})


class ProjectionProfile(StrEnum):
    """How engine references are recorded. Chosen explicitly; never inferred or downgraded."""

    KEYED = "keyed"  # K_ref present: keyed engine and approver references
    UNLINKED = "unlinked"  # explicit opt-in, no-ref-key sources only: no engine references


# --- Cryptographic helpers ---------------------------------------------------------------


def engine_reference(engine_ref_key: AuditKey, kind: str, value: str) -> str:
    """HMAC-SHA-256(K_eref, ``rig.audit-engine-ref/v1/<kind>`` NUL value)[:32 hex].

    ``kind`` is one of :data:`ENGINE_REF_KINDS`; ``value`` is an M1 SHA-256 hex digest.
    """
    if type(engine_ref_key) is not AuditKey:
        raise AuditError(AuditErrorCode.KEY_INVALID, "engine_ref_key")
    if engine_ref_key.purpose is not KeyPurpose.ENGINE_REF:
        raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "engine_ref_key")
    if type(kind) is not str or kind not in ENGINE_REF_KINDS:
        raise AuditError(AuditErrorCode.INVALID_FIELD, "engine_reference")
    if type(value) is not str:
        raise AuditError(AuditErrorCode.INVALID_FIELD, "engine_reference")
    v.require_sha256(value, "engine_reference")
    message = f"{ENGINE_REF_DOMAIN}/{kind}".encode("ascii") + _SEPARATOR + value.encode("ascii")
    return engine_ref_key._hmac_hex(KeyPurpose.ENGINE_REF, message)[:32]


def compute_projection_digest(body: Mapping[str, Any]) -> str:
    """SHA-256(``rig.audit-projection/v1`` NUL canonical(projection))."""
    try:
        return digest(PROJECTION_DIGEST_DOMAIN, body)
    except (TypeError, ValueError):
        raise AuditError(AuditErrorCode.SERIALIZATION_ERROR, "projection") from None


def compute_projection_mac(auth_key: AuditKey, body: Mapping[str, Any]) -> str:
    """HMAC-SHA-256(K_auth, ``rig.audit-projection-mac/v1`` NUL key_id NUL canonical(projection))."""
    if type(auth_key) is not AuditKey:
        raise AuditError(AuditErrorCode.KEY_INVALID, "auth")
    if auth_key.purpose is not KeyPurpose.AUTH:
        raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "auth")
    try:
        canonical = canonical_json(body)
    except (TypeError, ValueError):
        raise AuditError(AuditErrorCode.SERIALIZATION_ERROR, "projection") from None
    message = (
        PROJECTION_MAC_DOMAIN.encode("ascii") + _SEPARATOR
        + auth_key.key_id.encode("ascii") + _SEPARATOR + canonical
    )
    return auth_key._hmac_hex(KeyPurpose.AUTH, message)


# --- Schema ------------------------------------------------------------------------------


def _require_profile_source(profile: object, redaction_mode: object) -> None:
    """Fail closed unless the profile is paired with exactly its required source mode.

    ``KEYED`` requires ``RedactionMode.SCOPED``; ``UNLINKED`` requires
    ``RedactionMode.NO_REF_KEY``. Identity comparison only: strings, look-alike enums,
    ``None`` and anything else are refused, so a future or forged mode can never be
    mistaken for a permitted one.
    """
    if profile is ProjectionProfile.KEYED and redaction_mode is RedactionMode.SCOPED:
        return
    if profile is ProjectionProfile.UNLINKED and redaction_mode is RedactionMode.NO_REF_KEY:
        return
    raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "projection.engine_ref_mode")


def _parse_enum(enum_type: Any, value: object, path: str) -> Any:
    """Exact-string enum lookup that never raises inside an exception handler, so no
    attacker-supplied value can ride along in ``__context__``."""
    if type(value) is str:
        for member in enum_type:
            if member.value == value:
                return member
    raise AuditError(AuditErrorCode.INVALID_FIELD, path)


@dataclass(frozen=True)
class ProjectionApproval:
    """Approval requirement without raw approver ids or the unkeyed request binding.

    ``eligible_approver_refs``: keyed references of the approvers retained by the v3 source
    (the first ``min(count, 32)`` ids in sorted raw order), sorted by reference value.
    ``eligible_approver_count``: the total number of eligible approvers (M1: at most 100);
    ``count > len(refs)`` shows truncation. Both references are ``None`` in unlinked mode.
    """

    eligible_approver_refs: tuple[str, ...] | None
    eligible_approver_count: int
    binding_ref: str | None
    ttl_seconds: int

    def __post_init__(self) -> None:
        path = "engine.approval"
        v.optional(v.require_hex32_tuple, self.eligible_approver_refs, f"{path}.eligible_approver_refs")
        v.require_int(self.eligible_approver_count, f"{path}.eligible_approver_count", 0, MAX_APPROVERS)
        v.optional(v.require_hex32, self.binding_ref, f"{path}.binding_ref")
        v.require_int(self.ttl_seconds, f"{path}.ttl_seconds", v.MIN_APPROVAL_TTL, v.MAX_APPROVAL_TTL)
        if (self.eligible_approver_refs is None) != (self.binding_ref is None):
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, path)
        if self.eligible_approver_refs is not None and len(self.eligible_approver_refs) != min(
            self.eligible_approver_count, v.MAX_LIST_ITEMS
        ):
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, f"{path}.eligible_approver_count")

    def to_dict(self) -> dict[str, Any]:
        refs = self.eligible_approver_refs
        return {
            "eligible_approver_refs": None if refs is None else list(refs),
            "eligible_approver_count": self.eligible_approver_count,
            "binding_ref": self.binding_ref,
            "ttl_seconds": self.ttl_seconds,
        }


@dataclass(frozen=True)
class ProjectionEngine:
    """The v3 engine section without any unkeyed request-derived digest."""

    decision: Decision
    reason_code: ReasonCode
    protected: bool
    enforced: bool
    record_schema: str
    engine_version: str
    evaluated_at: str | None
    policy_id: str | None
    policy_version: str | None
    policy_sha256: str | None
    deciding_rule_ids: tuple[str, ...]
    deciding_rule_count: int
    matched_rule_ids: tuple[str, ...]
    matched_rule_count: int
    approval: ProjectionApproval | None
    error_class: str | None
    request_ref: str | None
    decision_ref_keyed: str | None
    engine_ref_key_id: str | None

    def __post_init__(self) -> None:
        v.require_enum(self.decision, Decision, "engine.decision")
        v.require_enum(self.reason_code, ReasonCode, "engine.reason_code")
        v.require_bool(self.protected, "engine.protected")
        if v.require_bool(self.enforced, "engine.enforced") is not False:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "engine.enforced")
        v.require_schema_tag(self.record_schema, "engine.record_schema")
        v.require_engine_version(self.engine_version, "engine.engine_version")
        v.optional(v.require_timestamp, self.evaluated_at, "engine.evaluated_at")
        v.optional(v.require_identifier, self.policy_id, "engine.policy_id")
        v.optional(v.require_policy_version, self.policy_version, "engine.policy_version")
        v.optional(v.require_sha256, self.policy_sha256, "engine.policy_sha256")
        for ids, count, name in (
            (self.deciding_rule_ids, self.deciding_rule_count, "deciding_rule"),
            (self.matched_rule_ids, self.matched_rule_count, "matched_rule"),
        ):
            v.require_identifier_tuple(ids, f"engine.{name}_ids")
            v.require_int(count, f"engine.{name}_count", 0, v.MAX_COUNT)
            if count < len(ids):
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, f"engine.{name}_count")
        if self.approval is not None and type(self.approval) is not ProjectionApproval:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "engine.approval")
        if (self.approval is not None) != (self.decision is Decision.REQUIRE_APPROVAL):
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval")
        v.optional(v.require_error_class, self.error_class, "engine.error_class")
        v.optional(v.require_hex32, self.request_ref, "engine.request_ref")
        v.optional(v.require_hex32, self.decision_ref_keyed, "engine.decision_ref_keyed")
        v.optional(v.require_hex32, self.engine_ref_key_id, "engine.engine_ref_key_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "protected": self.protected,
            "enforced": self.enforced,
            "record_schema": self.record_schema,
            "engine_version": self.engine_version,
            "evaluated_at": self.evaluated_at,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "deciding_rule_ids": list(self.deciding_rule_ids),
            "deciding_rule_count": self.deciding_rule_count,
            "matched_rule_ids": list(self.matched_rule_ids),
            "matched_rule_count": self.matched_rule_count,
            "approval": None if self.approval is None else self.approval.to_dict(),
            "error_class": self.error_class,
            "request_ref": self.request_ref,
            "decision_ref_keyed": self.decision_ref_keyed,
            "engine_ref_key_id": self.engine_ref_key_id,
        }


@dataclass(frozen=True)
class ProjectionMeta:
    projector_version: str
    source_schema: str
    engine_ref_mode: ProjectionProfile

    def __post_init__(self) -> None:
        if type(self.projector_version) is not str or self.projector_version != PROJECTOR_VERSION:
            raise AuditError(AuditErrorCode.UNSUPPORTED_SCHEMA, "projection.projector_version")
        if type(self.source_schema) is not str or self.source_schema != AUDIT_EVENT_SCHEMA_V3:
            raise AuditError(AuditErrorCode.UNSUPPORTED_SCHEMA, "projection.source_schema")
        v.require_enum(self.engine_ref_mode, ProjectionProfile, "projection.engine_ref_mode")

    def to_dict(self) -> dict[str, Any]:
        return {
            "projector_version": self.projector_version,
            "source_schema": self.source_schema,
            "engine_ref_mode": self.engine_ref_mode.value,
        }


@dataclass(frozen=True)
class ProjectionEvent:
    """``rig.audit-projection/v1``. Closed schema; validated on construction and on parse."""

    audit: AuditSection
    engine: ProjectionEngine
    caller: CallerSectionV3
    projection: ProjectionMeta

    def __post_init__(self) -> None:
        for section, kind, path in (
            (self.audit, AuditSection, "audit"),
            (self.engine, ProjectionEngine, "engine"),
            (self.caller, CallerSectionV3, "caller"),
            (self.projection, ProjectionMeta, "projection"),
        ):
            if type(section) is not kind:
                raise AuditError(AuditErrorCode.INVALID_FIELD, path)

        # Positive pairing only: KEYED <-> exactly SCOPED, UNLINKED <-> exactly NO_REF_KEY.
        # Any other redaction-mode value (even one that compares equal) fails closed.
        _require_profile_source(self.projection.engine_ref_mode, self.audit.redaction_mode)
        scoped = self.audit.redaction_mode is RedactionMode.SCOPED
        keyed = self.projection.engine_ref_mode is ProjectionProfile.KEYED
        if scoped != (self.audit.ref_key_id is not None):
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "audit.ref_key_id")
        expected_identity = IdentityMode.PSEUDONYMIZED if scoped else IdentityMode.OMITTED
        if self.caller.identity_mode is not expected_identity:
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "caller.identity_mode")

        engine = self.engine
        approval = engine.approval
        if keyed:
            if engine.decision_ref_keyed is None or engine.engine_ref_key_id is None:
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine")
            # Mirrors the v3 rule for request_digest: consistent => present, not_applicable => absent.
            consistency = self.caller.consistency
            if consistency is RequestConsistency.CONSISTENT and engine.request_ref is None:
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "caller.consistency")
            if consistency is RequestConsistency.NOT_APPLICABLE and engine.request_ref is not None:
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "caller.consistency")
            if approval is not None and approval.eligible_approver_refs is None:
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval")
        else:
            if any(item is not None for item in (
                engine.request_ref, engine.decision_ref_keyed, engine.engine_ref_key_id,
            )):
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine")
            if approval is not None and approval.eligible_approver_refs is not None:
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval")
            resource = self.caller.resource
            caller_keyed = (
                self.caller.agent_ref, self.caller.tool_ref, self.caller.label_refs,
                self.caller.manifest_ref, self.caller.session_ref, self.caller.request_ref,
                None if resource is None else resource.authority_ref,
                None if resource is None else resource.resource_ref,
            )
            if any(item is not None for item in caller_keyed):
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "audit.redaction_mode")

        if len(self.canonical_bytes()) > v.MAX_EVENT_BYTES:
            raise AuditError(AuditErrorCode.LIMIT_EXCEEDED, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AUDIT_PROJECTION_SCHEMA,
            "audit": self.audit.to_dict(),
            "engine": self.engine.to_dict(),
            "caller": self.caller.to_dict(),
            "projection": self.projection.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        return compute_projection_digest(self.to_dict())


@dataclass(frozen=True)
class ProjectionEnvelope:
    """``rig.audit-envelope/v2``: a projection, its digest and a mandatory HMAC tag."""

    projection: ProjectionEvent
    projection_digest: str
    auth: AuthTag

    def __post_init__(self) -> None:
        if type(self.projection) is not ProjectionEvent:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "projection")
        v.require_sha256(self.projection_digest, "projection_digest")
        if type(self.auth) is not AuthTag:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "auth")  # never unauthenticated
        if len(self.canonical_bytes()) > v.MAX_ENVELOPE_BYTES:
            raise AuditError(AuditErrorCode.LIMIT_EXCEEDED, "")

    @classmethod
    def seal(cls, projection: ProjectionEvent, auth_key: AuditKey) -> ProjectionEnvelope:
        if type(projection) is not ProjectionEvent:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "projection")
        if type(auth_key) is not AuditKey or auth_key.purpose is not KeyPurpose.AUTH:
            raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "auth")
        body = projection.to_dict()
        auth = AuthTag(MAC_ALGORITHM, auth_key.key_id, compute_projection_mac(auth_key, body))
        return cls(projection=projection, projection_digest=compute_projection_digest(body), auth=auth)

    def verify(self, keys: Mapping[str, AuditKey]) -> AuthStatus:
        """Check the digest and the MAC under K_auth. Never needs K_ref.

        ``keys`` must be an exact ``dict`` (as built by :func:`keyring`): a mapping subclass
        could run arbitrary code during lookup, so anything else is treated as no key.
        """
        body = self.projection.to_dict()
        if not macs_equal(compute_projection_digest(body), self.projection_digest):
            return AuthStatus.DIGEST_MISMATCH
        key = keys.get(self.auth.key_id) if type(keys) is dict else None
        if type(key) is not AuditKey or key.purpose is not KeyPurpose.AUTH:
            return AuthStatus.UNKNOWN_KEY
        if macs_equal(compute_projection_mac(key, body), self.auth.mac):
            return AuthStatus.AUTHENTIC
        return AuthStatus.MAC_MISMATCH

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_schema": AUDIT_ENVELOPE_SCHEMA_V2,
            "projection": self.projection.to_dict(),
            "projection_digest": self.projection_digest,
            "auth": self.auth.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


# --- Parsers -----------------------------------------------------------------------------


def _without_context(parse: Any, data: object) -> Any:
    """Run a parser; re-raise its AuditError as a fresh AuditError outside the handler.

    Some shared M2-B parsing helpers raise inside an ``except`` block, which leaves the
    original exception (which can quote the offending input value) in ``__context__``.
    Only :class:`AuditError` is rebuilt (its constructor and fields are known); every other
    exception, including ``BaseException`` subclasses, propagates unchanged.
    """
    code: AuditErrorCode | None = None
    path = ""
    try:
        return parse(data)
    except AuditError as exc:
        code, path = exc.code, exc.path
    raise AuditError(code, path)  # type: ignore[arg-type]


def projection_from_dict(data: object) -> ProjectionEvent:
    """Rebuild a projection from untrusted data. Accepts ``rig.audit-projection/v1`` only.

    Errors are value-free :class:`AuditError` objects with no chained context.
    """
    return _without_context(_projection_from_dict, data)


def projection_envelope_from_dict(data: object) -> ProjectionEnvelope:
    """Rebuild an envelope v2 from untrusted data. Envelope v1 and v2/v3 events are rejected.

    Errors are value-free :class:`AuditError` objects with no chained context.
    """
    return _without_context(_projection_envelope_from_dict, data)


def _projection_from_dict(data: object) -> ProjectionEvent:
    top = v._table(data, PROJECTION_FIELDS, "")
    v._schema_version(top, AUDIT_PROJECTION_SCHEMA)
    audit = v._audit_section(top["audit"])

    e = v._table(top["engine"], PROJECTION_ENGINE_FIELDS, "engine")
    approval = None
    if e["approval"] is not None:
        p = v._table(e["approval"], PROJECTION_APPROVAL_FIELDS, "engine.approval")
        refs = p["eligible_approver_refs"]
        approval = ProjectionApproval(
            eligible_approver_refs=None if refs is None else v._id_tuple(
                refs, "engine.approval.eligible_approver_refs"),
            eligible_approver_count=p["eligible_approver_count"],
            binding_ref=p["binding_ref"],
            ttl_seconds=p["ttl_seconds"],
        )
    engine = ProjectionEngine(
        decision=_parse_enum(Decision, e["decision"], "engine.decision"),
        reason_code=_parse_enum(ReasonCode, e["reason_code"], "engine.reason_code"),
        protected=e["protected"],
        enforced=e["enforced"],
        record_schema=e["record_schema"],
        engine_version=e["engine_version"],
        evaluated_at=e["evaluated_at"],
        policy_id=e["policy_id"],
        policy_version=e["policy_version"],
        policy_sha256=e["policy_sha256"],
        deciding_rule_ids=v._id_tuple(e["deciding_rule_ids"], "engine.deciding_rule_ids"),
        deciding_rule_count=e["deciding_rule_count"],
        matched_rule_ids=v._id_tuple(e["matched_rule_ids"], "engine.matched_rule_ids"),
        matched_rule_count=e["matched_rule_count"],
        approval=approval,
        error_class=e["error_class"],
        request_ref=e["request_ref"],
        decision_ref_keyed=e["decision_ref_keyed"],
        engine_ref_key_id=e["engine_ref_key_id"],
    )
    caller = v._caller_v3_section(top["caller"])
    m = v._table(top["projection"], PROJECTION_META_FIELDS, "projection")
    meta = ProjectionMeta(
        projector_version=m["projector_version"],
        source_schema=m["source_schema"],
        engine_ref_mode=_parse_enum(ProjectionProfile, m["engine_ref_mode"], "projection.engine_ref_mode"),
    )
    return ProjectionEvent(audit=audit, engine=engine, caller=caller, projection=meta)


def _projection_envelope_from_dict(data: object) -> ProjectionEnvelope:
    top = v._table(data, ENVELOPE_V2_FIELDS, "")
    schema = top["envelope_schema"]
    if type(schema) is not str or schema != AUDIT_ENVELOPE_SCHEMA_V2:
        raise AuditError(AuditErrorCode.UNSUPPORTED_SCHEMA, "envelope_schema")
    if top["auth"] is None:
        raise AuditError(AuditErrorCode.INVALID_FIELD, "auth")
    t = v._table(top["auth"], AUTH_FIELDS, "auth")
    auth = AuthTag(algorithm=t["algorithm"], key_id=t["key_id"], mac=t["mac"])
    projection = _projection_from_dict(top["projection"])
    return ProjectionEnvelope(projection=projection, projection_digest=top["projection_digest"], auth=auth)


def verify_projection_envelope_dict(data: object, keys: Mapping[str, AuditKey]) -> AuthStatus:
    """Verify an envelope v2 given as untrusted data. Never raises for bad content."""
    try:
        envelope = projection_envelope_from_dict(data)
    except Exception:  # closed parse failed; BaseException propagates
        return AuthStatus.SCHEMA_INVALID
    return envelope.verify(keys)


# --- Projector ---------------------------------------------------------------------------

_SOURCE_AUTH_ERRORS = {
    AuthStatus.DIGEST_MISMATCH: AuditErrorCode.DIGEST_MISMATCH,
    AuthStatus.UNAUTHENTICATED: AuditErrorCode.UNAUTHENTICATED_REJECTED,
    AuthStatus.UNKNOWN_KEY: AuditErrorCode.AUTHENTICATION_FAILED,
    AuthStatus.MAC_MISMATCH: AuditErrorCode.AUTHENTICATION_FAILED,
    AuthStatus.SCHEMA_INVALID: AuditErrorCode.INVALID_ENVELOPE,
}


def _verified_source(envelope: object, auth_key: AuditKey) -> AuditEventV3:
    """Return the v3 event re-parsed from authenticated, closed-schema bytes.

    Errors are raised outside exception handlers, so no attacker-influenced exception is
    chained to them, and they never carry values.
    """
    if type(envelope) is not AuditEnvelope:
        raise AuditError(AuditErrorCode.INVALID_ENVELOPE, "envelope")
    if type(envelope.event) is not AuditEventV3:
        raise AuditError(AuditErrorCode.UNSUPPORTED_SCHEMA, "envelope.event")

    reparsed = None
    try:
        raw = envelope.canonical_bytes()
        reparsed = v.envelope_from_dict(json.loads(raw))
        if type(reparsed.event) is not AuditEventV3 or reparsed.canonical_bytes() != raw:
            reparsed = None
    except Exception:  # malformed in-memory object: refused below
        reparsed = None
    if reparsed is None:
        raise AuditError(AuditErrorCode.INVALID_ENVELOPE, "envelope")

    # The closed re-parse above already enforced everything P1's check_persistable checks for a
    # v3 source (exact v3 shape, identical bytes, readable-label allowlist via CallerSectionV3).
    status = reparsed.verify({auth_key.key_id: auth_key})
    if status is not AuthStatus.AUTHENTIC:
        raise AuditError(_SOURCE_AUTH_ERRORS.get(status, AuditErrorCode.AUTHENTICATION_FAILED), "envelope")
    return reparsed.event


def project(
    envelope: object,
    keys: object,
    *,
    profile: object = ProjectionProfile.KEYED,
) -> ProjectionEnvelope:
    """Verify a sealed v3 envelope, then project and seal it as ``rig.audit-envelope/v2``.

    ``keys`` is an :class:`AuditKeys` whose ``auth`` key sealed the source and seals the
    projection. ``KEYED`` (the default) needs ``keys.ref`` from the source's K_ref epoch.
    ``UNLINKED`` must be requested explicitly and accepts only ``no-ref-key`` sources.
    Nothing ever falls back from ``KEYED`` to ``UNLINKED``.
    """
    if type(profile) is not ProjectionProfile:
        raise AuditError(AuditErrorCode.INVALID_FIELD, "profile")
    if type(keys) is not AuditKeys:
        raise AuditError(AuditErrorCode.KEY_INVALID, "keys")
    if keys.auth is None:
        raise AuditError(AuditErrorCode.KEY_INVALID, "keys.auth")

    source = _verified_source(envelope, keys.auth)  # all fields below come from authenticated bytes

    mode = source.audit.redaction_mode  # from the re-parsed, authenticated bytes
    if profile is ProjectionProfile.UNLINKED:
        # Positive requirement: only an exactly NO_REF_KEY source may be projected unlinked.
        _require_profile_source(profile, mode)
        ref_key = None
    else:
        # KEYED needs an exactly SCOPED source and K_ref; it never falls back to UNLINKED.
        if mode is not RedactionMode.SCOPED or keys.ref is None:
            raise AuditError(AuditErrorCode.REF_KEY_REQUIRED, "keys.ref")
        if keys.ref.key_id != source.audit.ref_key_id:
            raise AuditError(AuditErrorCode.REF_KEY_EPOCH_MISMATCH, "keys.ref")
        ref_key = keys.ref

    engine = source.engine
    if (engine.approval is not None) != (engine.decision is Decision.REQUIRE_APPROVAL):
        raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval")
    # request_digest presence follows the v3 rules already enforced on the source:
    # consistent and mismatch carry one; not_applicable and invalid_request (from the builder) do not.

    engine_ref_key = None if ref_key is None else derive_engine_ref_key(ref_key)

    approval = None
    if engine.approval is not None:
        source_approval = engine.approval
        count = source_approval.eligible_approver_count
        if count > MAX_APPROVERS:
            raise AuditError(AuditErrorCode.LIMIT_EXCEEDED, "engine.approval.eligible_approver_count")
        retained = source_approval.eligible_approvers
        if len(retained) != min(count, v.MAX_LIST_ITEMS):
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval.eligible_approvers")
        refs = binding = None
        if ref_key is not None and engine_ref_key is not None:
            refs = tuple(sorted({pseudonym(ref_key, APPROVER_NAMESPACE, item) for item in retained}))
            if len(refs) != len(retained):
                raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "engine.approval.eligible_approvers")
            binding = engine_reference(engine_ref_key, "approval-binding", source_approval.request_binding_sha256)
        approval = ProjectionApproval(
            eligible_approver_refs=refs,
            eligible_approver_count=count,
            binding_ref=binding,
            ttl_seconds=source_approval.ttl_seconds,
        )

    request_ref = decision_ref_keyed = engine_ref_key_id = None
    if engine_ref_key is not None:
        engine_ref_key_id = engine_ref_key.key_id
        decision_ref_keyed = engine_reference(engine_ref_key, "decision-digest", engine.decision_ref)
        if engine.request_digest is not None:
            request_ref = engine_reference(engine_ref_key, "request-digest", engine.request_digest)

    projected_engine = ProjectionEngine(
        decision=engine.decision,
        reason_code=engine.reason_code,
        protected=engine.protected,
        enforced=engine.enforced,
        record_schema=engine.record_schema,
        engine_version=engine.engine_version,
        evaluated_at=engine.evaluated_at,
        policy_id=engine.policy_id,
        policy_version=engine.policy_version,
        policy_sha256=engine.policy_sha256,
        deciding_rule_ids=engine.deciding_rule_ids,
        deciding_rule_count=engine.deciding_rule_count,
        matched_rule_ids=engine.matched_rule_ids,
        matched_rule_count=engine.matched_rule_count,
        approval=approval,
        error_class=engine.error_class,
        request_ref=request_ref,
        decision_ref_keyed=decision_ref_keyed,
        engine_ref_key_id=engine_ref_key_id,
    )
    meta = ProjectionMeta(
        projector_version=PROJECTOR_VERSION,
        source_schema=AUDIT_EVENT_SCHEMA_V3,
        engine_ref_mode=profile,
    )
    event = ProjectionEvent(audit=source.audit, engine=projected_engine, caller=source.caller, projection=meta)
    return ProjectionEnvelope.seal(event, keys.auth)


# --- P2-C: compatibility alias ------------------------------------------------------------

# Preferred name for P1's ``check_persistable``. Same function object and behaviour: it checks a
# sealed v3 envelope as a *projection source*. Neither name authorizes persistence; only
# :func:`check_projection_persistable` does (for projection envelopes).
check_v3_projection_source = check_persistable


# --- P2-C: key epochs -----------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectionEpoch:
    """The key epoch a persistent segment expects: profile plus K_ref and K_eref key ids.

    Build it with :meth:`keyed` (from K_ref, so the K_eref id is derived, not typed) or
    :meth:`unlinked`. Key ids are public fingerprints; no key material is held.
    """

    engine_ref_mode: ProjectionProfile
    ref_key_id: str | None
    engine_ref_key_id: str | None

    def __post_init__(self) -> None:
        v.require_enum(self.engine_ref_mode, ProjectionProfile, "epoch.engine_ref_mode")
        if self.engine_ref_mode is ProjectionProfile.KEYED:
            v.require_hex32(self.ref_key_id, "epoch.ref_key_id")
            v.require_hex32(self.engine_ref_key_id, "epoch.engine_ref_key_id")
        elif self.ref_key_id is not None or self.engine_ref_key_id is not None:
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "epoch")

    @classmethod
    def keyed(cls, ref_key: AuditKey) -> ProjectionEpoch:
        engine_ref_key = derive_engine_ref_key(ref_key)
        return cls(ProjectionProfile.KEYED, ref_key.key_id, engine_ref_key.key_id)

    @classmethod
    def unlinked(cls) -> ProjectionEpoch:
        return cls(ProjectionProfile.UNLINKED, None, None)


# --- P2-C: persistence gate -----------------------------------------------------------------


class ProjectionGateCode(StrEnum):
    """Why a projection envelope may or may not be handed to a persistent sink."""

    OK = "ok"
    NOT_A_PROJECTION = "not_a_projection"
    V2_EVENT_NOT_PERSISTABLE = "v2_event_not_persistable"
    V3_EVENT_NOT_PERSISTABLE = "v3_event_not_persistable"
    KEYRING_INVALID = "keyring_invalid"
    CONFIGURATION_INVALID = "configuration_invalid"
    SCHEMA_INVALID = "schema_invalid"
    FORBIDDEN_FIELD = "forbidden_field"
    DIGEST_MISMATCH = "digest_mismatch"
    UNKNOWN_KEY = "unknown_key"
    AUTHENTICATION_FAILED = "authentication_failed"
    EPOCH_MISMATCH = "epoch_mismatch"
    LABEL_NOT_ALLOWED = "label_not_allowed"


_GATE_ISSUER = object()  # private capability: only the gate issues ValidatedProjection objects


@dataclass(frozen=True)
class ValidatedProjection:
    """The byte-stable output of a passed gate, for a future persistent sink (M2-C).

    ``canonical`` is exactly the canonical JSON of the authenticated projection envelope
    that the gate checked; a sink must write these bytes unchanged. Holding one does not
    authorize writing through any sink other than one that re-applies the gate.
    """

    canonical: bytes = field(repr=False)
    projection_digest: str
    auth_key_id: str
    event_id: str
    engine_ref_mode: ProjectionProfile
    ref_key_id: str | None
    engine_ref_key_id: str | None
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _GATE_ISSUER:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "validated_projection")
        if type(self.canonical) is not bytes:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "validated_projection.canonical")


@dataclass(frozen=True)
class ProjectionGateResult:
    """Result of :func:`check_projection_persistable`. Codes only; never event values."""

    ok: bool
    code: ProjectionGateCode
    validated: ValidatedProjection | None

    def __post_init__(self) -> None:
        if type(self.code) is not ProjectionGateCode or type(self.ok) is not bool:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "gate_result")
        passed = self.code is ProjectionGateCode.OK
        if self.ok is not passed or (self.validated is not None) is not passed:
            raise AuditError(AuditErrorCode.INCONSISTENT_EVENT, "gate_result")
        if self.validated is not None and type(self.validated) is not ValidatedProjection:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "gate_result.validated")


def _refused(code: ProjectionGateCode) -> ProjectionGateResult:
    return ProjectionGateResult(ok=False, code=code, validated=None)


# Keys that must never appear anywhere in persisted bytes (raw M1 digests, raw identities,
# v2 readable fields, the source event's digest, the removed source_ref).
FORBIDDEN_PERSISTED_KEYS = frozenset(
    {
        "request_digest", "decision_ref", "decision_digest", "request_binding_sha256",
        "eligible_approvers", "event_digest", "source_ref", "agent_id", "tool_id",
        "manifest_sha256", "labels", "redacted_fields",
    }
)
# The only positions where a 64-hex value may be persisted: digests of persisted or public
# content (policy fingerprint, the projection's own digest, its MAC).
_PERMITTED_64_HEX = frozenset(
    {("projection", "engine", "policy_sha256"), ("projection_digest",), ("auth", "mac")}
)
_HEX64_RE = re.compile(r"[0-9A-Fa-f]{64}")


def _persisted_privacy_violation(tree: object, path: tuple[str, ...] = ()) -> tuple[str, ...] | None:
    """Defence-in-depth scan of parsed persisted JSON (the closed schema is the primary control).

    Returns the path of the first violation, or ``None``: a forbidden key at any depth, or a
    64-hex string (any case) outside the three permitted positions. Never returns values.
    """
    if type(tree) is dict:
        for key, value in tree.items():
            if key in FORBIDDEN_PERSISTED_KEYS:
                return (*path, str(key))
            found = _persisted_privacy_violation(value, (*path, str(key)))
            if found is not None:
                return found
        return None
    if type(tree) is list:
        for index, value in enumerate(tree):
            found = _persisted_privacy_violation(value, (*path, str(index)))
            if found is not None:
                return found
        return None
    if type(tree) is str and _HEX64_RE.search(tree) and path not in _PERMITTED_64_HEX:
        return path
    return None


def _valid_keyring(keys: object) -> bool:
    if type(keys) is not dict:
        return False
    for key_id, key in keys.items():
        if type(key_id) is not str or type(key) is not AuditKey:
            return False
        if key.purpose is not KeyPurpose.AUTH or key.key_id != key_id:
            return False
    return True


def _allowed_labels(readable_labels: object) -> frozenset[str] | None:
    if readable_labels is None:
        return APPROVED_READABLE_LABELS
    if type(readable_labels) is not frozenset and type(readable_labels) is not set:
        return None
    items = tuple(readable_labels)
    if not all(type(item) is str and item in APPROVED_READABLE_LABELS for item in items):
        return None
    return frozenset(items)


_GATE_AUTH_CODES = {
    AuthStatus.DIGEST_MISMATCH: ProjectionGateCode.DIGEST_MISMATCH,
    AuthStatus.UNKNOWN_KEY: ProjectionGateCode.UNKNOWN_KEY,
    AuthStatus.MAC_MISMATCH: ProjectionGateCode.AUTHENTICATION_FAILED,
}


def check_projection_persistable(
    envelope: object,
    keys: object,
    *,
    readable_labels: object = None,
    expected_epoch: object = None,
) -> ProjectionGateResult:
    """Decide whether ``envelope`` may be handed to a persistent sink (P2-C).

    Accepted only if all hold: ``keys`` is an exact ``dict`` keyring of AUTH keys; the
    envelope is exactly a :class:`ProjectionEnvelope`; its canonical bytes re-parse under the
    closed envelope v2 / projection v1 schemas to identical bytes; the deep privacy scan finds
    no forbidden key and no 64-hex value outside the permitted positions; digest and MAC verify
    under K_auth; the key epoch equals ``expected_epoch`` when one is given; readable labels are
    within ``readable_labels`` (default and maximum: the approved set).

    Pure: no I/O, never modifies the envelope, never raises for content (``BaseException``
    propagates). On success the result carries a :class:`ValidatedProjection` with the exact
    bytes to persist. A passed gate does not itself write anything and does not authorize
    writing through a sink that does not apply this gate.
    """
    try:
        return _check_projection_persistable(envelope, keys, readable_labels, expected_epoch)
    except Exception:  # never raise for content; BaseException propagates
        return _refused(ProjectionGateCode.SCHEMA_INVALID)


def _check_projection_persistable(
    envelope: object, keys: object, readable_labels: object, expected_epoch: object
) -> ProjectionGateResult:
    if not _valid_keyring(keys):
        return _refused(ProjectionGateCode.KEYRING_INVALID)
    allowed = _allowed_labels(readable_labels)
    if allowed is None:
        return _refused(ProjectionGateCode.CONFIGURATION_INVALID)
    if expected_epoch is not None and type(expected_epoch) is not ProjectionEpoch:
        return _refused(ProjectionGateCode.CONFIGURATION_INVALID)

    kind = type(envelope)
    if kind is not ProjectionEnvelope:
        if kind is AuditEnvelope:
            if type(envelope.event) is AuditEventV3:  # type: ignore[attr-defined]
                return _refused(ProjectionGateCode.V3_EVENT_NOT_PERSISTABLE)
            return _refused(ProjectionGateCode.V2_EVENT_NOT_PERSISTABLE)
        return _refused(ProjectionGateCode.NOT_A_PROJECTION)

    raw = envelope.canonical_bytes()  # type: ignore[attr-defined]
    tree = json.loads(raw)
    reparsed = projection_envelope_from_dict(tree)
    if reparsed.canonical_bytes() != raw:
        return _refused(ProjectionGateCode.SCHEMA_INVALID)
    if _persisted_privacy_violation(tree) is not None:
        return _refused(ProjectionGateCode.FORBIDDEN_FIELD)

    status = reparsed.verify(keys)  # type: ignore[arg-type]
    if status is not AuthStatus.AUTHENTIC:
        return _refused(_GATE_AUTH_CODES.get(status, ProjectionGateCode.AUTHENTICATION_FAILED))

    event = reparsed.projection
    mode = event.projection.engine_ref_mode
    if expected_epoch is not None and (
        expected_epoch.engine_ref_mode is not mode  # type: ignore[attr-defined]
        or expected_epoch.ref_key_id != event.audit.ref_key_id  # type: ignore[attr-defined]
        or expected_epoch.engine_ref_key_id != event.engine.engine_ref_key_id  # type: ignore[attr-defined]
    ):
        return _refused(ProjectionGateCode.EPOCH_MISMATCH)

    if not set(event.caller.readable_labels or ()) <= allowed:
        return _refused(ProjectionGateCode.LABEL_NOT_ALLOWED)

    validated = ValidatedProjection(
        canonical=raw,
        projection_digest=reparsed.projection_digest,
        auth_key_id=reparsed.auth.key_id,
        event_id=event.audit.event_id,
        engine_ref_mode=mode,
        ref_key_id=event.audit.ref_key_id,
        engine_ref_key_id=event.engine.engine_ref_key_id,
        _issuer=_GATE_ISSUER,
    )
    return ProjectionGateResult(ok=True, code=ProjectionGateCode.OK, validated=validated)


# --- P2-C: fidelity verification -------------------------------------------------------------


class FidelityResult(StrEnum):
    """Outcome of :func:`verify_projection_fidelity`. Exactly three values."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


def verify_projection_fidelity(envelope: object, record: object, keys: object) -> FidelityResult:
    """Compare an authentic keyed projection with an original M1 ``DecisionRecord``.

    * ``NOT_VERIFIABLE``: the projection is not an exact, authentic (under ``keys.auth``)
      ``ProjectionEnvelope``; it is ``unlinked``; ``keys`` lacks K_ref or K_auth; K_ref is not
      the projection's epoch (``ref_key_id``); or the record is missing, not an exact
      ``DecisionRecord``, not self-consistent, or not one the audit builder accepts.
    * ``MISMATCH``: the projection is authentic and verifiable but its engine section (copied
      fields, keyed references, K_eref epoch, approver references or count) differs from what
      the record yields.
    * ``MATCH``: everything the engine section records matches the record.

    Integrity (MAC under K_auth) is a precondition, not the result. ``MATCH`` means only that
    this projection is consistent with this self-consistent record under this K_ref epoch. It
    does not prove that ``PolicyEngine`` produced the record, that a tool ran or was blocked, or
    anything about the caller section (not compared). Never raises for content; ``BaseException``
    propagates. Requires K_ref, so it is itself a guess-confirmation tool for its caller.
    """
    try:
        return _verify_projection_fidelity(envelope, record, keys)
    except Exception:  # never raise for content; BaseException propagates
        return FidelityResult.NOT_VERIFIABLE


def _refs_equal(left: tuple[str, ...] | None, right: tuple[str, ...] | None) -> bool:
    if left is None or right is None:
        return left is None and right is None
    if len(left) != len(right):
        return False
    same = True
    for a, b in zip(left, right):  # constant-time per reference
        same &= hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))
    return same


def _verify_projection_fidelity(envelope: object, record: object, keys: object) -> FidelityResult:
    from rig_sentinel.audit.builder import _checked_engine_section, _record_snapshot

    if type(keys) is not AuditKeys or keys.ref is None or keys.auth is None:
        return FidelityResult.NOT_VERIFIABLE
    if type(envelope) is not ProjectionEnvelope:
        return FidelityResult.NOT_VERIFIABLE

    # Integrity first: exact, closed, byte-identical and authentic under keys.auth.
    raw = envelope.canonical_bytes()
    reparsed = projection_envelope_from_dict(json.loads(raw))
    if reparsed.canonical_bytes() != raw:
        return FidelityResult.NOT_VERIFIABLE
    if reparsed.verify({keys.auth.key_id: keys.auth}) is not AuthStatus.AUTHENTIC:
        return FidelityResult.NOT_VERIFIABLE

    projection = reparsed.projection
    if projection.projection.engine_ref_mode is not ProjectionProfile.KEYED:
        return FidelityResult.NOT_VERIFIABLE  # unlinked: no link to any record, by design
    if keys.ref.key_id != projection.audit.ref_key_id:
        return FidelityResult.NOT_VERIFIABLE  # wrong or missing historical K_ref epoch

    # M1 evidence: one detached, digest-checked snapshot, derived exactly as the builder does.
    snapshot = None
    expected_engine = None
    try:
        snapshot = _record_snapshot(record)
        expected_engine = _checked_engine_section(snapshot)
    except AuditError:
        snapshot = expected_engine = None
    if snapshot is None or expected_engine is None:
        return FidelityResult.NOT_VERIFIABLE

    engine_ref_key = derive_engine_ref_key(keys.ref)
    actual = projection.engine
    if actual.engine_ref_key_id != engine_ref_key.key_id:
        return FidelityResult.MISMATCH  # projection claims an epoch K_ref does not derive

    copied = (
        "decision", "reason_code", "protected", "enforced", "record_schema", "engine_version",
        "evaluated_at", "policy_id", "policy_version", "policy_sha256", "deciding_rule_ids",
        "deciding_rule_count", "matched_rule_ids", "matched_rule_count", "error_class",
    )
    same = all(getattr(actual, name) == getattr(expected_engine, name) for name in copied)

    expected_decision = engine_reference(engine_ref_key, "decision-digest", expected_engine.decision_ref)
    same &= _refs_equal(_one(actual.decision_ref_keyed), (expected_decision,))
    if expected_engine.request_digest is None:
        same &= actual.request_ref is None
    else:
        expected_request = engine_reference(engine_ref_key, "request-digest", expected_engine.request_digest)
        same &= _refs_equal(_one(actual.request_ref), (expected_request,))

    expected_approval = expected_engine.approval
    if (actual.approval is None) != (expected_approval is None):
        return FidelityResult.MISMATCH
    if expected_approval is not None and actual.approval is not None:
        raw_ids = snapshot["approval"]["eligible_approvers"]  # validated by the engine-section check
        ordered = sorted(raw_ids)  # 1. sort the raw approver identifiers
        selected = ordered[: min(len(ordered), v.MAX_LIST_ITEMS)]  # 2. first min(count, 32)
        keyed_refs = tuple(sorted(  # 3. HMAC each selected id; 4. sort the references
            pseudonym(keys.ref, APPROVER_NAMESPACE, item) for item in selected
        ))
        same &= _refs_equal(actual.approval.eligible_approver_refs, keyed_refs)  # 5. compare
        same &= actual.approval.eligible_approver_count == len(ordered)
        same &= actual.approval.ttl_seconds == expected_approval.ttl_seconds
        expected_binding = engine_reference(
            engine_ref_key, "approval-binding", expected_approval.request_binding_sha256
        )
        same &= _refs_equal(_one(actual.approval.binding_ref), (expected_binding,))
    return FidelityResult.MATCH if same else FidelityResult.MISMATCH


def _one(value: str | None) -> tuple[str, ...] | None:
    return None if value is None else (value,)
