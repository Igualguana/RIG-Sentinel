"""RIG Sentinel audit foundation (Genesis B2-M2-B, with B2-P1 privacy hardening).

Pure, in-memory components. Builds privacy-minimized, versioned audit events from
M1 decision records, pseudonymizes sensitive references with a keyed HMAC
(``K_ref``), and authenticates envelopes with a separate HMAC key (``K_auth``).
``MemorySink`` keeps envelopes in process memory only.

Two event schemas exist: ``rig.audit-event/v2`` (the default, unchanged) and
``rig.audit-event/v3`` (B2-P1, selected explicitly), in which caller identities
are keyed references or omitted. :func:`check_persistable` is the privacy gate a
future persistent sink must apply; it accepts authenticated v3 events only.

This is **not** a complete audit subsystem: there is no persistence, ordering
chain, checkpointing, key storage or rotation (M2-C), and no orchestration of
evaluation plus auditing (M2-D). Events record *decisions*; they never claim
that a tool ran or that a decision was enforced. The policy package does not
depend on this package.
"""

from __future__ import annotations

from rig_sentinel.audit.builder import AuditEventBuilder
from rig_sentinel.audit.chain import (
    EVENT_DIGEST_DOMAIN,
    MAC_ALGORITHM,
    MAC_DOMAIN,
    REF_DOMAIN,
    AuthStatus,
    keyring,
)
from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.audit.events import (
    APPROVED_READABLE_LABELS,
    AUDIT_ENVELOPE_SCHEMA,
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_SCHEMA_V3,
    ApprovalSection,
    AuditEnvelope,
    AuditEvent,
    AuditEventV3,
    AuditSection,
    AuthTag,
    CallerSection,
    CallerSectionV3,
    EngineSection,
    IdentityMode,
    RedactionMode,
    RequestConsistency,
    ResourceSection,
    verify_envelope_dict,
)
from rig_sentinel.audit.keys import KEY_BYTES, AuditKey, AuditKeys, KeyPurpose, derive_engine_ref_key
from rig_sentinel.audit.projection import (
    AUDIT_ENVELOPE_SCHEMA_V2,
    AUDIT_PROJECTION_SCHEMA,
    ENGINE_REF_DOMAIN,
    PROJECTION_DIGEST_DOMAIN,
    PROJECTION_MAC_DOMAIN,
    PROJECTOR_VERSION,
    FidelityResult,
    ProjectionApproval,
    ProjectionEngine,
    ProjectionEnvelope,
    ProjectionEpoch,
    ProjectionEvent,
    ProjectionGateCode,
    ProjectionGateResult,
    ProjectionMeta,
    ProjectionProfile,
    ValidatedProjection,
    check_projection_persistable,
    check_v3_projection_source,
    compute_projection_digest,
    compute_projection_mac,
    engine_reference,
    project,
    projection_envelope_from_dict,
    projection_from_dict,
    verify_projection_envelope_dict,
    verify_projection_fidelity,
)
from rig_sentinel.audit.redaction import PersistenceCode, PersistenceVerdict, check_persistable
from rig_sentinel.audit.sinks import (
    AuditReceipt,
    AuditSink,
    Durability,
    MemorySink,
    ReceiptStatus,
)
from rig_sentinel.audit.validation import (
    MAX_ENVELOPE_BYTES,
    MAX_EVENT_BYTES,
    MAX_LIST_ITEMS,
    envelope_from_dict,
    event_from_dict,
    event_v3_from_dict,
)

__all__ = [
    "APPROVED_READABLE_LABELS",
    "AUDIT_ENVELOPE_SCHEMA",
    "AUDIT_ENVELOPE_SCHEMA_V2",
    "AUDIT_EVENT_SCHEMA",
    "AUDIT_EVENT_SCHEMA_V3",
    "AUDIT_PROJECTION_SCHEMA",
    "ENGINE_REF_DOMAIN",
    "EVENT_DIGEST_DOMAIN",
    "KEY_BYTES",
    "MAC_ALGORITHM",
    "MAC_DOMAIN",
    "MAX_ENVELOPE_BYTES",
    "MAX_EVENT_BYTES",
    "MAX_LIST_ITEMS",
    "PROJECTION_DIGEST_DOMAIN",
    "PROJECTION_MAC_DOMAIN",
    "PROJECTOR_VERSION",
    "REF_DOMAIN",
    "ApprovalSection",
    "AuditEnvelope",
    "AuditError",
    "AuditErrorCode",
    "AuditEvent",
    "AuditEventBuilder",
    "AuditEventV3",
    "AuditKey",
    "AuditKeys",
    "AuditReceipt",
    "AuditSection",
    "AuditSink",
    "AuthStatus",
    "AuthTag",
    "CallerSection",
    "CallerSectionV3",
    "Durability",
    "EngineSection",
    "FidelityResult",
    "IdentityMode",
    "KeyPurpose",
    "MemorySink",
    "PersistenceCode",
    "PersistenceVerdict",
    "ProjectionApproval",
    "ProjectionEngine",
    "ProjectionEnvelope",
    "ProjectionEpoch",
    "ProjectionEvent",
    "ProjectionGateCode",
    "ProjectionGateResult",
    "ProjectionMeta",
    "ProjectionProfile",
    "ReceiptStatus",
    "RedactionMode",
    "RequestConsistency",
    "ResourceSection",
    "ValidatedProjection",
    "check_persistable",
    "check_projection_persistable",
    "check_v3_projection_source",
    "compute_projection_digest",
    "compute_projection_mac",
    "derive_engine_ref_key",
    "engine_reference",
    "envelope_from_dict",
    "event_from_dict",
    "event_v3_from_dict",
    "keyring",
    "project",
    "projection_envelope_from_dict",
    "projection_from_dict",
    "verify_envelope_dict",
    "verify_projection_envelope_dict",
    "verify_projection_fidelity",
]
