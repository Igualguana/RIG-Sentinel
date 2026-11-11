"""RIG Sentinel audit foundation (Genesis B2-M2-B): pure, in-memory components.

Builds privacy-minimized, versioned audit events from M1 decision records,
pseudonymizes sensitive references with a keyed HMAC (``K_ref``), and
authenticates envelopes with a separate HMAC key (``K_auth``). ``MemorySink``
keeps envelopes in process memory only.

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
    AUDIT_ENVELOPE_SCHEMA,
    AUDIT_EVENT_SCHEMA,
    ApprovalSection,
    AuditEnvelope,
    AuditEvent,
    AuditSection,
    AuthTag,
    CallerSection,
    EngineSection,
    RedactionMode,
    RequestConsistency,
    ResourceSection,
    verify_envelope_dict,
)
from rig_sentinel.audit.keys import KEY_BYTES, AuditKey, AuditKeys, KeyPurpose
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
)

__all__ = [
    "AUDIT_ENVELOPE_SCHEMA",
    "AUDIT_EVENT_SCHEMA",
    "EVENT_DIGEST_DOMAIN",
    "KEY_BYTES",
    "MAC_ALGORITHM",
    "MAC_DOMAIN",
    "MAX_ENVELOPE_BYTES",
    "MAX_EVENT_BYTES",
    "MAX_LIST_ITEMS",
    "REF_DOMAIN",
    "ApprovalSection",
    "AuditEnvelope",
    "AuditError",
    "AuditErrorCode",
    "AuditEvent",
    "AuditEventBuilder",
    "AuditKey",
    "AuditKeys",
    "AuditReceipt",
    "AuditSection",
    "AuditSink",
    "AuthStatus",
    "AuthTag",
    "CallerSection",
    "Durability",
    "EngineSection",
    "KeyPurpose",
    "MemorySink",
    "ReceiptStatus",
    "RedactionMode",
    "RequestConsistency",
    "ResourceSection",
    "envelope_from_dict",
    "event_from_dict",
    "keyring",
    "verify_envelope_dict",
]
