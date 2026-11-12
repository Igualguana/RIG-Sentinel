"""Closed error codes for the audit package.

Error messages contain a code and, at most, a fixed field path such as
``engine.policy_id``. They never contain values from events, requests,
records or keys.
"""

from __future__ import annotations

from enum import StrEnum


class AuditErrorCode(StrEnum):
    """Why an audit operation failed. Add members; never rename them."""

    # Schema and model validation
    INVALID_FIELD = "INVALID_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    INCONSISTENT_EVENT = "INCONSISTENT_EVENT"

    # Event construction
    INVALID_RECORD = "INVALID_RECORD"
    RECORD_INCONSISTENT = "RECORD_INCONSISTENT"
    INVALID_CLOCK = "INVALID_CLOCK"
    INVALID_ID = "INVALID_ID"
    SERIALIZATION_ERROR = "SERIALIZATION_ERROR"
    BUILD_FAILED = "BUILD_FAILED"  # unexpected internal failure while building an event

    # Keys
    KEY_INVALID = "KEY_INVALID"
    KEY_PURPOSE_MISMATCH = "KEY_PURPOSE_MISMATCH"
    KEYS_NOT_INDEPENDENT = "KEYS_NOT_INDEPENDENT"
    REF_KEY_REQUIRED = "REF_KEY_REQUIRED"  # a keyed projection needs K_ref (B2-P2)
    REF_KEY_EPOCH_MISMATCH = "REF_KEY_EPOCH_MISMATCH"  # K_ref is not the source event's epoch (B2-P2)

    # Sinks
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    UNAUTHENTICATED_REJECTED = "UNAUTHENTICATED_REJECTED"
    DUPLICATE_EVENT_ID = "DUPLICATE_EVENT_ID"
    SINK_FULL = "SINK_FULL"
    SINK_ERROR = "SINK_ERROR"


class AuditError(Exception):
    """An audit operation failed. ``code`` is machine-readable; ``path`` is a fixed field path."""

    def __init__(self, code: AuditErrorCode, path: str = "") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code.value} at {path or '<root>'}")
