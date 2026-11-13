"""Storage error codes for the persistent audit chain (Genesis B2-M2-C1, founder decision F10).

A separate enum from :class:`~rig_sentinel.audit.errors.AuditErrorCode`, so M2-B is unchanged
and every failure class has its own code: malformed input, non-canonical input, schema
violations, authentication failures, privacy failures and chain-structure failures are never
confused with one another. Errors carry a code and an optional fixed field path only: never
input bytes, record content or key material.
"""

from __future__ import annotations

from enum import StrEnum


class StorageErrorCode(StrEnum):
    # Input and size
    INPUT_TYPE_INVALID = "input_type_invalid"
    LINE_TOO_LONG = "line_too_long"
    PARTIAL_LINE = "partial_line"
    # Byte pre-scan
    BYTE_NOT_ALLOWED = "byte_not_allowed"
    DEPTH_EXCEEDED = "depth_exceeded"
    UNBALANCED = "unbalanced"
    TOKEN_INVALID = "token_invalid"
    NUMBER_TOO_LONG = "number_too_long"
    STRING_TOO_LONG = "string_too_long"
    BAD_ESCAPE = "bad_escape"
    SURROGATE_INVALID = "surrogate_invalid"  # H1-01: unpaired or misordered UTF-16 surrogate escape
    UNTERMINATED = "unterminated"
    # Parsing and canonical form
    MALFORMED_JSON = "malformed_json"
    DUPLICATE_KEY = "duplicate_key"
    NON_CANONICAL = "non_canonical"
    # Closed schemas
    SCHEMA_INVALID = "schema_invalid"
    # Authentication
    DIGEST_MISMATCH = "digest_mismatch"
    MAC_INVALID = "mac_invalid"
    UNKNOWN_KEY = "unknown_key"
    # Keys and configuration
    KEY_INVALID = "key_invalid"
    KEY_PURPOSE_MISMATCH = "key_purpose_mismatch"
    KEYS_NOT_INDEPENDENT = "keys_not_independent"
    KEYRING_INVALID = "keyring_invalid"
    # P2 boundary and privacy
    NOT_VALIDATED = "not_validated"
    PROJECTION_REJECTED = "projection_rejected"
    PROJECTION_AUTH_FAILED = "projection_auth_failed"
    PRIVACY_DAMAGE = "privacy_damage"
    EPOCH_MISMATCH = "epoch_mismatch"
    # Chain structure (verifier issues)
    EMPTY_CHAIN = "empty_chain"
    GENESIS_INVALID = "genesis_invalid"
    CHAIN_ID_MISMATCH = "chain_id_mismatch"
    SEQUENCE_GAP = "sequence_gap"
    LINK_BROKEN = "link_broken"
    SEGMENT_INVALID = "segment_invalid"
    KEY_CHANGE_INVALID = "key_change_invalid"
    DUPLICATE_EVENT_ID = "duplicate_event_id"
    RECOVERY_RECORDED = "recovery_recorded"
    ANCHOR_REINITIALIZED = "anchor_reinitialized"
    TOO_MANY_ISSUES = "too_many_issues"
    RECORD_BUDGET_EXCEEDED = "record_budget_exceeded"  # H1-02: more lines than max_records
    # Internal invariants (splice proof)
    INTERNAL_INVARIANT = "internal_invariant"


class StorageError(Exception):
    """A storage-layer refusal. ``path`` is a fixed field name, never a value."""

    def __init__(self, code: StorageErrorCode, path: str = "") -> None:
        if type(code) is not StorageErrorCode:
            code = StorageErrorCode.INTERNAL_INVARIANT
        if type(path) is not str:
            path = ""
        super().__init__(f"{code.value}: {path}" if path else code.value)
        self.code = code
        self.path = path
