"""Canonical digests, pseudonyms and envelope authentication (M2-B).

All functions are pure. Every digest and MAC uses M1's canonical JSON
(sorted keys, compact, ASCII-only, no NaN) and a domain tag followed by a NUL
separator, so values computed for one purpose can never be confused with
another.

What an authenticator proves: the event bytes were produced by a holder of
``K_auth``. HMAC is symmetric, so it does not say *which* holder, gives no
non-repudiation, does not prove that a tool ran, and does not detect deleted
or truncated events (that needs ordering plus an independent checkpoint, in
M2-C).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.audit.keys import AuditKey, KeyPurpose
from rig_sentinel.policy.canonical import canonical_json, digest

EVENT_DIGEST_DOMAIN = "rig.audit-event/v2"
MAC_DOMAIN = "rig.audit-mac/v1"
REF_DOMAIN = "rig.audit-ref/v1"
MAC_ALGORITHM = "HMAC-SHA256"
_SEPARATOR = bytes(1)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Raw HMAC-SHA-256 (RFC 2104). Exposed for known-answer tests."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def event_digest(event: Mapping[str, Any]) -> str:
    """SHA-256 of an event's canonical JSON, domain ``rig.audit-event/v2``."""
    try:
        return digest(EVENT_DIGEST_DOMAIN, event)
    except (TypeError, ValueError):
        raise AuditError(AuditErrorCode.SERIALIZATION_ERROR, "event") from None


def _mac_message(key_id: str, event: Mapping[str, Any]) -> bytes:
    try:
        body = canonical_json(event)
    except (TypeError, ValueError):
        raise AuditError(AuditErrorCode.SERIALIZATION_ERROR, "event") from None
    return (
        MAC_DOMAIN.encode("ascii")
        + _SEPARATOR
        + key_id.encode("ascii")
        + _SEPARATOR
        + body
    )


def compute_mac(auth_key: AuditKey, event: Mapping[str, Any]) -> str:
    """HMAC-SHA-256 over the domain tag, the key id and the canonical event."""
    if type(auth_key) is not AuditKey:
        raise AuditError(AuditErrorCode.KEY_INVALID, "auth")
    return auth_key._hmac_hex(KeyPurpose.AUTH, _mac_message(auth_key.key_id, event))


def macs_equal(expected: str, presented: object) -> bool:
    """Constant-time comparison of two hex MACs; False for anything malformed."""
    if type(presented) is not str or not presented.isascii():
        return False
    return hmac.compare_digest(expected.encode("ascii"), presented.encode("ascii"))


def pseudonym(ref_key: AuditKey, kind: str, value: str) -> str:
    """Keyed, 128-bit pseudonym of ``value`` within the namespace ``kind``.

    Equal inputs give equal pseudonyms under the same ``K_ref`` only. Without
    the key, a pseudonym cannot be recomputed or brute-forced offline.
    """
    if type(ref_key) is not AuditKey:
        raise AuditError(AuditErrorCode.KEY_INVALID, "ref")
    if type(kind) is not str or type(value) is not str or not kind.isascii():
        raise AuditError(AuditErrorCode.INVALID_FIELD, "pseudonym")
    message = (
        f"{REF_DOMAIN}/{kind}".encode("ascii")
        + _SEPARATOR
        + value.encode("utf-8", errors="strict")
    )
    return ref_key._hmac_hex(KeyPurpose.REF, message)[:32]


class AuthStatus(StrEnum):
    """Result of verifying an envelope. Only AUTHENTIC means the MAC was valid."""

    AUTHENTIC = "authentic"
    UNAUTHENTICATED = "unauthenticated"  # no authenticator attached
    UNKNOWN_KEY = "unknown_key"  # key id not in the keyring
    MAC_MISMATCH = "mac_mismatch"  # content or tag changed, or wrong key
    DIGEST_MISMATCH = "digest_mismatch"  # event_digest does not match the event
    SCHEMA_INVALID = "schema_invalid"  # not a well-formed envelope


def keyring(keys: Iterable[AuditKey]) -> dict[str, AuditKey]:
    """Map key ids to authentication keys for verification."""
    ring: dict[str, AuditKey] = {}
    for key in keys:
        if type(key) is not AuditKey or key.purpose is not KeyPurpose.AUTH:
            raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "keyring")
        ring[key.key_id] = key
    return ring
