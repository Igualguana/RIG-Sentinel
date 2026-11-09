"""Canonical JSON serialization and domain-separated SHA-256 digests."""

from __future__ import annotations

import hashlib
import json
from typing import Any

POLICY_DIGEST_DOMAIN = "rig.policy/v1"
REQUEST_DIGEST_DOMAIN = "rig.request/v1"
APPROVAL_BINDING_DOMAIN = "rig.approval-binding/v1"
DECISION_DIGEST_DOMAIN = "rig.decision/v1"


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` deterministically.

    Keys are sorted, whitespace is removed, output is pure ASCII, and NaN or
    infinity are rejected.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(domain: str, value: Any) -> str:
    """Return a hex SHA-256 of ``value`` prefixed with a domain tag.

    The domain tag ensures that, for example, a request digest can never be
    confused with a policy digest of identical JSON content.
    """
    hasher = hashlib.sha256()
    hasher.update(domain.encode("ascii"))
    hasher.update(b"\x00")
    hasher.update(canonical_json(value))
    return hasher.hexdigest()
