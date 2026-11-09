"""Load policies from TOML with strict limits and optional digest pinning.

Loading never "partially" succeeds: any problem raises and no policy is
returned. Callers that keep running after a failed load must treat the
engine as having no policy (deny-all), not reuse a stale one implicitly.
"""

from __future__ import annotations

import hmac
import tomllib
from pathlib import Path

from rig_sentinel.policy.errors import PolicyDigestMismatchError, PolicyLoadError
from rig_sentinel.policy.identifiers import is_sha256_hex
from rig_sentinel.policy.model import Policy
from rig_sentinel.policy.schema import MAX_POLICY_BYTES
from rig_sentinel.policy.validation import validate_policy

_UTF8_BOM = b"\xef\xbb\xbf"


def load_policy_file(
    path: str | Path, *, expected_sha256: str | None = None
) -> Policy:
    """Read, parse, validate and (optionally) pin a TOML policy file."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise PolicyLoadError(f"cannot read policy file ({type(exc).__name__})") from None
    return load_policy_bytes(raw, expected_sha256=expected_sha256)


def load_policy_bytes(raw: bytes, *, expected_sha256: str | None = None) -> Policy:
    """Parse a policy from UTF-8 encoded TOML bytes."""
    if type(raw) is not bytes:
        raise PolicyLoadError("policy content must be bytes")
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyLoadError(f"policy exceeds {MAX_POLICY_BYTES} bytes")
    if raw.startswith(_UTF8_BOM):
        raise PolicyLoadError("policy must be UTF-8 without a byte-order mark")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise PolicyLoadError("policy is not valid UTF-8") from None
    return load_policy_text(text, expected_sha256=expected_sha256)


def load_policy_text(text: str, *, expected_sha256: str | None = None) -> Policy:
    """Parse a policy from TOML text."""
    if type(text) is not str:
        raise PolicyLoadError("policy content must be a string")
    try:
        size = len(text.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise PolicyLoadError("policy contains unencodable characters") from None
    if size > MAX_POLICY_BYTES:
        raise PolicyLoadError(f"policy exceeds {MAX_POLICY_BYTES} bytes")

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        # tomllib messages report line/column, not file content.
        raise PolicyLoadError(f"malformed TOML: {exc}") from None
    except RecursionError:
        raise PolicyLoadError("policy nesting is too deep") from None

    policy = validate_policy(data)
    if expected_sha256 is not None:
        check_policy_digest(policy, expected_sha256)
    return policy


def check_policy_digest(policy: Policy, expected_sha256: str) -> None:
    """Raise :class:`PolicyDigestMismatchError` unless the digest matches."""
    if not is_sha256_hex(expected_sha256):
        raise PolicyDigestMismatchError(
            "expected policy digest must be 64 lowercase hexadecimal characters"
        )
    if not hmac.compare_digest(policy.sha256, expected_sha256):
        raise PolicyDigestMismatchError(
            "policy SHA-256 does not match the pinned value"
        )
