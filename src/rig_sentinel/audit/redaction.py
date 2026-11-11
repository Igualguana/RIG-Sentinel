"""Privacy minimization for audit events (M2-B).

Redaction here is mostly *by construction*: the event schema is a closed
allowlist, and every caller value has already passed M1's ASCII grammars. This
module adds the few transformations those values still need:

* resources are reduced to their kind and depth, plus HMAC pseudonyms of the
  authority and the full canonical resource **only when K_ref is present**;
* session and request ids become HMAC pseudonyms, or are dropped without K_ref;
* identifiers that look like credentials are dropped and counted;
* ``error_type`` is mapped to a built-in exception name, ``UnlistedError`` or
  ``InternalError``.

Unkeyed SHA-256 is never used as a pseudonym: guessable values (paths, table
names, hosts) could be recovered from it by brute force.

B2-P1 adds the **persistence privacy gate**, :func:`check_persistable`: a pure,
side-effect-free check that a future persistent sink must pass before storing an
envelope (see the end of this module).
"""

from __future__ import annotations

import builtins
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from rig_sentinel.audit.chain import AuthStatus, pseudonym
from rig_sentinel.audit.events import (
    APPROVED_READABLE_LABELS,
    AuditEnvelope,
    AuditEvent,
    AuditEventV3,
    ResourceSection,
)
from rig_sentinel.audit.keys import AuditKey
from rig_sentinel.policy.identifiers import split_tool_id
from rig_sentinel.policy.resources import ResourceRef

UNLISTED_ERROR_CLASS = "UnlistedError"
_FALLBACK_ERROR_CLASS = "InternalError"  # used by M1's import-time FALLBACK_DENY record

# Prefixes of common credential formats that fit M1's lowercase identifier grammar.
CREDENTIAL_PREFIXES = (
    "sk-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "xapp-", "glpat-", "pypi-", "akia", "asia",
)
# A long run of letters and digits that mixes both, typical of tokens and keys.
_HIGH_ENTROPY_RE = re.compile(r"[a-z0-9]{24,}")


def _builtin_exception_names() -> frozenset[str]:
    names = set()
    for name, obj in vars(builtins).items():
        if type(obj) is type and issubclass(obj, Exception) and obj.__name__ == name:
            names.add(name)
    return frozenset(names)


_ALLOWED_ERROR_CLASSES = _builtin_exception_names() | {UNLISTED_ERROR_CLASS, _FALLBACK_ERROR_CLASS}


def safe_error_class(error_type: object) -> str | None:
    """Map a record's ``error_type`` to an allowlisted class name."""
    if error_type is None:
        return None
    if type(error_type) is str and error_type in _ALLOWED_ERROR_CLASSES:
        return error_type
    return UNLISTED_ERROR_CLASS


def looks_like_credential(value: str) -> bool:
    """Heuristic, defense in depth only: never the primary control."""
    if value.startswith(CREDENTIAL_PREFIXES):
        return True
    for run in _HIGH_ENTROPY_RE.findall(value):
        digits = sum(char.isdigit() for char in run)
        if digits >= 6 and len(run) - digits >= 6:
            return True
    return False


def tool_id_looks_like_credential(tool_id: str) -> bool:
    _scheme, server, tool = split_tool_id(tool_id)
    return looks_like_credential(server) or looks_like_credential(tool)


def minimize_resource(resource: ResourceRef, ref_key: AuditKey | None) -> ResourceSection:
    """Kind and depth always; keyed authority and resource references only with K_ref."""
    kind = resource.kind.value
    authority_ref = None
    resource_ref = None
    if ref_key is not None:
        if resource.authority:
            authority_ref = pseudonym(ref_key, f"authority/{kind}", resource.authority)
        resource_ref = pseudonym(ref_key, f"resource/{kind}", resource.canonical)
    return ResourceSection(
        kind=resource.kind,
        depth=len(resource.segments),
        authority_ref=authority_ref,
        resource_ref=resource_ref,
    )


def reference(ref_key: AuditKey | None, namespace: str, value: str | None) -> str | None:
    """Keyed pseudonym of a caller-supplied id, or ``None`` without K_ref or value."""
    if ref_key is None or value is None:
        return None
    return pseudonym(ref_key, namespace, value)


# --- Persistence privacy gate (B2-P1) ----------------------------------------------------


class PersistenceCode(StrEnum):
    """Why an envelope may or may not be written to persistent storage."""

    OK = "ok"
    NOT_AN_ENVELOPE = "not_an_envelope"
    V2_EVENT_NOT_PERSISTABLE = "v2_event_not_persistable"
    UNSUPPORTED_EVENT_VERSION = "unsupported_event_version"
    KEYRING_INVALID = "keyring_invalid"
    CONFIGURATION_INVALID = "configuration_invalid"
    DIGEST_MISMATCH = "digest_mismatch"
    NOT_AUTHENTICATED = "not_authenticated"
    UNKNOWN_KEY = "unknown_key"
    AUTHENTICATION_FAILED = "authentication_failed"
    SCHEMA_INVALID = "schema_invalid"
    LABEL_NOT_ALLOWED = "label_not_allowed"


@dataclass(frozen=True)
class PersistenceVerdict:
    """Result of :func:`check_persistable`. Carries a code only, never event content."""

    ok: bool
    code: PersistenceCode


_AUTH_FAILURES = {
    AuthStatus.DIGEST_MISMATCH: PersistenceCode.DIGEST_MISMATCH,
    AuthStatus.UNAUTHENTICATED: PersistenceCode.NOT_AUTHENTICATED,
    AuthStatus.UNKNOWN_KEY: PersistenceCode.UNKNOWN_KEY,
    AuthStatus.MAC_MISMATCH: PersistenceCode.AUTHENTICATION_FAILED,
    AuthStatus.SCHEMA_INVALID: PersistenceCode.SCHEMA_INVALID,
}


def _verdict(code: PersistenceCode) -> PersistenceVerdict:
    return PersistenceVerdict(ok=code is PersistenceCode.OK, code=code)


def check_persistable(
    envelope: object,
    keys: Mapping[str, AuditKey],
    *,
    readable_labels: frozenset[str] | set[str] | None = None,
) -> PersistenceVerdict:
    """Decide whether ``envelope`` may be written to persistent storage.

    Accepted only if **all** hold:

    1. it is an :class:`AuditEnvelope` (exact type) holding a ``rig.audit-event/v3``
       event (v2 events, which carry readable identities, are refused);
    2. its digest and MAC verify under ``keys`` (an authenticator is mandatory; there
       is no unauthenticated mode);
    3. its canonical bytes re-parse under the closed v3 schema to an identical
       envelope (so in-memory objects altered behind the model's back are refused,
       even when a key holder sealed them);
    4. every readable label is within ``readable_labels`` (default and maximum:
       :data:`APPROVED_READABLE_LABELS`).

    The check is pure: it never modifies, repairs or re-seals the envelope, performs
    no I/O, and never raises for invalid content. Passing it proves that the event is
    privacy-compliant and was sealed by a holder of K_auth. It does **not** prove that
    ``PolicyEngine`` made the decision, that anything was stored, or that a tool ran.
    """
    try:
        return _check_persistable(envelope, keys, readable_labels)
    except Exception:  # never raise for content; BaseException propagates
        return _verdict(PersistenceCode.SCHEMA_INVALID)


def _check_persistable(envelope: object, keys: object, readable_labels: object) -> PersistenceVerdict:
    if type(envelope) is not AuditEnvelope:
        return _verdict(PersistenceCode.NOT_AN_ENVELOPE)
    if type(keys) is not dict:
        return _verdict(PersistenceCode.KEYRING_INVALID)
    if readable_labels is None:
        allowed = APPROVED_READABLE_LABELS
    elif type(readable_labels) is frozenset or type(readable_labels) is set:
        allowed_items = tuple(readable_labels)
        if not all(type(item) is str and item in APPROVED_READABLE_LABELS for item in allowed_items):
            return _verdict(PersistenceCode.CONFIGURATION_INVALID)
        allowed = frozenset(allowed_items)
    else:
        return _verdict(PersistenceCode.CONFIGURATION_INVALID)

    event_type = type(envelope.event)
    if event_type is AuditEvent:
        return _verdict(PersistenceCode.V2_EVENT_NOT_PERSISTABLE)
    if event_type is not AuditEventV3:
        return _verdict(PersistenceCode.UNSUPPORTED_EVENT_VERSION)

    status = envelope.verify(keys)
    if status is not AuthStatus.AUTHENTIC:
        return _verdict(_AUTH_FAILURES.get(status, PersistenceCode.AUTHENTICATION_FAILED))

    from rig_sentinel.audit.validation import envelope_from_dict

    raw = envelope.canonical_bytes()
    reparsed = envelope_from_dict(json.loads(raw))  # closed v3 schema; AuditError -> SCHEMA_INVALID
    if type(reparsed.event) is not AuditEventV3 or reparsed.canonical_bytes() != raw:
        return _verdict(PersistenceCode.SCHEMA_INVALID)

    readable = reparsed.event.caller.readable_labels or ()
    if not set(readable) <= allowed:
        return _verdict(PersistenceCode.LABEL_NOT_ALLOWED)
    return _verdict(PersistenceCode.OK)
