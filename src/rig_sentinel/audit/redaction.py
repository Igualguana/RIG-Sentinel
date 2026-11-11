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
"""

from __future__ import annotations

import builtins
import re

from rig_sentinel.audit.chain import pseudonym
from rig_sentinel.audit.events import ResourceSection
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
