"""Identifier grammars shared by policies and requests.

All identifiers are lowercase ASCII. Non-ASCII input is rejected rather than
normalized so that visually confusable names (for example a Cyrillic ``а``
in place of a Latin ``a``) can never match a policy entry.
"""

from __future__ import annotations

import re

IDENTIFIER_PATTERN = r"[a-z0-9][a-z0-9._-]{0,127}"
TOOL_SCHEMES = ("mcp", "local")

_IDENTIFIER_RE = re.compile(IDENTIFIER_PATTERN)
_TOOL_ID_RE = re.compile(
    rf"(mcp|local)://({IDENTIFIER_PATTERN})/({IDENTIFIER_PATTERN})"
)
_TOOL_SERVER_WILDCARD_RE = re.compile(
    rf"(mcp|local)://({IDENTIFIER_PATTERN})/\*"
)
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")

# Longest valid tool id: scheme (5) + "://" (3) + 128 + "/" (1) + 128.
_MAX_TOOL_ID_LENGTH = 5 + 3 + 128 + 1 + 128


def is_identifier(value: object) -> bool:
    """Return True for a canonical identifier such as ``support-bot``."""
    return (
        type(value) is str
        and len(value) <= 128
        and _IDENTIFIER_RE.fullmatch(value) is not None
    )


def is_tool_id(value: object) -> bool:
    """Return True for a fully qualified tool id such as ``mcp://mail/send``."""
    return (
        type(value) is str
        and len(value) <= _MAX_TOOL_ID_LENGTH
        and _TOOL_ID_RE.fullmatch(value) is not None
    )


def split_tool_id(value: str) -> tuple[str, str, str]:
    """Split a validated tool id into ``(scheme, server, tool_name)``."""
    match = _TOOL_ID_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        raise ValueError("not a fully qualified tool id")
    return match.group(1), match.group(2), match.group(3)


def server_wildcard_prefix(value: object) -> str | None:
    """Return ``scheme://server/`` for a pattern like ``mcp://server/*``."""
    if type(value) is not str or len(value) > _MAX_TOOL_ID_LENGTH:
        return None
    match = _TOOL_SERVER_WILDCARD_RE.fullmatch(value)
    if match is None:
        return None
    return f"{match.group(1)}://{match.group(2)}/"


def is_sha256_hex(value: object) -> bool:
    """Return True for a lowercase 64-character hexadecimal digest."""
    return type(value) is str and _SHA256_HEX_RE.fullmatch(value) is not None
