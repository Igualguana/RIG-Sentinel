"""Typed resource identifiers and their canonical form.

Resources are written as ``<kind>:<value>``. The engine parses and
canonicalizes every resource itself instead of trusting the caller's string,
so that two spellings of the same target always compare equal and spellings
that are ambiguous across platforms are rejected.

The checks here are purely lexical. No filesystem, DNS or network lookup is
performed (symlinks, mount points and name resolution are runtime concerns
for a future enforcement adapter).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from rig_sentinel.policy.identifiers import is_identifier

MAX_RESOURCE_LENGTH = 2048
MAX_SECRET_SEGMENTS = 16


class ResourceKind(StrEnum):
    FS = "fs"
    DB = "db"
    URL = "url"
    SHELL = "shell"
    EMAIL = "email"
    SECRET = "secret"
    NONE = "none"


HIERARCHICAL_KINDS = frozenset(
    {ResourceKind.FS, ResourceKind.DB, ResourceKind.URL, ResourceKind.SECRET}
)


class ResourceError(ValueError):
    """A resource identifier is malformed or ambiguous."""


# Visible ASCII only: no spaces, control characters or non-ASCII.
_VISIBLE_ASCII_RE = re.compile(r"[\x21-\x7e]+")
_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~+=,@-]+")
_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_TOP_LABEL_RE = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_RE = re.compile(rf"{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}")
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_URL_RE = re.compile(r"(https?)://([^/]+)(/.*)?")
_URL_FORBIDDEN_CHARS = frozenset("@?#%\\")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ResourceRef:
    """A parsed resource.

    ``authority`` holds the non-path part (URL origin, database name, shell
    command, e-mail domain). ``segments`` holds hierarchical path segments.
    Build instances with :func:`parse_resource`; the engine re-parses
    :attr:`canonical` before use, so hand-built instances cannot bypass
    validation.
    """

    kind: ResourceKind
    authority: str = ""
    segments: tuple[str, ...] = ()

    @property
    def canonical(self) -> str:
        path = "/".join(self.segments)
        kind = self.kind
        if kind == ResourceKind.FS:
            return "fs:/" + path
        if kind == ResourceKind.URL:
            return f"url:{self.authority}/{path}"
        if kind == ResourceKind.DB:
            return f"db:{self.authority}" + (f"/{path}" if path else "")
        if kind == ResourceKind.SECRET:
            return "secret:" + path
        if kind == ResourceKind.NONE:
            return "none:"
        return f"{kind}:{self.authority}"

    def __str__(self) -> str:
        return self.canonical


def parse_resource(value: object) -> ResourceRef:
    """Parse and canonicalize a resource identifier.

    Raises :class:`ResourceError` for anything malformed or ambiguous.
    """
    if type(value) is not str:
        raise ResourceError("resource must be a string")
    if not value or len(value) > MAX_RESOURCE_LENGTH:
        raise ResourceError("resource length out of range")
    if _VISIBLE_ASCII_RE.fullmatch(value) is None:
        raise ResourceError(
            "resource must be visible ASCII without whitespace or control characters"
        )

    kind_text, separator, rest = value.partition(":")
    if not separator:
        raise ResourceError("resource must use the form <kind>:<value>")

    try:
        kind = ResourceKind(kind_text)
    except ValueError:
        raise ResourceError("unsupported resource kind") from None

    return _PARSERS[kind](rest)


def _path_segments(path: str) -> tuple[str, ...]:
    """Lexically normalize an absolute POSIX-style path."""
    if not path.startswith("/"):
        raise ResourceError("path must be absolute")
    if path.startswith("//"):
        raise ResourceError("path must not start with '//'")

    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise ResourceError("'..' path segments are not allowed")
        if segment.endswith("."):
            # Windows silently strips trailing dots; reject to avoid ambiguity.
            raise ResourceError("path segments must not end with '.'")
        if _PATH_SEGMENT_RE.fullmatch(segment) is None:
            raise ResourceError("path segment contains unsupported characters")
        segments.append(segment)
    return tuple(segments)


def _host(value: str, *, allow_ip: bool) -> str:
    host = value.lower()
    if not host or len(host) > 253:
        raise ResourceError("host length out of range")
    if _IPV4_RE.fullmatch(host) is not None:
        if not allow_ip:
            raise ResourceError("IP literals are not allowed here")
        return host

    labels = host.split(".")
    for label in labels:
        if _HOST_LABEL_RE.fullmatch(label) is None:
            raise ResourceError("invalid host name")
    # The last label must start with a letter. This rejects ambiguous
    # numeric forms such as "1.2.3" or "0x7f000001" that some resolvers
    # interpret as IP addresses.
    if _TOP_LABEL_RE.fullmatch(labels[-1]) is None:
        raise ResourceError("invalid top-level host label")
    return host


def _parse_fs(rest: str) -> ResourceRef:
    return ResourceRef(ResourceKind.FS, "", _path_segments(rest))


def _parse_url(rest: str) -> ResourceRef:
    if any(char in _URL_FORBIDDEN_CHARS for char in rest):
        raise ResourceError(
            "URLs must not contain credentials, queries, fragments, "
            "percent-encoding or backslashes"
        )
    match = _URL_RE.fullmatch(rest)
    if match is None:
        raise ResourceError("URL must be http(s)://host[:port][/path]")

    scheme, host_port, path = match.group(1), match.group(2), match.group(3)
    host_text, colon, port_text = host_port.partition(":")
    host = _host(host_text, allow_ip=True)

    authority = f"{scheme}://{host}"
    if colon:
        if _PORT_RE.fullmatch(port_text) is None:
            raise ResourceError("invalid port")
        port = int(port_text)
        if port > 65535:
            raise ResourceError("invalid port")
        if port != _DEFAULT_PORTS[scheme]:
            authority += f":{port}"

    segments = _path_segments(path) if path else ()
    return ResourceRef(ResourceKind.URL, authority, segments)


def _parse_db(rest: str) -> ResourceRef:
    parts = rest.split("/")
    if len(parts) > 2 or not all(is_identifier(part) for part in parts):
        raise ResourceError("database resource must be db:<database>[/<table>]")
    return ResourceRef(ResourceKind.DB, parts[0], tuple(parts[1:]))


def _parse_shell(rest: str) -> ResourceRef:
    if not is_identifier(rest):
        raise ResourceError("shell resource must be shell:<command-name>")
    return ResourceRef(ResourceKind.SHELL, rest)


def _parse_email(rest: str) -> ResourceRef:
    return ResourceRef(ResourceKind.EMAIL, _host(rest, allow_ip=False))


def _parse_secret(rest: str) -> ResourceRef:
    parts = rest.split("/")
    if len(parts) > MAX_SECRET_SEGMENTS or not all(
        is_identifier(part) for part in parts
    ):
        raise ResourceError("secret resource must be secret:<name>[/<name>...]")
    return ResourceRef(ResourceKind.SECRET, "", tuple(parts))


def _parse_none(rest: str) -> ResourceRef:
    if rest:
        raise ResourceError("the 'none' resource takes no value")
    return ResourceRef(ResourceKind.NONE)


_PARSERS = {
    ResourceKind.FS: _parse_fs,
    ResourceKind.URL: _parse_url,
    ResourceKind.DB: _parse_db,
    ResourceKind.SHELL: _parse_shell,
    ResourceKind.EMAIL: _parse_email,
    ResourceKind.SECRET: _parse_secret,
    ResourceKind.NONE: _parse_none,
}
