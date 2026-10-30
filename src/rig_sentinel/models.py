from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Permission:
    name: str
    action: str
    resource: str
    risk: str = "UNKNOWN"


@dataclass(frozen=True)
class Resource:
    name: str
    resource_type: str
    sensitivity: str = "UNKNOWN"


@dataclass(frozen=True)
class Tool:
    name: str
    category: str
    provider: str | None = None
    permissions: tuple[Permission, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Identity:
    name: str
    identity_type: str
    provider: str | None = None


@dataclass(frozen=True)
class Agent:
    name: str
    provider: str | None = None
    identity: Identity | None = None
    tools: tuple[Tool, ...] = field(default_factory=tuple)
    resources: tuple[Resource, ...] = field(default_factory=tuple)