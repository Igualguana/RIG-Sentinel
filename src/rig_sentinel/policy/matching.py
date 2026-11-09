"""Pattern parsing and rule matching.

Pattern grammar (no regular expressions, no globs in the middle):

* agents:     ``*`` or an exact identifier
* tools:      ``*``, an exact tool id, or ``<scheme>://<server>/*``
* operations: ``*`` or an exact operation class
* resources:  ``*``, an exact resource, or ``<hierarchical-resource>/**``

``/**`` matches the prefix itself and anything below it, at path-segment
boundaries only: ``fs:/srv/data/**`` matches ``fs:/srv/data/x`` but not
``fs:/srv/database``.
"""

from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.policy.identifiers import is_identifier, is_tool_id, server_wildcard_prefix
from rig_sentinel.policy.model import (
    ASSURANCE_RANK,
    AuthorizationRequest,
    Effect,
    OperationClass,
    Rule,
    RuleConditions,
)
from rig_sentinel.policy.resources import (
    HIERARCHICAL_KINDS,
    ResourceError,
    ResourceKind,
    ResourceRef,
    parse_resource,
)
from rig_sentinel.policy.schema import WILDCARD

_PREFIX_SUFFIX = "/**"


class PatternError(ValueError):
    """A rule pattern is malformed."""


# ---------------------------------------------------------------------------
# Resource patterns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourcePattern:
    match_any: bool = False
    ref: ResourceRef | None = None
    prefix: bool = False

    @property
    def canonical(self) -> str:
        if self.match_any or self.ref is None:
            return WILDCARD
        if not self.prefix:
            return self.ref.canonical
        return self.ref.canonical.rstrip("/") + _PREFIX_SUFFIX

    def matches(self, resource: ResourceRef) -> bool:
        if self.match_any:
            return True
        ref = self.ref
        if ref is None or ref.kind != resource.kind or ref.authority != resource.authority:
            return False
        if not self.prefix:
            return ref.segments == resource.segments
        depth = len(ref.segments)
        return resource.segments[:depth] == ref.segments


def parse_resource_pattern(value: object) -> ResourcePattern:
    if type(value) is not str:
        raise PatternError("resource pattern must be a string")
    if value == WILDCARD:
        return ResourcePattern(match_any=True)

    prefix = value.endswith(_PREFIX_SUFFIX)
    base = value[: -len(_PREFIX_SUFFIX)] if prefix else value
    if prefix and base in ("fs:", "fs:/"):
        base = "fs:/"
    if "*" in base:
        raise PatternError("'*' is only allowed as '*' or a trailing '/**'")

    try:
        ref = parse_resource(base)
    except ResourceError as exc:
        raise PatternError(f"invalid resource pattern: {exc}") from None

    if prefix and ref.kind not in HIERARCHICAL_KINDS:
        raise PatternError("'/**' is only allowed for fs, db, url and secret resources")
    if prefix and ref.kind == ResourceKind.DB and ref.segments:
        raise PatternError("'/**' on a database resource must follow the database name")
    return ResourcePattern(ref=ref, prefix=prefix)


# ---------------------------------------------------------------------------
# Tool patterns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolPattern:
    value: str
    server_prefix: str | None = None

    @property
    def match_any(self) -> bool:
        return self.value == WILDCARD

    def matches(self, tool_id: str) -> bool:
        if self.match_any:
            return True
        if self.server_prefix is not None:
            return tool_id.startswith(self.server_prefix)
        return tool_id == self.value


def parse_tool_pattern(value: object) -> ToolPattern:
    if value == WILDCARD and type(value) is str:
        return ToolPattern(WILDCARD)
    prefix = server_wildcard_prefix(value)
    if prefix is not None:
        return ToolPattern(value, server_prefix=prefix)  # type: ignore[arg-type]
    if is_tool_id(value):
        return ToolPattern(value)  # type: ignore[arg-type]
    raise PatternError(
        "tool pattern must be '*', a fully qualified tool id, or '<scheme>://<server>/*'"
    )


def parse_agent_pattern(value: object) -> str:
    if type(value) is str and (value == WILDCARD or is_identifier(value)):
        return value
    raise PatternError("agent pattern must be '*' or an identifier")


def parse_operation_pattern(value: object) -> str:
    if type(value) is not str:
        raise PatternError("operation pattern must be a string")
    if value == WILDCARD:
        return value
    try:
        return OperationClass(value).value
    except ValueError:
        raise PatternError("unsupported operation") from None


# ---------------------------------------------------------------------------
# Compiled rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    effect: Effect
    agents: frozenset[str] | None
    tools: tuple[ToolPattern, ...]
    operations: frozenset[OperationClass] | None
    resources: tuple[ResourcePattern, ...]
    conditions: RuleConditions


def compile_rule(rule: Rule) -> CompiledRule:
    agents = tuple(parse_agent_pattern(item) for item in rule.agents)
    operations = tuple(parse_operation_pattern(item) for item in rule.operations)
    return CompiledRule(
        rule_id=rule.rule_id,
        effect=rule.effect,
        agents=None if WILDCARD in agents else frozenset(agents),
        tools=tuple(parse_tool_pattern(item) for item in rule.tools),
        operations=(
            None
            if WILDCARD in operations
            else frozenset(OperationClass(item) for item in operations)
        ),
        resources=tuple(parse_resource_pattern(item) for item in rule.resources),
        conditions=rule.conditions,
    )


def conditions_hold(conditions: RuleConditions, request: AuthorizationRequest) -> bool:
    context = request.context
    agent = request.agent
    if conditions.environments is not None and context.environment not in conditions.environments:
        return False
    if conditions.min_assurance is not None:
        if agent is None:
            return False
        if ASSURANCE_RANK[agent.assurance] < ASSURANCE_RANK[conditions.min_assurance]:
            return False
    labels = frozenset(context.labels)
    if not labels.issuperset(conditions.labels_all):
        return False
    if labels.intersection(conditions.labels_none):
        return False
    return True


def rule_matches(rule: CompiledRule, request: AuthorizationRequest) -> bool:
    """Return True if every field of ``rule`` matches and its conditions hold."""
    agent = request.agent
    if agent is None:
        return False
    if rule.agents is not None and agent.agent_id not in rule.agents:
        return False
    if not any(pattern.matches(request.tool.tool_id) for pattern in rule.tools):
        return False
    if rule.operations is not None and request.operation not in rule.operations:
        return False
    if not any(pattern.matches(request.resource) for pattern in rule.resources):
        return False
    return conditions_hold(rule.conditions, request)
