"""Typed models for authorization requests and validated policies.

All models are frozen dataclasses holding only immutable values (strings,
enums, tuples). Requests can be built directly or parsed from a mapping with
:func:`parse_request`; either way the engine re-validates them before use.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rig_sentinel.policy.errors import RequestValidationError
from rig_sentinel.policy.identifiers import is_identifier, is_sha256_hex, is_tool_id
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.resources import (
    ResourceError,
    ResourceKind,
    ResourceRef,
    parse_resource,
)

MAX_REQUEST_LABELS = 32


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class OperationClass(StrEnum):
    """Closed set of operation classes.

    The first six values reuse the capability categories reported by the
    v0.1.0 scanner (``tools.py``), so scanner findings and policy rules share
    one vocabulary.
    """

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    EXTERNAL_SEND = "external_send"
    FINANCIAL = "financial"
    DATABASE_WRITE = "database_write"
    CREDENTIAL_ACCESS = "credential_access"
    ADMIN = "admin"


PROTECTED_OPERATIONS = frozenset(
    operation for operation in OperationClass if operation is not OperationClass.READ
)


class Assurance(StrEnum):
    """How the enforcement adapter established the agent identity.

    The engine does not authenticate agents; it records the assurance level
    supplied by the (trusted) adapter and lets rules require a minimum.
    """

    ASSERTED = "asserted"
    AUTHENTICATED = "authenticated"


ASSURANCE_RANK = {Assurance.ASSERTED: 0, Assurance.AUTHENTICATED: 1}


class Environment(StrEnum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


def _invalid(reason: ReasonCode, message: str) -> RequestValidationError:
    return RequestValidationError(reason, message)


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    assurance: Assurance = Assurance.ASSERTED

    def __post_init__(self) -> None:
        if not is_identifier(self.agent_id):
            raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid agent id")
        if not isinstance(self.assurance, Assurance):
            raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid assurance level")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.agent_id, "assurance": self.assurance.value}


@dataclass(frozen=True)
class ToolIdentity:
    tool_id: str
    manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        if not is_tool_id(self.tool_id):
            raise _invalid(ReasonCode.INVALID_TOOL_ID, "invalid tool id")
        if self.manifest_sha256 is not None and not is_sha256_hex(
            self.manifest_sha256
        ):
            raise _invalid(ReasonCode.INVALID_REQUEST, "invalid manifest digest")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.tool_id}
        if self.manifest_sha256 is not None:
            data["manifest_sha256"] = self.manifest_sha256
        return data


@dataclass(frozen=True)
class AuthorizationContext:
    environment: Environment
    request_id: str | None = None
    session_id: str | None = None
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.environment, Environment):
            raise _invalid(ReasonCode.INVALID_REQUEST, "invalid environment")
        for value in (self.request_id, self.session_id):
            if value is not None and not is_identifier(value):
                raise _invalid(ReasonCode.INVALID_REQUEST, "invalid request or session id")
        if type(self.labels) is not tuple or len(self.labels) > MAX_REQUEST_LABELS:
            raise _invalid(ReasonCode.INVALID_REQUEST, "labels must be a short tuple")
        if not all(is_identifier(label) for label in self.labels):
            raise _invalid(ReasonCode.INVALID_REQUEST, "invalid label")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "environment": self.environment.value,
            "labels": sorted(set(self.labels)),
        }
        if self.request_id is not None:
            data["request_id"] = self.request_id
        if self.session_id is not None:
            data["session_id"] = self.session_id
        return data


@dataclass(frozen=True)
class AuthorizationRequest:
    """A request to perform ``operation`` with ``tool`` on ``resource``.

    ``agent`` may be ``None`` so that adapters can always build a request;
    the engine answers such requests with ``DENY / MISSING_IDENTITY``.
    """

    agent: AgentIdentity | None
    tool: ToolIdentity
    operation: OperationClass
    resource: ResourceRef
    context: AuthorizationContext

    def __post_init__(self) -> None:
        if self.agent is not None and not isinstance(self.agent, AgentIdentity):
            raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid agent")
        if not isinstance(self.tool, ToolIdentity):
            raise _invalid(ReasonCode.INVALID_TOOL_ID, "invalid tool")
        if not isinstance(self.operation, OperationClass):
            raise _invalid(ReasonCode.UNKNOWN_OPERATION, "unknown operation")
        if not isinstance(self.resource, ResourceRef):
            raise _invalid(ReasonCode.INVALID_RESOURCE, "invalid resource")
        if not isinstance(self.context, AuthorizationContext):
            raise _invalid(ReasonCode.INVALID_REQUEST, "invalid context")

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": None if self.agent is None else self.agent.to_dict(),
            "tool": self.tool.to_dict(),
            "operation": self.operation.value,
            "resource": self.resource.canonical,
            "context": self.context.to_dict(),
        }


_REQUEST_KEYS = frozenset({"agent", "tool", "operation", "resource", "context"})
_AGENT_KEYS = frozenset({"id", "assurance"})
_TOOL_KEYS = frozenset({"id", "manifest_sha256"})
_CONTEXT_KEYS = frozenset({"environment", "request_id", "session_id", "labels"})


def _snapshot(value: object, reason: ReasonCode, what: str) -> dict[str, Any]:
    """Copy a mapping once so later mutation cannot change what is evaluated."""
    if not isinstance(value, Mapping):
        raise _invalid(reason, f"{what} must be a mapping")
    snapshot = dict(value)
    if not all(type(key) is str for key in snapshot):
        raise _invalid(reason, f"{what} keys must be strings")
    return snapshot


def _reject_unknown(data: dict[str, Any], allowed: frozenset[str], what: str) -> None:
    if not set(data) <= allowed:
        raise _invalid(ReasonCode.INVALID_REQUEST, f"unknown field in {what}")


def parse_request(data: object) -> AuthorizationRequest:
    """Build a validated :class:`AuthorizationRequest` from a mapping.

    Expected shape::

        {
          "agent": {"id": "support-bot", "assurance": "authenticated"},
          "tool": {"id": "mcp://helpdesk/tickets.get", "manifest_sha256": "..."},
          "operation": "read",
          "resource": "db:helpdesk/tickets",
          "context": {"environment": "staging", "session_id": "s-1",
                      "request_id": "r-1", "labels": []},
        }

    Raises :class:`RequestValidationError` whose ``reason_code`` explains the
    first problem found. Checks run in a fixed order (identity, tool,
    operation, resource, context) so the reason code is deterministic.
    """
    request = _snapshot(data, ReasonCode.INVALID_REQUEST, "request")
    _reject_unknown(request, _REQUEST_KEYS, "request")

    agent = _parse_agent(request.get("agent"))
    tool = _parse_tool(request.get("tool"))
    operation = _parse_operation(request.get("operation"))
    resource = _parse_resource_field(request.get("resource"))
    context = _parse_context(request.get("context"))

    return AuthorizationRequest(
        agent=agent,
        tool=tool,
        operation=operation,
        resource=resource,
        context=context,
    )


def _parse_agent(value: object) -> AgentIdentity:
    if value is None:
        raise _invalid(ReasonCode.MISSING_IDENTITY, "agent identity is missing")
    agent = _snapshot(value, ReasonCode.INVALID_IDENTITY, "agent")
    _reject_unknown(agent, _AGENT_KEYS, "agent")

    agent_id = agent.get("id")
    if agent_id is None or (type(agent_id) is str and not agent_id.strip()):
        raise _invalid(ReasonCode.MISSING_IDENTITY, "agent id is missing")
    if not is_identifier(agent_id):
        raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid agent id")

    assurance_value = agent.get("assurance", Assurance.ASSERTED.value)
    if type(assurance_value) is not str:
        raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid assurance level")
    try:
        assurance = Assurance(assurance_value)
    except ValueError:
        raise _invalid(ReasonCode.INVALID_IDENTITY, "invalid assurance level") from None
    return AgentIdentity(agent_id=agent_id, assurance=assurance)


def _parse_tool(value: object) -> ToolIdentity:
    tool = _snapshot(value, ReasonCode.INVALID_TOOL_ID, "tool")
    _reject_unknown(tool, _TOOL_KEYS, "tool")
    tool_id = tool.get("id")
    if not is_tool_id(tool_id):
        raise _invalid(ReasonCode.INVALID_TOOL_ID, "invalid tool id")
    return ToolIdentity(tool_id=tool_id, manifest_sha256=tool.get("manifest_sha256"))


def _parse_operation(value: object) -> OperationClass:
    if type(value) is not str:
        raise _invalid(ReasonCode.UNKNOWN_OPERATION, "operation must be a string")
    try:
        return OperationClass(value)
    except ValueError:
        raise _invalid(ReasonCode.UNKNOWN_OPERATION, "unknown operation") from None


def _parse_resource_field(value: object) -> ResourceRef:
    try:
        return parse_resource(value)
    except ResourceError as exc:
        raise _invalid(ReasonCode.INVALID_RESOURCE, str(exc)) from None


def _parse_context(value: object) -> AuthorizationContext:
    context = _snapshot(value, ReasonCode.INVALID_REQUEST, "context")
    _reject_unknown(context, _CONTEXT_KEYS, "context")

    environment_value = context.get("environment")
    if type(environment_value) is not str:
        raise _invalid(ReasonCode.INVALID_REQUEST, "environment is required")
    try:
        environment = Environment(environment_value)
    except ValueError:
        raise _invalid(ReasonCode.INVALID_REQUEST, "unknown environment") from None

    labels_value = context.get("labels", ())
    if type(labels_value) not in (list, tuple):
        raise _invalid(ReasonCode.INVALID_REQUEST, "labels must be a list")
    if len(labels_value) > MAX_REQUEST_LABELS:
        raise _invalid(ReasonCode.INVALID_REQUEST, "too many labels")
    labels = tuple(sorted(set(labels_value))) if all(
        type(label) is str for label in labels_value
    ) else None
    if labels is None:
        raise _invalid(ReasonCode.INVALID_REQUEST, "labels must be strings")

    return AuthorizationContext(
        environment=environment,
        request_id=context.get("request_id"),
        session_id=context.get("session_id"),
        labels=labels,
    )


# ---------------------------------------------------------------------------
# Policy models (built only by rig_sentinel.policy.validation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDefaults:
    decision: Effect = Effect.DENY
    approval_ttl_seconds: int = 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "approval_ttl_seconds": self.approval_ttl_seconds,
        }


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    operations: tuple[OperationClass, ...]
    protected: bool = True
    manifest_sha256: str | None = None
    resource_kind: ResourceKind | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.tool_id,
            "operations": [operation.value for operation in self.operations],
            "protected": self.protected,
        }
        if self.manifest_sha256 is not None:
            data["manifest_sha256"] = self.manifest_sha256
        if self.resource_kind is not None:
            data["resource_kind"] = self.resource_kind.value
        if self.description is not None:
            data["description"] = self.description
        return data


@dataclass(frozen=True)
class ApproverSpec:
    approver_id: str
    scopes: tuple[str, ...]
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.approver_id, "scopes": list(self.scopes)}
        if self.description is not None:
            data["description"] = self.description
        return data


@dataclass(frozen=True)
class RuleConditions:
    environments: tuple[Environment, ...] | None = None
    min_assurance: Assurance | None = None
    labels_all: tuple[str, ...] = ()
    labels_none: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return (
            self.environments is None
            and self.min_assurance is None
            and not self.labels_all
            and not self.labels_none
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.environments is not None:
            data["environment"] = [env.value for env in self.environments]
        if self.min_assurance is not None:
            data["min_assurance"] = self.min_assurance.value
        if self.labels_all:
            data["labels_all"] = list(self.labels_all)
        if self.labels_none:
            data["labels_none"] = list(self.labels_none)
        return data


@dataclass(frozen=True)
class Rule:
    """A validated rule. Pattern fields hold canonical pattern strings."""

    rule_id: str
    effect: Effect
    agents: tuple[str, ...]
    tools: tuple[str, ...]
    operations: tuple[str, ...]
    resources: tuple[str, ...]
    conditions: RuleConditions = field(default_factory=RuleConditions)
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.rule_id,
            "effect": self.effect.value,
            "agents": list(self.agents),
            "tools": list(self.tools),
            "operations": list(self.operations),
            "resources": list(self.resources),
        }
        if not self.conditions.is_empty:
            data["conditions"] = self.conditions.to_dict()
        if self.description is not None:
            data["description"] = self.description
        return data


@dataclass(frozen=True)
class Policy:
    """A fully validated, canonical policy.

    Obtain instances from :func:`rig_sentinel.policy.load_policy_file`,
    :func:`~rig_sentinel.policy.load_policy_text` or
    :func:`~rig_sentinel.policy.validate_policy`. Tools, approvers and rules
    are sorted by id and pattern lists are sorted, so semantically identical
    policies have identical ``to_dict()`` output and ``sha256``.
    """

    schema_version: str
    policy_id: str
    policy_version: str
    defaults: PolicyDefaults
    tools: tuple[ToolSpec, ...]
    approvers: tuple[ApproverSpec, ...]
    rules: tuple[Rule, ...]
    description: str | None = None
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical policy document (without ``sha256``)."""
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "defaults": self.defaults.to_dict(),
            "tools": [tool.to_dict() for tool in self.tools],
            "approvers": [approver.to_dict() for approver in self.approvers],
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.description is not None:
            data["description"] = self.description
        return data
