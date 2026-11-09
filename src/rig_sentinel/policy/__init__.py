"""RIG Sentinel Policy & Authorization Engine (Genesis B2 - milestone M1).

A deterministic, fail-closed *decision point* for AI-agent tool requests.
It returns ALLOW, DENY or REQUIRE_APPROVAL. It does not execute tools,
block calls, detect prompt injection or authenticate agents: enforcement is
the job of a separate, trusted adapter (planned for Genesis D). Every
decision record carries ``enforced = False``.
"""

from __future__ import annotations

from rig_sentinel.policy.decision import (
    ENGINE_VERSION,
    ApprovalRequirement,
    DecisionRecord,
)
from rig_sentinel.policy.engine import PolicyEngine
from rig_sentinel.policy.errors import (
    PolicyDigestMismatchError,
    PolicyError,
    PolicyIssue,
    PolicyLoadError,
    PolicyValidationError,
    RequestValidationError,
)
from rig_sentinel.policy.loader import (
    check_policy_digest,
    load_policy_bytes,
    load_policy_file,
    load_policy_text,
)
from rig_sentinel.policy.model import (
    PROTECTED_OPERATIONS,
    AgentIdentity,
    ApproverSpec,
    Assurance,
    AuthorizationContext,
    AuthorizationRequest,
    Decision,
    Effect,
    Environment,
    OperationClass,
    Policy,
    PolicyDefaults,
    Rule,
    RuleConditions,
    ToolIdentity,
    ToolSpec,
    parse_request,
)
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.resources import ResourceKind, ResourceRef, parse_resource
from rig_sentinel.policy.schema import SCHEMA_VERSION
from rig_sentinel.policy.validation import lint_policy, policy_sha256, validate_policy

__all__ = [
    "ENGINE_VERSION",
    "PROTECTED_OPERATIONS",
    "SCHEMA_VERSION",
    "AgentIdentity",
    "ApprovalRequirement",
    "ApproverSpec",
    "Assurance",
    "AuthorizationContext",
    "AuthorizationRequest",
    "Decision",
    "DecisionRecord",
    "Effect",
    "Environment",
    "OperationClass",
    "Policy",
    "PolicyDefaults",
    "PolicyDigestMismatchError",
    "PolicyEngine",
    "PolicyError",
    "PolicyIssue",
    "PolicyLoadError",
    "PolicyValidationError",
    "ReasonCode",
    "RequestValidationError",
    "ResourceKind",
    "ResourceRef",
    "Rule",
    "RuleConditions",
    "ToolIdentity",
    "ToolSpec",
    "check_policy_digest",
    "lint_policy",
    "load_policy_bytes",
    "load_policy_file",
    "load_policy_text",
    "parse_request",
    "parse_resource",
    "policy_sha256",
    "validate_policy",
]
