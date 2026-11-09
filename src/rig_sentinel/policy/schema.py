"""Policy schema constants: version, allowed fields, limits and issue codes."""

from __future__ import annotations

SCHEMA_VERSION = "rig.policy/v1"

# Size and count limits (protect against resource exhaustion).
MAX_POLICY_BYTES = 256 * 1024
MAX_RULES = 1000
MAX_TOOLS = 500
MAX_APPROVERS = 100
MAX_PATTERNS_PER_FIELD = 64
MAX_CONDITION_LABELS = 32
MAX_DESCRIPTION_LENGTH = 1024
MAX_POLICY_VERSION_LENGTH = 64
MIN_APPROVAL_TTL_SECONDS = 30
MAX_APPROVAL_TTL_SECONDS = 3600
DEFAULT_APPROVAL_TTL_SECONDS = 300

# Allowed fields. Anything else is rejected (UNKNOWN_FIELD).
ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "policy_version",
        "description",
        "defaults",
        "tools",
        "approvers",
        "rules",
    }
)
ROOT_REQUIRED = frozenset({"schema_version", "policy_id", "policy_version"})

DEFAULTS_FIELDS = frozenset({"decision", "approval_ttl_seconds"})

TOOL_FIELDS = frozenset(
    {"id", "operations", "protected", "manifest_sha256", "resource_kind", "description"}
)
TOOL_REQUIRED = frozenset({"id", "operations"})

APPROVER_FIELDS = frozenset({"id", "scopes", "description"})
APPROVER_REQUIRED = frozenset({"id", "scopes"})

RULE_FIELDS = frozenset(
    {
        "id",
        "effect",
        "agents",
        "tools",
        "operations",
        "resources",
        "conditions",
        "description",
    }
)
RULE_REQUIRED = frozenset({"id", "effect", "agents", "tools", "operations", "resources"})

CONDITION_FIELDS = frozenset({"environment", "min_assurance", "labels_all", "labels_none"})

WILDCARD = "*"


class IssueCode:
    """Validation error codes (policy is rejected)."""

    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_TYPE = "INVALID_TYPE"
    INVALID_VALUE = "INVALID_VALUE"
    UNSUPPORTED_VALUE = "UNSUPPORTED_VALUE"
    UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
    DEFAULT_ALLOW_FORBIDDEN = "DEFAULT_ALLOW_FORBIDDEN"
    DUPLICATE_ID = "DUPLICATE_ID"
    DUPLICATE_VALUE = "DUPLICATE_VALUE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID_PATTERN = "INVALID_PATTERN"
    UNREGISTERED_TOOL_REFERENCE = "UNREGISTERED_TOOL_REFERENCE"
    UNKNOWN_RULE_REFERENCE = "UNKNOWN_RULE_REFERENCE"
    MISSING_APPROVER = "MISSING_APPROVER"
    CONFLICTING_CONDITIONS = "CONFLICTING_CONDITIONS"


class LintCode:
    """Lint warning codes (policy still loads)."""

    BROAD_ALLOW = "BROAD_ALLOW"
    HIGH_RISK_ALLOW = "HIGH_RISK_ALLOW"
    UNUSED_TOOL = "UNUSED_TOOL"
    UNPROTECTED_WRITE_TOOL = "UNPROTECTED_WRITE_TOOL"
