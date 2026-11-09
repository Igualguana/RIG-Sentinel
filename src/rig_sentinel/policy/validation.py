"""Strict policy validation and lint.

:func:`validate_policy` turns parsed policy data (for example the output of
``tomllib``) into a canonical :class:`~rig_sentinel.policy.model.Policy`, or
raises :class:`~rig_sentinel.policy.errors.PolicyValidationError` listing
*every* problem found. A policy is never partially loaded.

Issues report field paths and problem types, not raw values, so that a
rejected policy cannot leak sensitive content through error messages.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from rig_sentinel.policy.canonical import POLICY_DIGEST_DOMAIN, digest
from rig_sentinel.policy.errors import PolicyIssue, PolicyValidationError
from rig_sentinel.policy.identifiers import is_identifier, is_sha256_hex, is_tool_id, split_tool_id
from rig_sentinel.policy.matching import (
    PatternError,
    ResourcePattern,
    ToolPattern,
    parse_agent_pattern,
    parse_operation_pattern,
    parse_resource_pattern,
    parse_tool_pattern,
)
from rig_sentinel.policy.model import (
    PROTECTED_OPERATIONS,
    ApproverSpec,
    Assurance,
    Effect,
    Environment,
    OperationClass,
    Policy,
    PolicyDefaults,
    Rule,
    RuleConditions,
    ToolSpec,
)
from rig_sentinel.policy.resources import ResourceKind
from rig_sentinel.policy.schema import (
    APPROVER_FIELDS,
    APPROVER_REQUIRED,
    CONDITION_FIELDS,
    DEFAULT_APPROVAL_TTL_SECONDS,
    DEFAULTS_FIELDS,
    MAX_APPROVAL_TTL_SECONDS,
    MAX_APPROVERS,
    MAX_CONDITION_LABELS,
    MAX_DESCRIPTION_LENGTH,
    MAX_PATTERNS_PER_FIELD,
    MAX_POLICY_VERSION_LENGTH,
    MAX_RULES,
    MAX_TOOLS,
    MIN_APPROVAL_TTL_SECONDS,
    ROOT_FIELDS,
    ROOT_REQUIRED,
    RULE_FIELDS,
    RULE_REQUIRED,
    SCHEMA_VERSION,
    TOOL_FIELDS,
    TOOL_REQUIRED,
    WILDCARD,
    IssueCode,
    LintCode,
)

_VERSION_FIRST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_VERSION_CHARS = frozenset(_VERSION_FIRST + "._+-")


class _Issues:
    def __init__(self) -> None:
        self.items: list[PolicyIssue] = []

    def add(self, code: str, path: str, message: str) -> None:
        self.items.append(PolicyIssue(code=code, path=path, message=message))

    def __bool__(self) -> bool:
        return bool(self.items)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _index(path: str, index: int) -> str:
    return f"{path}[{index}]"


def _check_fields(
    table: dict[str, Any],
    allowed: frozenset[str],
    required: frozenset[str],
    path: str,
    issues: _Issues,
) -> None:
    for key in table:
        if type(key) is not str or key not in allowed:
            issues.add(IssueCode.UNKNOWN_FIELD, path, "unknown field is not allowed")
    for key in sorted(required):
        if key not in table:
            issues.add(IssueCode.MISSING_FIELD, _join(path, key), "required field is missing")


def _description(table: dict[str, Any], path: str, issues: _Issues) -> str | None:
    if "description" not in table:
        return None
    value = table["description"]
    where = _join(path, "description")
    if type(value) is not str:
        issues.add(IssueCode.INVALID_TYPE, where, "must be a string")
        return None
    if len(value) > MAX_DESCRIPTION_LENGTH:
        issues.add(IssueCode.LIMIT_EXCEEDED, where, "description is too long")
        return None
    if not value.isprintable():
        issues.add(IssueCode.INVALID_VALUE, where, "must not contain control characters")
        return None
    return value


def _identifier(table: dict[str, Any], key: str, path: str, issues: _Issues) -> str | None:
    if key not in table:
        return None
    value = table[key]
    where = _join(path, key)
    if type(value) is not str:
        issues.add(IssueCode.INVALID_TYPE, where, "must be a string")
        return None
    if not is_identifier(value):
        issues.add(
            IssueCode.INVALID_VALUE,
            where,
            "must be a lowercase ASCII identifier ([a-z0-9][a-z0-9._-]{0,127})",
        )
        return None
    return value


def _string_list(
    table: dict[str, Any],
    key: str,
    path: str,
    issues: _Issues,
    *,
    max_items: int,
    allow_empty: bool = False,
) -> list[str] | None:
    if key not in table:
        return None
    value = table[key]
    where = _join(path, key)
    if type(value) is not list:
        issues.add(IssueCode.INVALID_TYPE, where, "must be a list of strings")
        return None
    if not value and not allow_empty:
        issues.add(IssueCode.INVALID_VALUE, where, "must not be empty")
        return None
    if len(value) > max_items:
        issues.add(IssueCode.LIMIT_EXCEEDED, where, f"at most {max_items} entries allowed")
        return None
    if not all(type(item) is str for item in value):
        issues.add(IssueCode.INVALID_TYPE, where, "every entry must be a string")
        return None
    if len(set(value)) != len(value):
        issues.add(IssueCode.DUPLICATE_VALUE, where, "entries must be unique")
        return None
    return list(value)


def _table_list(
    data: dict[str, Any], key: str, issues: _Issues, *, max_items: int
) -> list[Any]:
    if key not in data:
        return []
    value = data[key]
    if type(value) is not list:
        issues.add(IssueCode.INVALID_TYPE, key, "must be an array of tables")
        return []
    if len(value) > max_items:
        issues.add(IssueCode.LIMIT_EXCEEDED, key, f"at most {max_items} entries allowed")
        return []
    return value


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _defaults(data: dict[str, Any], issues: _Issues) -> PolicyDefaults:
    if "defaults" not in data:
        return PolicyDefaults()
    table = data["defaults"]
    if type(table) is not dict:
        issues.add(IssueCode.INVALID_TYPE, "defaults", "must be a table")
        return PolicyDefaults()
    _check_fields(table, DEFAULTS_FIELDS, frozenset(), "defaults", issues)

    decision = Effect.DENY
    if "decision" in table:
        value = table["decision"]
        if type(value) is not str:
            issues.add(IssueCode.INVALID_TYPE, "defaults.decision", "must be a string")
        elif value == Effect.ALLOW.value:
            issues.add(
                IssueCode.DEFAULT_ALLOW_FORBIDDEN,
                "defaults.decision",
                "default decision must be 'deny' or 'require_approval'",
            )
        elif value == Effect.DENY.value:
            decision = Effect.DENY
        elif value == Effect.REQUIRE_APPROVAL.value:
            decision = Effect.REQUIRE_APPROVAL
        else:
            issues.add(
                IssueCode.UNSUPPORTED_VALUE,
                "defaults.decision",
                "must be 'deny' or 'require_approval'",
            )

    ttl = DEFAULT_APPROVAL_TTL_SECONDS
    if "approval_ttl_seconds" in table:
        value = table["approval_ttl_seconds"]
        where = "defaults.approval_ttl_seconds"
        if type(value) is not int:
            issues.add(IssueCode.INVALID_TYPE, where, "must be an integer")
        elif not MIN_APPROVAL_TTL_SECONDS <= value <= MAX_APPROVAL_TTL_SECONDS:
            issues.add(
                IssueCode.INVALID_VALUE,
                where,
                f"must be between {MIN_APPROVAL_TTL_SECONDS} and {MAX_APPROVAL_TTL_SECONDS}",
            )
        else:
            ttl = value

    return PolicyDefaults(decision=decision, approval_ttl_seconds=ttl)


def _tools(data: dict[str, Any], issues: _Issues) -> list[ToolSpec]:
    tools: list[ToolSpec] = []
    seen: set[str] = set()
    for index, table in enumerate(_table_list(data, "tools", issues, max_items=MAX_TOOLS)):
        path = _index("tools", index)
        if type(table) is not dict:
            issues.add(IssueCode.INVALID_TYPE, path, "must be a table")
            continue
        before = len(issues.items)
        _check_fields(table, TOOL_FIELDS, TOOL_REQUIRED, path, issues)

        tool_id = table.get("id")
        if "id" in table and not is_tool_id(tool_id):
            issues.add(
                IssueCode.INVALID_VALUE,
                _join(path, "id"),
                "must be a fully qualified tool id such as 'mcp://server/tool'",
            )
        elif is_tool_id(tool_id):
            if tool_id in seen:
                issues.add(IssueCode.DUPLICATE_ID, _join(path, "id"), "duplicate tool id")
            seen.add(tool_id)

        operations: list[OperationClass] = []
        raw_operations = _string_list(
            table, "operations", path, issues, max_items=len(OperationClass)
        )
        for value in raw_operations or ():
            try:
                operations.append(OperationClass(value))
            except ValueError:
                issues.add(
                    IssueCode.UNSUPPORTED_VALUE,
                    _join(path, "operations"),
                    "unsupported operation (wildcards are not allowed in the tool registry)",
                )

        protected = True
        if "protected" in table:
            if type(table["protected"]) is not bool:
                issues.add(IssueCode.INVALID_TYPE, _join(path, "protected"), "must be a boolean")
            else:
                protected = table["protected"]

        manifest = table.get("manifest_sha256")
        if "manifest_sha256" in table and not is_sha256_hex(manifest):
            issues.add(
                IssueCode.INVALID_VALUE,
                _join(path, "manifest_sha256"),
                "must be 64 lowercase hexadecimal characters",
            )

        resource_kind: ResourceKind | None = None
        if "resource_kind" in table:
            value = table["resource_kind"]
            try:
                if type(value) is not str:
                    raise ValueError
                resource_kind = ResourceKind(value)
            except ValueError:
                issues.add(
                    IssueCode.UNSUPPORTED_VALUE,
                    _join(path, "resource_kind"),
                    "unsupported resource kind",
                )

        description = _description(table, path, issues)

        if len(issues.items) == before:
            tools.append(
                ToolSpec(
                    tool_id=tool_id,
                    operations=tuple(sorted(operations, key=lambda op: op.value)),
                    protected=protected,
                    manifest_sha256=manifest,
                    resource_kind=resource_kind,
                    description=description,
                )
            )
    return tools


def _canonical_pattern(parsed: object) -> str:
    if isinstance(parsed, ResourcePattern):
        return parsed.canonical
    if isinstance(parsed, ToolPattern):
        return parsed.value
    if type(parsed) is str:
        return parsed
    raise PatternError("unsupported pattern type")


def _patterns(
    table: dict[str, Any],
    key: str,
    path: str,
    issues: _Issues,
    parse: Any,
) -> tuple[str, ...] | None:
    values = _string_list(table, key, path, issues, max_items=MAX_PATTERNS_PER_FIELD)
    if values is None:
        return None
    where = _join(path, key)
    canonical: list[str] = []
    ok = True
    for value in values:
        try:
            parsed = parse(value)
        except PatternError as exc:
            issues.add(IssueCode.INVALID_PATTERN, where, str(exc))
            ok = False
            continue
        canonical.append(_canonical_pattern(parsed))
    if not ok:
        return None
    if WILDCARD in canonical and len(canonical) > 1:
        issues.add(IssueCode.INVALID_PATTERN, where, "'*' must be the only entry when used")
        return None
    if len(set(canonical)) != len(canonical):
        issues.add(IssueCode.DUPLICATE_VALUE, where, "entries are duplicates after normalization")
        return None
    return tuple(sorted(canonical))


def _conditions(table: dict[str, Any], path: str, issues: _Issues) -> RuleConditions | None:
    if "conditions" not in table:
        return RuleConditions()
    value = table["conditions"]
    where = _join(path, "conditions")
    if type(value) is not dict:
        issues.add(IssueCode.INVALID_TYPE, where, "must be a table")
        return None
    before = len(issues.items)
    _check_fields(value, CONDITION_FIELDS, frozenset(), where, issues)

    environments: tuple[Environment, ...] | None = None
    raw_envs = _string_list(value, "environment", where, issues, max_items=len(Environment))
    if raw_envs is not None:
        try:
            environments = tuple(sorted((Environment(env) for env in raw_envs), key=str))
        except ValueError:
            issues.add(
                IssueCode.UNSUPPORTED_VALUE,
                _join(where, "environment"),
                "environment must be one of dev, staging, prod",
            )

    min_assurance: Assurance | None = None
    if "min_assurance" in value:
        raw = value["min_assurance"]
        try:
            if type(raw) is not str:
                raise ValueError
            min_assurance = Assurance(raw)
        except ValueError:
            issues.add(
                IssueCode.UNSUPPORTED_VALUE,
                _join(where, "min_assurance"),
                "must be 'asserted' or 'authenticated'",
            )

    label_sets: dict[str, tuple[str, ...]] = {}
    for key in ("labels_all", "labels_none"):
        labels = _string_list(value, key, where, issues, max_items=MAX_CONDITION_LABELS)
        if labels is None:
            label_sets[key] = ()
            continue
        if not all(is_identifier(label) for label in labels):
            issues.add(IssueCode.INVALID_VALUE, _join(where, key), "labels must be identifiers")
        label_sets[key] = tuple(sorted(labels))

    if set(label_sets["labels_all"]) & set(label_sets["labels_none"]):
        issues.add(
            IssueCode.CONFLICTING_CONDITIONS,
            where,
            "a label cannot be both required and forbidden",
        )

    if len(issues.items) != before:
        return None
    return RuleConditions(
        environments=environments,
        min_assurance=min_assurance,
        labels_all=label_sets["labels_all"],
        labels_none=label_sets["labels_none"],
    )


def _rules(
    data: dict[str, Any], tool_ids: set[str], issues: _Issues
) -> tuple[list[Rule], set[str]]:
    rules: list[Rule] = []
    seen: set[str] = set()
    servers = {f"{scheme}://{server}/" for scheme, server, _ in map(split_tool_id, tool_ids)}

    for index, table in enumerate(_table_list(data, "rules", issues, max_items=MAX_RULES)):
        path = _index("rules", index)
        if type(table) is not dict:
            issues.add(IssueCode.INVALID_TYPE, path, "must be a table")
            continue
        before = len(issues.items)
        _check_fields(table, RULE_FIELDS, RULE_REQUIRED, path, issues)

        rule_id = _identifier(table, "id", path, issues)
        if rule_id is not None:
            if rule_id in seen:
                issues.add(IssueCode.DUPLICATE_ID, _join(path, "id"), "duplicate rule id")
            seen.add(rule_id)

        effect: Effect | None = None
        if "effect" in table:
            raw = table["effect"]
            try:
                if type(raw) is not str:
                    raise ValueError
                effect = Effect(raw)
            except ValueError:
                issues.add(
                    IssueCode.UNSUPPORTED_VALUE,
                    _join(path, "effect"),
                    "effect must be 'allow', 'deny' or 'require_approval' (lowercase)",
                )

        agents = _patterns(table, "agents", path, issues, parse_agent_pattern)
        tools = _patterns(table, "tools", path, issues, parse_tool_pattern)
        operations = _patterns(table, "operations", path, issues, parse_operation_pattern)
        resources = _patterns(table, "resources", path, issues, parse_resource_pattern)
        conditions = _conditions(table, path, issues)
        description = _description(table, path, issues)

        for pattern in tools or ():
            if pattern == WILDCARD:
                continue
            if pattern.endswith("/*"):
                if pattern[:-1] not in servers:
                    issues.add(
                        IssueCode.UNREGISTERED_TOOL_REFERENCE,
                        _join(path, "tools"),
                        "server wildcard matches no registered tool",
                    )
            elif pattern not in tool_ids:
                issues.add(
                    IssueCode.UNREGISTERED_TOOL_REFERENCE,
                    _join(path, "tools"),
                    "tool is not declared in [[tools]]",
                )

        if len(issues.items) == before:
            rules.append(
                Rule(
                    rule_id=rule_id,  # type: ignore[arg-type]
                    effect=effect,  # type: ignore[arg-type]
                    agents=agents,  # type: ignore[arg-type]
                    tools=tools,  # type: ignore[arg-type]
                    operations=operations,  # type: ignore[arg-type]
                    resources=resources,  # type: ignore[arg-type]
                    conditions=conditions,  # type: ignore[arg-type]
                    description=description,
                )
            )
    return rules, seen


def _approvers(
    data: dict[str, Any], rule_ids: set[str], issues: _Issues
) -> list[ApproverSpec]:
    approvers: list[ApproverSpec] = []
    seen: set[str] = set()
    for index, table in enumerate(
        _table_list(data, "approvers", issues, max_items=MAX_APPROVERS)
    ):
        path = _index("approvers", index)
        if type(table) is not dict:
            issues.add(IssueCode.INVALID_TYPE, path, "must be a table")
            continue
        before = len(issues.items)
        _check_fields(table, APPROVER_FIELDS, APPROVER_REQUIRED, path, issues)

        approver_id = _identifier(table, "id", path, issues)
        if approver_id is not None:
            if approver_id in seen:
                issues.add(IssueCode.DUPLICATE_ID, _join(path, "id"), "duplicate approver id")
            seen.add(approver_id)

        scopes = _string_list(table, "scopes", path, issues, max_items=MAX_RULES)
        if scopes is not None:
            if WILDCARD in scopes and len(scopes) > 1:
                issues.add(
                    IssueCode.INVALID_PATTERN,
                    _join(path, "scopes"),
                    "'*' must be the only entry when used",
                )
            for scope in scopes:
                if scope != WILDCARD and scope not in rule_ids:
                    issues.add(
                        IssueCode.UNKNOWN_RULE_REFERENCE,
                        _join(path, "scopes"),
                        "scope refers to an unknown rule id",
                    )
        description = _description(table, path, issues)

        if len(issues.items) == before:
            approvers.append(
                ApproverSpec(
                    approver_id=approver_id,  # type: ignore[arg-type]
                    scopes=tuple(sorted(scopes)),  # type: ignore[arg-type]
                    description=description,
                )
            )
    return approvers


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def validate_policy(data: object) -> Policy:
    """Validate parsed policy data and return a canonical :class:`Policy`.

    Raises :class:`PolicyValidationError` (with all issues) on any problem.
    """
    issues = _Issues()

    if type(data) is not dict:
        issues.add(IssueCode.INVALID_TYPE, "", "policy root must be a table")
        raise PolicyValidationError(tuple(issues.items))

    _check_fields(data, ROOT_FIELDS, ROOT_REQUIRED, "", issues)

    if "schema_version" in data:
        version = data["schema_version"]
        if type(version) is not str:
            issues.add(IssueCode.INVALID_TYPE, "schema_version", "must be a string")
        elif version != SCHEMA_VERSION:
            issues.add(
                IssueCode.UNSUPPORTED_SCHEMA_VERSION,
                "schema_version",
                f"only '{SCHEMA_VERSION}' is supported",
            )

    policy_id = _identifier(data, "policy_id", "", issues)

    policy_version: str | None = None
    if "policy_version" in data:
        value = data["policy_version"]
        if type(value) is not str:
            issues.add(IssueCode.INVALID_TYPE, "policy_version", "must be a string")
        elif (
            not 0 < len(value) <= MAX_POLICY_VERSION_LENGTH
            or value[0] not in _VERSION_FIRST
            or not set(value) <= _VERSION_CHARS
        ):
            issues.add(
                IssueCode.INVALID_VALUE,
                "policy_version",
                "must be 1-64 characters of [A-Za-z0-9._+-] starting with a letter or digit",
            )
        else:
            policy_version = value

    description = _description(data, "", issues)
    defaults = _defaults(data, issues)
    tools = _tools(data, issues)
    tool_ids = {tool.tool_id for tool in tools}
    rules, rule_ids = _rules(data, tool_ids, issues)
    approvers = _approvers(data, rule_ids, issues)

    # Every approval path must have at least one eligible approver.
    wildcard_approver = any(WILDCARD in approver.scopes for approver in approvers)
    scoped_rule_ids = {
        scope for approver in approvers for scope in approver.scopes if scope != WILDCARD
    }
    for rule in rules:
        if (
            rule.effect is Effect.REQUIRE_APPROVAL
            and not wildcard_approver
            and rule.rule_id not in scoped_rule_ids
        ):
            issues.add(
                IssueCode.MISSING_APPROVER,
                "rules",
                "a require_approval rule has no approver in scope",
            )
    if defaults.decision is Effect.REQUIRE_APPROVAL and not wildcard_approver:
        issues.add(
            IssueCode.MISSING_APPROVER,
            "defaults.decision",
            "default 'require_approval' needs an approver with scopes = ['*']",
        )

    if issues:
        raise PolicyValidationError(tuple(issues.items))

    policy = Policy(
        schema_version=SCHEMA_VERSION,
        policy_id=policy_id,  # type: ignore[arg-type]
        policy_version=policy_version,  # type: ignore[arg-type]
        description=description,
        defaults=defaults,
        tools=tuple(sorted(tools, key=lambda tool: tool.tool_id)),
        approvers=tuple(sorted(approvers, key=lambda approver: approver.approver_id)),
        rules=tuple(sorted(rules, key=lambda rule: rule.rule_id)),
    )
    return replace(policy, sha256=policy_sha256(policy))


def policy_sha256(policy: Policy) -> str:
    """Return the SHA-256 fingerprint of a policy's canonical document."""
    return digest(POLICY_DIGEST_DOMAIN, policy.to_dict())


_HIGH_RISK_OPERATIONS = frozenset(
    {
        OperationClass.EXECUTE.value,
        OperationClass.FINANCIAL.value,
        OperationClass.CREDENTIAL_ACCESS.value,
        OperationClass.ADMIN.value,
    }
)
_WRITE_CLASS_OPERATIONS = PROTECTED_OPERATIONS


def lint_policy(policy: Policy) -> tuple[PolicyIssue, ...]:
    """Return non-blocking warnings about risky but valid policy content."""
    warnings: list[PolicyIssue] = []
    referenced_exact: set[str] = set()
    referenced_servers: set[str] = set()
    any_tool = False

    for rule in policy.rules:
        path = f"rules[{rule.rule_id}]"
        for pattern in rule.tools:
            if pattern == WILDCARD:
                any_tool = True
            elif pattern.endswith("/*"):
                referenced_servers.add(pattern[:-1])
            else:
                referenced_exact.add(pattern)

        if rule.effect is not Effect.ALLOW:
            continue
        if rule.agents == (WILDCARD,) and rule.tools == (WILDCARD,):
            warnings.append(
                PolicyIssue(
                    LintCode.BROAD_ALLOW,
                    path,
                    "allow rule applies to every agent and every tool",
                )
            )
        operations = set(rule.operations)
        if WILDCARD in operations or operations & _HIGH_RISK_OPERATIONS:
            warnings.append(
                PolicyIssue(
                    LintCode.HIGH_RISK_ALLOW,
                    path,
                    "allow rule covers execute, financial, credential or admin operations",
                )
            )

    for tool in policy.tools:
        scheme, server, _ = split_tool_id(tool.tool_id)
        used = (
            any_tool
            or tool.tool_id in referenced_exact
            or f"{scheme}://{server}/" in referenced_servers
        )
        if not used:
            warnings.append(
                PolicyIssue(
                    LintCode.UNUSED_TOOL,
                    f"tools[{tool.tool_id}]",
                    "tool is registered but no rule refers to it",
                )
            )
        if not tool.protected and set(tool.operations) & _WRITE_CLASS_OPERATIONS:
            warnings.append(
                PolicyIssue(
                    LintCode.UNPROTECTED_WRITE_TOOL,
                    f"tools[{tool.tool_id}]",
                    "tool performs non-read operations but is marked protected = false",
                )
            )
    return tuple(warnings)
