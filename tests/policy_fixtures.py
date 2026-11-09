"""Shared synthetic fixtures for the policy-engine tests.

Not a test module (pytest only collects ``test_*.py``). All identifiers,
hosts and paths are synthetic; ``example.com`` domains only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rig_sentinel.policy import PolicyEngine, load_policy_text

FIXED_NOW = datetime(2026, 11, 9, 15, 4, 5, 123456, tzinfo=UTC)
FIXED_NOW_TEXT = "2026-11-09T15:04:05.123456Z"


def fixed_clock() -> datetime:
    return FIXED_NOW


POLICY_HEADER = """\
schema_version = "rig.policy/v1"
policy_id = "acme-support-agents"
policy_version = "2026.11.09-1"
description = "Synthetic policy for automated tests."

[defaults]
decision = "deny"
approval_ttl_seconds = 300

[[tools]]
id = "mcp://helpdesk/tickets.get"
operations = ["read"]
resource_kind = "db"

[[tools]]
id = "mcp://helpdesk/tickets.update"
operations = ["database_write"]
resource_kind = "db"

[[tools]]
id = "mcp://mail/send"
operations = ["external_send"]
resource_kind = "email"

[[tools]]
id = "mcp://fs/write_file"
operations = ["write", "delete"]
resource_kind = "fs"

[[tools]]
id = "mcp://shell/run"
operations = ["execute"]
resource_kind = "shell"

[[tools]]
id = "mcp://web/fetch"
operations = ["network"]
resource_kind = "url"

[[approvers]]
id = "oncall-lead"
scopes = ["approve-ticket-updates", "approve-customer-mail"]
"""

# Each rule is a separate block so tests can permute their order.
RULE_BLOCKS = (
    """\
[[rules]]
id = "read-tickets"
effect = "allow"
agents = ["support-bot"]
tools = ["mcp://helpdesk/tickets.get"]
operations = ["read"]
resources = ["db:helpdesk/tickets"]

[rules.conditions]
environment = ["dev", "staging"]
min_assurance = "authenticated"
""",
    """\
[[rules]]
id = "approve-ticket-updates"
effect = "require_approval"
agents = ["support-bot"]
tools = ["mcp://helpdesk/tickets.update"]
operations = ["database_write"]
resources = ["db:helpdesk/tickets"]
""",
    """\
[[rules]]
id = "approve-customer-mail"
effect = "require_approval"
agents = ["support-bot"]
tools = ["mcp://mail/send"]
operations = ["external_send"]
resources = ["email:customer.example.com"]
""",
    """\
[[rules]]
id = "allow-customer-mail"
effect = "allow"
agents = ["support-bot"]
tools = ["mcp://mail/send"]
operations = ["external_send"]
resources = ["email:customer.example.com"]
""",
    """\
[[rules]]
id = "write-workspace"
effect = "allow"
agents = ["build-agent"]
tools = ["mcp://fs/write_file"]
operations = ["write"]
resources = ["fs:/srv/workspace/src/**"]
""",
    """\
[[rules]]
id = "protect-policy-dir"
effect = "deny"
agents = ["*"]
tools = ["*"]
operations = ["write", "delete"]
resources = ["fs:/srv/workspace/.rig-sentinel/**"]
""",
    """\
[[rules]]
id = "no-shell-anywhere"
effect = "deny"
agents = ["*"]
tools = ["*"]
operations = ["execute"]
resources = ["*"]
""",
    """\
[[rules]]
id = "allow-shell-for-ops"
effect = "allow"
agents = ["ops-bot"]
tools = ["mcp://shell/run"]
operations = ["execute"]
resources = ["shell:git"]
""",
    """\
[[rules]]
id = "fetch-docs"
effect = "allow"
agents = ["research-bot"]
tools = ["mcp://web/*"]
operations = ["network"]
resources = ["url:https://docs.example.com/**"]
""",
    """\
[[rules]]
id = "tainted-no-egress"
effect = "deny"
agents = ["*"]
tools = ["*"]
operations = ["external_send", "network"]
resources = ["*"]

[rules.conditions]
labels_all = ["untrusted_content_present"]
""",
)


def policy_text(rule_blocks: tuple[str, ...] | list[str] = RULE_BLOCKS) -> str:
    return POLICY_HEADER + "\n" + "\n".join(rule_blocks)


BASELINE_POLICY = policy_text()


def baseline_engine(**kwargs: Any) -> PolicyEngine:
    kwargs.setdefault("clock", fixed_clock)
    return PolicyEngine(load_policy_text(BASELINE_POLICY), **kwargs)


def make_request(
    *,
    agent: str | None = "support-bot",
    assurance: str = "authenticated",
    tool: str = "mcp://helpdesk/tickets.get",
    manifest_sha256: str | None = None,
    operation: str = "read",
    resource: str = "db:helpdesk/tickets",
    environment: str = "staging",
    labels: list[str] | None = None,
    session_id: str | None = "s-1",
    request_id: str | None = "r-1",
) -> dict[str, Any]:
    tool_data: dict[str, Any] = {"id": tool}
    if manifest_sha256 is not None:
        tool_data["manifest_sha256"] = manifest_sha256
    context: dict[str, Any] = {"environment": environment, "labels": list(labels or [])}
    if session_id is not None:
        context["session_id"] = session_id
    if request_id is not None:
        context["request_id"] = request_id
    return {
        "agent": None if agent is None else {"id": agent, "assurance": assurance},
        "tool": tool_data,
        "operation": operation,
        "resource": resource,
        "context": context,
    }


def minimal_policy_dict() -> dict[str, Any]:
    """A small valid policy as a plain dict (for mutation-based tests)."""
    return {
        "schema_version": "rig.policy/v1",
        "policy_id": "minimal",
        "policy_version": "1",
        "defaults": {"decision": "deny", "approval_ttl_seconds": 300},
        "tools": [
            {"id": "mcp://notes/read", "operations": ["read"], "resource_kind": "fs"},
        ],
        "approvers": [{"id": "lead", "scopes": ["*"]}],
        "rules": [
            {
                "id": "read-notes",
                "effect": "allow",
                "agents": ["notes-bot"],
                "tools": ["mcp://notes/read"],
                "operations": ["read"],
                "resources": ["fs:/srv/notes/**"],
            }
        ],
    }
