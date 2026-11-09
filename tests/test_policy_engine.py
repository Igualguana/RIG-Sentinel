import json

import pytest
from policy_fixtures import (
    FIXED_NOW_TEXT,
    baseline_engine,
    fixed_clock,
    make_request,
    minimal_policy_dict,
)

from rig_sentinel.policy import (
    AgentIdentity,
    AuthorizationContext,
    AuthorizationRequest,
    Decision,
    Environment,
    OperationClass,
    PolicyEngine,
    ReasonCode,
    ToolIdentity,
    parse_resource,
    validate_policy,
)


@pytest.fixture(scope="module")
def engine():
    return baseline_engine()


def _decide(engine, **overrides):
    return engine.evaluate(make_request(**overrides))


# --- ALLOW ---------------------------------------------------------------------


def test_allow(engine):
    record = _decide(engine)
    assert record.decision is Decision.ALLOW
    assert record.allowed
    assert record.reason_code is ReasonCode.RULE_ALLOW
    assert record.deciding_rule_ids == ("read-tickets",)
    assert record.matched_rule_ids == ("read-tickets",)
    assert record.approval is None


def test_allow_with_typed_request(engine):
    request = AuthorizationRequest(
        agent=AgentIdentity("build-agent"),
        tool=ToolIdentity("mcp://fs/write_file"),
        operation=OperationClass.WRITE,
        resource=parse_resource("fs:/srv/workspace/src/main.py"),
        context=AuthorizationContext(Environment.DEV),
    )
    assert engine.evaluate(request).decision is Decision.ALLOW


def test_server_wildcard_allow(engine):
    record = _decide(
        engine,
        agent="research-bot",
        tool="mcp://web/fetch",
        operation="network",
        resource="url:https://docs.example.com/guide/intro",
    )
    assert record.decision is Decision.ALLOW
    assert record.deciding_rule_ids == ("fetch-docs",)


# --- DENY / default deny ------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"environment": "prod"},  # condition: environment
        {"assurance": "asserted"},  # condition: min_assurance
        {"agent": "other-bot"},  # no rule for this agent
        {"resource": "db:helpdesk/customers"},  # different table
        {
            "agent": "research-bot",
            "tool": "mcp://web/fetch",
            "operation": "network",
            "resource": "url:https://docs.example.com.evil.example/x",
        },
    ],
)
def test_default_deny(engine, overrides):
    record = _decide(engine, **overrides)
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.DEFAULT_DENY
    assert record.deciding_rule_ids == ()
    assert not record.allowed


def test_explicit_deny(engine):
    record = _decide(
        engine,
        agent="build-agent",
        tool="mcp://fs/write_file",
        operation="delete",
        resource="fs:/srv/workspace/.rig-sentinel/policy.toml",
    )
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.RULE_DENY
    assert record.deciding_rule_ids == ("protect-policy-dir",)


# --- Conflict resolution ------------------------------------------------------


def test_deny_overrides_allow(engine):
    record = _decide(
        engine, agent="ops-bot", tool="mcp://shell/run", operation="execute", resource="shell:git"
    )
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.RULE_DENY
    assert record.deciding_rule_ids == ("no-shell-anywhere",)
    assert record.matched_rule_ids == ("allow-shell-for-ops", "no-shell-anywhere")


def test_narrow_deny_overrides_broad_allow(engine):
    record = _decide(
        engine,
        agent="build-agent",
        tool="mcp://fs/write_file",
        operation="write",
        resource="fs:/srv/workspace/.rig-sentinel/policy.toml",
    )
    assert record.decision is Decision.DENY
    assert record.matched_rule_ids == ("protect-policy-dir", "write-workspace")


def test_require_approval_overrides_allow(engine):
    record = _decide(
        engine, tool="mcp://mail/send", operation="external_send", resource="email:customer.example.com"
    )
    assert record.decision is Decision.REQUIRE_APPROVAL
    assert record.reason_code is ReasonCode.RULE_REQUIRES_APPROVAL
    assert record.deciding_rule_ids == ("approve-customer-mail",)
    assert record.matched_rule_ids == ("allow-customer-mail", "approve-customer-mail")
    assert not record.allowed


def test_deny_overrides_require_approval(engine):
    record = _decide(
        engine,
        tool="mcp://mail/send",
        operation="external_send",
        resource="email:customer.example.com",
        labels=["untrusted_content_present"],
    )
    assert record.decision is Decision.DENY
    assert record.deciding_rule_ids == ("tainted-no-egress",)


# --- REQUIRE_APPROVAL ------------------------------------------------------------


def test_require_approval(engine):
    record = _decide(engine, tool="mcp://helpdesk/tickets.update", operation="database_write")
    assert record.decision is Decision.REQUIRE_APPROVAL
    assert record.approval is not None
    assert record.approval.eligible_approvers == ("oncall-lead",)
    assert record.approval.ttl_seconds == 300
    assert len(record.approval.request_binding_sha256) == 64


def test_approval_binding_is_request_specific(engine):
    base = _decide(engine, tool="mcp://helpdesk/tickets.update", operation="database_write")
    other_session = _decide(
        engine, tool="mcp://helpdesk/tickets.update", operation="database_write", session_id="s-2"
    )
    same = _decide(
        engine, tool="mcp://helpdesk/tickets.update", operation="database_write", request_id="r-9"
    )
    assert base.approval.request_binding_sha256 != other_session.approval.request_binding_sha256
    assert base.approval.request_binding_sha256 == same.approval.request_binding_sha256


def test_default_require_approval():
    data = minimal_policy_dict()
    data["defaults"]["decision"] = "require_approval"
    engine = PolicyEngine(validate_policy(data), clock=fixed_clock)
    record = engine.evaluate(
        make_request(agent="other-bot", tool="mcp://notes/read", resource="fs:/srv/notes/a")
    )
    assert record.decision is Decision.REQUIRE_APPROVAL
    assert record.reason_code is ReasonCode.DEFAULT_REQUIRE_APPROVAL
    assert record.approval.eligible_approvers == ("lead",)


# --- Tool registry checks -------------------------------------------------------


def test_unknown_tool_denied_even_with_wildcard_rules(engine):
    record = _decide(engine, tool="mcp://helpdesk/tickets.delete", operation="delete")
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.UNKNOWN_TOOL


def test_operation_not_declared_for_tool(engine):
    record = _decide(engine, operation="delete")
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.OPERATION_NOT_DECLARED


def test_privilege_escalation_via_operation_relabel(engine):
    # A read-only tool asked to perform a database write.
    record = _decide(engine, operation="database_write")
    assert record.reason_code is ReasonCode.OPERATION_NOT_DECLARED


def test_resource_kind_mismatch(engine):
    record = _decide(engine, resource="fs:/srv/helpdesk/tickets")
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.RESOURCE_KIND_MISMATCH


def test_manifest_pinning():
    data = minimal_policy_dict()
    data["tools"][0]["manifest_sha256"] = "a" * 64
    engine = PolicyEngine(validate_policy(data), clock=fixed_clock)
    request = dict(agent="notes-bot", tool="mcp://notes/read", resource="fs:/srv/notes/a")

    assert engine.evaluate(make_request(**request, manifest_sha256="a" * 64)).allowed
    for manifest in (None, "b" * 64):
        record = engine.evaluate(make_request(**request, manifest_sha256=manifest))
        assert record.decision is Decision.DENY
        assert record.reason_code is ReasonCode.TOOL_MANIFEST_MISMATCH


def test_protected_flag():
    data = minimal_policy_dict()
    data["tools"].append(
        {"id": "mcp://notes/edit", "operations": ["read", "write"], "protected": False}
    )
    data["rules"][0]["tools"] = ["mcp://notes/*"]
    data["rules"][0]["operations"] = ["read", "write"]
    engine = PolicyEngine(validate_policy(data), clock=fixed_clock)
    base = dict(agent="notes-bot", resource="fs:/srv/notes/a")

    # Registry default is protected = true.
    assert engine.evaluate(make_request(tool="mcp://notes/read", **base)).protected is True
    # protected = false only lowers the flag for read operations.
    assert engine.evaluate(make_request(tool="mcp://notes/edit", **base)).protected is False
    write = engine.evaluate(make_request(tool="mcp://notes/edit", operation="write", **base))
    assert write.protected is True
    # Unknown tools are always reported as protected.
    assert engine.evaluate(make_request(tool="mcp://x/y", **base)).protected is True


# --- Record contents ------------------------------------------------------------


def test_record_metadata(engine):
    record = _decide(engine)
    assert record.enforced is False
    assert record.policy_id == "acme-support-agents"
    assert record.policy_version == "2026.11.09-1"
    assert record.policy_sha256 == engine.policy_sha256
    assert record.schema_version == "rig.policy/v1"
    assert record.engine_version == "genesis-b2-m1"
    assert record.record_schema == "rig.decision/v1"
    assert record.evaluated_at == FIXED_NOW_TEXT
    assert len(record.request_digest) == 64
    assert len(record.decision_digest) == 64
    assert record.error_type is None


def test_record_to_dict_is_json_and_stable(engine):
    record = _decide(engine, tool="mcp://helpdesk/tickets.update", operation="database_write")
    payload = record.to_dict()
    assert payload["enforced"] is False
    assert payload["decision"] == "REQUIRE_APPROVAL"
    assert list(payload) == [
        "record_schema", "decision", "reason_code", "deciding_rule_ids", "matched_rule_ids",
        "policy_id", "policy_version", "policy_sha256", "schema_version", "engine_version",
        "request_digest", "evaluated_at", "protected", "approval", "error_type", "enforced",
        "decision_digest",
    ]
    assert json.loads(json.dumps(payload)) == payload


def test_request_digest_ignores_spelling_variants(engine):
    a = _decide(engine, resource="db:helpdesk/tickets", labels=["b", "a"])
    b = engine.evaluate(make_request(resource="db:helpdesk/tickets", labels=["a", "b", "a"]))
    assert a.request_digest == b.request_digest
    assert a.decision_digest == b.decision_digest
