import dataclasses

import pytest
from policy_fixtures import make_request

from rig_sentinel.policy import (
    AgentIdentity,
    Assurance,
    AuthorizationContext,
    AuthorizationRequest,
    Decision,
    Effect,
    Environment,
    OperationClass,
    ReasonCode,
    RequestValidationError,
    ToolIdentity,
    parse_request,
    parse_resource,
)
from rig_sentinel.policy.decision import DecisionRecord


def test_public_enum_values_are_stable():
    assert [d.value for d in Decision] == ["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    assert [e.value for e in Effect] == ["allow", "deny", "require_approval"]
    assert {o.value for o in OperationClass} >= {
        "read", "write", "delete", "execute", "network", "external_send", "financial",
    }


def test_parse_request_round_trip():
    request = parse_request(make_request(labels=["b", "a", "a"]))
    assert request.agent == AgentIdentity("support-bot", Assurance.AUTHENTICATED)
    assert request.operation is OperationClass.READ
    assert request.context.labels == ("a", "b")
    assert parse_request(request.to_dict()) == request


def test_typed_request_construction():
    request = AuthorizationRequest(
        agent=AgentIdentity("support-bot"),
        tool=ToolIdentity("mcp://helpdesk/tickets.get"),
        operation=OperationClass.READ,
        resource=parse_resource("db:helpdesk/tickets"),
        context=AuthorizationContext(Environment.DEV),
    )
    assert request.agent.assurance is Assurance.ASSERTED


@pytest.mark.parametrize(
    ("factory", "reason"),
    [
        (lambda: AgentIdentity("Bad Id"), ReasonCode.INVALID_IDENTITY),
        (lambda: AgentIdentity("bot", "authenticated"), ReasonCode.INVALID_IDENTITY),
        (lambda: ToolIdentity("send_email"), ReasonCode.INVALID_TOOL_ID),
        (lambda: ToolIdentity("mcp://a/b", "XYZ"), ReasonCode.INVALID_REQUEST),
        (lambda: AuthorizationContext("dev"), ReasonCode.INVALID_REQUEST),
        (lambda: AuthorizationContext(Environment.DEV, labels=["x"]), ReasonCode.INVALID_REQUEST),
    ],
)
def test_direct_construction_is_validated(factory, reason):
    with pytest.raises(RequestValidationError) as info:
        factory()
    assert info.value.reason_code is reason


def test_models_are_frozen():
    agent = AgentIdentity("support-bot")
    with pytest.raises(dataclasses.FrozenInstanceError):
        agent.agent_id = "other"  # type: ignore[misc]


def test_decision_record_cannot_be_constructed_as_enforced():
    with pytest.raises(TypeError):
        DecisionRecord(  # type: ignore[call-arg]
            decision=Decision.ALLOW,
            reason_code=ReasonCode.RULE_ALLOW,
            deciding_rule_ids=(),
            matched_rule_ids=(),
            policy_id=None,
            policy_version=None,
            policy_sha256=None,
            request_digest=None,
            evaluated_at=None,
            protected=True,
            enforced=True,
        )


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda r: r.update(agent=None), ReasonCode.MISSING_IDENTITY),
        (lambda r: r.pop("agent"), ReasonCode.MISSING_IDENTITY),
        (lambda r: r["agent"].update(id=""), ReasonCode.MISSING_IDENTITY),
        (lambda r: r["agent"].update(id="   "), ReasonCode.MISSING_IDENTITY),
        (lambda r: r["agent"].pop("id"), ReasonCode.MISSING_IDENTITY),
        (lambda r: r["agent"].update(id="*"), ReasonCode.INVALID_IDENTITY),
        (lambda r: r["agent"].update(assurance="root"), ReasonCode.INVALID_IDENTITY),
        (lambda r: r["agent"].update(role="admin"), ReasonCode.INVALID_REQUEST),
        (lambda r: r.update(extra=1), ReasonCode.INVALID_REQUEST),
        (lambda r: r.update(tool="mcp://helpdesk/tickets.get"), ReasonCode.INVALID_TOOL_ID),
        (lambda r: r.update(operation="READ"), ReasonCode.UNKNOWN_OPERATION),
        (lambda r: r.update(resource="fs:/a/../b"), ReasonCode.INVALID_RESOURCE),
        (lambda r: r.pop("context"), ReasonCode.INVALID_REQUEST),
        (lambda r: r["context"].update(environment="production"), ReasonCode.INVALID_REQUEST),
        (lambda r: r["context"].update(labels="tainted"), ReasonCode.INVALID_REQUEST),
        (lambda r: r["context"].update(labels=[1]), ReasonCode.INVALID_REQUEST),
        (lambda r: r["context"].update(labels=[f"l{i}" for i in range(33)]), ReasonCode.INVALID_REQUEST),
        (lambda r: r["context"].update(session_id="S 1"), ReasonCode.INVALID_REQUEST),
    ],
)
def test_parse_request_reason_codes(mutate, reason):
    request = make_request()
    mutate(request)
    with pytest.raises(RequestValidationError) as info:
        parse_request(request)
    assert info.value.reason_code is reason
