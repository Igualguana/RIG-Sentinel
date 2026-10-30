from rig_sentinel.agents import AgentFinding
from rig_sentinel.remediation import RemediationEngine


def test_recommends_shell_remediation() -> None:
    finding = AgentFinding(
        name="admin_agent",
        file="admin_agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    engine = RemediationEngine()

    recommendations = engine.recommend(finding)

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation.tool == "shell"
    assert recommendation.priority == "CRITICAL"
    assert recommendation.expected_risk_reduction == "HIGH"


def test_recommends_financial_approval() -> None:
    finding = AgentFinding(
        name="finance_agent",
        file="finance_agent.py",
        provider="openai",
        has_mcp=False,
        tools=("financial_action",),
        confidence="HIGH",
    )

    engine = RemediationEngine()

    recommendations = engine.recommend(finding)

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation.tool == "financial_action"
    assert recommendation.priority == "CRITICAL"
    assert recommendation.expected_risk_reduction == "CRITICAL"


def test_recommends_multiple_controls() -> None:
    finding = AgentFinding(
        name="multi_agent",
        file="multi_agent.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "shell",
            "financial_action",
            "email_send",
            "http_request",
        ),
        confidence="HIGH",
    )

    engine = RemediationEngine()

    recommendations = engine.recommend(finding)

    assert len(recommendations) == 4

    tools = {
        recommendation.tool
        for recommendation in recommendations
    }

    assert tools == {
        "shell",
        "financial_action",
        "email_send",
        "http_request",
    }


def test_unknown_tool_has_no_recommendation() -> None:
    finding = AgentFinding(
        name="unknown_agent",
        file="unknown_agent.py",
        provider=None,
        has_mcp=False,
        tools=("unknown_tool",),
        confidence="MEDIUM",
    )

    engine = RemediationEngine()

    recommendations = engine.recommend(finding)

    assert recommendations == ()