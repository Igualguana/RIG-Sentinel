from rig_sentinel.agents import AgentFinding
from rig_sentinel.shadow_agents import ShadowAgentAnalyzer


def test_detects_unapproved_agent() -> None:
    agent = AgentFinding(
        name="experimental_bot",
        file="experimental_bot.py",
        provider="openai",
        has_mcp=False,
        tools=(),
        confidence="MEDIUM",
    )

    analyzer = ShadowAgentAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.agent == "experimental_bot"
    assert finding.severity == "MEDIUM"
    assert finding.sensitive_capabilities == ()


def test_approved_agent_is_not_shadow() -> None:
    agent = AgentFinding(
        name="billing_agent",
        file="billing_agent.py",
        provider="openai",
        has_mcp=False,
        tools=("financial_action",),
        confidence="HIGH",
    )

    analyzer = ShadowAgentAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        ("billing_agent",),
    )

    assert findings == ()


def test_shadow_agent_with_financial_action_is_critical() -> None:
    agent = AgentFinding(
        name="unknown_billing_bot",
        file="unknown_billing_bot.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "financial_action",
            "http_request",
        ),
        confidence="HIGH",
    )

    analyzer = ShadowAgentAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.severity == "CRITICAL"
    assert finding.sensitive_capabilities == (
        "financial_action",
        "http_request",
    )


def test_shadow_agent_with_network_access_is_high() -> None:
    agent = AgentFinding(
        name="network_bot",
        file="network_bot.py",
        provider="anthropic",
        has_mcp=False,
        tools=("http_request",),
        confidence="HIGH",
    )

    analyzer = ShadowAgentAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (),
    )

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"