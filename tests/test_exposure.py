from rig_sentinel.agents import AgentFinding
from rig_sentinel.exposure import ExposureAnalyzer


def test_analyzes_agent_exposure() -> None:
    finding = AgentFinding(
        name="finance_agent",
        file="finance_agent.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "shell",
            "http_request",
            "email_send",
            "financial_action",
        ),
        confidence="HIGH",
    )

    analyzer = ExposureAnalyzer()

    result = analyzer.analyze(finding)

    assert result.agent == "finance_agent"

    assert "host_system" in result.reachable_resources
    assert "external_network" in result.reachable_resources
    assert "external_email" in result.reachable_resources
    assert "payments" in result.reachable_resources

    assert result.attack_paths == 4

    assert result.critical_paths >= 2
    assert result.high_paths >= 1

    assert result.blast_radius_score > 0
    assert result.severity in {
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


def test_empty_agent_has_zero_exposure() -> None:
    finding = AgentFinding(
        name="empty_agent",
        file="empty_agent.py",
        provider=None,
        has_mcp=False,
        tools=(),
        confidence="MEDIUM",
    )

    analyzer = ExposureAnalyzer()

    result = analyzer.analyze(finding)

    assert result.reachable_resources == ()
    assert result.attack_paths == 0
    assert result.critical_paths == 0
    assert result.high_paths == 0
    assert result.medium_paths == 0
    assert result.blast_radius_score == 0
    assert result.severity == "LOW"


def test_shell_and_financial_actions_raise_critical_exposure() -> None:
    finding = AgentFinding(
        name="admin_agent",
        file="admin_agent.py",
        provider="openai",
        has_mcp=False,
        tools=(
            "shell",
            "financial_action",
        ),
        confidence="HIGH",
    )

    analyzer = ExposureAnalyzer()

    result = analyzer.analyze(finding)

    assert result.critical_paths >= 2
    assert result.blast_radius_score >= 60
    assert result.severity in {
        "HIGH",
        "CRITICAL",
    }