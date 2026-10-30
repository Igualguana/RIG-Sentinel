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

    assert set(result.reachable_resources) == {
        "external_email",
        "external_network",
        "host_system",
        "payments",
    }

    assert result.attack_paths == 4

    assert result.critical_paths >= 2
    assert result.high_paths >= 1

    assert result.blast_radius_score > 0

    assert result.severity in {
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


def test_empty_agent_has_no_exposure() -> None:
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

    assert result.agent == "empty_agent"
    assert result.reachable_resources == ()
    assert result.attack_paths == 0
    assert result.critical_paths == 0
    assert result.high_paths == 0
    assert result.medium_paths == 0
    assert result.blast_radius_score == 0
    assert result.severity == "LOW"
    assert result.recommendations == ()


def test_critical_tools_create_high_exposure() -> None:
    finding = AgentFinding(
        name="critical_agent",
        file="critical_agent.py",
        provider="openai",
        has_mcp=True,
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


def test_exposure_includes_recommended_remediation() -> None:
    finding = AgentFinding(
        name="finance_agent",
        file="finance_agent.py",
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

    analyzer = ExposureAnalyzer()

    result = analyzer.analyze(finding)

    assert len(result.recommendations) == 4

    tools = {
        recommendation.tool
        for recommendation in result.recommendations
    }

    assert tools == {
        "shell",
        "financial_action",
        "email_send",
        "http_request",
    }

    priorities = {
        recommendation.priority
        for recommendation in result.recommendations
    }

    assert "CRITICAL" in priorities
    assert "HIGH" in priorities
    assert "MEDIUM" in priorities
def test_exposure_includes_attack_path_details() -> None:
    finding = AgentFinding(
        name="finance_agent",
        file="finance_agent.py",
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

    analyzer = ExposureAnalyzer()

    result = analyzer.analyze(finding)

    assert result.attack_paths == 4
    assert len(result.attack_path_details) == 4

    targets = {
        path.target
        for path in result.attack_path_details
    }

    assert targets == {
        "resource:host_system",
        "resource:payments",
        "resource:external_email",
        "resource:external_network",
    }

    risks = {
        path.risk
        for path in result.attack_path_details
    }

    assert "CRITICAL" in risks
    assert "HIGH" in risks
    assert "MEDIUM" in risks