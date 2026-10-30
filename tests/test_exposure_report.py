from rig_sentinel.agents import AgentFinding
from rig_sentinel.exposure_report import ExposureReportBuilder


def test_builds_repository_exposure_report() -> None:
    agents = (
        AgentFinding(
            name="finance_agent",
            file="finance_agent.py",
            provider="openai",
            has_mcp=True,
            tools=(
                "shell",
                "financial_action",
            ),
            confidence="HIGH",
        ),
        AgentFinding(
            name="support_agent",
            file="support_agent.py",
            provider="openai",
            has_mcp=False,
            tools=(
                "email_send",
                "http_request",
            ),
            confidence="HIGH",
        ),
    )

    builder = ExposureReportBuilder()

    report = builder.build(agents)

    assert report.agent_count == 2
    assert len(report.exposures) == 2
    assert report.max_blast_radius > 0


def test_counts_critical_agents() -> None:
    agents = (
        AgentFinding(
            name="admin_agent",
            file="admin_agent.py",
            provider="openai",
            has_mcp=True,
            tools=(
                "shell",
                "financial_action",
            ),
            confidence="HIGH",
        ),
    )

    builder = ExposureReportBuilder()

    report = builder.build(agents)

    assert report.agent_count == 1
    assert report.critical_agents == 1


def test_empty_repository_has_zero_exposure() -> None:
    builder = ExposureReportBuilder()

    report = builder.build(())

    assert report.agent_count == 0
    assert report.critical_agents == 0
    assert report.high_agents == 0
    assert report.medium_agents == 0
    assert report.low_agents == 0
    assert report.max_blast_radius == 0