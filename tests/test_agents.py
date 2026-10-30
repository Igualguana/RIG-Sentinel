from pathlib import Path

from rig_sentinel.agents import AgentDetector
from rig_sentinel.mcp import MCPFinding
from rig_sentinel.providers import ProviderFinding
from rig_sentinel.tools import ToolFinding


def test_detects_agent_from_provider_and_tools() -> None:
    detector = AgentDetector()

    providers = (
        ProviderFinding(
            provider="openai",
            confidence="HIGH",
            file="agent.py",
            evidence="python import: openai",
        ),
    )

    tools = (
        ToolFinding(
            name="shell",
            category="execute",
            confidence="HIGH",
            file="agent.py",
            evidence="python call: subprocess.run",
        ),
        ToolFinding(
            name="http_request",
            category="network",
            confidence="HIGH",
            file="agent.py",
            evidence="python call: requests.post",
        ),
    )

    finding = detector.detect(
        Path("agent.py"),
        providers,
        (),
        tools,
    )

    assert finding is not None
    assert finding.name == "agent"
    assert finding.provider == "openai"
    assert finding.tools == (
        "http_request",
        "shell",
    )
    assert finding.confidence == "HIGH"


def test_detects_mcp_agent() -> None:
    detector = AgentDetector()

    mcp_findings = (
        MCPFinding(
            kind="mcp_runtime",
            confidence="HIGH",
            file="server.py",
            evidence="python import: mcp",
        ),
    )

    finding = detector.detect(
        Path("server.py"),
        (),
        mcp_findings,
        (),
    )

    assert finding is not None
    assert finding.name == "server"
    assert finding.has_mcp is True
    assert finding.confidence == "MEDIUM"


def test_returns_none_for_normal_file() -> None:
    detector = AgentDetector()

    finding = detector.detect(
        Path("utils.py"),
        (),
        (),
        (),
    )

    assert finding is None


def test_detects_agent_with_mcp_provider_and_tools() -> None:
    detector = AgentDetector()

    providers = (
        ProviderFinding(
            provider="openai",
            confidence="HIGH",
            file="finance_agent.py",
            evidence="python import: openai",
        ),
    )

    mcp_findings = (
        MCPFinding(
            kind="mcp_runtime",
            confidence="HIGH",
            file="finance_agent.py",
            evidence="python import: mcp",
        ),
    )

    tools = (
        ToolFinding(
            name="financial_action",
            category="financial",
            confidence="HIGH",
            file="finance_agent.py",
            evidence="python call: stripe.refunds.create",
        ),
    )

    finding = detector.detect(
        Path("finance_agent.py"),
        providers,
        mcp_findings,
        tools,
    )

    assert finding is not None
    assert finding.name == "finance_agent"
    assert finding.provider == "openai"
    assert finding.has_mcp is True
    assert "financial_action" in finding.tools
    assert finding.confidence == "HIGH"