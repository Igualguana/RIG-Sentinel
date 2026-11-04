"""Regression checks for false-positive agent classifications in public repos."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from rig_sentinel.agents import AgentDetector
from rig_sentinel.scanner import RepositoryScanner


def _signal(path: str, **fields):
    return SimpleNamespace(file=path, **fields)


@pytest.mark.parametrize("path", [
    "README.md",
    "RELEASING.md",
    ".agents/skills/code-change-verification/SKILL.md",
    "AGENTS.md",
    ".github/workflows/claude.yml",
    ".mcp.json",
    "tests/test_agent.py",
    ".agents/skills/release/scripts/test_prepare.py",
    "src/conftest.py",
])
def test_documentation_configuration_and_tests_are_not_agents(path):
    detector = AgentDetector()
    result = detector.detect(
        Path(path),
        (_signal(path, provider="openai"),),
        (_signal(path, kind="mcp_runtime"),),
        (_signal(path, name="shell"),),
    )
    assert result is None


def test_generic_provider_reference_is_not_agent():
    path = "src/settings.py"
    assert AgentDetector().detect(
        Path(path), (_signal(path, provider="openai"),), (), ()
    ) is None


def test_generic_tool_call_is_not_agent():
    path = "src/prepare.py"
    assert AgentDetector().detect(
        Path(path), (), (), (_signal(path, name="shell"),)
    ) is None


def test_agent_file_remains_detected_with_provider_only():
    path = "agent.py"
    found = AgentDetector().detect(
        Path(path), (_signal(path, provider="openai"),), (), ()
    )
    assert found is not None
    assert found.name == "agent"


def test_mcp_python_server_remains_detected():
    path = "src/git/server.py"
    found = AgentDetector().detect(
        Path(path), (), (_signal(path, kind="mcp_runtime"),), ()
    )
    assert found is not None
    assert found.has_mcp


def test_scanner_keeps_documentation_evidence_but_not_document_agent(tmp_path):
    (tmp_path / "README.md").write_text(
        "OPENAI_API_KEY=example; from openai import OpenAI", encoding="utf-8"
    )
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8"
    )
    report = RepositoryScanner(tmp_path).scan()
    assert "agent" in {a.name for a in report.agents}
    assert "README" not in {a.name for a in report.agents}
    assert all(p.agent != "README" for p in report.security_policies)


def test_mcp_server_matches_posix_evidence_on_windows_path():
    path = Path(r"src\git\server.py")
    found = AgentDetector().detect(
        path, (), (_signal("src/git/server.py", kind="mcp_runtime"),), ()
    )
    assert found is not None
    assert found.name == "server"
    assert found.has_mcp


def test_mcp_server_matches_windows_evidence_on_posix_path():
    path = Path("src/git/server.py")
    found = AgentDetector().detect(
        path, (), (_signal(r"src\git\server.py", kind="mcp_runtime"),), ()
    )
    assert found is not None
    assert found.name == "server"
    assert found.has_mcp
