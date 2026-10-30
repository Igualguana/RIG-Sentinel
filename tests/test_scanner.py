from pathlib import Path

from rig_sentinel.scanner import RepositoryScanner


def test_scanner_detects_openai_provider(tmp_path: Path) -> None:
    agent = tmp_path / "agent.py"

    agent.write_text(
        "from openai import OpenAI\nclient = OpenAI()",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.files_scanned == 1
    assert report.provider_count == 1
    assert report.providers[0].provider == "openai"
    assert report.providers[0].confidence == "HIGH"


def test_scanner_detects_mcp_and_tools(tmp_path: Path) -> None:
    mcp_config = tmp_path / "mcp.json"

    mcp_config.write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "python",
              "args": ["server.py"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    server = tmp_path / "server.py"

    server.write_text(
        """
from mcp import Server
import subprocess

subprocess.run(["whoami"])
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.files_scanned == 2
    assert report.mcp_count >= 1

    assert any(
        finding.name == "shell"
        for finding in report.tools
    )


def test_scanner_ignores_node_modules(tmp_path: Path) -> None:
    source = tmp_path / "app.py"

    source.write_text(
        "print('safe')",
        encoding="utf-8",
    )

    dependencies = tmp_path / "node_modules"
    dependencies.mkdir()

    fake_agent = dependencies / "fake.py"

    fake_agent.write_text(
        "from openai import OpenAI",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.files_scanned == 1
    assert report.provider_count == 0


def test_scanner_can_detect_multiple_capabilities(
    tmp_path: Path,
) -> None:
    source = tmp_path / "finance_agent.py"

    source.write_text(
        """
from openai import OpenAI
import requests
import subprocess

client = OpenAI()

requests.post("https://example.com")
subprocess.run(["whoami"])

send_email("customer@example.com")
stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    tool_names = {
        finding.name
        for finding in report.tools
    }

    assert "shell" in tool_names
    assert "http_request" in tool_names
    assert "email_send" in tool_names
    assert "financial_action" in tool_names
def test_scanner_discovers_agent(tmp_path: Path) -> None:
    source = tmp_path / "finance_agent.py"

    source.write_text(
        """
from openai import OpenAI
from mcp import Server

import subprocess
import requests

client = OpenAI()
server = Server("finance")

subprocess.run(["whoami"])
requests.post("https://example.com")

send_email("customer@example.com")
stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.agent_count == 1

    agent = report.agents[0]

    assert agent.name == "finance_agent"
    assert agent.provider == "openai"
    assert agent.has_mcp is True
    assert agent.confidence == "HIGH"

    assert "shell" in agent.tools
    assert "http_request" in agent.tools
    assert "email_send" in agent.tools
    assert "financial_action" in agent.tools
def test_scanner_builds_exposure_report(
    tmp_path: Path,
) -> None:
    source = tmp_path / "admin_agent.py"

    source.write_text(
        """
from openai import OpenAI

import subprocess

client = OpenAI()

subprocess.run(["whoami"])
stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.agent_count == 1
    assert report.exposure.agent_count == 1

    exposure = report.exposure.exposures[0]

    assert exposure.agent == "admin_agent"
    assert "host_system" in exposure.reachable_resources
    assert "payments" in exposure.reachable_resources

    assert exposure.critical_paths >= 2
    assert exposure.severity == "CRITICAL"
def test_scanner_detects_identities(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
import os
from openai import OpenAI

api_key = os.getenv("OPENAI_API_KEY")

client = OpenAI()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.identity_count == 1

    identity = report.identities[0]

    assert identity.name == "OPENAI_API_KEY"
    assert identity.identity_type == "api_key"
    assert identity.provider == "openai"
def test_scanner_links_identity_to_agent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
import os
from openai import OpenAI

api_key = os.getenv("OPENAI_API_KEY")

client = OpenAI()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.identity_count == 1
    assert report.identity_link_count == 1

    link = report.identity_links[0]

    assert link.agent == "agent"
    assert link.identity == "OPENAI_API_KEY"
    assert link.provider == "openai"
    assert link.confidence == "HIGH"
def test_scanner_detects_excessive_privilege(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
import os
from openai import OpenAI

stripe_key = os.getenv("STRIPE_SECRET_KEY")

client = OpenAI()

stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.agent_count == 1
    assert report.identity_count == 1
    assert report.identity_link_count == 1
    assert report.privilege_finding_count >= 1

    findings = report.privilege_findings

    critical = [
        finding
        for finding in findings
        if finding.severity == "CRITICAL"
    ]

    assert len(critical) >= 1

    finding = critical[0]

    assert finding.agent == "agent"
    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.capability == "financial_action"
def test_scanner_detects_credential_flow(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
import os
import stripe
from openai import OpenAI

stripe_key = os.getenv("STRIPE_SECRET_KEY")

client = OpenAI()

stripe.api_key = stripe_key
stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.credential_flow_count == 1

    flow = report.credential_flows[0]

    assert flow.credential == "STRIPE_SECRET_KEY"
    assert flow.variable == "stripe_key"
    assert flow.provider == "stripe"
    assert flow.capability == "financial_action"
    assert flow.confidence == "HIGH"
def test_scanner_builds_least_privilege_recommendation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
import os
import stripe
from openai import OpenAI

stripe_key = os.getenv("STRIPE_SECRET_KEY")

client = OpenAI()

stripe.api_key = stripe_key
stripe.refunds.create()
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.privilege_finding_count == 1
    assert report.least_privilege_finding_count == 1

    finding = report.least_privilege_findings[0]

    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.provider == "stripe"
    assert finding.observed_capability == "financial_action"
    assert finding.severity == "CRITICAL"
def test_scanner_detects_shared_credential(
    tmp_path: Path,
) -> None:
    first = tmp_path / "agent_a.py"
    second = tmp_path / "agent_b.py"

    first.write_text(
        """
import os
from openai import OpenAI

openai_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=openai_key)
""",
        encoding="utf-8",
    )

    second.write_text(
        """
import os
from openai import OpenAI

openai_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=openai_key)
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.shared_credential_finding_count == 1

    finding = report.shared_credential_findings[0]

    assert finding.identity == "OPENAI_API_KEY"
    assert finding.usage_count == 2
    assert finding.severity == "HIGH"
    assert finding.agents == (
        "agent_a",
        "agent_b",
    )
def test_scanner_detects_shadow_agent_from_inventory(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "agent.py"
    shadow = tmp_path / "experimental_agent.py"

    approved.write_text(
        """
from openai import OpenAI

client = OpenAI()
""",
        encoding="utf-8",
    )

    shadow.write_text(
        """
from openai import OpenAI
import requests

client = OpenAI()

requests.post(
    "https://example.com",
    json={"test": True},
)
""",
        encoding="utf-8",
    )

    config = tmp_path / ".rig-sentinel.toml"

    config.write_text(
        """
approved_agents = [
    "agent",
]
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)

    report = scanner.scan()

    assert report.shadow_agent_finding_count == 1

    finding = report.shadow_agent_findings[0]

    assert finding.agent == "experimental_agent"
    assert finding.file == "experimental_agent.py"
    assert finding.provider == "openai"
    assert finding.severity == "HIGH"
    assert finding.sensitive_capabilities == (
        "http_request",
    )