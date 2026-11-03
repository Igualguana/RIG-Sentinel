from pathlib import Path

from rig_sentinel.credential_flow import CredentialFlowAnalyzer


def test_detects_stripe_credential_flow() -> None:
    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        Path("agent.py"),
        Path("agent.py"),
        """
import os
import stripe

stripe_key = os.getenv("STRIPE_SECRET_KEY")

stripe.api_key = stripe_key

stripe.refunds.create()
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.credential == "STRIPE_SECRET_KEY"
    assert finding.variable == "stripe_key"
    assert finding.provider == "stripe"
    assert finding.capability == "financial_action"
    assert finding.confidence == "HIGH"


def test_detects_openai_credential_flow() -> None:
    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        Path("agent.py"),
        Path("agent.py"),
        """
import os
from openai import OpenAI

openai_key = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=openai_key)
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.credential == "OPENAI_API_KEY"
    assert finding.provider == "openai"
    assert finding.capability == "ai_provider_access"
    assert finding.confidence == "HIGH"


def test_does_not_link_openai_key_to_shell() -> None:
    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        Path("agent.py"),
        Path("agent.py"),
        """
import os
import subprocess

openai_key = os.getenv("OPENAI_API_KEY")

subprocess.run(["whoami"])
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.credential == "OPENAI_API_KEY"
    assert finding.capability != "shell"


def test_detects_unproven_credential_reference() -> None:
    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        Path("agent.py"),
        Path("agent.py"),
        """
import os

database_url = os.getenv("DATABASE_URL")
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.credential == "DATABASE_URL"
    assert finding.capability is None
    assert finding.confidence == "MEDIUM"


def test_invalid_python_returns_no_findings() -> None:
    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        Path("agent.py"),
        Path("agent.py"),
        "this is not valid python(",
    )

    assert findings == ()

def test_stripe_credential_without_binding_is_not_financial_flow(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"

    text = """
import os
import stripe

stripe_key = os.getenv("STRIPE_SECRET_KEY")

# The credential is loaded, but never assigned
# to the Stripe client.
stripe.refunds.create()
"""

    analyzer = CredentialFlowAnalyzer()

    findings = analyzer.analyze(
        source,
        "agent.py",
        text,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.credential == "STRIPE_SECRET_KEY"
    assert finding.capability != "financial_action"
