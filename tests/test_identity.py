from pathlib import Path

from rig_sentinel.identity import IdentityDetector


def test_detects_openai_api_key_reference() -> None:
    detector = IdentityDetector()

    findings = detector.detect(
        Path("agent.py"),
        Path("agent.py"),
        """
import os

api_key = os.getenv("OPENAI_API_KEY")
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.name == "OPENAI_API_KEY"
    assert finding.identity_type == "api_key"
    assert finding.provider == "openai"
    assert finding.confidence == "HIGH"


def test_detects_stripe_secret_key_reference() -> None:
    detector = IdentityDetector()

    findings = detector.detect(
        Path("billing.py"),
        Path("billing.py"),
        """
import os

stripe_key = os.getenv("STRIPE_SECRET_KEY")
""",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.name == "STRIPE_SECRET_KEY"
    assert finding.provider == "stripe"


def test_detects_multiple_identity_references() -> None:
    detector = IdentityDetector()

    findings = detector.detect(
        Path("agent.py"),
        Path("agent.py"),
        """
import os

openai_key = os.getenv("OPENAI_API_KEY")
github_token = os.getenv("GITHUB_TOKEN")
database = os.getenv("DATABASE_URL")
""",
    )

    names = {
        finding.name
        for finding in findings
    }

    assert names == {
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "DATABASE_URL",
    }


def test_does_not_detect_unknown_environment_variable() -> None:
    detector = IdentityDetector()

    findings = detector.detect(
        Path("agent.py"),
        Path("agent.py"),
        """
import os

value = os.getenv("SOME_RANDOM_VARIABLE")
""",
    )

    assert findings == []


def test_detects_identity_in_env_style_text() -> None:
    detector = IdentityDetector()

    findings = detector.detect(
        Path(".env.example"),
        Path(".env.example"),
        """
OPENAI_API_KEY=
STRIPE_SECRET_KEY=
""",
    )

    names = {
        finding.name
        for finding in findings
    }

    assert names == {
        "OPENAI_API_KEY",
        "STRIPE_SECRET_KEY",
    }