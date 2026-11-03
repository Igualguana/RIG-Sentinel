
from pathlib import Path

from rig_sentinel.credential_flow import CredentialFlowAnalyzer


def analyze_source(
    tmp_path: Path,
    source: str,
):
    path = tmp_path / "agent.py"

    path.write_text(
        source,
        encoding="utf-8",
    )

    analyzer = CredentialFlowAnalyzer()

    return analyzer.analyze(
        path,
        "agent.py",
        source,
    )


def test_v3_stripe_credential_passed_to_function(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

def configure_stripe(secret):
    stripe.api_key = secret

stripe_key = os.getenv("STRIPE_SECRET_KEY")
configure_stripe(stripe_key)
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability == "financial_action"


def test_v3_stripe_credential_passed_through_two_functions(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

def bind_stripe(secret):
    stripe.api_key = secret

def configure_payments(key):
    bind_stripe(key)

stripe_key = os.getenv("STRIPE_SECRET_KEY")
configure_payments(stripe_key)
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability == "financial_action"


def test_v3_unrelated_credential_is_not_financial_flow(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

stripe_key = os.getenv("STRIPE_SECRET_KEY")

def configure_stripe(secret):
    stripe.api_key = secret

configure_stripe("some-other-key")
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability != "financial_action"


def test_v3_openai_credential_passed_to_factory(
    tmp_path: Path,
) -> None:
    source = """
import os
from openai import OpenAI

def create_client(secret):
    return OpenAI(api_key=secret)

key = os.getenv("OPENAI_API_KEY")
client = create_client(key)
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "OPENAI_API_KEY"
    assert findings[0].capability == "ai_provider_access"


def test_v3_unused_credential_does_not_gain_capability(
    tmp_path: Path,
) -> None:
    source = """
import os
from openai import OpenAI

key = os.getenv("OPENAI_API_KEY")

def create_client(secret):
    return OpenAI(api_key=secret)

client = create_client("unrelated-key")
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "OPENAI_API_KEY"
    assert findings[0].capability != "ai_provider_access"
