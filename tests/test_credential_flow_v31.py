
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


def test_v31_tracks_credential_variable_alias(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

stripe_key = os.getenv("STRIPE_SECRET_KEY")
payment_key = stripe_key

stripe.api_key = payment_key
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability == "financial_action"


def test_v31_does_not_infer_binding_in_uninvoked_function(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

stripe_key = os.getenv("STRIPE_SECRET_KEY")

def configure_stripe():
    stripe.api_key = stripe_key

stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability != "financial_action"


def test_v31_tracks_credential_through_nested_calls(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

def configure(secret):
    def bind(value):
        stripe.api_key = value

    bind(secret)

stripe_key = os.getenv("STRIPE_SECRET_KEY")
configure(stripe_key)
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability == "financial_action"


def test_v31_recursive_functions_do_not_create_false_binding(
    tmp_path: Path,
) -> None:
    source = """
import os
import stripe

def first(secret):
    second(secret)

def second(secret):
    first(secret)

stripe_key = os.getenv("STRIPE_SECRET_KEY")
first(stripe_key)
stripe.refunds.create()
"""

    findings = analyze_source(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].credential == "STRIPE_SECRET_KEY"
    assert findings[0].capability != "financial_action"
