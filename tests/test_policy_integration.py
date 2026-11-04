
from pathlib import Path

from rig_sentinel.policy_generator import PolicyGenerator
from rig_sentinel.scanner import RepositoryScanner


def test_policy_generator_integrates_with_scanner(
    tmp_path: Path,
) -> None:
    source = tmp_path / "finance_agent.py"

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

    report = RepositoryScanner(tmp_path).scan()

    assert report.privilege_finding_count == 1

    policies = PolicyGenerator().generate(report)

    assert len(policies) == 1

    policy = policies[0]

    assert policy.agent == "finance_agent"
    assert policy.identity == "STRIPE_SECRET_KEY"
    assert policy.severity == "CRITICAL"
    assert policy.enforcement == "advisory"
    assert "require_human_approval" in policy.controls
    assert "restrict_financial_operations" in policy.controls
