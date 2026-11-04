from __future__ import annotations

import json
from pathlib import Path

from rig_sentinel.cli import print_report, report_to_dict
from rig_sentinel.scanner import RepositoryScanner


OPENAI_SOURCE = '''
import os
from openai import OpenAI

key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=key)
'''

STRIPE_SOURCE = '''
import os
import stripe
from openai import OpenAI

stripe_key = os.getenv("STRIPE_SECRET_KEY")
client = OpenAI()
stripe.api_key = stripe_key
stripe.refunds.create()
'''


def test_scanner_includes_advisory_policies_for_shared_reference(tmp_path: Path) -> None:
    (tmp_path / "agent_a.py").write_text(OPENAI_SOURCE, encoding="utf-8")
    (tmp_path / "agent_b.py").write_text(OPENAI_SOURCE, encoding="utf-8")

    report = RepositoryScanner(tmp_path).scan()

    assert report.shared_credential_finding_count == 1
    assert report.policy_count == 2
    assert {policy.agent for policy in report.security_policies} == {
        "agent_a", "agent_b"
    }
    for policy in report.security_policies:
        assert policy.identity == "OPENAI_API_KEY"
        assert policy.enforcement == "advisory"
        assert "verify_shared_credential" in policy.controls


def test_json_report_includes_financial_advisory_policy(tmp_path: Path) -> None:
    (tmp_path / "finance_agent.py").write_text(
        STRIPE_SOURCE, encoding="utf-8"
    )

    report = RepositoryScanner(tmp_path).scan()
    payload = json.loads(json.dumps(report_to_dict(report)))

    assert report.privilege_finding_count == 1
    assert payload["policy_count"] == 1
    assert len(payload["security_policies"]) == 1
    policy = payload["security_policies"][0]
    assert policy["agent"] == "finance_agent"
    assert policy["identity"] == "STRIPE_SECRET_KEY"
    assert policy["severity"] == "CRITICAL"
    assert policy["enforcement"] == "advisory"
    assert "require_human_approval" in policy["controls"]


def test_terminal_report_displays_advisory_policies(
    tmp_path: Path, capsys
) -> None:
    (tmp_path / "finance_agent.py").write_text(
        STRIPE_SOURCE, encoding="utf-8"
    )

    report = RepositoryScanner(tmp_path).scan()
    print_report(report)
    output = capsys.readouterr().out

    assert "SECURITY POLICIES (ADVISORY)" in output
    assert "STRIPE_SECRET_KEY" in output
    assert "require_human_approval" in output
    assert "Policies are recommendations only" in output
    assert "Advisory policies:" in output
