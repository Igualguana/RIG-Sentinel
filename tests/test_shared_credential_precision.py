from types import SimpleNamespace

import pytest

from rig_sentinel.identity_linking import AgentIdentityLink
from rig_sentinel.policy_generator import PolicyGenerator
from rig_sentinel.shared_credentials import SharedCredentialAnalyzer


def make_links(count, identity="OPENAI_API_KEY"):
    return tuple(
        AgentIdentityLink(
            agent=f"agent_{i}", identity=identity,
            identity_type="api_key", provider="openai",
            file=f"agent_{i}.py", confidence="MEDIUM",
        )
        for i in range(count)
    )


@pytest.mark.parametrize("count", [2, 3, 4, 12])
def test_shared_reference_count_cannot_make_high_or_critical(count):
    findings = SharedCredentialAnalyzer().analyze(make_links(count))
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].usage_count == count
    assert "does not" in findings[0].reason.lower()
    assert "verify" in findings[0].recommendation.lower()


def test_single_reference_is_not_reported():
    assert SharedCredentialAnalyzer().analyze(make_links(1)) == ()


def test_duplicate_reference_is_not_double_counted():
    first = make_links(1)[0]
    assert SharedCredentialAnalyzer().analyze((first, first)) == ()


def test_policy_from_references_is_advisory_and_medium():
    finding = SharedCredentialAnalyzer().analyze(make_links(4))[0]
    report = SimpleNamespace(privilege_findings=(), shared_credential_findings=(finding,))
    policies = PolicyGenerator().generate(report)
    assert len(policies) == 4
    assert all(p.severity == "MEDIUM" and p.enforcement == "advisory" for p in policies)
    assert all("verify_shared_credential" in p.controls for p in policies)


def test_stale_critical_reference_cannot_elevate_policy():
    stale = SimpleNamespace(
        identity="OPENAI_API_KEY", agents=("a", "b"), severity="CRITICAL"
    )
    report = SimpleNamespace(privilege_findings=(), shared_credential_findings=(stale,))
    policies = PolicyGenerator().generate(report)
    assert all(p.severity == "MEDIUM" for p in policies)


def test_financial_critical_privilege_is_preserved_when_merged():
    privilege = SimpleNamespace(
        agent="a", identity="STRIPE_SECRET_KEY", capability="financial_action",
        severity="CRITICAL", reason="Financial mutation capability detected.",
    )
    shared = SimpleNamespace(
        identity="STRIPE_SECRET_KEY", agents=("a", "b"), severity="CRITICAL"
    )
    report = SimpleNamespace(
        privilege_findings=(privilege,), shared_credential_findings=(shared,),
    )
    policies = {p.agent: p for p in PolicyGenerator().generate(report)}
    assert policies["a"].severity == "CRITICAL"
    assert "require_human_approval" in policies["a"].controls
    assert "verify_shared_credential" in policies["a"].controls
    assert policies["b"].severity == "MEDIUM"
