from rig_sentinel.credential_flow import CredentialFlowFinding
from rig_sentinel.least_privilege import LeastPrivilegeAnalyzer
from rig_sentinel.privilege import PrivilegeFinding


def test_recommends_least_privilege_for_stripe() -> None:
    flow = CredentialFlowFinding(
        credential="STRIPE_SECRET_KEY",
        variable="stripe_key",
        provider="stripe",
        capability="financial_action",
        file="agent.py",
        confidence="HIGH",
        evidence="Stripe financial flow",
    )

    privilege = PrivilegeFinding(
        agent="agent",
        identity="STRIPE_SECRET_KEY",
        capability="financial_action",
        severity="CRITICAL",
        reason="Stripe credential enables financial action.",
        recommendation="Restrict the credential.",
    )

    analyzer = LeastPrivilegeAnalyzer()

    findings = analyzer.analyze(
        (flow,),
        (privilege,),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.provider == "stripe"
    assert finding.observed_capability == "financial_action"
    assert finding.severity == "CRITICAL"
    assert len(finding.avoid_permissions) >= 1


def test_requires_privilege_evidence() -> None:
    flow = CredentialFlowFinding(
        credential="STRIPE_SECRET_KEY",
        variable="stripe_key",
        provider="stripe",
        capability="financial_action",
        file="agent.py",
        confidence="HIGH",
        evidence="Stripe financial flow",
    )

    analyzer = LeastPrivilegeAnalyzer()

    findings = analyzer.analyze(
        (flow,),
        (),
    )

    assert findings == ()


def test_recommends_least_privilege_for_github() -> None:
    flow = CredentialFlowFinding(
        credential="GITHUB_TOKEN",
        variable="github_token",
        provider="github",
        capability="repository_access",
        file="agent.py",
        confidence="HIGH",
        evidence="GitHub repository flow",
    )

    privilege = PrivilegeFinding(
        agent="agent",
        identity="GITHUB_TOKEN",
        capability="repository_access",
        severity="HIGH",
        reason="Credential provides repository access.",
        recommendation="Restrict repository access.",
    )

    analyzer = LeastPrivilegeAnalyzer()

    findings = analyzer.analyze(
        (flow,),
        (privilege,),
    )

    assert len(findings) == 1
    assert findings[0].provider == "github"
    assert findings[0].severity == "HIGH"


def test_unknown_capability_has_no_recommendation() -> None:
    flow = CredentialFlowFinding(
        credential="OPENAI_API_KEY",
        variable="openai_key",
        provider="openai",
        capability="ai_provider_access",
        file="agent.py",
        confidence="HIGH",
        evidence="OpenAI credential flow",
    )

    privilege = PrivilegeFinding(
        agent="agent",
        identity="OPENAI_API_KEY",
        capability="ai_provider_access",
        severity="MEDIUM",
        reason="AI provider access.",
        recommendation="Restrict access.",
    )

    analyzer = LeastPrivilegeAnalyzer()

    findings = analyzer.analyze(
        (flow,),
        (privilege,),
    )

    assert findings == ()