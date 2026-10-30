from rig_sentinel.identity_linking import AgentIdentityLink
from rig_sentinel.shared_credentials import SharedCredentialAnalyzer


def test_detects_shared_credential_between_two_agents() -> None:
    links = (
        AgentIdentityLink(
            agent="agent_a",
            identity="STRIPE_SECRET_KEY",
            identity_type="api_key",
            provider="stripe",
            file="agent_a.py",
            confidence="MEDIUM",
        ),
        AgentIdentityLink(
            agent="agent_b",
            identity="STRIPE_SECRET_KEY",
            identity_type="api_key",
            provider="stripe",
            file="agent_b.py",
            confidence="MEDIUM",
        ),
    )

    analyzer = SharedCredentialAnalyzer()

    findings = analyzer.analyze(links)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.usage_count == 2
    assert finding.agents == (
        "agent_a",
        "agent_b",
    )
    assert finding.severity == "HIGH"


def test_single_agent_credential_is_not_shared() -> None:
    links = (
        AgentIdentityLink(
            agent="agent_a",
            identity="OPENAI_API_KEY",
            identity_type="api_key",
            provider="openai",
            file="agent_a.py",
            confidence="HIGH",
        ),
    )

    analyzer = SharedCredentialAnalyzer()

    findings = analyzer.analyze(links)

    assert findings == ()


def test_four_agents_raise_critical_shared_credential() -> None:
    links = tuple(
        AgentIdentityLink(
            agent=f"agent_{index}",
            identity="GITHUB_TOKEN",
            identity_type="token",
            provider="github",
            file=f"agent_{index}.py",
            confidence="MEDIUM",
        )
        for index in range(4)
    )

    analyzer = SharedCredentialAnalyzer()

    findings = analyzer.analyze(links)

    assert len(findings) == 1
    assert findings[0].usage_count == 4
    assert findings[0].severity == "CRITICAL"


def test_duplicate_link_for_same_agent_is_not_double_counted() -> None:
    link = AgentIdentityLink(
        agent="agent_a",
        identity="STRIPE_SECRET_KEY",
        identity_type="api_key",
        provider="stripe",
        file="agent_a.py",
        confidence="MEDIUM",
    )

    analyzer = SharedCredentialAnalyzer()

    findings = analyzer.analyze(
        (
            link,
            link,
        )
    )

    assert findings == ()