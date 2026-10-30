from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity_linking import AgentIdentityLink
from rig_sentinel.privilege import PrivilegeAnalyzer


def test_detects_critical_stripe_financial_privilege() -> None:
    agent = AgentFinding(
        name="finance_agent",
        file="finance_agent.py",
        provider="openai",
        has_mcp=True,
        tools=("financial_action",),
        confidence="HIGH",
    )

    link = AgentIdentityLink(
        agent="finance_agent",
        identity="STRIPE_SECRET_KEY",
        identity_type="api_key",
        provider="stripe",
        file="finance_agent.py",
        confidence="MEDIUM",
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (link,),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.agent == "finance_agent"
    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.capability == "financial_action"
    assert finding.severity == "CRITICAL"


def test_detects_shell_privilege() -> None:
    agent = AgentFinding(
        name="admin_agent",
        file="admin_agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    link = AgentIdentityLink(
        agent="admin_agent",
        identity="OPENAI_API_KEY",
        identity_type="api_key",
        provider="openai",
        file="admin_agent.py",
        confidence="HIGH",
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (link,),
    )

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].capability == "shell"


def test_detects_multiple_privilege_findings() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "financial_action",
            "email_send",
            "http_request",
        ),
        confidence="HIGH",
    )

    links = (
        AgentIdentityLink(
            agent="agent",
            identity="STRIPE_SECRET_KEY",
            identity_type="api_key",
            provider="stripe",
            file="agent.py",
            confidence="MEDIUM",
        ),
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        links,
    )

    severities = {
        finding.severity
        for finding in findings
    }

    assert len(findings) == 3
    assert "CRITICAL" in severities
    assert "HIGH" in severities
    assert "MEDIUM" in severities


def test_agent_without_identity_link_has_no_privilege_findings() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (),
    )

    assert findings == ()
from rig_sentinel.credential_flow import CredentialFlowFinding


def test_proven_flow_removes_false_positive_shell_link() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "shell",
            "financial_action",
        ),
        confidence="HIGH",
    )

    links = (
        AgentIdentityLink(
            agent="agent",
            identity="OPENAI_API_KEY",
            identity_type="api_key",
            provider="openai",
            file="agent.py",
            confidence="HIGH",
        ),
        AgentIdentityLink(
            agent="agent",
            identity="STRIPE_SECRET_KEY",
            identity_type="api_key",
            provider="stripe",
            file="agent.py",
            confidence="MEDIUM",
        ),
    )

    flows = (
        CredentialFlowFinding(
            credential="OPENAI_API_KEY",
            variable="openai_key",
            provider="openai",
            capability="ai_provider_access",
            file="agent.py",
            confidence="HIGH",
            evidence="OpenAI credential flow",
        ),
        CredentialFlowFinding(
            credential="STRIPE_SECRET_KEY",
            variable="stripe_key",
            provider="stripe",
            capability="financial_action",
            file="agent.py",
            confidence="HIGH",
            evidence="Stripe financial flow",
        ),
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        links,
        flows,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.identity == "STRIPE_SECRET_KEY"
    assert finding.capability == "financial_action"
    assert finding.severity == "CRITICAL"


def test_unproven_flow_does_not_create_privilege_finding() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    link = AgentIdentityLink(
        agent="agent",
        identity="OPENAI_API_KEY",
        identity_type="api_key",
        provider="openai",
        file="agent.py",
        confidence="HIGH",
    )

    flow = CredentialFlowFinding(
        credential="OPENAI_API_KEY",
        variable="openai_key",
        provider="openai",
        capability="ai_provider_access",
        file="agent.py",
        confidence="HIGH",
        evidence="OpenAI credential flow",
    )

    analyzer = PrivilegeAnalyzer()

    findings = analyzer.analyze(
        (agent,),
        (link,),
        (flow,),
    )

    assert findings == ()