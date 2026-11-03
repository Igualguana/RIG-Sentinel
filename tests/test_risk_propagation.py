
from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity_linking import AgentIdentityLink
from rig_sentinel.multi_agent_graph import MultiAgentGraphBuilder
from rig_sentinel.risk_propagation import RiskPropagationAnalyzer


def make_agent(name: str) -> AgentFinding:
    return AgentFinding(
        name=name,
        file=f"{name}.py",
        provider="openai",
        has_mcp=False,
        tools=(),
        confidence="MEDIUM",
    )


def make_link(agent: str, identity: str) -> AgentIdentityLink:
    return AgentIdentityLink(
        agent=agent,
        identity=identity,
        identity_type="api_key",
        provider="openai",
        file=f"{agent}.py",
        confidence="HIGH",
    )


def test_detects_shared_identity_exposure() -> None:
    graph = MultiAgentGraphBuilder().build(
        (make_agent("agent_a"), make_agent("agent_b")),
        (
            make_link("agent_a", "OPENAI_API_KEY"),
            make_link("agent_b", "OPENAI_API_KEY"),
        ),
    )

    findings = RiskPropagationAnalyzer().analyze(graph)

    assert len(findings) == 1
    assert findings[0].source_agent == "agent_a"
    assert findings[0].related_agent == "agent_b"
    assert findings[0].shared_identity == "OPENAI_API_KEY"


def test_shared_reference_is_not_confirmed_attack_path() -> None:
    graph = MultiAgentGraphBuilder().build(
        (make_agent("agent_a"), make_agent("agent_b")),
        (
            make_link("agent_a", "OPENAI_API_KEY"),
            make_link("agent_b", "OPENAI_API_KEY"),
        ),
    )

    findings = RiskPropagationAnalyzer().analyze(graph)

    assert findings[0].confirmed_lateral_movement is False
    assert findings[0].classification == "SHARED_IDENTITY_REFERENCE"


def test_separate_identities_do_not_create_relationship() -> None:
    graph = MultiAgentGraphBuilder().build(
        (make_agent("agent_a"), make_agent("agent_b")),
        (
            make_link("agent_a", "KEY_A"),
            make_link("agent_b", "KEY_B"),
        ),
    )

    findings = RiskPropagationAnalyzer().analyze(graph)

    assert findings == ()


def test_duplicate_links_do_not_create_duplicate_findings() -> None:
    link_a = make_link("agent_a", "OPENAI_API_KEY")
    link_b = make_link("agent_b", "OPENAI_API_KEY")

    graph = MultiAgentGraphBuilder().build(
        (make_agent("agent_a"), make_agent("agent_b")),
        (link_a, link_a, link_b),
    )

    findings = RiskPropagationAnalyzer().analyze(graph)

    assert len(findings) == 1
