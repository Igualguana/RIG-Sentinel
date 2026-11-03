
from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity_linking import AgentIdentityLink
from rig_sentinel.multi_agent_graph import MultiAgentGraphBuilder


def make_agent(name: str) -> AgentFinding:
    return AgentFinding(
        name=name,
        file=f"{name}.py",
        provider="openai",
        has_mcp=False,
        tools=(),
        confidence="MEDIUM",
    )


def make_link(
    agent: str,
    identity: str,
) -> AgentIdentityLink:
    return AgentIdentityLink(
        agent=agent,
        identity=identity,
        identity_type="api_key",
        provider="openai",
        file=f"{agent}.py",
        confidence="HIGH",
    )


def test_builds_two_agent_graph() -> None:
    builder = MultiAgentGraphBuilder()

    result = builder.build(
        (
            make_agent("agent_a"),
            make_agent("agent_b"),
        ),
        (
            make_link("agent_a", "OPENAI_API_KEY"),
            make_link("agent_b", "OPENAI_API_KEY"),
        ),
    )

    assert result.node_count == 3
    assert result.edge_count == 2
    assert result.shared_identity_count == 1


def test_detects_shared_identity() -> None:
    builder = MultiAgentGraphBuilder()

    result = builder.build(
        (
            make_agent("agent_a"),
            make_agent("agent_b"),
        ),
        (
            make_link("agent_a", "OPENAI_API_KEY"),
            make_link("agent_b", "OPENAI_API_KEY"),
        ),
    )

    relation = result.shared_identities[0]

    assert relation.identity == "OPENAI_API_KEY"
    assert relation.agent_count == 2
    assert relation.agents == (
        "agent_a",
        "agent_b",
    )


def test_separate_identities_are_not_shared() -> None:
    builder = MultiAgentGraphBuilder()

    result = builder.build(
        (
            make_agent("agent_a"),
            make_agent("agent_b"),
        ),
        (
            make_link("agent_a", "KEY_A"),
            make_link("agent_b", "KEY_B"),
        ),
    )

    assert result.shared_identity_count == 0
    assert result.node_count == 4
    assert result.edge_count == 2


def test_duplicate_identity_link_is_not_double_counted() -> None:
    builder = MultiAgentGraphBuilder()

    link = make_link("agent_a", "OPENAI_API_KEY")

    result = builder.build(
        (make_agent("agent_a"),),
        (link, link),
    )

    assert result.node_count == 2
    assert result.edge_count == 1
    assert result.shared_identity_count == 0


def test_empty_graph() -> None:
    builder = MultiAgentGraphBuilder()

    result = builder.build((), ())

    assert result.node_count == 0
    assert result.edge_count == 0
    assert result.shared_identity_count == 0


def test_does_not_invent_agent_to_agent_access() -> None:
    builder = MultiAgentGraphBuilder()

    result = builder.build(
        (
            make_agent("agent_a"),
            make_agent("agent_b"),
        ),
        (
            make_link("agent_a", "OPENAI_API_KEY"),
            make_link("agent_b", "OPENAI_API_KEY"),
        ),
    )

    assert all(
        edge.relation == "references_identity"
        for edge in result.edges
    )
