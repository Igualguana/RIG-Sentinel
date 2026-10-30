from rig_sentinel.graph import PermissionGraph
from rig_sentinel.models import (
    Agent,
    Identity,
    Permission,
    Resource,
    Tool,
)


def test_builds_permission_graph() -> None:
    permission = Permission(
        name="gmail.send",
        action="send",
        resource="external_email",
        risk="HIGH",
    )

    tool = Tool(
        name="gmail",
        category="external_send",
        permissions=(permission,),
    )

    identity = Identity(
        name="sofia-service",
        identity_type="service_account",
    )

    agent = Agent(
        name="Sofia",
        provider="openai",
        identity=identity,
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    assert graph.has_path(
        "agent:Sofia",
        "resource:external_email",
    )


def test_agent_connects_to_identity() -> None:
    identity = Identity(
        name="finance-service",
        identity_type="service_account",
    )

    agent = Agent(
        name="FinanceAgent",
        identity=identity,
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    edges = graph.neighbors("agent:FinanceAgent")

    assert any(
        edge.relation == "uses_identity"
        and edge.target == "identity:finance-service"
        for edge in edges
    )


def test_graph_does_not_duplicate_edges() -> None:
    graph = PermissionGraph()

    graph.add_edge(
        "agent:Sofia",
        "uses_tool",
        "tool:gmail",
    )

    graph.add_edge(
        "agent:Sofia",
        "uses_tool",
        "tool:gmail",
    )

    assert len(graph.edges) == 1


def test_detects_missing_path() -> None:
    graph = PermissionGraph()

    graph.add_edge(
        "agent:Sofia",
        "uses_tool",
        "tool:gmail",
    )

    assert not graph.has_path(
        "agent:Sofia",
        "resource:stripe",
    )