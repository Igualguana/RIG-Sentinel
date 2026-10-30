from rig_sentinel.blast_radius import BlastRadiusEngine
from rig_sentinel.graph import PermissionGraph
from rig_sentinel.models import (
    Agent,
    Permission,
    Tool,
)


def test_calculates_low_blast_radius() -> None:
    permission = Permission(
        name="docs.read",
        action="read",
        resource="internal_docs",
        risk="LOW",
    )

    tool = Tool(
        name="docs",
        category="read",
        permissions=(permission,),
    )

    agent = Agent(
        name="ResearchAgent",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = BlastRadiusEngine(graph)

    result = engine.analyze("ResearchAgent")

    assert result.agent == "ResearchAgent"
    assert "internal_docs" in result.reachable_resources
    assert result.score < 30
    assert result.severity == "LOW"


def test_calculates_high_blast_radius() -> None:
    permissions = (
        Permission(
            name="database.read_customer",
            action="read",
            resource="customer_pii",
            risk="HIGH",
        ),
        Permission(
            name="gmail.send",
            action="send",
            resource="external_email",
            risk="HIGH",
        ),
        Permission(
            name="quotes.write",
            action="write",
            resource="quotes",
            risk="HIGH",
        ),
    )

    tool = Tool(
        name="support_tools",
        category="mixed",
        permissions=permissions,
    )

    agent = Agent(
        name="SupportAgent",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = BlastRadiusEngine(graph)

    result = engine.analyze("SupportAgent")

    assert len(result.reachable_resources) == 3
    assert result.high_paths >= 1
    assert result.score >= 60
    assert result.severity in {"HIGH", "CRITICAL"}


def test_calculates_critical_blast_radius() -> None:
    permissions = (
        Permission(
            name="stripe.refund",
            action="refund",
            resource="payments",
            risk="CRITICAL",
        ),
        Permission(
            name="database.delete",
            action="delete",
            resource="customer_database",
            risk="CRITICAL",
        ),
        Permission(
            name="shell.execute",
            action="execute",
            resource="production_server",
            risk="CRITICAL",
        ),
    )

    tool = Tool(
        name="admin_tools",
        category="admin",
        permissions=permissions,
    )

    agent = Agent(
        name="AdminAgent",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = BlastRadiusEngine(graph)

    result = engine.analyze("AdminAgent")

    assert result.critical_paths >= 3
    assert result.score == 100
    assert result.severity == "CRITICAL"


def test_agent_with_no_access_has_zero_blast_radius() -> None:
    agent = Agent(
        name="EmptyAgent",
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = BlastRadiusEngine(graph)

    result = engine.analyze("EmptyAgent")

    assert result.reachable_resources == ()
    assert result.score == 0
    assert result.severity == "LOW"