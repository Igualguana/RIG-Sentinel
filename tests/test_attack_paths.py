from rig_sentinel.attack_paths import AttackPathEngine
from rig_sentinel.graph import PermissionGraph
from rig_sentinel.models import (
    Agent,
    Permission,
    Tool,
)


def test_finds_attack_path_to_external_email() -> None:
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

    agent = Agent(
        name="Sofia",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = AttackPathEngine(graph)

    path = engine.find_path(
        "agent:Sofia",
        "resource:external_email",
    )

    assert path is not None
    assert path.source == "agent:Sofia"
    assert path.target == "resource:external_email"
    assert path.risk == "HIGH"


def test_returns_none_when_no_path_exists() -> None:
    graph = PermissionGraph()

    graph.add_edge(
        "agent:Sofia",
        "uses_tool",
        "tool:gmail",
    )

    engine = AttackPathEngine(graph)

    path = engine.find_path(
        "agent:Sofia",
        "resource:stripe",
    )

    assert path is None


def test_detects_critical_attack_path() -> None:
    permission = Permission(
        name="stripe.refund",
        action="refund",
        resource="payments",
        risk="CRITICAL",
    )

    tool = Tool(
        name="stripe",
        category="financial",
        permissions=(permission,),
    )

    agent = Agent(
        name="FinanceAgent",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = AttackPathEngine(graph)

    path = engine.find_path(
        "agent:FinanceAgent",
        "resource:payments",
    )

    assert path is not None
    assert path.risk == "CRITICAL"


def test_finds_all_reachable_resources() -> None:
    permissions = (
        Permission(
            name="gmail.send",
            action="send",
            resource="external_email",
            risk="HIGH",
        ),
        Permission(
            name="database.read",
            action="read",
            resource="customer_pii",
            risk="HIGH",
        ),
    )

    tool = Tool(
        name="support_tool",
        category="mixed",
        permissions=permissions,
    )

    agent = Agent(
        name="SupportAgent",
        tools=(tool,),
    )

    graph = PermissionGraph()
    graph.add_agent(agent)

    engine = AttackPathEngine(graph)

    paths = engine.find_paths_from_agent(
        "SupportAgent"
    )

    targets = {
        path.target
        for path in paths
    }

    assert "resource:external_email" in targets
    assert "resource:customer_pii" in targets