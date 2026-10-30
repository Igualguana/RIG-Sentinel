from rig_sentinel.models import (
    Agent,
    Identity,
    Permission,
    Resource,
    Tool,
)


def test_builds_agent_security_model() -> None:
    permission = Permission(
        name="gmail.send",
        action="send",
        resource="external_email",
        risk="HIGH",
    )

    tool = Tool(
        name="gmail",
        category="external_send",
        provider="google",
        permissions=(permission,),
    )

    identity = Identity(
        name="sofia-service",
        identity_type="service_account",
        provider="google",
    )

    resource = Resource(
        name="customer_email",
        resource_type="pii",
        sensitivity="HIGH",
    )

    agent = Agent(
        name="Sofia",
        provider="openai",
        identity=identity,
        tools=(tool,),
        resources=(resource,),
    )

    assert agent.name == "Sofia"
    assert agent.identity is not None
    assert agent.identity.name == "sofia-service"
    assert agent.tools[0].name == "gmail"
    assert agent.tools[0].permissions[0].name == "gmail.send"
    assert agent.resources[0].sensitivity == "HIGH"


def test_tool_can_have_multiple_permissions() -> None:
    permissions = (
        Permission(
            name="database.read",
            action="read",
            resource="customers",
            risk="MEDIUM",
        ),
        Permission(
            name="database.delete",
            action="delete",
            resource="customers",
            risk="CRITICAL",
        ),
    )

    tool = Tool(
        name="postgres",
        category="database",
        permissions=permissions,
    )

    assert len(tool.permissions) == 2
    assert tool.permissions[1].risk == "CRITICAL"


def test_agent_can_exist_without_identity() -> None:
    agent = Agent(
        name="ResearchAgent",
        provider="anthropic",
    )

    assert agent.name == "ResearchAgent"
    assert agent.identity is None
    assert agent.tools == ()
    assert agent.resources == ()