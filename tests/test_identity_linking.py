from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity import IdentityFinding
from rig_sentinel.identity_linking import IdentityLinker


def test_links_identity_to_agent_in_same_file() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    identity = IdentityFinding(
        name="OPENAI_API_KEY",
        identity_type="api_key",
        provider="openai",
        confidence="HIGH",
        file="agent.py",
        evidence="credential reference: OPENAI_API_KEY",
    )

    linker = IdentityLinker()

    links = linker.link(
        (agent,),
        (identity,),
    )

    assert len(links) == 1

    link = links[0]

    assert link.agent == "agent"
    assert link.identity == "OPENAI_API_KEY"
    assert link.provider == "openai"
    assert link.confidence == "HIGH"


def test_does_not_link_identity_from_different_file() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=("shell",),
        confidence="HIGH",
    )

    identity = IdentityFinding(
        name="STRIPE_SECRET_KEY",
        identity_type="api_key",
        provider="stripe",
        confidence="HIGH",
        file="billing.py",
        evidence="credential reference: STRIPE_SECRET_KEY",
    )

    linker = IdentityLinker()

    links = linker.link(
        (agent,),
        (identity,),
    )

    assert links == ()


def test_links_multiple_identities_to_same_agent() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=(
            "financial_action",
            "shell",
        ),
        confidence="HIGH",
    )

    identities = (
        IdentityFinding(
            name="OPENAI_API_KEY",
            identity_type="api_key",
            provider="openai",
            confidence="HIGH",
            file="agent.py",
            evidence="credential reference: OPENAI_API_KEY",
        ),
        IdentityFinding(
            name="STRIPE_SECRET_KEY",
            identity_type="api_key",
            provider="stripe",
            confidence="HIGH",
            file="agent.py",
            evidence="credential reference: STRIPE_SECRET_KEY",
        ),
    )

    linker = IdentityLinker()

    links = linker.link(
        (agent,),
        identities,
    )

    assert len(links) == 2

    identity_names = {
        link.identity
        for link in links
    }

    assert identity_names == {
        "OPENAI_API_KEY",
        "STRIPE_SECRET_KEY",
    }


def test_provider_mismatch_is_medium_confidence() -> None:
    agent = AgentFinding(
        name="agent",
        file="agent.py",
        provider="openai",
        has_mcp=True,
        tools=("financial_action",),
        confidence="HIGH",
    )

    identity = IdentityFinding(
        name="STRIPE_SECRET_KEY",
        identity_type="api_key",
        provider="stripe",
        confidence="HIGH",
        file="agent.py",
        evidence="credential reference: STRIPE_SECRET_KEY",
    )

    linker = IdentityLinker()

    links = linker.link(
        (agent,),
        (identity,),
    )

    assert len(links) == 1
    assert links[0].confidence == "MEDIUM"