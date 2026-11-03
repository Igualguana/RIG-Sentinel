
from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity_linking import AgentIdentityLink


@dataclass(frozen=True)
class MultiAgentNode:
    id: str
    kind: str
    label: str


@dataclass(frozen=True)
class MultiAgentEdge:
    source: str
    target: str
    relation: str


@dataclass(frozen=True)
class SharedIdentityRelation:
    identity: str
    agents: tuple[str, ...]
    agent_count: int


@dataclass(frozen=True)
class MultiAgentGraphResult:
    nodes: tuple[MultiAgentNode, ...]
    edges: tuple[MultiAgentEdge, ...]
    shared_identities: tuple[SharedIdentityRelation, ...]

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def shared_identity_count(self) -> int:
        return len(self.shared_identities)


class MultiAgentGraphBuilder:
    def build(
        self,
        agents: tuple[AgentFinding, ...],
        identity_links: tuple[AgentIdentityLink, ...],
    ) -> MultiAgentGraphResult:
        nodes: set[MultiAgentNode] = set()
        edges: set[MultiAgentEdge] = set()

        agent_names = {agent.name for agent in agents}
        identity_usage: dict[str, set[str]] = {}

        for agent in agents:
            nodes.add(
                MultiAgentNode(
                    id=f"agent:{agent.name}",
                    kind="agent",
                    label=agent.name,
                )
            )

        for link in identity_links:
            if link.agent not in agent_names:
                continue

            identity_id = f"identity:{link.identity}"
            agent_id = f"agent:{link.agent}"

            nodes.add(
                MultiAgentNode(
                    id=identity_id,
                    kind="identity",
                    label=link.identity,
                )
            )

            edges.add(
                MultiAgentEdge(
                    source=agent_id,
                    target=identity_id,
                    relation="references_identity",
                )
            )

            identity_usage.setdefault(
                link.identity,
                set(),
            ).add(link.agent)

        shared_identities: list[SharedIdentityRelation] = []

        for identity, linked_agents in identity_usage.items():
            if len(linked_agents) < 2:
                continue

            shared_identities.append(
                SharedIdentityRelation(
                    identity=identity,
                    agents=tuple(sorted(linked_agents)),
                    agent_count=len(linked_agents),
                )
            )

        return MultiAgentGraphResult(
            nodes=tuple(
                sorted(nodes, key=lambda item: item.id)
            ),
            edges=tuple(
                sorted(
                    edges,
                    key=lambda item: (
                        item.source,
                        item.target,
                        item.relation,
                    ),
                )
            ),
            shared_identities=tuple(
                sorted(
                    shared_identities,
                    key=lambda item: item.identity,
                )
            ),
        )
