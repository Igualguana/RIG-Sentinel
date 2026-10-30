from __future__ import annotations

from dataclasses import dataclass, field

from rig_sentinel.models import Agent


@dataclass(frozen=True)
class GraphEdge:
    source: str
    relation: str
    target: str


@dataclass
class PermissionGraph:
    edges: list[GraphEdge] = field(default_factory=list)

    def add_edge(self, source: str, relation: str, target: str) -> None:
        edge = GraphEdge(
            source=source,
            relation=relation,
            target=target,
        )

        if edge not in self.edges:
            self.edges.append(edge)

    def add_agent(self, agent: Agent) -> None:
        agent_node = f"agent:{agent.name}"

        if agent.identity is not None:
            identity_node = f"identity:{agent.identity.name}"

            self.add_edge(
                agent_node,
                "uses_identity",
                identity_node,
            )

        for tool in agent.tools:
            tool_node = f"tool:{tool.name}"

            self.add_edge(
                agent_node,
                "uses_tool",
                tool_node,
            )

            for permission in tool.permissions:
                permission_node = f"permission:{permission.name}"
                resource_node = f"resource:{permission.resource}"

                self.add_edge(
                    tool_node,
                    "grants",
                    permission_node,
                )

                self.add_edge(
                    permission_node,
                    "accesses",
                    resource_node,
                )

        for resource in agent.resources:
            resource_node = f"resource:{resource.name}"

            self.add_edge(
                agent_node,
                "knows_resource",
                resource_node,
            )

    def neighbors(self, node: str) -> list[GraphEdge]:
        return [
            edge
            for edge in self.edges
            if edge.source == node
        ]

    def has_path(self, source: str, target: str) -> bool:
        visited: set[str] = set()
        stack = [source]

        while stack:
            current = stack.pop()

            if current == target:
                return True

            if current in visited:
                continue

            visited.add(current)

            for edge in self.neighbors(current):
                stack.append(edge.target)

        return False