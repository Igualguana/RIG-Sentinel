from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.graph import PermissionGraph


@dataclass(frozen=True)
class AttackPath:
    source: str
    target: str
    nodes: tuple[str, ...]
    risk: str


class AttackPathEngine:
    def __init__(self, graph: PermissionGraph) -> None:
        self.graph = graph

    def find_path(
        self,
        source: str,
        target: str,
    ) -> AttackPath | None:
        visited: set[str] = set()

        stack: list[tuple[str, list[str]]] = [
            (
                source,
                [source],
            )
        ]

        while stack:
            current, path = stack.pop()

            if current == target:
                risk = self._calculate_risk(path)

                return AttackPath(
                    source=source,
                    target=target,
                    nodes=tuple(path),
                    risk=risk,
                )

            if current in visited:
                continue

            visited.add(current)

            for edge in self.graph.neighbors(current):
                # "knows_resource" only means the agent is aware
                # of the resource. It is not an actionable
                # permission path, so it must not be used
                # to calculate attack paths.
                if edge.relation == "knows_resource":
                    continue

                if edge.target not in visited:
                    stack.append(
                        (
                            edge.target,
                            path + [edge.target],
                        )
                    )

        return None

    def find_paths_from_agent(
        self,
        agent_name: str,
    ) -> list[AttackPath]:
        source = f"agent:{agent_name}"

        paths: list[AttackPath] = []

        targets = {
            edge.target
            for edge in self.graph.edges
            if edge.target.startswith("resource:")
        }

        for target in targets:
            path = self.find_path(
                source,
                target,
            )

            if path is not None:
                paths.append(path)

        return paths

    def _calculate_risk(
        self,
        nodes: list[str],
    ) -> str:
        joined = " ".join(nodes).lower()

        critical_markers = [
            "delete",
            "shell",
            "refund",
            "payment",
            "admin",
            "system.execute",
            "payments.modify",
            "host_system",
        ]

        high_markers = [
            "external_email",
            "customer",
            "pii",
            "database",
            "write",
            "email.send_external",
            "filesystem",
        ]

        medium_markers = [
            "external_network",
            "network.external_request",
            "connect",
        ]

        if any(
            marker in joined
            for marker in critical_markers
        ):
            return "CRITICAL"

        if any(
            marker in joined
            for marker in high_markers
        ):
            return "HIGH"

        if any(
            marker in joined
            for marker in medium_markers
        ):
            return "MEDIUM"

        return "LOW"