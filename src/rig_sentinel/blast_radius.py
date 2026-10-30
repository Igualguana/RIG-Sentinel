from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.attack_paths import AttackPathEngine
from rig_sentinel.graph import PermissionGraph


@dataclass(frozen=True)
class BlastRadiusResult:
    agent: str
    reachable_resources: tuple[str, ...]
    critical_paths: int
    high_paths: int
    medium_paths: int
    score: int
    severity: str


class BlastRadiusEngine:
    def __init__(self, graph: PermissionGraph) -> None:
        self.graph = graph
        self.attack_path_engine = AttackPathEngine(graph)

    def analyze(self, agent_name: str) -> BlastRadiusResult:
        paths = self.attack_path_engine.find_paths_from_agent(
            agent_name
        )

        reachable_resources = tuple(
            sorted(
                path.target.removeprefix("resource:")
                for path in paths
            )
        )

        critical_paths = sum(
            1
            for path in paths
            if path.risk == "CRITICAL"
        )

        high_paths = sum(
            1
            for path in paths
            if path.risk == "HIGH"
        )

        medium_paths = sum(
            1
            for path in paths
            if path.risk == "MEDIUM"
        )

        score = self._calculate_score(
            reachable_count=len(reachable_resources),
            critical_paths=critical_paths,
            high_paths=high_paths,
            medium_paths=medium_paths,
        )

        severity = self._severity(
            score=score,
            critical_paths=critical_paths,
            high_paths=high_paths,
        )

        return BlastRadiusResult(
            agent=agent_name,
            reachable_resources=reachable_resources,
            critical_paths=critical_paths,
            high_paths=high_paths,
            medium_paths=medium_paths,
            score=score,
            severity=severity,
        )

    def _calculate_score(
        self,
        reachable_count: int,
        critical_paths: int,
        high_paths: int,
        medium_paths: int,
    ) -> int:
        score = (
            reachable_count * 8
            + critical_paths * 26
            + high_paths * 15
            + medium_paths * 5
        )

        return min(100, score)

    def _severity(
        self,
        score: int,
        critical_paths: int,
        high_paths: int,
    ) -> str:
        if critical_paths >= 2:
            return "CRITICAL"

        if score >= 80:
            return "CRITICAL"

        if critical_paths >= 1:
            return "HIGH"

        if score >= 60:
            return "HIGH"

        if high_paths >= 2:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"