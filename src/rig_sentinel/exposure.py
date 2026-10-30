from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.attack_paths import AttackPathEngine
from rig_sentinel.blast_radius import BlastRadiusEngine
from rig_sentinel.graph import PermissionGraph
from rig_sentinel.models import Agent
from rig_sentinel.permissions import PermissionInferenceEngine


@dataclass(frozen=True)
class ExposureResult:
    agent: str
    reachable_resources: tuple[str, ...]
    attack_paths: int
    critical_paths: int
    high_paths: int
    medium_paths: int
    blast_radius_score: int
    severity: str


class ExposureAnalyzer:
    def __init__(self) -> None:
        self.permission_engine = PermissionInferenceEngine()

    def analyze(self, finding: AgentFinding) -> ExposureResult:
        inference_results = self.permission_engine.infer_many(
            finding.tools
        )

        tools = tuple(
            result.tool
            for result in inference_results
        )

        resources = tuple(
            resource
            for result in inference_results
            for resource in result.resources
        )

        agent = Agent(
            name=finding.name,
            provider=finding.provider,
            tools=tools,
            resources=resources,
        )

        graph = PermissionGraph()
        graph.add_agent(agent)

        attack_engine = AttackPathEngine(graph)
        attack_paths = attack_engine.find_paths_from_agent(
            finding.name
        )

        blast_engine = BlastRadiusEngine(graph)
        blast_result = blast_engine.analyze(
            finding.name
        )

        return ExposureResult(
            agent=finding.name,
            reachable_resources=blast_result.reachable_resources,
            attack_paths=len(attack_paths),
            critical_paths=blast_result.critical_paths,
            high_paths=blast_result.high_paths,
            medium_paths=blast_result.medium_paths,
            blast_radius_score=blast_result.score,
            severity=blast_result.severity,
        )