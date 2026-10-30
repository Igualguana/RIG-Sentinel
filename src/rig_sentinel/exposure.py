from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.attack_paths import AttackPath, AttackPathEngine
from rig_sentinel.blast_radius import BlastRadiusEngine
from rig_sentinel.graph import PermissionGraph
from rig_sentinel.models import Agent
from rig_sentinel.permissions import PermissionInferenceEngine
from rig_sentinel.remediation import (
    RemediationEngine,
    RemediationRecommendation,
)


@dataclass(frozen=True)
class ExposureResult:
    agent: str
    reachable_resources: tuple[str, ...]
    attack_paths: int
    attack_path_details: tuple[AttackPath, ...]
    critical_paths: int
    high_paths: int
    medium_paths: int
    blast_radius_score: int
    severity: str
    recommendations: tuple[RemediationRecommendation, ...]


class ExposureAnalyzer:
    def __init__(self) -> None:
        self.permission_engine = PermissionInferenceEngine()
        self.remediation_engine = RemediationEngine()

    def analyze(
        self,
        finding: AgentFinding,
    ) -> ExposureResult:
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

        blast = blast_engine.analyze(
            finding.name
        )

        recommendations = self.remediation_engine.recommend(
            finding
        )

        return ExposureResult(
            agent=finding.name,
            reachable_resources=blast.reachable_resources,
            attack_paths=len(attack_paths),
            attack_path_details=tuple(attack_paths),
            critical_paths=blast.critical_paths,
            high_paths=blast.high_paths,
            medium_paths=blast.medium_paths,
            blast_radius_score=blast.score,
            severity=blast.severity,
            recommendations=recommendations,
        )