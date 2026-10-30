from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.exposure import ExposureAnalyzer, ExposureResult


@dataclass(frozen=True)
class ExposureReport:
    exposures: tuple[ExposureResult, ...]

    @property
    def agent_count(self) -> int:
        return len(self.exposures)

    @property
    def critical_agents(self) -> int:
        return sum(
            1
            for exposure in self.exposures
            if exposure.severity == "CRITICAL"
        )

    @property
    def high_agents(self) -> int:
        return sum(
            1
            for exposure in self.exposures
            if exposure.severity == "HIGH"
        )

    @property
    def medium_agents(self) -> int:
        return sum(
            1
            for exposure in self.exposures
            if exposure.severity == "MEDIUM"
        )

    @property
    def low_agents(self) -> int:
        return sum(
            1
            for exposure in self.exposures
            if exposure.severity == "LOW"
        )

    @property
    def max_blast_radius(self) -> int:
        if not self.exposures:
            return 0

        return max(
            exposure.blast_radius_score
            for exposure in self.exposures
        )


class ExposureReportBuilder:
    def __init__(self) -> None:
        self.analyzer = ExposureAnalyzer()

    def build(
        self,
        agents: tuple[AgentFinding, ...],
    ) -> ExposureReport:

        exposures = tuple(
            self.analyzer.analyze(agent)
            for agent in agents
        )

        return ExposureReport(
            exposures=exposures,
        )