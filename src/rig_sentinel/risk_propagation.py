
from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.multi_agent_graph import MultiAgentGraphResult


@dataclass(frozen=True)
class RiskPropagationFinding:
    source_agent: str
    related_agent: str
    shared_identity: str
    classification: str
    confirmed_lateral_movement: bool
    recommendation: str


class RiskPropagationAnalyzer:
    def analyze(
        self,
        graph: MultiAgentGraphResult,
    ) -> tuple[RiskPropagationFinding, ...]:
        findings: list[RiskPropagationFinding] = []

        for relation in graph.shared_identities:
            agents = sorted(set(relation.agents))

            for index, source in enumerate(agents):
                for related in agents[index + 1:]:
                    findings.append(
                        RiskPropagationFinding(
                            source_agent=source,
                            related_agent=related,
                            shared_identity=relation.identity,
                            classification="SHARED_IDENTITY_REFERENCE",
                            confirmed_lateral_movement=False,
                            recommendation=(
                                "Verify whether these agents use the "
                                "same underlying credential. If they do, "
                                "separate their runtime identities and "
                                "apply least-privilege permissions."
                            ),
                        )
                    )

        return tuple(
            sorted(
                findings,
                key=lambda item: (
                    item.shared_identity,
                    item.source_agent,
                    item.related_agent,
                ),
            )
        )
