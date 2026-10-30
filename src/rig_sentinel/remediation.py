from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding


@dataclass(frozen=True)
class RemediationRecommendation:
    tool: str
    priority: str
    title: str
    recommendation: str
    expected_risk_reduction: str


class RemediationEngine:
    def recommend(
        self,
        finding: AgentFinding,
    ) -> tuple[RemediationRecommendation, ...]:
        recommendations: list[RemediationRecommendation] = []

        for tool in finding.tools:
            recommendation = self._recommend_for_tool(tool)

            if recommendation is not None:
                recommendations.append(recommendation)

        return tuple(recommendations)

    def _recommend_for_tool(
        self,
        tool: str,
    ) -> RemediationRecommendation | None:
        mapping: dict[str, RemediationRecommendation] = {
            "shell": RemediationRecommendation(
                tool="shell",
                priority="CRITICAL",
                title="Restrict shell execution",
                recommendation=(
                    "Remove unrestricted shell execution where possible. "
                    "If required, allow only approved commands and execute "
                    "them inside an isolated environment."
                ),
                expected_risk_reduction="HIGH",
            ),
            "financial_action": RemediationRecommendation(
                tool="financial_action",
                priority="CRITICAL",
                title="Require approval for financial actions",
                recommendation=(
                    "Require explicit human approval before refunds, "
                    "transfers, payments, or other financial mutations."
                ),
                expected_risk_reduction="CRITICAL",
            ),
            "email_send": RemediationRecommendation(
                tool="email_send",
                priority="HIGH",
                title="Restrict external email capability",
                recommendation=(
                    "Limit recipient domains or approved recipient lists "
                    "and require confirmation for sensitive outbound email."
                ),
                expected_risk_reduction="HIGH",
            ),
            "http_request": RemediationRecommendation(
                tool="http_request",
                priority="MEDIUM",
                title="Restrict outbound network destinations",
                recommendation=(
                    "Allow outbound requests only to approved domains, "
                    "APIs, and network destinations."
                ),
                expected_risk_reduction="MEDIUM",
            ),
            "filesystem_write": RemediationRecommendation(
                tool="filesystem_write",
                priority="HIGH",
                title="Restrict filesystem write access",
                recommendation=(
                    "Limit write access to approved directories and "
                    "prevent modification of sensitive application or "
                    "system files."
                ),
                expected_risk_reduction="HIGH",
            ),
            "filesystem_delete": RemediationRecommendation(
                tool="filesystem_delete",
                priority="CRITICAL",
                title="Restrict filesystem deletion",
                recommendation=(
                    "Remove unrestricted delete permissions or require "
                    "approval before destructive filesystem operations."
                ),
                expected_risk_reduction="CRITICAL",
            ),
        }

        return mapping.get(tool)