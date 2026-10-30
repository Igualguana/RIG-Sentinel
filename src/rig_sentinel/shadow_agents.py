from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding


@dataclass(frozen=True)
class ShadowAgentFinding:
    agent: str
    file: str
    provider: str | None
    severity: str
    sensitive_capabilities: tuple[str, ...]
    reason: str
    recommendation: str


class ShadowAgentAnalyzer:
    SENSITIVE_CAPABILITIES = {
        "shell",
        "financial_action",
        "email_send",
        "filesystem_delete",
        "filesystem_write",
        "http_request",
    }

    CRITICAL_CAPABILITIES = {
        "shell",
        "financial_action",
        "filesystem_delete",
    }

    def analyze(
        self,
        agents: tuple[AgentFinding, ...],
        approved_agents: tuple[str, ...],
    ) -> tuple[ShadowAgentFinding, ...]:
        approved = {
            name.strip()
            for name in approved_agents
            if name.strip()
        }

        findings: list[ShadowAgentFinding] = []

        for agent in agents:
            if agent.name in approved:
                continue

            sensitive_capabilities = tuple(
                sorted(
                    capability
                    for capability in agent.tools
                    if capability in self.SENSITIVE_CAPABILITIES
                )
            )

            severity = self._severity(
                sensitive_capabilities
            )

            findings.append(
                ShadowAgentFinding(
                    agent=agent.name,
                    file=agent.file,
                    provider=agent.provider,
                    severity=severity,
                    sensitive_capabilities=sensitive_capabilities,
                    reason=(
                        "The agent was discovered in the repository "
                        "but is not present in the approved agent "
                        "inventory."
                    ),
                    recommendation=(
                        "Review this agent, register it in the "
                        "approved inventory if authorized, or remove "
                        "and disable it if it is not required."
                    ),
                )
            )

        return tuple(
            sorted(
                findings,
                key=self._sort_key,
            )
        )

    def _severity(
        self,
        capabilities: tuple[str, ...],
    ) -> str:
        if any(
            capability in self.CRITICAL_CAPABILITIES
            for capability in capabilities
        ):
            return "CRITICAL"

        if capabilities:
            return "HIGH"

        return "MEDIUM"

    @staticmethod
    def _sort_key(
        finding: ShadowAgentFinding,
    ) -> tuple[int, str]:
        priority = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }

        return (
            priority.get(
                finding.severity,
                99,
            ),
            finding.agent,
        )