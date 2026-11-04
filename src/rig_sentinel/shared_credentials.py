from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.identity_linking import AgentIdentityLink


@dataclass(frozen=True)
class SharedCredentialFinding:
    identity: str
    agents: tuple[str, ...]
    usage_count: int
    severity: str
    reason: str
    recommendation: str


class SharedCredentialAnalyzer:
    def analyze(
        self,
        identity_links: tuple[AgentIdentityLink, ...],
    ) -> tuple[SharedCredentialFinding, ...]:
        usage: dict[str, set[str]] = {}

        for link in identity_links:
            usage.setdefault(
                link.identity,
                set(),
            ).add(link.agent)

        findings: list[SharedCredentialFinding] = []

        for identity, agents in usage.items():
            if len(agents) < 2:
                continue

            sorted_agents = tuple(sorted(agents))
            usage_count = len(sorted_agents)

            severity = self._severity(usage_count)

            findings.append(
                SharedCredentialFinding(
                    identity=identity,
                    agents=sorted_agents,
                    usage_count=usage_count,
                    severity=severity,
                    reason=(
                        "Multiple agents or workloads reference the "
                        "same credential identity name. This does not "
                        "establish that the underlying secret is shared "
                        "or that the credential is exposed."
                    ),
                    recommendation=(
                        "Verify whether these workloads use the same "
                        "underlying secret. If sharing is confirmed, "
                        "use separate scoped credentials or workload "
                        "identities where appropriate."
                    ),
                )
            )

        return tuple(
            sorted(
                findings,
                key=lambda finding: (
                    self._severity_rank(finding.severity),
                    finding.identity,
                ),
            )
        )

    def _severity(
        self,
        usage_count: int,
    ) -> str:
        # The analyzer only sees identity *names* and same-file links.
        # It cannot prove that the same secret is reused. Count alone
        # must never escalate this finding to HIGH or CRITICAL.
        if usage_count >= 2:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _severity_rank(
        severity: str,
    ) -> int:
        priority = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }

        return priority.get(severity, 99)