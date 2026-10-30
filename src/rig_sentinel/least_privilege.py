from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.credential_flow import CredentialFlowFinding
from rig_sentinel.privilege import PrivilegeFinding


@dataclass(frozen=True)
class LeastPrivilegeFinding:
    identity: str
    provider: str | None
    observed_capability: str
    severity: str
    recommended_scope: str
    avoid_permissions: tuple[str, ...]
    recommendation: str


class LeastPrivilegeAnalyzer:
    def analyze(
        self,
        credential_flows: tuple[CredentialFlowFinding, ...],
        privilege_findings: tuple[PrivilegeFinding, ...],
    ) -> tuple[LeastPrivilegeFinding, ...]:
        findings: list[LeastPrivilegeFinding] = []

        privileged_pairs = {
            (
                finding.identity,
                finding.capability,
            )
            for finding in privilege_findings
        }

        for flow in credential_flows:
            if flow.capability is None:
                continue

            if (
                flow.credential,
                flow.capability,
            ) not in privileged_pairs:
                continue

            finding = self._recommend_for_flow(flow)

            if finding is not None:
                findings.append(finding)

        return self._unique(findings)

    def _recommend_for_flow(
        self,
        flow: CredentialFlowFinding,
    ) -> LeastPrivilegeFinding | None:
        if (
            flow.provider == "stripe"
            and flow.capability == "financial_action"
        ):
            return LeastPrivilegeFinding(
                identity=flow.credential,
                provider="stripe",
                observed_capability="financial_action",
                severity="CRITICAL",
                recommended_scope=(
                    "Use a dedicated restricted credential limited "
                    "to only the financial operations required by "
                    "this agent."
                ),
                avoid_permissions=(
                    "unrelated payment operations",
                    "transfers not required by the agent",
                    "payout administration",
                    "account administration",
                ),
                recommendation=(
                    "Replace broad financial credentials with a "
                    "dedicated restricted credential and require "
                    "human approval for destructive or high-value "
                    "financial actions."
                ),
            )

        if (
            flow.provider == "github"
            and flow.capability == "repository_access"
        ):
            return LeastPrivilegeFinding(
                identity=flow.credential,
                provider="github",
                observed_capability="repository_access",
                severity="HIGH",
                recommended_scope=(
                    "Limit the credential to only the repositories "
                    "and repository operations required by the agent."
                ),
                avoid_permissions=(
                    "organization administration",
                    "unrelated repositories",
                    "repository deletion",
                    "workflow administration unless required",
                ),
                recommendation=(
                    "Use a dedicated repository-scoped credential "
                    "with the minimum read/write permissions needed."
                ),
            )

        if (
            flow.provider == "aws"
            and flow.capability == "cloud_access"
        ):
            return LeastPrivilegeFinding(
                identity=flow.credential,
                provider="aws",
                observed_capability="cloud_access",
                severity="HIGH",
                recommended_scope=(
                    "Use a dedicated runtime identity restricted to "
                    "the exact services, actions, and resources used "
                    "by the agent."
                ),
                avoid_permissions=(
                    "wildcard actions",
                    "wildcard resources",
                    "IAM administration",
                    "unrelated cloud services",
                ),
                recommendation=(
                    "Replace broad cloud credentials with a "
                    "least-privilege role or service identity."
                ),
            )

        return None

    @staticmethod
    def _unique(
        findings: list[LeastPrivilegeFinding],
    ) -> tuple[LeastPrivilegeFinding, ...]:
        seen = set()
        result: list[LeastPrivilegeFinding] = []

        for finding in findings:
            if finding in seen:
                continue

            seen.add(finding)
            result.append(finding)

        return tuple(result)