from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.credential_flow import CredentialFlowFinding
from rig_sentinel.identity_linking import AgentIdentityLink


@dataclass(frozen=True)
class PrivilegeFinding:
    agent: str
    identity: str
    capability: str
    severity: str
    reason: str
    recommendation: str


class PrivilegeAnalyzer:
    def analyze(
        self,
        agents: tuple[AgentFinding, ...],
        identity_links: tuple[AgentIdentityLink, ...],
        credential_flows: tuple[CredentialFlowFinding, ...] = (),
    ) -> tuple[PrivilegeFinding, ...]:
        if credential_flows:
            return self._analyze_with_flows(
                agents,
                identity_links,
                credential_flows,
            )

        # Backward-compatible fallback for tests and cases where
        # credential-flow evidence is not available yet.
        return self._analyze_heuristically(
            agents,
            identity_links,
        )

    def _analyze_with_flows(
        self,
        agents: tuple[AgentFinding, ...],
        identity_links: tuple[AgentIdentityLink, ...],
        credential_flows: tuple[CredentialFlowFinding, ...],
    ) -> tuple[PrivilegeFinding, ...]:
        findings: list[PrivilegeFinding] = []

        agents_by_file = {
            agent.file: agent
            for agent in agents
        }

        linked_identities = {
            (
                link.agent,
                link.identity,
            )
            for link in identity_links
        }

        for flow in credential_flows:
            if flow.capability is None:
                continue

            agent = agents_by_file.get(flow.file)

            if agent is None:
                continue

            if (
                agent.name,
                flow.credential,
            ) not in linked_identities:
                continue

            finding = self._finding_from_proven_flow(
                agent=agent,
                flow=flow,
            )

            if finding is not None:
                findings.append(finding)

        return self._unique(findings)

    def _finding_from_proven_flow(
        self,
        agent: AgentFinding,
        flow: CredentialFlowFinding,
    ) -> PrivilegeFinding | None:
        if (
            flow.capability == "financial_action"
            and flow.provider == "stripe"
        ):
            return PrivilegeFinding(
                agent=agent.name,
                identity=flow.credential,
                capability="financial_action",
                severity="CRITICAL",
                reason=(
                    "Credential flow analysis shows that the Stripe "
                    "credential is associated with a financial "
                    "mutation capability."
                ),
                recommendation=(
                    "Use a scoped Stripe credential, restrict "
                    "financial permissions, and require explicit "
                    "human approval for refunds, transfers, and "
                    "other financial mutations."
                ),
            )

        if flow.capability == "repository_access":
            return PrivilegeFinding(
                agent=agent.name,
                identity=flow.credential,
                capability="repository_access",
                severity="HIGH",
                reason=(
                    "Credential flow analysis shows that the "
                    "credential provides repository access."
                ),
                recommendation=(
                    "Use a repository-scoped token with the minimum "
                    "required permissions and restrict write or "
                    "administrative access."
                ),
            )

        if flow.capability == "cloud_access":
            return PrivilegeFinding(
                agent=agent.name,
                identity=flow.credential,
                capability="cloud_access",
                severity="HIGH",
                reason=(
                    "Credential flow analysis shows that the "
                    "credential is used for cloud resource access."
                ),
                recommendation=(
                    "Use a dedicated least-privilege cloud identity "
                    "with narrowly scoped actions and resources."
                ),
            )

        return None

    def _analyze_heuristically(
        self,
        agents: tuple[AgentFinding, ...],
        identity_links: tuple[AgentIdentityLink, ...],
    ) -> tuple[PrivilegeFinding, ...]:
        findings: list[PrivilegeFinding] = []

        for agent in agents:
            links = tuple(
                link
                for link in identity_links
                if link.agent == agent.name
            )

            for link in links:
                for tool in agent.tools:
                    finding = self._analyze_combination(
                        agent=agent,
                        link=link,
                        tool=tool,
                    )

                    if finding is not None:
                        findings.append(finding)

        return self._unique(findings)

    def _analyze_combination(
        self,
        agent: AgentFinding,
        link: AgentIdentityLink,
        tool: str,
    ) -> PrivilegeFinding | None:
        if (
            tool == "financial_action"
            and link.provider == "stripe"
        ):
            return PrivilegeFinding(
                agent=agent.name,
                identity=link.identity,
                capability=tool,
                severity="CRITICAL",
                reason=(
                    "A Stripe credential is linked to an agent "
                    "with financial mutation capability."
                ),
                recommendation=(
                    "Use a scoped Stripe credential, restrict "
                    "financial permissions, and require explicit "
                    "human approval for refunds, transfers, and "
                    "other financial mutations."
                ),
            )

        if tool == "shell":
            return PrivilegeFinding(
                agent=agent.name,
                identity=link.identity,
                capability=tool,
                severity="CRITICAL",
                reason=(
                    "The agent can execute shell commands while "
                    "operating with an application credential."
                ),
                recommendation=(
                    "Remove unrestricted shell access or isolate "
                    "execution with a strict command allowlist and "
                    "least-privilege runtime identity."
                ),
            )

        if tool == "email_send":
            return PrivilegeFinding(
                agent=agent.name,
                identity=link.identity,
                capability=tool,
                severity="HIGH",
                reason=(
                    "The agent can send external messages while "
                    "operating with a linked credential."
                ),
                recommendation=(
                    "Restrict recipient scope, separate messaging "
                    "credentials, and require approval for sensitive "
                    "outbound communication."
                ),
            )

        if tool == "http_request":
            return PrivilegeFinding(
                agent=agent.name,
                identity=link.identity,
                capability=tool,
                severity="MEDIUM",
                reason=(
                    "The agent can make outbound network requests "
                    "while operating with a linked credential."
                ),
                recommendation=(
                    "Restrict outbound destinations and use "
                    "credential scopes that cannot access "
                    "unrelated services."
                ),
            )

        return None

    @staticmethod
    def _unique(
        findings: list[PrivilegeFinding],
    ) -> tuple[PrivilegeFinding, ...]:
        seen = set()
        result: list[PrivilegeFinding] = []

        for finding in findings:
            if finding in seen:
                continue

            seen.add(finding)
            result.append(finding)

        return tuple(result)