from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.agents import AgentFinding
from rig_sentinel.identity import IdentityFinding


@dataclass(frozen=True)
class AgentIdentityLink:
    agent: str
    identity: str
    identity_type: str
    provider: str | None
    file: str
    confidence: str


class IdentityLinker:
    def link(
        self,
        agents: tuple[AgentFinding, ...],
        identities: tuple[IdentityFinding, ...],
    ) -> tuple[AgentIdentityLink, ...]:
        links: list[AgentIdentityLink] = []

        for agent in agents:
            for identity in identities:
                if identity.file != agent.file:
                    continue

                links.append(
                    AgentIdentityLink(
                        agent=agent.name,
                        identity=identity.name,
                        identity_type=identity.identity_type,
                        provider=identity.provider,
                        file=identity.file,
                        confidence=self._confidence(
                            agent,
                            identity,
                        ),
                    )
                )

        return tuple(links)

    def _confidence(
        self,
        agent: AgentFinding,
        identity: IdentityFinding,
    ) -> str:
        if (
            agent.provider is not None
            and identity.provider == agent.provider
        ):
            return "HIGH"

        if identity.provider is not None:
            return "MEDIUM"

        return "MEDIUM"