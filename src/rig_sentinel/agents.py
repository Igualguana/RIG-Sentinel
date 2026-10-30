from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.mcp import MCPFinding
from rig_sentinel.providers import ProviderFinding
from rig_sentinel.tools import ToolFinding


@dataclass(frozen=True)
class AgentFinding:
    name: str
    file: str
    provider: str | None
    has_mcp: bool
    tools: tuple[str, ...]
    confidence: str


class AgentDetector:
    def detect(
        self,
        relative_path: Path,
        providers: tuple[ProviderFinding, ...],
        mcp_findings: tuple[MCPFinding, ...],
        tools: tuple[ToolFinding, ...],
    ) -> AgentFinding | None:

        file_name = str(relative_path)

        file_providers = [
            item
            for item in providers
            if item.file == file_name
        ]

        file_mcp = [
            item
            for item in mcp_findings
            if item.file == file_name
        ]

        file_tools = [
            item
            for item in tools
            if item.file == file_name
        ]

        if not file_providers and not file_mcp and not file_tools:
            return None

        provider = (
            file_providers[0].provider
            if file_providers
            else None
        )

        tool_names = tuple(
            sorted(
                {
                    item.name
                    for item in file_tools
                }
            )
        )

        agent_name = relative_path.stem

        confidence = self._calculate_confidence(
            has_provider=bool(file_providers),
            has_mcp=bool(file_mcp),
            tool_count=len(tool_names),
        )

        return AgentFinding(
            name=agent_name,
            file=file_name,
            provider=provider,
            has_mcp=bool(file_mcp),
            tools=tool_names,
            confidence=confidence,
        )

    def _calculate_confidence(
        self,
        has_provider: bool,
        has_mcp: bool,
        tool_count: int,
    ) -> str:

        signals = 0

        if has_provider:
            signals += 1

        if has_mcp:
            signals += 1

        if tool_count > 0:
            signals += 1

        if signals >= 2:
            return "HIGH"

        return "MEDIUM"