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
    """Identify executable agent candidates, not documentation or test fixtures.

    Provider, MCP, tool and credential findings are recorded separately by
    RepositoryScanner. Rejecting a file as an agent does not discard those
    findings from the repository report.
    """

    SOURCE_SUFFIXES = frozenset({
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    })
    TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec", "specs"})
    NON_AGENT_MODULE_NAMES = frozenset({
        "conftest", "setup", "config", "configuration", "__init__",
    })

    def detect(
        self,
        relative_path: Path,
        providers: tuple[ProviderFinding, ...],
        mcp_findings: tuple[MCPFinding, ...],
        tools: tuple[ToolFinding, ...],
    ) -> AgentFinding | None:
        relative_path = Path(relative_path)
        file_name = str(relative_path)
        normalized_file = self._normalize_path(file_name)

        # Documentation, GitHub workflows and MCP configuration files may
        # provide security evidence, but they are not executable agents.
        if not self._eligible_source(Path(self._normalize_path(relative_path))):
            return None

        file_providers = [item for item in providers if self._normalize_path(item.file) == normalized_file]
        file_mcp = [item for item in mcp_findings if self._normalize_path(item.file) == normalized_file]
        file_tools = [item for item in tools if self._normalize_path(item.file) == normalized_file]

        if not file_providers and not file_mcp and not file_tools:
            return None

        normalized_path = Path(normalized_file)
        agent_name = normalized_path.stem
        agent_named = self._agent_named(normalized_path)

        # A generic source file that only references an AI provider is not
        # evidence of a running agent. The same applies to standalone calls
        # to ordinary tools such as subprocess/HTTP.
        if not file_mcp and not agent_named:
            if not file_providers or not file_tools:
                return None

        provider = file_providers[0].provider if file_providers else None
        tool_names = tuple(sorted({item.name for item in file_tools}))
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

    @staticmethod
    def _normalize_path(value: str | Path) -> str:
        """Compare detector paths consistently on Windows, macOS and Linux.

        Evidence may use POSIX separators while pathlib renders native
        separators. This normalizes separators, not the evidence itself.
        """
        return str(value).replace("\\", "/")

    @classmethod
    def _eligible_source(cls, path: Path) -> bool:
        if path.suffix.lower() not in cls.SOURCE_SUFFIXES:
            return False
        parts = [part.lower() for part in path.parts]
        if any(part in cls.TEST_DIR_NAMES for part in parts[:-1]):
            return False
        stem = path.stem.lower()
        if (
            stem.startswith("test_")
            or stem.endswith("_test")
            or stem.endswith(".test")
            or stem.endswith(".spec")
            or stem in cls.NON_AGENT_MODULE_NAMES
        ):
            return False
        return True

    @staticmethod
    def _agent_named(path: Path) -> bool:
        stem = path.stem.lower().replace("-", "_")
        parts = [part.lower().replace("-", "_") for part in path.parts[:-1]]
        return (
            "agent" in stem.split("_")
            or "assistant" in stem.split("_")
            or stem.endswith("agent")
            or stem.endswith("assistant")
            or "agents" in parts
            or "assistants" in parts
        )

    def _calculate_confidence(
        self,
        has_provider: bool,
        has_mcp: bool,
        tool_count: int,
    ) -> str:
        signals = int(has_provider) + int(has_mcp) + int(tool_count > 0)
        return "HIGH" if signals >= 2 else "MEDIUM"
