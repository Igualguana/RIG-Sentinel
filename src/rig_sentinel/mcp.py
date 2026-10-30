from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.python_analysis import PythonAnalyzer


@dataclass(frozen=True)
class MCPFinding:
    kind: str
    confidence: str
    file: str
    evidence: str


class MCPDetector:
    def __init__(self) -> None:
        self.python_analyzer = PythonAnalyzer()

    def detect(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> list[MCPFinding]:

        findings: list[MCPFinding] = []

        if path.suffix.lower() == ".py":
            return self._detect_python(
                relative_path,
                text,
            )

        if path.suffix.lower() == ".json":
            findings.extend(
                self._detect_json(
                    path,
                    relative_path,
                    text,
                )
            )

        return findings

    def _detect_python(
        self,
        relative_path: Path,
        text: str,
    ) -> list[MCPFinding]:

        findings: list[MCPFinding] = []

        analysis = self.python_analyzer.analyze(text)

        for imported_module in analysis.imports:
            if (
                imported_module == "mcp"
                or imported_module.startswith("mcp.")
                or imported_module == "modelcontextprotocol"
                or imported_module.startswith("modelcontextprotocol.")
            ):
                findings.append(
                    MCPFinding(
                        kind="mcp_runtime",
                        confidence="HIGH",
                        file=str(relative_path),
                        evidence=f"python import: {imported_module}",
                    )
                )
                break

        mcp_calls = {
            "FastMCP",
            "mcp.FastMCP",
            "mcp.server.Server",
        }

        for call in analysis.calls:
            if call in mcp_calls:
                findings.append(
                    MCPFinding(
                        kind="mcp_runtime",
                        confidence="HIGH",
                        file=str(relative_path),
                        evidence=f"python call: {call}",
                    )
                )
                break

        return findings

    def _detect_json(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> list[MCPFinding]:

        findings: list[MCPFinding] = []

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings

        if not isinstance(data, dict):
            return findings

        if "mcpServers" in data:
            findings.append(
                MCPFinding(
                    kind="mcp_servers",
                    confidence="HIGH",
                    file=str(relative_path),
                    evidence="mcpServers",
                )
            )

        if path.name.lower() in {
            "mcp.json",
            "mcp-config.json",
            "mcp_config.json",
        }:
            findings.append(
                MCPFinding(
                    kind="mcp_config",
                    confidence="HIGH",
                    file=str(relative_path),
                    evidence=path.name,
                )
            )

        return findings