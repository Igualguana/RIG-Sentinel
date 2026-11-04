from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


class SARIFReportGenerator:
    """SARIF 2.1.0 output for static indicators, not proof of exploitation.

    Never includes repository source snippets or raw credential evidence.
    """

    RULES = {
        "RIG001": ("Shadow agent", "Agent absent from approved inventory"),
        "RIG002": ("Shared credential reference", "Multiple agents reference a credential name"),
        "RIG003": ("Excessive privilege", "Observed credential capability may be excessive"),
        "RIG004": ("Sensitive agent capability", "Sensitive tool capability detected"),
    }
    LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    SENSITIVE_TOOLS = {"shell", "financial_action", "email_send", "http_request"}

    def generate(self, report: Mapping[str, Any]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for item in report.get("shadow_agent_findings", []):
            results.append(self._result(
                "RIG001", item.get("severity", "MEDIUM"),
                f"Agent {item.get('agent', 'unknown')} is not in the approved inventory; verify authorization.",
                item.get("file"),
            ))

        for item in report.get("shared_credential_findings", []):
            identity = str(item.get("identity", "unknown"))
            agents = ", ".join(str(x) for x in item.get("agents", []))
            results.append(self._result(
                "RIG002", item.get("severity", "HIGH"),
                f"Credential reference {identity} appears in agents [{agents}]; underlying secret sharing is unverified.",
            ))

        for item in report.get("privilege_findings", []):
            results.append(self._result(
                "RIG003", item.get("severity", "HIGH"),
                f"Agent {item.get('agent', 'unknown')} has credential-linked capability {item.get('capability', 'unknown')}; review scope.",
            ))

        for item in report.get("tools", []):
            if item.get("name") not in self.SENSITIVE_TOOLS:
                continue
            results.append(self._result(
                "RIG004", "CRITICAL" if item.get("name") in {"shell", "financial_action"} else "HIGH",
                f"Sensitive capability {item.get('name')} detected; verify runtime controls.",
                item.get("file"),
            ))

        rules = [{
            "id": rule_id,
            "shortDescription": {"text": short},
            "fullDescription": {"text": long},
            "properties": {"tags": ["security", "ai-agent", "static-analysis"]},
        } for rule_id, (short, long) in self.RULES.items()]

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "RIG Sentinel", "informationUri": "https://github.com/Igualguana/RIG-Sentinel", "rules": rules}},
                "results": results,
            }],
        }

    def write(self, report: Mapping[str, Any], destination: str | Path) -> Path:
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.generate(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    def _result(self, rule_id: str, severity: Any, message: str, file: Any = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": self.LEVELS.get(str(severity).upper(), "warning"),
            "message": {"text": message},
            "properties": {"classification": "static-indicator", "severity": str(severity).upper()},
        }
        path = self._safe_relative_path(file)
        if path:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"}}}]
        return result

    @staticmethod
    def _safe_relative_path(file: Any) -> str | None:
        if not isinstance(file, str) or not file or "\\" in file or ":" in file:
            return None
        path = PurePosixPath(file)
        if path.is_absolute() or any(part in {"..", "."} for part in file.split("/")):
            return None
        if any(ord(c) < 32 for c in file):
            return None
        from urllib.parse import quote
        return quote(path.as_posix(), safe="/-._~")
