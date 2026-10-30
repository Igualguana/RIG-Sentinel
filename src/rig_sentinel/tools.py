from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.python_analysis import PythonAnalyzer


@dataclass(frozen=True)
class ToolFinding:
    name: str
    category: str
    confidence: str
    file: str
    evidence: str


class ToolDetector:
    def __init__(self) -> None:
        self.python_analyzer = PythonAnalyzer()

    def detect(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> list[ToolFinding]:

        if path.suffix.lower() != ".py":
            return []

        analysis = self.python_analyzer.analyze(text)

        findings: list[ToolFinding] = []

        rules = {
            "shell": {
                "category": "execute",
                "calls": {
                    "subprocess.run",
                    "subprocess.Popen",
                    "os.system",
                },
            },
            "filesystem_write": {
                "category": "write",
                "calls": {
                    "write_text",
                    "write_bytes",
                },
            },
            "filesystem_delete": {
                "category": "delete",
                "calls": {
                    "unlink",
                    "os.remove",
                    "shutil.rmtree",
                },
            },
            "http_request": {
                "category": "network",
                "calls": {
                    "requests.get",
                    "requests.post",
                    "requests.put",
                    "requests.delete",
                    "httpx.get",
                    "httpx.post",
                    "httpx.put",
                    "httpx.delete",
                },
            },
            "email_send": {
                "category": "external_send",
                "calls": {
                    "send_email",
                    "send_message",
                    "gmail.users.messages.send",
                },
            },
            "financial_action": {
                "category": "financial",
                "calls": {
                    "refund",
                    "transfer",
                    "stripe.refunds.create",
                },
            },
        }

        for tool_name, config in rules.items():
            matched_call = self._find_matching_call(
                analysis.calls,
                config["calls"],
            )

            if matched_call is not None:
                findings.append(
                    ToolFinding(
                        name=tool_name,
                        category=config["category"],
                        confidence="HIGH",
                        file=str(relative_path),
                        evidence=f"python call: {matched_call}",
                    )
                )

        return findings

    def _find_matching_call(
        self,
        actual_calls: tuple[str, ...],
        allowed_calls: set[str],
    ) -> str | None:

        for actual in actual_calls:
            for allowed in allowed_calls:
                if (
                    actual == allowed
                    or actual.endswith(f".{allowed}")
                ):
                    return actual

        return None