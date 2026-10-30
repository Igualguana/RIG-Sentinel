from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.python_analysis import PythonAnalyzer


@dataclass(frozen=True)
class ProviderFinding:
    provider: str
    confidence: str
    file: str
    evidence: str


class ProviderDetector:
    def __init__(self) -> None:
        self.python_analyzer = PythonAnalyzer()

    def detect(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> list[ProviderFinding]:

        if path.suffix.lower() == ".py":
            return self._detect_python(
                relative_path,
                text,
            )

        return self._detect_text(
            relative_path,
            text,
        )

    def _detect_python(
        self,
        relative_path: Path,
        text: str,
    ) -> list[ProviderFinding]:

        findings: list[ProviderFinding] = []
        analysis = self.python_analyzer.analyze(text)

        providers = {
            "openai": {
                "imports": {
                    "openai",
                },
            },
            "anthropic": {
                "imports": {
                    "anthropic",
                },
            },
            "langchain": {
                "imports": {
                    "langchain",
                    "langchain_core",
                    "langchain_openai",
                    "langchain_anthropic",
                },
            },
            "crewai": {
                "imports": {
                    "crewai",
                },
            },
        }

        for provider, config in providers.items():
            for imported_module in analysis.imports:
                if any(
                    imported_module == allowed
                    or imported_module.startswith(
                        f"{allowed}."
                    )
                    for allowed in config["imports"]
                ):
                    findings.append(
                        ProviderFinding(
                            provider=provider,
                            confidence="HIGH",
                            file=str(relative_path),
                            evidence=f"python import: {imported_module}",
                        )
                    )
                    break

        return findings

    def _detect_text(
        self,
        relative_path: Path,
        text: str,
    ) -> list[ProviderFinding]:

        findings: list[ProviderFinding] = []
        lower_text = text.lower()

        medium_rules = {
            "openai": [
                "openai_api_key",
            ],
            "anthropic": [
                "anthropic_api_key",
            ],
            "langchain": [
                "langchain",
            ],
            "crewai": [
                "crewai",
            ],
        }

        for provider, markers in medium_rules.items():
            for marker in markers:
                if marker in lower_text:
                    findings.append(
                        ProviderFinding(
                            provider=provider,
                            confidence="MEDIUM",
                            file=str(relative_path),
                            evidence=marker,
                        )
                    )
                    break

        return findings