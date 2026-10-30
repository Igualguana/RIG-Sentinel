from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IdentityFinding:
    name: str
    identity_type: str
    provider: str | None
    confidence: str
    file: str
    evidence: str


class IdentityDetector:
    def detect(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> list[IdentityFinding]:
        suffix = path.suffix.lower()

        if suffix == ".py":
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
    ) -> list[IdentityFinding]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []

        findings: list[IdentityFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                finding = self._from_name(
                    node.id,
                    relative_path,
                )

                if finding is not None:
                    findings.append(finding)

            elif isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    finding = self._from_name(
                        node.value,
                        relative_path,
                    )

                    if finding is not None:
                        findings.append(finding)

        return self._unique(findings)

    def _detect_text(
        self,
        relative_path: Path,
        text: str,
    ) -> list[IdentityFinding]:
        findings: list[IdentityFinding] = []

        for match in re.findall(
            r"\b[A-Z][A-Z0-9_]{5,}\b",
            text,
        ):
            finding = self._from_name(
                match,
                relative_path,
            )

            if finding is not None:
                findings.append(finding)

        return self._unique(findings)

    def _from_name(
        self,
        value: str,
        relative_path: Path,
    ) -> IdentityFinding | None:
        normalized = value.upper()

        mapping = {
            "OPENAI_API_KEY": (
                "api_key",
                "openai",
                "HIGH",
            ),
            "ANTHROPIC_API_KEY": (
                "api_key",
                "anthropic",
                "HIGH",
            ),
            "STRIPE_SECRET_KEY": (
                "api_key",
                "stripe",
                "HIGH",
            ),
            "STRIPE_API_KEY": (
                "api_key",
                "stripe",
                "HIGH",
            ),
            "GITHUB_TOKEN": (
                "token",
                "github",
                "HIGH",
            ),
            "GH_TOKEN": (
                "token",
                "github",
                "HIGH",
            ),
            "AWS_ACCESS_KEY_ID": (
                "access_key",
                "aws",
                "HIGH",
            ),
            "AWS_SECRET_ACCESS_KEY": (
                "secret_key",
                "aws",
                "HIGH",
            ),
            "GOOGLE_APPLICATION_CREDENTIALS": (
                "service_account",
                "google",
                "HIGH",
            ),
            "AZURE_CLIENT_SECRET": (
                "client_secret",
                "azure",
                "HIGH",
            ),
            "DATABASE_URL": (
                "database_credential",
                None,
                "MEDIUM",
            ),
            "DB_PASSWORD": (
                "database_credential",
                None,
                "HIGH",
            ),
        }

        config = mapping.get(normalized)

        if config is None:
            return None

        identity_type, provider, confidence = config

        return IdentityFinding(
            name=normalized,
            identity_type=identity_type,
            provider=provider,
            confidence=confidence,
            file=str(relative_path),
            evidence=f"credential reference: {normalized}",
        )

    @staticmethod
    def _unique(
        findings: list[IdentityFinding],
    ) -> list[IdentityFinding]:
        seen = set()
        result = []

        for finding in findings:
            if finding in seen:
                continue

            seen.add(finding)
            result.append(finding)

        return result