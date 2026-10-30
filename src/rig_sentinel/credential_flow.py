from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CredentialFlowFinding:
    credential: str
    variable: str
    provider: str | None
    capability: str | None
    file: str
    confidence: str
    evidence: str


class CredentialFlowAnalyzer:
    def analyze(
        self,
        path: Path,
        relative_path: Path,
        text: str,
    ) -> tuple[CredentialFlowFinding, ...]:
        if path.suffix.lower() != ".py":
            return ()

        try:
            tree = ast.parse(text)
        except SyntaxError:
            return ()

        credential_variables = self._find_credential_variables(tree)
        findings: list[CredentialFlowFinding] = []

        for credential, variable in credential_variables.items():
            provider = self._provider_for_credential(credential)

            capability = self._find_capability_for_variable(
                tree,
                variable,
                provider,
            )

            findings.append(
                CredentialFlowFinding(
                    credential=credential,
                    variable=variable,
                    provider=provider,
                    capability=capability,
                    file=str(relative_path),
                    confidence=(
                        "HIGH"
                        if capability is not None
                        else "MEDIUM"
                    ),
                    evidence=self._build_evidence(
                        credential,
                        variable,
                        capability,
                    ),
                )
            )

        return tuple(findings)

    def _find_credential_variables(
        self,
        tree: ast.AST,
    ) -> dict[str, str]:
        result: dict[str, str] = {}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            if len(node.targets) != 1:
                continue

            target = node.targets[0]

            if not isinstance(target, ast.Name):
                continue

            credential = self._credential_from_call(node.value)

            if credential is None:
                continue

            result[credential] = target.id

        return result

    def _credential_from_call(
        self,
        node: ast.AST,
    ) -> str | None:
        if not isinstance(node, ast.Call):
            return None

        call_name = self._call_name(node.func)

        if call_name not in {
            "os.getenv",
            "getenv",
        }:
            return None

        if not node.args:
            return None

        first_arg = node.args[0]

        if not isinstance(first_arg, ast.Constant):
            return None

        if not isinstance(first_arg.value, str):
            return None

        credential = first_arg.value.upper()

        if not self._is_supported_credential(credential):
            return None

        return credential

    def _find_capability_for_variable(
        self,
        tree: ast.AST,
        variable: str,
        provider: str | None,
    ) -> str | None:
        if provider == "stripe":
            if self._tree_has_call(
                tree,
                {
                    "stripe.refunds.create",
                    "stripe.transfers.create",
                    "stripe.PaymentIntent.create",
                    "stripe.payment_intents.create",
                },
            ):
                return "financial_action"

        if provider == "openai":
            if self._tree_has_call(
                tree,
                {
                    "OpenAI",
                    "openai.OpenAI",
                    "openai.Client",
                },
            ):
                return "ai_provider_access"

        if provider == "github":
            if self._tree_has_call(
                tree,
                {
                    "Github",
                    "github.Github",
                },
            ):
                return "repository_access"

        if provider == "aws":
            if self._tree_has_call(
                tree,
                {
                    "boto3.client",
                    "boto3.resource",
                },
            ):
                return "cloud_access"

        if self._variable_is_used(tree, variable):
            return "credential_usage"

        return None

    def _tree_has_call(
        self,
        tree: ast.AST,
        candidates: set[str],
    ) -> bool:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._call_name(node.func)

            if call_name in candidates:
                return True

        return False

    def _variable_is_used(
        self,
        tree: ast.AST,
        variable: str,
    ) -> bool:
        usage_count = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if node.id == variable:
                    usage_count += 1

        # One occurrence is normally the assignment target itself.
        return usage_count > 1

    def _call_name(
        self,
        node: ast.AST,
    ) -> str:
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = self._call_name(node.value)

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""

    def _provider_for_credential(
        self,
        credential: str,
    ) -> str | None:
        mapping = {
            "OPENAI_API_KEY": "openai",
            "ANTHROPIC_API_KEY": "anthropic",
            "STRIPE_SECRET_KEY": "stripe",
            "STRIPE_API_KEY": "stripe",
            "GITHUB_TOKEN": "github",
            "GH_TOKEN": "github",
            "AWS_ACCESS_KEY_ID": "aws",
            "AWS_SECRET_ACCESS_KEY": "aws",
            "GOOGLE_APPLICATION_CREDENTIALS": "google",
            "AZURE_CLIENT_SECRET": "azure",
            "DATABASE_URL": None,
            "DB_PASSWORD": None,
        }

        return mapping.get(credential)

    def _is_supported_credential(
        self,
        credential: str,
    ) -> bool:
        return credential in {
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "STRIPE_SECRET_KEY",
            "STRIPE_API_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_CLIENT_SECRET",
            "DATABASE_URL",
            "DB_PASSWORD",
        }

    def _build_evidence(
        self,
        credential: str,
        variable: str,
        capability: str | None,
    ) -> str:
        if capability is None:
            return (
                f"{credential} assigned to variable "
                f"{variable}"
            )

        return (
            f"{credential} assigned to variable "
            f"{variable}; inferred capability: "
            f"{capability}"
        )