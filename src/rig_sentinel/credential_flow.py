
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
    """
    RIG Sentinel - Credential Flow Analysis v2.

    Detects:
    - Credential references loaded from environment variables.
    - Variables receiving credential references.
    - Known provider authentication bindings.
    - Provider capabilities associated with those bindings.

    Security notes:
    - Uses static AST analysis.
    - Does not execute scanned source code.
    - Does not retrieve credential values.
    - Does not prove runtime permissions or actual execution.
    """

    SUPPORTED_CREDENTIALS = {
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

    STRIPE_FINANCIAL_CALLS = {
        "stripe.refunds.create",
        "stripe.transfers.create",
        "stripe.PaymentIntent.create",
        "stripe.payment_intents.create",
    }

    OPENAI_CLIENT_CALLS = {
        "OpenAI",
        "openai.OpenAI",
        "openai.Client",
    }

    GITHUB_CLIENT_CALLS = {
        "Github",
        "github.Github",
    }

    AWS_CLIENT_CALLS = {
        "boto3.client",
        "boto3.resource",
    }

    def analyze(
        self,
        path: Path,
        relative_path: str | Path,
        text: str,
    ) -> tuple[CredentialFlowFinding, ...]:
        """
        Analyze a Python file for credential flows.

        The relative path is normalized to str to ensure
        compatibility with IdentityLinker and PrivilegeAnalyzer.
        """

        if path.suffix.lower() != ".py":
            return ()

        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return ()

        credential_variables = (
            self._find_credential_variables(tree)
        )

        findings: list[CredentialFlowFinding] = []

        normalized_file = str(relative_path)

        for credential, variable in credential_variables:
            provider = self._provider_for_credential(
                credential
            )

            capability = self._find_capability_for_variable(
                tree=tree,
                variable=variable,
                provider=provider,
            )

            confidence = (
                "HIGH"
                if capability is not None
                and capability != "credential_usage"
                else "MEDIUM"
            )

            evidence = (
                f"{credential} assigned to variable "
                f"{variable}"
            )

            if capability is not None:
                evidence += (
                    f"; inferred capability: {capability}"
                )
            else:
                evidence += (
                    "; no supported capability binding found"
                )

            findings.append(
                CredentialFlowFinding(
                    credential=credential,
                    variable=variable,
                    provider=provider,
                    capability=capability,
                    file=normalized_file,
                    confidence=confidence,
                    evidence=evidence,
                )
            )

        return tuple(
            sorted(
                set(findings),
                key=lambda item: (
                    item.file,
                    item.credential,
                    item.variable,
                ),
            )
        )

    # ========================================================
    # CREDENTIAL VARIABLE DISCOVERY
    # ========================================================

    def _find_credential_variables(
        self,
        tree: ast.AST,
    ) -> tuple[tuple[str, str], ...]:

        results: set[tuple[str, str]] = set()

        for node in ast.walk(tree):

            if isinstance(node, ast.Assign):
                credential = self._credential_from_call(
                    node.value
                )

                if credential is None:
                    continue

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        results.add(
                            (
                                credential,
                                target.id,
                            )
                        )

            elif isinstance(node, ast.AnnAssign):
                credential = self._credential_from_call(
                    node.value
                )

                if (
                    credential is not None
                    and isinstance(node.target, ast.Name)
                ):
                    results.add(
                        (
                            credential,
                            node.target.id,
                        )
                    )

        return tuple(sorted(results))

    def _credential_from_call(
        self,
        node: ast.AST | None,
    ) -> str | None:

        if not isinstance(node, ast.Call):
            return None

        call_name = self._call_name(node.func)

        if call_name not in {
            "os.getenv",
            "getenv",
            "os.environ.get",
        }:
            return None

        if not node.args:
            return None

        first_argument = node.args[0]

        if not isinstance(
            first_argument,
            ast.Constant,
        ):
            return None

        if not isinstance(
            first_argument.value,
            str,
        ):
            return None

        credential = first_argument.value

        if credential not in self.SUPPORTED_CREDENTIALS:
            return None

        return credential

    # ========================================================
    # CAPABILITY DETECTION
    # ========================================================

    def _find_capability_for_variable(
        self,
        tree: ast.AST,
        variable: str,
        provider: str | None,
    ) -> str | None:

        if provider == "stripe":

            if self._stripe_credential_is_bound(
                tree,
                variable,
            ):
                if self._tree_has_call(
                    tree,
                    self.STRIPE_FINANCIAL_CALLS,
                ):
                    return "financial_action"

        if provider == "openai":

            if self._client_uses_variable(
                tree=tree,
                variable=variable,
                client_calls=self.OPENAI_CLIENT_CALLS,
                allowed_keywords={"api_key"},
                allow_positional=False,
            ):
                return "ai_provider_access"

        if provider == "github":

            if self._client_uses_variable(
                tree=tree,
                variable=variable,
                client_calls=self.GITHUB_CLIENT_CALLS,
                allowed_keywords={
                    "login_or_token",
                    "token",
                    "auth",
                },
                allow_positional=True,
            ):
                return "repository_access"

        if provider == "aws":

            if self._client_uses_variable(
                tree=tree,
                variable=variable,
                client_calls=self.AWS_CLIENT_CALLS,
                allowed_keywords={
                    "aws_access_key_id",
                    "aws_secret_access_key",
                    "aws_session_token",
                },
                allow_positional=False,
            ):
                return "cloud_access"

        if self._variable_is_used(
            tree,
            variable,
        ):
            return "credential_usage"

        return None

    # ========================================================
    # STRIPE AUTHENTICATION BINDING
    # ========================================================

    def _stripe_credential_is_bound(
        self,
        tree: ast.AST,
        variable: str,
    ) -> bool:

        for node in ast.walk(tree):

            if isinstance(node, ast.Assign):

                if not self._is_variable(
                    node.value,
                    variable,
                ):
                    continue

                for target in node.targets:
                    if self._call_name(target) == (
                        "stripe.api_key"
                    ):
                        return True

            elif isinstance(node, ast.AnnAssign):

                if (
                    self._is_variable(
                        node.value,
                        variable,
                    )
                    and self._call_name(
                        node.target
                    ) == "stripe.api_key"
                ):
                    return True

        return False

    # ========================================================
    # CLIENT AUTHENTICATION BINDING
    # ========================================================

    def _client_uses_variable(
        self,
        tree: ast.AST,
        variable: str,
        client_calls: set[str],
        allowed_keywords: set[str],
        allow_positional: bool,
    ) -> bool:

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            call_name = self._call_name(node.func)

            if call_name not in client_calls:
                continue

            for keyword in node.keywords:

                if keyword.arg not in allowed_keywords:
                    continue

                if self._is_variable(
                    keyword.value,
                    variable,
                ):
                    return True

            if allow_positional:

                for argument in node.args:

                    if self._is_variable(
                        argument,
                        variable,
                    ):
                        return True

        return False

    # ========================================================
    # AST HELPERS
    # ========================================================

    @staticmethod
    def _is_variable(
        node: ast.AST | None,
        variable: str,
    ) -> bool:

        return (
            isinstance(node, ast.Name)
            and node.id == variable
            and isinstance(node.ctx, ast.Load)
        )

    def _tree_has_call(
        self,
        tree: ast.AST,
        call_names: set[str],
    ) -> bool:

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            name = self._call_name(node.func)

            if name in call_names:
                return True

        return False

    @staticmethod
    def _variable_is_used(
        tree: ast.AST,
        variable: str,
    ) -> bool:

        for node in ast.walk(tree):

            if not isinstance(node, ast.Name):
                continue

            if (
                node.id == variable
                and isinstance(node.ctx, ast.Load)
            ):
                return True

        return False

    @staticmethod
    def _call_name(
        node: ast.AST,
    ) -> str:

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = CredentialFlowAnalyzer._call_name(
                node.value
            )

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""

    # ========================================================
    # PROVIDER RESOLUTION
    # ========================================================

    @staticmethod
    def _provider_for_credential(
        credential: str,
    ) -> str | None:

        providers = {
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
        }

        return providers.get(credential)
