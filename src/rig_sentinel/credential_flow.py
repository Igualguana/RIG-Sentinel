
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
    RIG Sentinel - Credential Flow Analysis v3.

    Detects credential references and known authentication
    bindings, including simple flows through local functions.

    Scope:
    - Python static AST analysis
    - Same-file functions
    - Positional and keyword arguments
    - Multiple local function calls
    - Bounded recursive analysis

    Limitations:
    - No cross-file analysis
    - No complete control-flow analysis
    - No runtime verification
    - No proof of effective provider permissions
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

    MAX_FUNCTION_DEPTH = 8

    def analyze(
        self,
        path: Path,
        relative_path: str | Path,
        text: str,
    ) -> tuple[CredentialFlowFinding, ...]:

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
    # CREDENTIAL DISCOVERY
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
                            (credential, target.id)
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
                        (credential, node.target.id)
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

        if not isinstance(first_argument, ast.Constant):
            return None

        if not isinstance(first_argument.value, str):
            return None

        credential = first_argument.value

        if credential not in self.SUPPORTED_CREDENTIALS:
            return None

        return credential

    # ========================================================
    # CAPABILITY ANALYSIS
    # ========================================================

    def _find_capability_for_variable(
        self,
        tree: ast.AST,
        variable: str,
        provider: str | None,
    ) -> str | None:

        # Preserve v2 detection of direct bindings.
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

        # V3: follow the credential through local functions.
        if self._reaches_binding_through_functions(
            tree=tree,
            variable=variable,
            provider=provider,
        ):
            if provider == "stripe":
                if self._tree_has_call(
                    tree,
                    self.STRIPE_FINANCIAL_CALLS,
                ):
                    return "financial_action"

            if provider == "openai":
                return "ai_provider_access"

            if provider == "github":
                return "repository_access"

            if provider == "aws":
                return "cloud_access"

        if self._variable_is_used(tree, variable):
            return "credential_usage"

        return None

    # ========================================================
    # V3 - INTERPROCEDURAL ANALYSIS
    # ========================================================

    def _reaches_binding_through_functions(
        self,
        tree: ast.AST,
        variable: str,
        provider: str | None,
    ) -> bool:
        """
        Follow a tracked variable through calls to functions
        defined at module level.

        A function is analyzed only when a tracked variable
        is passed into one of its parameters.
        """

        if not isinstance(tree, ast.Module):
            return False

        functions: dict[
            str,
            ast.FunctionDef | ast.AsyncFunctionDef,
        ] = {}

        for statement in tree.body:
            if isinstance(
                statement,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                functions[statement.name] = statement

        visited: set[
            tuple[str, tuple[str, ...]]
        ] = set()

        return self._analyze_scope(
            scope=tree,
            tainted_names={variable},
            provider=provider,
            functions=functions,
            visited=visited,
            depth=0,
        )

    def _analyze_scope(
        self,
        scope: ast.AST,
        tainted_names: set[str],
        provider: str | None,
        functions: dict,
        visited: set,
        depth: int,
    ) -> bool:

        if depth > self.MAX_FUNCTION_DEPTH:
            return False

        nodes = tuple(self._scope_nodes(scope))

        # Detect supported authentication sinks in this scope.
        for node in nodes:
            if self._is_authentication_binding(
                node=node,
                tainted_names=tainted_names,
                provider=provider,
            ):
                return True

        # Follow references through calls to local functions.
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Name):
                continue

            function_name = node.func.id
            function = functions.get(function_name)

            if function is None:
                continue

            parameter_names = [
                argument.arg
                for argument in function.args.posonlyargs
            ] + [
                argument.arg
                for argument in function.args.args
            ]

            mapped_names: set[str] = set()

            for index, argument in enumerate(node.args):
                if index >= len(parameter_names):
                    break

                if self._references_tracked_name(
                    argument,
                    tainted_names,
                ):
                    mapped_names.add(
                        parameter_names[index]
                    )

            for keyword in node.keywords:
                if keyword.arg is None:
                    continue

                if keyword.arg not in parameter_names:
                    continue

                if self._references_tracked_name(
                    keyword.value,
                    tainted_names,
                ):
                    mapped_names.add(keyword.arg)

            if not mapped_names:
                continue

            state = (
                function_name,
                tuple(sorted(mapped_names)),
            )

            if state in visited:
                continue

            visited.add(state)

            if self._analyze_scope(
                scope=function,
                tainted_names=mapped_names,
                provider=provider,
                functions=functions,
                visited=visited,
                depth=depth + 1,
            ):
                return True

        return False

    @staticmethod
    def _scope_nodes(
        scope: ast.AST,
    ):
        """
        Walk expressions within the current scope without
        automatically entering unrelated function bodies.
        """

        stack = [scope]

        while stack:
            node = stack.pop()
            yield node

            for child in reversed(
                list(ast.iter_child_nodes(node))
            ):
                if isinstance(
                    child,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.Lambda,
                        ast.ClassDef,
                    ),
                ):
                    continue

                stack.append(child)

    @staticmethod
    def _references_tracked_name(
        node: ast.AST,
        tainted_names: set[str],
    ) -> bool:

        return (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in tainted_names
        )

    # ========================================================
    # AUTHENTICATION SINKS
    # ========================================================

    def _is_authentication_binding(
        self,
        node: ast.AST,
        tainted_names: set[str],
        provider: str | None,
    ) -> bool:

        if provider == "stripe":
            if isinstance(node, ast.Assign):
                if not self._references_tracked_name(
                    node.value,
                    tainted_names,
                ):
                    return False

                return any(
                    self._call_name(target)
                    == "stripe.api_key"
                    for target in node.targets
                )

            if isinstance(node, ast.AnnAssign):
                return (
                    self._call_name(node.target)
                    == "stripe.api_key"
                    and self._references_tracked_name(
                        node.value,
                        tainted_names,
                    )
                )

            return False

        if not isinstance(node, ast.Call):
            return False

        call_name = self._call_name(node.func)

        if provider == "openai":
            calls = self.OPENAI_CLIENT_CALLS
            keywords = {"api_key"}
            allow_positional = False

        elif provider == "github":
            calls = self.GITHUB_CLIENT_CALLS
            keywords = {
                "login_or_token",
                "token",
                "auth",
            }
            allow_positional = True

        elif provider == "aws":
            calls = self.AWS_CLIENT_CALLS
            keywords = {
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
            }
            allow_positional = False

        else:
            return False

        if call_name not in calls:
            return False

        for keyword in node.keywords:
            if keyword.arg not in keywords:
                continue

            if self._references_tracked_name(
                keyword.value,
                tainted_names,
            ):
                return True

        if allow_positional:
            return any(
                self._references_tracked_name(
                    argument,
                    tainted_names,
                )
                for argument in node.args
            )

        return False

    # ========================================================
    # V2 - STRIPE DIRECT BINDINGS
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
                    if (
                        self._call_name(target)
                        == "stripe.api_key"
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
    # V2 - CLIENT AUTHENTICATION BINDINGS
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

            if self._call_name(node.func) in call_names:
                return True

        return False

    @staticmethod
    def _variable_is_used(
        tree: ast.AST,
        variable: str,
    ) -> bool:

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and node.id == variable
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
