from __future__ import annotations

import ast
from dataclasses import dataclass, field
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


@dataclass
class _FlowState:
    bound: bool = False
    financial_action: bool = False
    used: bool = False
    active_calls: set[tuple[str, int]] = field(default_factory=set)


class CredentialFlowAnalyzer:
    """Bounded, same-file Python credential-flow analysis (v3.1).

    Analyzes reachable local function bodies and simple name aliases.
    It is a static approximation, not runtime or permission verification.
    """

    SUPPORTED_CREDENTIALS = {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY",
        "STRIPE_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
        "DATABASE_URL", "DB_PASSWORD",
    }
    STRIPE_FINANCIAL_CALLS = {
        "stripe.refunds.create", "stripe.transfers.create",
        "stripe.PaymentIntent.create", "stripe.payment_intents.create",
    }
    OPENAI_CLIENT_CALLS = {"OpenAI", "openai.OpenAI", "openai.Client"}
    GITHUB_CLIENT_CALLS = {"Github", "github.Github"}
    AWS_CLIENT_CALLS = {"boto3.client", "boto3.resource"}
    MAX_FUNCTION_DEPTH = 8

    def analyze(
        self,
        path: Path,
        relative_path: str | Path,
        text: str,
    ) -> tuple[CredentialFlowFinding, ...]:
        if Path(path).suffix.lower() != ".py":
            return ()
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return ()

        findings: list[CredentialFlowFinding] = []
        for credential, variable in self._find_credential_variables(tree):
            provider = self._provider_for_credential(credential)
            state = _FlowState()
            self._execute_block(
                tree.body, {}, {}, state, credential, variable, provider, 0
            )
            if provider == "stripe" and state.bound and state.financial_action:
                capability = "financial_action"
            elif state.bound and provider == "openai":
                capability = "ai_provider_access"
            elif state.bound and provider == "github":
                capability = "repository_access"
            elif state.bound and provider == "aws":
                capability = "cloud_access"
            elif state.used:
                capability = "credential_usage"
            else:
                capability = None

            confidence = (
                "HIGH" if capability not in (None, "credential_usage")
                else "MEDIUM"
            )
            evidence = f"{credential} assigned to variable {variable}"
            if capability is None:
                evidence += "; no supported capability binding found"
            else:
                evidence += f"; inferred capability: {capability}"
            findings.append(CredentialFlowFinding(
                credential=credential, variable=variable, provider=provider,
                capability=capability, file=str(relative_path),
                confidence=confidence, evidence=evidence,
            ))
        return tuple(sorted(set(findings), key=lambda f: (f.file, f.credential, f.variable)))

    def _execute_block(
        self,
        statements: list[ast.stmt],
        environment: dict[str, bool],
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        state: _FlowState,
        credential: str,
        origin: str,
        provider: str | None,
        depth: int,
    ) -> None:
        # Definitions are available independently of their source order,
        # but their bodies are inspected only when invoked.
        available = dict(functions)
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                available[stmt.name] = stmt

        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = stmt.value
                if value is None:
                    continue
                self._inspect_expr(value, environment, available, state, provider, depth)
                tainted = (
                    self._credential_from_call(value) == credential
                    or self._is_tainted(value, environment)
                )
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        # Only the original source assignment seeds this flow.
                        if self._credential_from_call(value) == credential:
                            environment[target.id] = (target.id == origin)
                        else:
                            environment[target.id] = tainted
                    elif (
                        provider == "stripe"
                        and self._call_name(target) == "stripe.api_key"
                        and tainted
                    ):
                        state.bound = True
                continue
            if isinstance(stmt, ast.AugAssign):
                self._inspect_expr(stmt.value, environment, available, state, provider, depth)
                if isinstance(stmt.target, ast.Name):
                    environment[stmt.target.id] = False
                continue
            if isinstance(stmt, ast.Expr):
                self._inspect_expr(stmt.value, environment, available, state, provider, depth)
            elif isinstance(stmt, ast.Return) and stmt.value is not None:
                self._inspect_expr(stmt.value, environment, available, state, provider, depth)
            elif isinstance(stmt, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                # Conservative branch traversal: does not prove branch execution.
                expr = stmt.test if isinstance(stmt, (ast.If, ast.While)) else stmt.iter
                self._inspect_expr(expr, environment, available, state, provider, depth)
                self._execute_block(stmt.body, environment.copy(), available, state, credential, origin, provider, depth)
                self._execute_block(stmt.orelse, environment.copy(), available, state, credential, origin, provider, depth)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self._inspect_expr(item.context_expr, environment, available, state, provider, depth)
                self._execute_block(stmt.body, environment.copy(), available, state, credential, origin, provider, depth)
            elif isinstance(stmt, ast.Try):
                for branch in [stmt.body, *(h.body for h in stmt.handlers), stmt.orelse, stmt.finalbody]:
                    self._execute_block(branch, environment.copy(), available, state, credential, origin, provider, depth)

    def _inspect_expr(
        self,
        expr: ast.AST,
        environment: dict[str, bool],
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        state: _FlowState,
        provider: str | None,
        depth: int,
    ) -> None:
        if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
            if environment.get(expr.id, False):
                state.used = True
            return
        if isinstance(expr, ast.Lambda):
            return
        if isinstance(expr, ast.Call):
            call_name = self._call_name(expr.func)
            if provider == "stripe":
                if state.bound and call_name in self.STRIPE_FINANCIAL_CALLS:
                    state.financial_action = True
            elif self._is_authentication_call(expr, environment, provider):
                state.bound = True

            if isinstance(expr.func, ast.Name) and expr.func.id in functions:
                function = functions[expr.func.id]
                parameters = [
                    *function.args.posonlyargs,
                    *function.args.args,
                ]
                local_env = environment.copy()  # lexical/global references
                for param in parameters:
                    local_env[param.arg] = False  # shadow captured names
                for index, value in enumerate(expr.args):
                    if index < len(parameters):
                        local_env[parameters[index].arg] = self._is_tainted(value, environment)
                for kw in expr.keywords:
                    if kw.arg in {p.arg for p in parameters}:
                        local_env[kw.arg] = self._is_tainted(kw.value, environment)
                key = (function.name, function.lineno)
                if depth < self.MAX_FUNCTION_DEPTH and key not in state.active_calls:
                    state.active_calls.add(key)
                    try:
                        self._execute_block(
                            function.body, local_env, functions, state,
                            "", "", provider, depth + 1,
                        )
                    finally:
                        state.active_calls.remove(key)

            for argument in expr.args:
                self._inspect_expr(argument, environment, functions, state, provider, depth)
            for keyword in expr.keywords:
                self._inspect_expr(keyword.value, environment, functions, state, provider, depth)
            return
        for child in ast.iter_child_nodes(expr):
            self._inspect_expr(child, environment, functions, state, provider, depth)

    def _is_authentication_call(
        self, node: ast.Call, env: dict[str, bool], provider: str | None
    ) -> bool:
        call = self._call_name(node.func)
        if provider == "openai":
            names, keywords, positional = self.OPENAI_CLIENT_CALLS, {"api_key"}, False
        elif provider == "github":
            names, keywords, positional = self.GITHUB_CLIENT_CALLS, {"login_or_token", "token", "auth"}, True
        elif provider == "aws":
            names, keywords, positional = self.AWS_CLIENT_CALLS, {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}, False
        else:
            return False
        if call not in names:
            return False
        return any(k.arg in keywords and self._is_tainted(k.value, env) for k in node.keywords) or (
            positional and any(self._is_tainted(a, env) for a in node.args)
        )

    @staticmethod
    def _is_tainted(node: ast.AST, env: dict[str, bool]) -> bool:
        return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and env.get(node.id, False)

    def _find_credential_variables(self, tree: ast.AST) -> tuple[tuple[str, str], ...]:
        results: set[tuple[str, str]] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                credential = self._credential_from_call(node.value)
                if credential:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            results.add((credential, target.id))
            elif isinstance(node, ast.AnnAssign):
                credential = self._credential_from_call(node.value)
                if credential and isinstance(node.target, ast.Name):
                    results.add((credential, node.target.id))
        return tuple(sorted(results))

    def _credential_from_call(self, node: ast.AST | None) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        if self._call_name(node.func) not in {"os.getenv", "getenv", "os.environ.get"}:
            return None
        if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            return None
        name = node.args[0].value
        return name if name in self.SUPPORTED_CREDENTIALS else None

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = CredentialFlowAnalyzer._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _provider_for_credential(credential: str) -> str | None:
        return {
            "OPENAI_API_KEY": "openai", "ANTHROPIC_API_KEY": "anthropic",
            "STRIPE_SECRET_KEY": "stripe", "STRIPE_API_KEY": "stripe",
            "GITHUB_TOKEN": "github", "GH_TOKEN": "github",
            "AWS_ACCESS_KEY_ID": "aws", "AWS_SECRET_ACCESS_KEY": "aws",
            "GOOGLE_APPLICATION_CREDENTIALS": "google",
            "AZURE_CLIENT_SECRET": "azure",
        }.get(credential)
