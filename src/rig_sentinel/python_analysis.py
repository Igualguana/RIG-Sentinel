from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class PythonAnalysis:
    imports: tuple[str, ...]
    calls: tuple[str, ...]
    attributes: tuple[str, ...]


class PythonAnalyzer:
    def analyze(self, text: str) -> PythonAnalysis:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return PythonAnalysis(
                imports=(),
                calls=(),
                attributes=(),
            )

        imports: set[str] = set()
        calls: set[str] = set()
        attributes: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)

            elif isinstance(node, ast.Call):
                call_name = self._call_name(node.func)

                if call_name:
                    calls.add(call_name)

            elif isinstance(node, ast.Attribute):
                attr_name = self._attribute_name(node)

                if attr_name:
                    attributes.add(attr_name)

        return PythonAnalysis(
            imports=tuple(sorted(imports)),
            calls=tuple(sorted(calls)),
            attributes=tuple(sorted(attributes)),
        )

    def _call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            return self._attribute_name(node)

        return None

    def _attribute_name(self, node: ast.AST) -> str | None:
        parts: list[str] = []

        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        if not parts:
            return None

        return ".".join(reversed(parts))