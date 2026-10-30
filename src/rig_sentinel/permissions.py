from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.models import Permission, Resource, Tool


@dataclass(frozen=True)
class PermissionInferenceResult:
    tool: Tool
    resources: tuple[Resource, ...]


class PermissionInferenceEngine:
    def infer(self, tool_name: str) -> PermissionInferenceResult | None:
        mappings = {
            "shell": {
                "tool_category": "execute",
                "permission": Permission(
                    name="system.execute",
                    action="execute",
                    resource="host_system",
                    risk="CRITICAL",
                ),
                "resource": Resource(
                    name="host_system",
                    resource_type="system",
                    sensitivity="CRITICAL",
                ),
            },
            "http_request": {
                "tool_category": "network",
                "permission": Permission(
                    name="network.external_request",
                    action="connect",
                    resource="external_network",
                    risk="MEDIUM",
                ),
                "resource": Resource(
                    name="external_network",
                    resource_type="network",
                    sensitivity="MEDIUM",
                ),
            },
            "email_send": {
                "tool_category": "external_send",
                "permission": Permission(
                    name="email.send_external",
                    action="send",
                    resource="external_email",
                    risk="HIGH",
                ),
                "resource": Resource(
                    name="external_email",
                    resource_type="communication",
                    sensitivity="HIGH",
                ),
            },
            "financial_action": {
                "tool_category": "financial",
                "permission": Permission(
                    name="payments.modify",
                    action="modify",
                    resource="payments",
                    risk="CRITICAL",
                ),
                "resource": Resource(
                    name="payments",
                    resource_type="financial",
                    sensitivity="CRITICAL",
                ),
            },
            "filesystem_write": {
                "tool_category": "write",
                "permission": Permission(
                    name="filesystem.write",
                    action="write",
                    resource="filesystem",
                    risk="HIGH",
                ),
                "resource": Resource(
                    name="filesystem",
                    resource_type="storage",
                    sensitivity="HIGH",
                ),
            },
            "filesystem_delete": {
                "tool_category": "delete",
                "permission": Permission(
                    name="filesystem.delete",
                    action="delete",
                    resource="filesystem",
                    risk="CRITICAL",
                ),
                "resource": Resource(
                    name="filesystem",
                    resource_type="storage",
                    sensitivity="HIGH",
                ),
            },
        }

        mapping = mappings.get(tool_name)

        if mapping is None:
            return None

        tool = Tool(
            name=tool_name,
            category=mapping["tool_category"],
            permissions=(
                mapping["permission"],
            ),
        )

        return PermissionInferenceResult(
            tool=tool,
            resources=(
                mapping["resource"],
            ),
        )

    def infer_many(
        self,
        tool_names: tuple[str, ...],
    ) -> tuple[PermissionInferenceResult, ...]:

        results: list[PermissionInferenceResult] = []

        for tool_name in tool_names:
            result = self.infer(tool_name)

            if result is not None:
                results.append(result)

        return tuple(results)