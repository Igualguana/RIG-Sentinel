
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SecurityPolicy:
    agent: str
    identity: str
    severity: str
    enforcement: str
    controls: tuple[str, ...]
    reasons: tuple[str, ...]


class PolicyGenerator:
    """
    RIG Sentinel - Policy Generator v1.

    Creates advisory security policies from scanner findings.

    This module does not:
    - Modify credentials.
    - Change permissions.
    - Block API calls.
    - Enforce policies at runtime.
    """

    SEVERITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    CAPABILITY_CONTROLS = {
        "financial_action": (
            "restrict_financial_operations",
            "require_human_approval",
            "use_restricted_credential",
        ),
        "shell": (
            "restrict_shell_execution",
            "isolate_execution_environment",
            "allowlist_commands",
        ),
        "email_send": (
            "restrict_external_recipients",
            "require_approval_for_sensitive_messages",
        ),
        "http_request": (
            "restrict_outbound_destinations",
            "allowlist_api_domains",
        ),
        "repository_access": (
            "restrict_repository_permissions",
            "use_scoped_repository_token",
        ),
        "cloud_access": (
            "restrict_cloud_permissions",
            "use_workload_identity",
        ),
    }

    def generate(
        self,
        report: Any,
    ) -> tuple[SecurityPolicy, ...]:
        """
        Generate policies from privilege findings and
        potentially shared credential references.
        """

        policies: dict[
            tuple[str, str],
            dict[str, Any],
        ] = {}

        for finding in report.privilege_findings:
            key = (
                finding.agent,
                finding.identity,
            )

            entry = self._get_or_create(
                policies,
                key,
            )

            entry["severity"] = self._highest_severity(
                entry["severity"],
                finding.severity,
            )

            controls = self.CAPABILITY_CONTROLS.get(
                finding.capability,
                ("review_excessive_permissions",),
            )

            entry["controls"].update(controls)
            entry["reasons"].add(finding.reason)

        for finding in report.shared_credential_findings:
            for agent in finding.agents:
                key = (
                    agent,
                    finding.identity,
                )

                entry = self._get_or_create(
                    policies,
                    key,
                )

                entry["severity"] = self._highest_severity(
                    entry["severity"],
                    # This source establishes shared identity *references*,
                    # not reuse of the same secret. Cap it independently
                    # of potentially stale upstream severity values.
                    self._reference_only_severity(finding.severity),
                )

                entry["controls"].update(
                    {
                        "verify_shared_credential",
                        "isolate_runtime_identity",
                        "apply_least_privilege",
                    }
                )

                entry["reasons"].add(
                    "Multiple agents reference this "
                    "credential identity. Verify whether "
                    "the underlying secret is actually shared."
                )

        results: list[SecurityPolicy] = []

        for (agent, identity), entry in sorted(
            policies.items()
        ):
            results.append(
                SecurityPolicy(
                    agent=agent,
                    identity=identity,
                    severity=entry["severity"],
                    enforcement="advisory",
                    controls=tuple(
                        sorted(entry["controls"])
                    ),
                    reasons=tuple(
                        sorted(entry["reasons"])
                    ),
                )
            )

        return tuple(results)

    def to_dict(
        self,
        policies: tuple[SecurityPolicy, ...],
    ) -> dict[str, Any]:
        """
        Convert generated policies into a JSON-compatible
        dictionary.
        """

        return {
            "product": "RIG Sentinel",
            "policy_version": "1.0",
            "enforcement": "advisory",
            "policy_count": len(policies),
            "policies": [
                asdict(policy)
                for policy in policies
            ],
        }

    @classmethod
    def _reference_only_severity(cls, incoming: str) -> str:
        # Shared-reference findings alone cannot justify HIGH/CRITICAL.
        if cls.SEVERITY_ORDER.get(incoming, 0) > cls.SEVERITY_ORDER["MEDIUM"]:
            return "MEDIUM"
        return incoming

    @staticmethod
    def _get_or_create(
        policies: dict,
        key: tuple[str, str],
    ) -> dict[str, Any]:
        if key not in policies:
            policies[key] = {
                "severity": "LOW",
                "controls": set(),
                "reasons": set(),
            }

        return policies[key]

    def _highest_severity(
        self,
        current: str,
        incoming: str,
    ) -> str:
        current_rank = self.SEVERITY_ORDER.get(
            current,
            0,
        )

        incoming_rank = self.SEVERITY_ORDER.get(
            incoming,
            0,
        )

        if incoming_rank > current_rank:
            return incoming

        return current
