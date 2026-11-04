
from __future__ import annotations

import json
import sys
from pathlib import Path

from rig_sentinel.html_report import HTMLReportGenerator
from rig_sentinel.scanner import RepositoryScanner
from rig_sentinel.sarif_report import SARIFReportGenerator


# ============================================================
# JSON REPORT
# ============================================================

def report_to_dict(report) -> dict:
    return {
        "product": "RIG Sentinel",
        "version": "0.1.0",
        "root": report.root,
        "files_scanned": report.files_scanned,

        "providers": [
            {
                "provider": item.provider,
                "confidence": item.confidence,
                "file": item.file,
                "evidence": item.evidence,
            }
            for item in report.providers
        ],

        "mcp_findings": [
            {
                "kind": item.kind,
                "confidence": item.confidence,
                "file": item.file,
                "evidence": item.evidence,
            }
            for item in report.mcp_findings
        ],

        "tools": [
            {
                "name": item.name,
                "category": item.category,
                "confidence": item.confidence,
                "file": item.file,
                "evidence": item.evidence,
            }
            for item in report.tools
        ],

        "identities": [
            {
                "name": item.name,
                "identity_type": item.identity_type,
                "provider": item.provider,
                "confidence": item.confidence,
                "file": item.file,
                "evidence": item.evidence,
            }
            for item in report.identities
        ],

        "identity_links": [
            {
                "agent": link.agent,
                "identity": link.identity,
                "identity_type": link.identity_type,
                "provider": link.provider,
                "file": link.file,
                "confidence": link.confidence,
            }
            for link in report.identity_links
        ],

        "credential_flows": [
            {
                "credential": flow.credential,
                "variable": flow.variable,
                "provider": flow.provider,
                "capability": flow.capability,
                "file": flow.file,
                "confidence": flow.confidence,
                "evidence": flow.evidence,
            }
            for flow in report.credential_flows
        ],

        "privilege_findings": [
            {
                "agent": finding.agent,
                "identity": finding.identity,
                "capability": finding.capability,
                "severity": finding.severity,
                "reason": finding.reason,
                "recommendation": finding.recommendation,
            }
            for finding in report.privilege_findings
        ],

        "least_privilege_findings": [
            {
                "identity": finding.identity,
                "provider": finding.provider,
                "observed_capability": finding.observed_capability,
                "severity": finding.severity,
                "recommended_scope": finding.recommended_scope,
                "avoid_permissions": list(
                    finding.avoid_permissions
                ),
                "recommendation": finding.recommendation,
            }
            for finding in report.least_privilege_findings
        ],

        "shared_credential_findings": [
            {
                "identity": finding.identity,
                "agents": list(finding.agents),
                "usage_count": finding.usage_count,
                "severity": finding.severity,
                "reason": finding.reason,
                "recommendation": finding.recommendation,
            }
            for finding in report.shared_credential_findings
        ],

        "shadow_agent_findings": [
            {
                "agent": finding.agent,
                "file": finding.file,
                "provider": finding.provider,
                "severity": finding.severity,
                "sensitive_capabilities": list(
                    finding.sensitive_capabilities
                ),
                "reason": finding.reason,
                "recommendation": finding.recommendation,
            }
            for finding in report.shadow_agent_findings
        ],

        "multi_agent_graph": {
            "node_count": report.multi_agent_node_count,
            "edge_count": report.multi_agent_edge_count,
            "shared_identity_count": (
                report.shared_identity_relation_count
            ),
            "nodes": [
                {
                    "id": node.id,
                    "kind": node.kind,
                    "label": node.label,
                }
                for node in report.multi_agent_graph.nodes
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                }
                for edge in report.multi_agent_graph.edges
            ],
            "shared_identities": [
                {
                    "identity": relation.identity,
                    "agents": list(relation.agents),
                    "agent_count": relation.agent_count,
                }
                for relation in (
                    report.multi_agent_graph.shared_identities
                )
            ],
        },

        "risk_propagation_findings": [
            {
                "source_agent": finding.source_agent,
                "related_agent": finding.related_agent,
                "shared_identity": finding.shared_identity,
                "classification": finding.classification,
                "confirmed_lateral_movement": (
                    finding.confirmed_lateral_movement
                ),
                "recommendation": finding.recommendation,
            }
            for finding in report.risk_propagation_findings
        ],

        "security_policies": [
            {
                "agent": policy.agent,
                "identity": policy.identity,
                "severity": policy.severity,
                "enforcement": policy.enforcement,
                "controls": list(policy.controls),
                "reasons": list(policy.reasons),
            }
            for policy in report.security_policies
        ],
        "policy_count": report.policy_count,

        "agents": [
            {
                "name": item.name,
                "file": item.file,
                "provider": item.provider,
                "has_mcp": item.has_mcp,
                "tools": list(item.tools),
                "confidence": item.confidence,
            }
            for item in report.agents
        ],

        "exposure": {
            "agent_count": report.exposure.agent_count,
            "critical_agents": report.exposure.critical_agents,
            "high_agents": report.exposure.high_agents,
            "medium_agents": report.exposure.medium_agents,
            "low_agents": report.exposure.low_agents,
            "max_blast_radius": report.exposure.max_blast_radius,
            "agents": [
                {
                    "agent": exposure.agent,
                    "reachable_resources": list(
                        exposure.reachable_resources
                    ),
                    "attack_paths": exposure.attack_paths,
                    "attack_path_details": [
                        {
                            "source": path.source,
                            "target": path.target,
                            "risk": path.risk,
                            "nodes": list(path.nodes),
                        }
                        for path in exposure.attack_path_details
                    ],
                    "critical_paths": exposure.critical_paths,
                    "high_paths": exposure.high_paths,
                    "medium_paths": exposure.medium_paths,
                    "blast_radius_score": (
                        exposure.blast_radius_score
                    ),
                    "severity": exposure.severity,
                    "recommendations": [
                        {
                            "tool": recommendation.tool,
                            "priority": recommendation.priority,
                            "title": recommendation.title,
                            "recommendation": (
                                recommendation.recommendation
                            ),
                            "expected_risk_reduction": (
                                recommendation.expected_risk_reduction
                            ),
                        }
                        for recommendation
                        in exposure.recommendations
                    ],
                }
                for exposure in report.exposure.exposures
            ],
        },
    }


# ============================================================
# TERMINAL REPORT
# ============================================================

def print_report(report) -> None:
    print("RIG SENTINEL — Agent Exposure Management")
    print("=" * 52)
    print(f"Repository:       {report.root}")
    print(f"Files scanned:    {report.files_scanned}")
    print()

    # --------------------------------------------------------
    # AI PROVIDERS
    # --------------------------------------------------------

    print("AI PROVIDERS")
    print("-" * 52)

    if not report.providers:
        print("None detected")
    else:
        for finding in report.providers:
            print(
                f"{finding.provider.upper():12} "
                f"{finding.confidence:8} "
                f"{finding.file}"
            )

    print()

    # --------------------------------------------------------
    # MCP
    # --------------------------------------------------------

    print("MCP")
    print("-" * 52)

    if not report.mcp_findings:
        print("None detected")
    else:
        for finding in report.mcp_findings:
            print(
                f"{finding.kind:18} "
                f"{finding.confidence:8} "
                f"{finding.file}"
            )

    print()

    # --------------------------------------------------------
    # TOOLS / CAPABILITIES
    # --------------------------------------------------------

    print("TOOLS / CAPABILITIES")
    print("-" * 52)

    if not report.tools:
        print("None detected")
    else:
        for finding in report.tools:
            print(
                f"{finding.name:20} "
                f"{finding.category:15} "
                f"{finding.file}"
            )

    print()

    # --------------------------------------------------------
    # IDENTITIES
    # --------------------------------------------------------

    print("IDENTITIES / CREDENTIAL REFERENCES")
    print("-" * 52)

    if not report.identities:
        print("None detected")
    else:
        for identity in report.identities:
            provider = identity.provider or "-"

            print(
                f"{identity.name:28} "
                f"{identity.identity_type:20} "
                f"{provider:12} "
                f"{identity.confidence}"
            )

    print()

    # --------------------------------------------------------
    # AGENT IDENTITIES
    # --------------------------------------------------------

    print("AGENT IDENTITIES")
    print("-" * 52)

    if not report.identity_links:
        print("No agent identity links detected")
    else:
        agents_with_links = sorted(
            {
                link.agent
                for link in report.identity_links
            }
        )

        for agent_name in agents_with_links:
            print(f"Agent: {agent_name}")

            links = [
                link
                for link in report.identity_links
                if link.agent == agent_name
            ]

            for link in sorted(
                links,
                key=lambda item: item.identity,
            ):
                provider = link.provider or "-"

                print(f"  -> {link.identity}")
                print(f"     Type: {link.identity_type}")
                print(f"     Provider: {provider}")
                print(
                    f"     Link confidence: "
                    f"{link.confidence}"
                )

            print()

    # --------------------------------------------------------
    # CREDENTIAL FLOWS
    # --------------------------------------------------------

    print("CREDENTIAL FLOWS")
    print("-" * 52)

    if not report.credential_flows:
        print("No credential flows detected")
    else:
        for flow in report.credential_flows:
            provider = flow.provider or "-"
            capability = flow.capability or "unproven"

            print(f"Credential:  {flow.credential}")
            print(f"Variable:    {flow.variable}")
            print(f"Provider:    {provider}")
            print(f"Capability:  {capability}")
            print(f"Confidence:  {flow.confidence}")
            print(f"Evidence:    {flow.evidence}")
            print()

    # --------------------------------------------------------
    # EXCESSIVE PRIVILEGE
    # --------------------------------------------------------

    print("EXCESSIVE PRIVILEGE")
    print("-" * 52)

    if not report.privilege_findings:
        print("No excessive privilege findings detected")
    else:
        for finding in sorted(
            report.privilege_findings,
            key=_privilege_sort_key,
        ):
            print(f"[{finding.severity}]")
            print(f"Agent:      {finding.agent}")
            print(f"Identity:   {finding.identity}")
            print(f"Capability: {finding.capability}")
            print(f"Reason:     {finding.reason}")
            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )
            print()

    # --------------------------------------------------------
    # LEAST PRIVILEGE
    # --------------------------------------------------------

    print("LEAST PRIVILEGE")
    print("-" * 52)

    if not report.least_privilege_findings:
        print("No least-privilege findings detected")
    else:
        for finding in sorted(
            report.least_privilege_findings,
            key=_least_privilege_sort_key,
        ):
            provider = finding.provider or "-"

            print(f"[{finding.severity}]")
            print(f"Identity: {finding.identity}")
            print(f"Provider: {provider}")
            print(
                f"Observed capability: "
                f"{finding.observed_capability}"
            )
            print(
                f"Recommended scope: "
                f"{finding.recommended_scope}"
            )

            if finding.avoid_permissions:
                print("Avoid:")

                for permission in finding.avoid_permissions:
                    print(f"  - {permission}")

            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )
            print()

    # --------------------------------------------------------
    # SHARED CREDENTIALS
    # --------------------------------------------------------

    print("SHARED CREDENTIALS")
    print("-" * 52)

    if not report.shared_credential_findings:
        print("No shared credentials detected")
    else:
        for finding in sorted(
            report.shared_credential_findings,
            key=_shared_credential_sort_key,
        ):
            print(f"[{finding.severity}]")
            print(f"Identity: {finding.identity}")
            print(f"Usage count: {finding.usage_count}")
            print("Used by:")

            for agent in finding.agents:
                print(f"  - {agent}")

            print(f"Reason: {finding.reason}")
            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )
            print()

    # --------------------------------------------------------
    # SHADOW AGENTS
    # --------------------------------------------------------

    print("SHADOW AGENTS")
    print("-" * 52)

    if not report.shadow_agent_findings:
        print("No shadow agents detected")
    else:
        for finding in sorted(
            report.shadow_agent_findings,
            key=_shadow_agent_sort_key,
        ):
            provider = finding.provider or "-"

            print(f"[{finding.severity}]")
            print(f"Agent:    {finding.agent}")
            print(f"File:     {finding.file}")
            print(f"Provider: {provider}")

            if finding.sensitive_capabilities:
                print("Sensitive capabilities:")

                for capability in finding.sensitive_capabilities:
                    print(f"  - {capability}")

            print(f"Reason: {finding.reason}")
            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )
            print()

    # --------------------------------------------------------
    # MULTI-AGENT GRAPH
    # --------------------------------------------------------

    print("MULTI-AGENT GRAPH")
    print("-" * 52)

    print(
        f"Nodes:              "
        f"{report.multi_agent_node_count}"
    )
    print(
        f"Edges:              "
        f"{report.multi_agent_edge_count}"
    )
    print(
        f"Shared identities:  "
        f"{report.shared_identity_relation_count}"
    )

    if not report.multi_agent_graph.shared_identities:
        print("No shared identity relationships detected")
    else:
        for relation in (
            report.multi_agent_graph.shared_identities
        ):
            print()
            print(f"Identity: {relation.identity}")
            print("Connected agents:")

            for agent in relation.agents:
                print(f"  - {agent}")

    print()

    # --------------------------------------------------------
    # RISK PROPAGATION ANALYSIS
    # --------------------------------------------------------

    print("RISK PROPAGATION")
    print("-" * 52)

    if not report.risk_propagation_findings:
        print("No shared exposure relationships detected")
    else:
        for finding in report.risk_propagation_findings:
            print(f"Classification: {finding.classification}")
            print(f"Source agent: {finding.source_agent}")
            print(f"Related agent: {finding.related_agent}")
            print(f"Shared identity: {finding.shared_identity}")
            print(
                f"Confirmed lateral movement: "
                f"{'Yes' if finding.confirmed_lateral_movement else 'No'}"
            )
            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )
            print()

    print()

    # --------------------------------------------------------
    # SECURITY POLICIES (ADVISORY)
    # --------------------------------------------------------

    print("SECURITY POLICIES (ADVISORY)")
    print("-" * 52)

    if not report.security_policies:
        print("No advisory identity policies generated")
    else:
        for policy in sorted(
            report.security_policies,
            key=lambda item: (
                _severity_rank(item.severity),
                item.agent,
                item.identity,
            ),
        ):
            print(f"[{policy.severity}] Agent: {policy.agent}")
            print(f"Identity:    {policy.identity}")
            print(f"Enforcement: {policy.enforcement}")
            print("Proposed controls:")
            for control in policy.controls:
                print(f"  - {control}")
            if policy.reasons:
                print("Reasons:")
                for reason in policy.reasons:
                    print(f"  - {reason}")
            print()

    print("Policies are recommendations only; no controls are enforced.")
    print()

    # --------------------------------------------------------
    # AGENTS
    # --------------------------------------------------------

    print("AGENTS")
    print("-" * 52)

    if not report.agents:
        print("None detected")
    else:
        for agent in report.agents:
            print(f"Agent:       {agent.name}")
            print(f"File:        {agent.file}")
            print(
                f"Provider:    "
                f"{agent.provider or 'Unknown'}"
            )
            print(
                f"MCP:         "
                f"{'Yes' if agent.has_mcp else 'No'}"
            )
            print(f"Confidence:  {agent.confidence}")

            if agent.tools:
                print("Tools:")

                for tool in agent.tools:
                    print(f"  - {tool}")

            print()

    # --------------------------------------------------------
    # EXPOSURE
    # --------------------------------------------------------

    print("EXPOSURE")
    print("-" * 52)

    if not report.exposure.exposures:
        print("No agent exposure detected")
    else:
        for exposure in report.exposure.exposures:
            print(f"Agent:               {exposure.agent}")
            print(
                f"Reachable resources: "
                f"{len(exposure.reachable_resources)}"
            )
            print(
                f"Attack paths:        "
                f"{exposure.attack_paths}"
            )
            print(
                f"Critical paths:      "
                f"{exposure.critical_paths}"
            )
            print(
                f"High paths:          "
                f"{exposure.high_paths}"
            )
            print(
                f"Medium paths:        "
                f"{exposure.medium_paths}"
            )
            print(
                f"Blast Radius:        "
                f"{exposure.blast_radius_score}/100"
            )
            print(
                f"Severity:            "
                f"{exposure.severity}"
            )

            if exposure.reachable_resources:
                print("Resources:")

                for resource in exposure.reachable_resources:
                    print(f"  - {resource}")

            print()

            print("ATTACK PATHS")
            print("-" * 52)

            if not exposure.attack_path_details:
                print("No actionable attack paths detected")
            else:
                for path in sorted(
                    exposure.attack_path_details,
                    key=_attack_path_sort_key,
                ):
                    print(f"[{path.risk}]")

                    for index, node in enumerate(path.nodes):
                        if index == 0:
                            print(node)
                        else:
                            print(f"  -> {node}")

                    print()

            print("RECOMMENDED REMEDIATION")
            print("-" * 52)

            if not exposure.recommendations:
                print("No remediation recommendations")
            else:
                for recommendation in sorted(
                    exposure.recommendations,
                    key=_remediation_sort_key,
                ):
                    print(
                        f"[{recommendation.priority}] "
                        f"{recommendation.title}"
                    )
                    print(
                        f"Tool: "
                        f"{recommendation.tool}"
                    )
                    print(
                        f"Expected risk reduction: "
                        f"{recommendation.expected_risk_reduction}"
                    )
                    print(
                        f"Recommendation: "
                        f"{recommendation.recommendation}"
                    )
                    print()

    # --------------------------------------------------------
    # EXPOSURE SUMMARY
    # --------------------------------------------------------

    print("EXPOSURE SUMMARY")
    print("-" * 52)

    print(
        f"Critical agents:  "
        f"{report.exposure.critical_agents}"
    )
    print(
        f"High agents:      "
        f"{report.exposure.high_agents}"
    )
    print(
        f"Medium agents:    "
        f"{report.exposure.medium_agents}"
    )
    print(
        f"Low agents:       "
        f"{report.exposure.low_agents}"
    )
    print(
        f"Max blast radius: "
        f"{report.exposure.max_blast_radius}/100"
    )

    print()

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("SUMMARY")
    print("-" * 52)

    print(f"Providers:               {report.provider_count}")
    print(f"MCP findings:            {report.mcp_count}")
    print(f"Tools:                   {report.tool_count}")
    print(f"Identities:              {report.identity_count}")
    print(f"Identity links:          {report.identity_link_count}")
    print(f"Credential flows:        {report.credential_flow_count}")

    print(
        f"Privilege findings:      "
        f"{report.privilege_finding_count}"
    )
    print(
        f"Least privilege findings: "
        f"{report.least_privilege_finding_count}"
    )
    print(
        f"Shared credentials:      "
        f"{report.shared_credential_finding_count}"
    )
    print(
        f"Shadow agents:           "
        f"{report.shadow_agent_finding_count}"
    )
    print(
        f"Graph nodes:             "
        f"{report.multi_agent_node_count}"
    )
    print(
        f"Graph edges:             "
        f"{report.multi_agent_edge_count}"
    )
    print(
        f"Shared identity relations: "
        f"{report.shared_identity_relation_count}"
    )
    print(
        f"Risk propagation findings: "
        f"{report.risk_propagation_finding_count}"
    )
    print(f"Advisory policies:       {report.policy_count}")
    print(f"Agents:                  {report.agent_count}")


# ============================================================
# SORTING HELPERS
# ============================================================

def _severity_rank(severity: str) -> int:
    priority = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    return priority.get(severity, 99)


def _attack_path_sort_key(path) -> tuple[int, str]:
    return (
        _severity_rank(path.risk),
        path.target,
    )


def _remediation_sort_key(recommendation) -> tuple[int, str]:
    return (
        _severity_rank(recommendation.priority),
        recommendation.title,
    )


def _privilege_sort_key(finding) -> tuple[int, str, str]:
    return (
        _severity_rank(finding.severity),
        finding.agent,
        finding.capability,
    )


def _least_privilege_sort_key(finding) -> tuple[int, str]:
    return (
        _severity_rank(finding.severity),
        finding.identity,
    )


def _shared_credential_sort_key(finding) -> tuple[int, str]:
    return (
        _severity_rank(finding.severity),
        finding.identity,
    )


def _shadow_agent_sort_key(finding) -> tuple[int, str]:
    return (
        _severity_rank(finding.severity),
        finding.agent,
    )


# ============================================================
# CLI ENTRY POINT
# ============================================================

def main() -> None:
    args = sys.argv[1:]
    usage = (
        "Usage: rig-sentinel scan <path> "
        "[--json | --html <output.html> | --sarif <output.sarif>]"
    )

    if args and args[0] in {"--help", "-h"}:
        print(usage)
        return
    if not args or args[0] != "scan":
        print(usage, file=sys.stderr)
        raise SystemExit(2)
    if "--help" in args or "-h" in args:
        print(usage)
        return

    requested_modes = [flag for flag in ("--json", "--html", "--sarif") if flag in args]
    if len(requested_modes) > 1:
        print("Error: select only one output format.", file=sys.stderr)
        raise SystemExit(2)

    output_html: Path | None = None
    output_sarif: Path | None = None
    positional: list[str] = []
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--json":
            index += 1
            continue
        if arg in {"--html", "--sarif"}:
            if index + 1 >= len(args) or args[index + 1].startswith("--"):
                print(f"Error: {arg} requires an output filename.", file=sys.stderr)
                raise SystemExit(2)
            if arg == "--html":
                output_html = Path(args[index + 1])
            else:
                output_sarif = Path(args[index + 1])
            index += 2
            continue
        if arg.startswith("--"):
            print(f"Error: unknown option {arg}", file=sys.stderr)
            raise SystemExit(2)
        positional.append(arg)
        index += 1

    if len(positional) > 1:
        print("Error: expected at most one repository path.", file=sys.stderr)
        raise SystemExit(2)

    target = Path(positional[0]) if positional else Path(".")
    report = RepositoryScanner(target).scan()
    payload = report_to_dict(report)

    if output_html is not None:
        destination = HTMLReportGenerator().write(payload, output_html)
        print(f"HTML report created: {destination}")
    elif output_sarif is not None:
        destination = SARIFReportGenerator().write(payload, output_sarif)
        print(f"SARIF report created: {destination}")
    elif "--json" in args:
        print(json.dumps(payload, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
