from __future__ import annotations

import json
import sys
from pathlib import Path

from rig_sentinel.scanner import RepositoryScanner


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


def print_report(report) -> None:
    print("RIG SENTINEL — Agent Exposure Management")
    print("=" * 52)
    print(f"Repository:       {report.root}")
    print(f"Files scanned:    {report.files_scanned}")
    print()

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

            print("RECOMMENDED REMEDIATION")
            print("-" * 52)

            if not exposure.recommendations:
                print("No remediation recommendations")
            else:
                for recommendation in exposure.recommendations:
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
    print("SUMMARY")
    print("-" * 52)
    print(f"Providers:        {report.provider_count}")
    print(f"MCP findings:     {report.mcp_count}")
    print(f"Tools:            {report.tool_count}")
    print(f"Agents:           {report.agent_count}")


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] not in {
        "scan",
        "--help",
        "-h",
    }:
        print(
            "Usage: rig-sentinel scan "
            "<path> [--json]"
        )
        raise SystemExit(2)

    if args[0] in {
        "--help",
        "-h",
    }:
        print(
            "Usage: rig-sentinel scan "
            "<path> [--json]"
        )
        return

    target = Path(
        args[1]
        if len(args) > 1
        and not args[1].startswith("--")
        else "."
    )

    scanner = RepositoryScanner(target)
    report = scanner.scan()

    if "--json" in args:
        print(
            json.dumps(
                report_to_dict(report),
                indent=2,
            )
        )
    else:
        print_report(report)


if __name__ == "__main__":
    main()