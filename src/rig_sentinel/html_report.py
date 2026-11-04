
from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Mapping


class HTMLReportGenerator:
    """
    RIG Sentinel - HTML Security Report v1.

    Generates a standalone, offline HTML report from
    the JSON-compatible scanner report.

    Security:
    - Escapes untrusted repository-derived content.
    - Does not execute JavaScript.
    - Does not load external CSS or resources.
    - Does not enforce security policies.
    """

    def generate(self, report: Mapping[str, Any]) -> str:
        agents = report.get("agents", [])
        exposure = report.get("exposure", {})
        policies = report.get("security_policies", [])
        credential_flows = report.get("credential_flows", [])
        risk_findings = report.get(
            "risk_propagation_findings", []
        )

        if not isinstance(exposure, dict):
            exposure = {}

        exposure_agents = exposure.get("agents", [])

        styles = """
        :root {
            color-scheme: dark;
            font-family: Inter, Segoe UI, Arial, sans-serif;
            background: #0b1220;
            color: #e5edf7;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            background: #0b1220;
            color: #e5edf7;
            line-height: 1.55;
        }

        .container {
            max-width: 1200px;
            margin: auto;
            padding: 36px 24px 70px;
        }

        header {
            padding: 28px;
            border: 1px solid #263449;
            border-radius: 16px;
            background: #101b2d;
            margin-bottom: 24px;
        }

        h1 { margin: 0 0 8px; font-size: 30px; }
        h2 { margin: 0 0 18px; font-size: 21px; }
        h3 { margin: 0 0 10px; font-size: 17px; }

        p { margin: 6px 0 12px; }
        .muted { color: #a5b4c7; }
        .small { font-size: 13px; }
        .break { overflow-wrap: anywhere; }

        .grid {
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat, .card, section {
            background: #101b2d;
            border: 1px solid #263449;
            border-radius: 14px;
        }

        .stat {
            padding: 20px;
        }

        .stat .number {
            font-size: 30px;
            font-weight: 750;
            margin-bottom: 4px;
        }

        .stat .label {
            color: #a5b4c7;
            font-size: 13px;
        }

        section {
            padding: 24px;
            margin-bottom: 22px;
        }

        .card {
            padding: 18px;
            margin-bottom: 14px;
        }

        .heading {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            background: #263449;
            color: #dce8f8;
            font-weight: 650;
            font-size: 12px;
        }

        .critical { background: #71333a; color: #ffe1e1; }
        .high { background: #70472c; color: #ffe4cc; }
        .medium { background: #665723; color: #fff0b5; }
        .low { background: #204d40; color: #d2ffeb; }

        .meter {
            background: #28364b;
            height: 9px;
            border-radius: 8px;
            overflow: hidden;
            margin-top: 12px;
        }

        .meter-fill {
            background: #e47968;
            height: 100%;
        }

        ul { padding-left: 22px; }
        li { margin: 5px 0; overflow-wrap: anywhere; }

        .path {
            background: #0b1220;
            border: 1px solid #27384d;
            border-radius: 8px;
            padding: 12px;
            margin: 8px 0;
            overflow-wrap: anywhere;
        }

        .notice {
            padding: 14px;
            border-left: 4px solid #e6b15a;
            background: #293022;
            border-radius: 6px;
            margin-top: 15px;
        }

        footer {
            color: #a5b4c7;
            font-size: 13px;
            padding-top: 10px;
        }

        @media print {
            :root { color-scheme: light; }
            body { background: white; color: #111827; }
            header, section, .card, .stat {
                background: white;
                color: #111827;
                border-color: #cbd5e1;
            }
            .muted, .stat .label { color: #475569; }
            .path { background: #f1f5f9; color: #111827; }
            .notice { background: #fff8e8; color: #111827; }
            .badge { color: #111827; background: #e2e8f0; }
        }
        """

        body = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; style-src \'unsafe-inline\';">',
            "<title>RIG Sentinel - Security Report</title>",
            f"<style>{styles}</style>",
            "</head>",
            "<body>",
            '<main class="container">',
            "<header>",
            "<h1>RIG Sentinel</h1>",
            "<p>Agent Exposure Management | Security Report</p>",
            '<p class="muted break">Repository: '
            f"{self._safe(report.get('root', 'Unknown'))}</p>",
            '<p class="muted small">Static analysis report. '
            "Findings require human validation.</p>",
            "</header>",
            '<div class="grid">',
            self._stat("AI Agents", len(agents)),
            self._stat(
                "Attack Paths",
                sum(
                    int(item.get("attack_paths", 0))
                    for item in exposure_agents
                ),
            ),
            self._stat("Advisory Policies", len(policies)),
            self._stat(
                "Max Blast Radius",
                f"{exposure.get('max_blast_radius', 0)}/100",
            ),
            "</div>",
            "<section>",
            "<h2>Agent Exposure</h2>",
        ]

        if not exposure_agents:
            body.append(
                '<p class="muted">No agent exposure results.</p>'
            )

        for agent in exposure_agents:
            severity = self._safe(agent.get("severity", "LOW"))
            severity_class = self._severity_class(
                agent.get("severity", "LOW")
            )
            score = self._score(
                agent.get("blast_radius_score", 0)
            )

            body.extend([
                '<article class="card">',
                '<div class="heading">',
                f"<h3>{self._safe(agent.get('agent', 'Unknown'))}</h3>",
                f'<span class="badge {severity_class}">'
                f"{severity}</span>",
                "</div>",
                f"<p>Blast Radius: <strong>{score}/100</strong></p>",
                '<div class="meter"><div class="meter-fill" '
                f'style="width: {score}%"></div></div>',
                "<p>Reachable resources:</p>",
                self._items(agent.get("reachable_resources", [])),
                "<p>Attack paths:</p>",
            ])

            paths = agent.get("attack_path_details", [])
            if not paths:
                body.append(
                    '<p class="muted">None detected.</p>'
                )

            for path in paths:
                nodes = path.get("nodes", [])
                chain = " → ".join(
                    self._safe(node) for node in nodes
                )
                body.append(
                    '<div class="path">'
                    f"<strong>{self._safe(path.get('risk', 'UNKNOWN'))}"
                    f"</strong>: {chain}</div>"
                )

            body.append("</article>")

        body.extend([
            "</section>",
            "<section>",
            "<h2>Security Policies (Advisory)</h2>",
        ])

        if not policies:
            body.append(
                '<p class="muted">No advisory policies generated.</p>'
            )

        for policy in policies:
            severity = policy.get("severity", "LOW")
            body.extend([
                '<article class="card">',
                '<div class="heading">',
                f"<h3>{self._safe(policy.get('agent', 'Unknown'))}</h3>",
                f'<span class="badge {self._severity_class(severity)}">'
                f"{self._safe(severity)}</span>",
                "</div>",
                "<p>Identity: "
                f"<strong>{self._safe(policy.get('identity', '-'))}</strong></p>",
                "<p>Proposed controls:</p>",
                self._items(policy.get("controls", [])),
                "<p>Reasons:</p>",
                self._items(policy.get("reasons", [])),
                "</article>",
            ])

        body.extend([
            '<div class="notice">'
            "<strong>Advisory only.</strong> "
            "No credentials or runtime permissions are modified. "
            "Shared identity references do not prove that underlying "
            "secrets are identical.</div>",
            "</section>",
            "<section>",
            "<h2>Credential Flows</h2>",
        ])

        if not credential_flows:
            body.append(
                '<p class="muted">No credential flows detected.</p>'
            )

        for flow in credential_flows:
            body.extend([
                '<article class="card">',
                "<h3>"
                f"{self._safe(flow.get('credential', 'Unknown'))}"
                "</h3>",
                f"<p>Provider: {self._safe(flow.get('provider', '-'))}</p>",
                "<p>Capability: "
                f"{self._safe(flow.get('capability') or 'unproven')}</p>",
                "<p>Confidence: "
                f"{self._safe(flow.get('confidence', '-'))}</p>",
                '<p class="muted small break">'
                f"{self._safe(flow.get('evidence', ''))}</p>",
                "</article>",
            ])

        body.extend([
            "</section>",
            "<section>",
            "<h2>Risk Propagation</h2>",
        ])

        if not risk_findings:
            body.append(
                '<p class="muted">No shared-identity relationships '
                "reported.</p>"
            )

        for finding in risk_findings:
            body.extend([
                '<article class="card">',
                "<h3>"
                f"{self._safe(finding.get('source_agent', '-'))}"
                " → "
                f"{self._safe(finding.get('related_agent', '-'))}"
                "</h3>",
                "<p>Identity reference: "
                f"{self._safe(finding.get('shared_identity', '-'))}</p>",
                "<p>Classification: "
                f"{self._safe(finding.get('classification', '-'))}</p>",
                "<p>Confirmed lateral movement: "
                f"{'Yes' if finding.get('confirmed_lateral_movement') is True else 'No'}"
                "</p>",
                "</article>",
            ])

        body.extend([
            "</section>",
            "<footer>",
            "RIG Sentinel | Offline HTML Security Report v1",
            "<p>Static findings are not proof of exploitation "
            "or effective runtime privileges.</p>",
            "</footer>",
            "</main>",
            "</body>",
            "</html>",
        ])

        return "\n".join(body)

    def write(
        self,
        report: Mapping[str, Any],
        destination: str | Path,
    ) -> Path:
        target = Path(destination).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            self.generate(report),
            encoding="utf-8",
        )
        return target

    @staticmethod
    def _safe(value: Any) -> str:
        if value is None:
            return "-"
        return escape(str(value), quote=True)

    @staticmethod
    def _stat(label: str, value: Any) -> str:
        return (
            '<div class="stat">'
            f'<div class="number">{escape(str(value), quote=True)}</div>'
            f'<div class="label">{escape(label, quote=True)}</div>'
            "</div>"
        )

    @classmethod
    def _items(cls, values: Any) -> str:
        if not values:
            return '<p class="muted">None.</p>'
        return "<ul>" + "".join(
            f"<li>{cls._safe(value)}</li>"
            for value in values
        ) + "</ul>"

    @staticmethod
    def _severity_class(value: Any) -> str:
        severity = str(value).upper()
        return {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }.get(severity, "")

    @staticmethod
    def _score(value: Any) -> int:
        try:
            return max(0, min(100, int(value)))
        except (TypeError, ValueError, OverflowError):
            return 0
