
from pathlib import Path

from rig_sentinel.html_report import HTMLReportGenerator


def sample_report():
    return {
        "root": "D:/project/RIG-Sentinel-Lab",
        "agents": [
            {"name": "finance_agent"},
        ],
        "exposure": {
            "max_blast_radius": 100,
            "agents": [
                {
                    "agent": "finance_agent",
                    "severity": "CRITICAL",
                    "blast_radius_score": 100,
                    "attack_paths": 1,
                    "reachable_resources": ["payments"],
                    "attack_path_details": [
                        {
                            "risk": "CRITICAL",
                            "nodes": [
                                "agent:finance_agent",
                                "tool:financial_action",
                                "resource:payments",
                            ],
                        },
                    ],
                },
            ],
        },
        "security_policies": [
            {
                "agent": "finance_agent",
                "identity": "STRIPE_SECRET_KEY",
                "severity": "CRITICAL",
                "enforcement": "advisory",
                "controls": [
                    "require_human_approval",
                    "restrict_financial_operations",
                ],
                "reasons": [
                    "Financial operation detected.",
                ],
            },
        ],
        "credential_flows": [
            {
                "credential": "STRIPE_SECRET_KEY",
                "provider": "stripe",
                "capability": "financial_action",
                "confidence": "HIGH",
                "evidence": "Authenticated Stripe binding detected.",
            },
        ],
        "risk_propagation_findings": [],
    }


def test_html_report_contains_security_summary():
    html = HTMLReportGenerator().generate(
        sample_report()
    )

    assert "<!DOCTYPE html>" in html
    assert "RIG Sentinel" in html
    assert "Agent Exposure" in html
    assert "100/100" in html
    assert "finance_agent" in html


def test_html_report_includes_advisory_policies():
    html = HTMLReportGenerator().generate(
        sample_report()
    )

    assert "Security Policies (Advisory)" in html
    assert "STRIPE_SECRET_KEY" in html
    assert "require_human_approval" in html
    assert "restrict_financial_operations" in html
    assert "No credentials or runtime permissions are modified" in html


def test_html_report_escapes_untrusted_content():
    report = sample_report()

    report["root"] = "<script>alert(1)</script>"
    report["security_policies"][0]["identity"] = (
        '<img src=x onerror="alert(1)">'
    )

    html = HTMLReportGenerator().generate(report)

    assert "<script>alert(1)</script>" not in html
    assert '<img src=x onerror="alert(1)">' not in html

    assert "&lt;script&gt;" in html
    assert "&lt;img" in html

    assert "Content-Security-Policy" in html


def test_html_report_writes_offline_file(
    tmp_path: Path,
):
    destination = tmp_path / "reports" / "sentinel.html"

    result = HTMLReportGenerator().write(
        sample_report(),
        destination,
    )

    assert result == destination
    assert destination.exists()

    html = destination.read_text(encoding="utf-8")

    assert "finance_agent" in html
    assert "Security Policies (Advisory)" in html


def test_html_report_handles_empty_findings():
    report = {
        "root": "empty-repository",
        "agents": [],
        "exposure": {
            "max_blast_radius": 0,
            "agents": [],
        },
        "security_policies": [],
        "credential_flows": [],
        "risk_propagation_findings": [],
    }

    html = HTMLReportGenerator().generate(report)

    assert "No agent exposure results" in html
    assert "No advisory policies generated" in html
    assert "No credential flows detected" in html
