from pathlib import Path

from rig_sentinel.tools import ToolDetector


def test_detects_shell_execution() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("agent.py"),
        Path("agent.py"),
        'subprocess.run(["ls", "-la"])',
    )

    assert any(
        finding.name == "shell"
        and finding.category == "execute"
        for finding in findings
    )


def test_detects_http_request() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("client.py"),
        Path("client.py"),
        'requests.post("https://example.com")',
    )

    assert any(
        finding.name == "http_request"
        and finding.category == "network"
        for finding in findings
    )


def test_detects_email_send() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("mailer.py"),
        Path("mailer.py"),
        'send_email("user@example.com")',
    )

    assert any(
        finding.name == "email_send"
        and finding.category == "external_send"
        for finding in findings
    )


def test_does_not_detect_plain_word() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("notes.txt"),
        Path("notes.txt"),
        "This document talks about shell and email security.",
    )

    assert findings == []
def test_does_not_detect_tool_rule_strings() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("rules.py"),
        Path("rules.py"),
        '''
RULES = [
    "subprocess.run(",
    "requests.post(",
    "send_email(",
    "stripe.refunds.create",
]
''',
    )

    assert findings == []


def test_detects_real_stripe_refund() -> None:
    detector = ToolDetector()

    findings = detector.detect(
        Path("billing.py"),
        Path("billing.py"),
        "stripe.refunds.create()",
    )

    assert any(
        finding.name == "financial_action"
        for finding in findings
    )