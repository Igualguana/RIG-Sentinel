from pathlib import Path

from rig_sentinel.mcp import MCPDetector


def test_detects_mcp_json_config() -> None:
    detector = MCPDetector()

    findings = detector.detect(
        Path("mcp.json"),
        Path("mcp.json"),
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["server-filesystem"]
            }
          }
        }
        """,
    )

    assert any(
        finding.kind == "mcp_servers"
        and finding.confidence == "HIGH"
        for finding in findings
    )


def test_detects_python_mcp_import() -> None:
    detector = MCPDetector()

    findings = detector.detect(
        Path("server.py"),
        Path("server.py"),
        "from mcp import Server",
    )

    assert any(
        finding.kind == "mcp_runtime"
        and finding.confidence == "HIGH"
        for finding in findings
    )


def test_does_not_detect_plain_mcp_word() -> None:
    detector = MCPDetector()

    findings = detector.detect(
        Path("notes.txt"),
        Path("notes.txt"),
        "This document talks about MCP security.",
    )

    assert findings == []
def test_does_not_detect_mcp_rule_string_in_python() -> None:
    detector = MCPDetector()

    findings = detector.detect(
        Path("rules.py"),
        Path("rules.py"),
        '''
RULES = [
    "from mcp import",
    "mcp.server",
]
''',
    )

    assert findings == []


def test_does_not_detect_rig_sentinel_mcp_import() -> None:
    detector = MCPDetector()

    findings = detector.detect(
        Path("scanner.py"),
        Path("scanner.py"),
        "from rig_sentinel.mcp import MCPDetector",
    )

    assert findings == []