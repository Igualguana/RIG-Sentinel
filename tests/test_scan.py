from pathlib import Path

from rig_sentinel.scanner import RepositoryScanner


def test_scan_repository(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"

    source.write_text(
        """
from openai import OpenAI
import requests

client = OpenAI()

requests.post("https://example.com")
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(tmp_path)
    report = scanner.scan()

    assert report.files_scanned == 1

    assert any(
        finding.provider == "openai"
        for finding in report.providers
    )

    assert any(
        finding.name == "http_request"
        for finding in report.tools
    )