
from __future__ import annotations

import json
import sys
from pathlib import Path

from rig_sentinel.cli import main


def test_cli_generates_html_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    (repository / "agent.py").write_text(
        """
from openai import OpenAI

client = OpenAI()
""",
        encoding="utf-8",
    )

    destination = tmp_path / "reports" / "sentinel.html"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rig-sentinel",
            "scan",
            str(repository),
            "--html",
            str(destination),
        ],
    )

    main()

    assert destination.exists()

    html = destination.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in html
    assert "RIG Sentinel" in html
    assert "Agent Exposure" in html
    assert "Security Policies (Advisory)" in html


def test_cli_html_does_not_break_json(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rig-sentinel",
            "scan",
            str(tmp_path),
            "--json",
        ],
    )

    main()

    output = capsys.readouterr().out
    payload = json.loads(output)

    assert payload["product"] == "RIG Sentinel"
    assert "security_policies" in payload
    assert "policy_count" in payload
