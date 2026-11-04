from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from rig_sentinel.cli import main
from rig_sentinel.sarif_report import SARIFReportGenerator


def test_sarif_structure_and_sanitized_locations():
    report = {
        "shadow_agent_findings": [{"agent": "extra", "file": "src/extra.py", "severity": "MEDIUM"}],
        "shared_credential_findings": [{"identity": "OPENAI_API_KEY", "agents": ["extra", "agent"], "severity": "HIGH"}],
        "privilege_findings": [],
        "tools": [{"name": "shell", "file": "../escape.py", "evidence": "SECRET=should-not-appear"}],
    }
    sarif = SARIFReportGenerator().generate(report)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/extra.py"
    assert "locations" not in results[2]
    assert "should-not-appear" not in json.dumps(sarif)


def test_sarif_empty_report():
    sarif = SARIFReportGenerator().generate({})
    assert sarif["runs"][0]["results"] == []


def test_cli_sarif_writes_file(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8")
    target = tmp_path / "reports" / "result.sarif"
    monkeypatch.setattr(sys, "argv", ["rig-sentinel", "scan", str(repo), "--sarif", str(target)])
    main()
    assert target.exists()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["runs"][0]["tool"]["driver"]["name"] == "RIG Sentinel"


def test_cli_rejects_conflicting_formats(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["rig-sentinel", "scan", str(tmp_path), "--json", "--sarif", "out.sarif"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_cli_rejects_missing_sarif_filename(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["rig-sentinel", "scan", str(tmp_path), "--sarif"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
