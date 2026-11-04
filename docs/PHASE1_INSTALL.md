# Phase 1 quick start (release candidate)

## Windows PowerShell
```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e . pytest
python -m pytest -q
rig-sentinel scan .
rig-sentinel scan . --json
rig-sentinel scan . --html sentinel-report.html
rig-sentinel scan . --sarif sentinel-report.sarif
```

## Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e . pytest
python -m pytest -q
rig-sentinel scan . --sarif sentinel-report.sarif
```

SARIF output is a static-analysis indicator report, not confirmed exploitation. The CLI does not fail CI based on findings; choose and document a policy gate before adopting blocking use.
