# CLI Reference

```text
Usage: rig-sentinel scan <path> [--json | --html <output.html> | --sarif <output.sarif>]
```

The console script `rig-sentinel` is installed by `pip` and maps to
`rig_sentinel.cli:main`. It can also be run as `python -m rig_sentinel.cli`.

## Commands

### `scan`

Statically scans a directory tree and reports findings.

| Argument / option | Description |
|---|---|
| `<path>` | Directory to scan. Optional; defaults to the current directory (`.`). Only one path is accepted. |
| `--json` | Print the full report as JSON to standard output. |
| `--html <file>` | Write a self-contained offline HTML report to `<file>`. Parent directories are created. |
| `--sarif <file>` | Write a SARIF 2.1.0 report to `<file>`. Parent directories are created. |
| `-h`, `--help` | Print usage and exit. |

Without an output option, a human-readable report is printed to the terminal.

Only **one** of `--json`, `--html`, `--sarif` can be used per run. To produce several
formats, run the command several times.

### Global options

| Option | Description |
|---|---|
| `-h`, `--help` | Print usage and exit with code `0`. |

There is no `--version` option in v0.1.0; the version is included in the JSON report
(`"version": "0.1.0"`) and available via `pip show rig-sentinel`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (findings do **not** change the exit code), or help was printed. |
| `1` | Unhandled error, e.g. the target path does not exist (a Python traceback is printed). |
| `2` | Usage error: missing `scan` command, unknown option, more than one output format, missing output filename, more than one path. |

Because findings never change the exit code, RIG Sentinel does not block CI pipelines on
its own. If you need gating, post-process the JSON report with your own policy.

## What is scanned

- Files with extensions `.py .js .ts .tsx .jsx .json .yaml .yml .toml .md .env .txt .ini .cfg .sh .ps1`,
  plus `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`, `.env.example`, `.env.sample`.
- Files up to **1 MB**.
- These directories are skipped anywhere in the tree: `.git`, `.venv`, `.venv-1`, `venv`,
  `node_modules`, `dist`, `build`, `__pycache__`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `.next`, `coverage`, `vendor`, `tests`, `test`, `__tests__`, `fixtures`,
  `examples`.

## Configuration file

If a file named `.rig-sentinel.toml` exists at the root of the scanned directory, it is
read for the approved agent inventory:

```toml
approved_agents = ["billing_agent", "support_agent"]
```

Agents found in the repository but not listed here are reported as **shadow agents**.
Invalid or unreadable configuration is ignored (the scan continues with an empty
inventory).

## Output formats

### Terminal

Sections, in order: AI providers, MCP, tools/capabilities, identities/credential
references, agent identities, credential flows, excessive privilege, least privilege,
shared credentials, shadow agents, multi-agent graph, risk propagation, security
policies (advisory), agents, exposure (per-agent attack paths, blast radius and
remediation), exposure summary and summary counts.

### JSON

Top-level keys:

```text
product, version, root, files_scanned, providers, mcp_findings, tools, identities,
identity_links, credential_flows, privilege_findings, least_privilege_findings,
shared_credential_findings, shadow_agent_findings, multi_agent_graph,
risk_propagation_findings, security_policies, policy_count, agents, exposure
```

`root` is the **absolute path** of the scanned directory. Review it before sharing.

### HTML

A single offline file with inline CSS, no JavaScript and no external resources. A
`Content-Security-Policy` of `default-src 'none'; style-src 'unsafe-inline'` is embedded
and all values are HTML-escaped.

### SARIF output

SARIF `2.1.0` with tool name `RIG Sentinel` and these rules:

| Rule | Short description |
|---|---|
| `RIG001` | Shadow agent |
| `RIG002` | Shared credential reference |
| `RIG003` | Excessive privilege |
| `RIG004` | Sensitive agent capability |

Each result carries `properties.classification = "static-indicator"` and the original
`properties.severity`. Severities map to SARIF levels (e.g. `CRITICAL` → `error`).

A `locations` entry is added only when the finding has a safe, relative, forward-slash
file path. On Windows (backslash paths) and for some finding types, results have **no
location**. GitHub code scanning expects locations, so uploading to code scanning is not
a verified integration in v0.1.0. See [LIMITATIONS.md](LIMITATIONS.md#sarif).

## Examples

```bash
rig-sentinel scan .
rig-sentinel scan ./services/agents --json > report.json
rig-sentinel scan . --html out/rig-sentinel.html
rig-sentinel scan . --sarif out/rig-sentinel.sarif
```
