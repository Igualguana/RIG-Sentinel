# RIG Sentinel Community v0.1.0

**Release date:** 2026-11-04 · **License:** Apache License 2.0 · **Status:** first public release

RIG Sentinel is an open-source security scanner for AI agents, MCP servers, identities,
permissions, and exposure risks.

It statically scans a source repository to find AI agent candidates, MCP integrations,
sensitive capabilities and credential references, then models how they connect: possible
attack paths, an estimated blast radius per agent, and prioritized, advisory
remediation. It runs locally, has **no runtime dependencies**, and never executes the
code it scans.

## Features

| Area | What v0.1.0 provides |
|---|---|
| Discovery | OpenAI, Anthropic, LangChain and CrewAI usage; heuristic agent candidates; MCP configuration (`mcpServers`, `mcp.json`) and Python MCP SDK usage; shell, filesystem, HTTP and e-mail capabilities |
| Identities | Well-known credential references (names only — never values) and agent ↔ identity links |
| Analysis | Credential flow (Python, inter-procedural), excessive and least-privilege indicators, shared credential references, shadow agents against an approved inventory (`.rig-sentinel.toml`) |
| Exposure | Multi-agent identity graph, risk propagation, attack paths (agent → tool → permission → resource), 0–100 blast-radius estimate |
| Guidance | Prioritized remediation and advisory least-privilege policies |
| Reports | Terminal, JSON, offline HTML (CSP-hardened, no scripts) and SARIF 2.1.0 export |

All features are part of RIG Sentinel Community and free to use under Apache License 2.0.

## Installation

Requires **Python 3.11+** (validated with Python 3.13).

**From the release assets** (download the wheel attached to this release):

```bash
python -m pip install rig_sentinel-0.1.0-py3-none-any.whl
```

**Directly from the tag:**

```bash
python -m pip install "git+https://github.com/Igualguana/RIG-Sentinel.git@v0.1.0"
```

**Quick start:**

```bash
rig-sentinel scan path/to/repo
rig-sentinel scan path/to/repo --html rig-sentinel.html
rig-sentinel scan path/to/repo --sarif rig-sentinel.sarif
```

### Verify the download

`SHA256SUMS.txt` is attached to this release. Verify the files you downloaded:

```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

```powershell
# Windows PowerShell — compare with the value in SHA256SUMS.txt
Get-FileHash .\rig_sentinel-0.1.0-py3-none-any.whl -Algorithm SHA256
```

## Validation

| Platform (Python 3.13) | Result |
|---|---|
| Windows | ✅ 179 tests passed |
| Ubuntu 24.04 (GitHub Actions) | ✅ 179 tests passed |
| Ubuntu 26.04 (GitHub Actions) | ✅ 179 tests passed |
| macOS 15 Intel (GitHub Actions) | ✅ 179 tests passed |
| macOS Apple Silicon ARM64 (GitHub Actions) | ✅ 179 tests passed |

GitHub Actions results are for commit `2fd5f2e` (main CI run `41896617740`, Apple Silicon run
`41896617670`). Each CI job also generates HTML and SARIF reports and validates the SARIF
version. Platforms and Python versions not listed here have not been tested. Precision
regression tests are derived from reviewing the OpenAI Agents SDK and MCP reference servers
repositories.

## Known limitations

- Analysis is **static**; detected agents are **heuristic candidates**.
- A shared credential **reference** does **not** prove that agents share the same secret.
- Attack paths are **modeled possibilities**; blast radius is an **estimate**, not a measured
  incident.
- Policies are **advisory**; nothing is enforced at runtime.
- The exit code is `0` regardless of findings (no built-in CI gating).
- **SARIF 2.1.0** works as an export format, but **GitHub Code Scanning integration is not
  yet validated**: some results lack file locations (all results when scanning on Windows).
- Directories such as `tests/`, `examples/`, `fixtures/` and `vendor/` are skipped; files over
  1 MB are ignored. Deep analysis is Python-focused.
- Python 3.11 and 3.12 are declared supported but not yet validated in CI (all platforms
  above were tested with Python 3.13).

Full details: [Limitations](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/docs/LIMITATIONS.md).

## Security

Please report vulnerabilities privately as described in
[SECURITY.md](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/SECURITY.md). A
pre-release security audit and a third-party provenance review are included in `docs/`.

## Credits

**Founder, Creator & Lead Maintainer:** Randy Igualguana
([@Igualguana](https://github.com/Igualguana))

RIG Industrial Technologies LLC (<https://rigindustrialusa.com>) is the proposed commercial
operator for future commercial offerings, subject to a separate written license agreement.
RIG Sentinel Enterprise is a planned future product and is not available.

## License

RIG Sentinel Community is licensed under the
[Apache License 2.0](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/LICENSE).
Copyright 2026 Randy Igualguana.

**Full changelog:** [CHANGELOG.md](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/CHANGELOG.md)
