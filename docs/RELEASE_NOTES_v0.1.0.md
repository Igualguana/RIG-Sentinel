# RIG Sentinel Community v0.1.0

**First public release** of RIG Sentinel — an open-source security scanner for AI
agents, MCP servers, identities, permissions, and exposure risks.

RIG Sentinel statically scans a repository to find AI agent candidates, MCP integrations,
sensitive capabilities and credential references, then models attack paths, blast
radius and prioritized remediation. It runs locally, has no runtime dependencies and
never executes scanned code.

## Highlights

- **Discovery** — OpenAI, Anthropic, LangChain and CrewAI usage; heuristic agent
  candidates; MCP configuration and SDK usage; shell, filesystem, HTTP and e-mail
  capabilities; well-known credential references (names only).
- **Analysis** — credential flow (Python, inter-procedural), excessive and
  least-privilege findings, shared credential references, shadow agents against an
  approved inventory, multi-agent identity graph and risk propagation.
- **Exposure** — attack paths (agent → tool → permission → resource), a 0–100
  blast-radius estimate per agent and prioritized remediation.
- **Policies** — advisory least-privilege policies (no runtime enforcement).
- **Reports** — terminal, JSON, offline HTML (CSP-hardened, no scripts) and SARIF 2.1.0.

## Install

```bash
python -m pip install "git+https://github.com/Igualguana/RIG-Sentinel.git@v0.1.0"
rig-sentinel scan path/to/repo --html rig-sentinel.html
```

Requires Python 3.11+ (tested with 3.13).

## Validation

- 179 automated tests passing on Windows (Python 3.13) and in GitHub Actions on
  Ubuntu 24.04, Ubuntu 26.04 and macOS 15 Intel.
- macOS Apple Silicon: pending <!-- UPDATE BEFORE PUBLISHING: passing / pending -->
- Precision regression tests derived from reviewing the OpenAI Agents SDK and the MCP
  reference servers repositories.

## Please read before using results

- Analysis is **static**; agents are **heuristic candidates**.
- A shared credential **reference** does **not** prove that agents share a secret.
- Attack paths are **modeled possibilities**; blast radius is an **estimate**.
- Policies are **advisory**; nothing is enforced at runtime.
- The exit code is `0` regardless of findings.
- SARIF results may lack file locations (always on Windows); GitHub code-scanning upload
  is not yet verified.

Full details: [Limitations](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/docs/LIMITATIONS.md).

## About

RIG Sentinel was founded and is maintained by Randy Igualguana
([@Igualguana](https://github.com/Igualguana)). RIG Industrial Technologies LLC
(<https://rigindustrialusa.com>) is the proposed commercial operator for future
commercial offerings, subject to a separate written license agreement; RIG Sentinel Enterprise is a planned future product and is not
available.

## License

Apache License 2.0. Enterprise offerings, if any, are developed separately and are not
part of this release.

Copyright 2026 Randy Igualguana.

**Full changelog:** [CHANGELOG.md](https://github.com/Igualguana/RIG-Sentinel/blob/v0.1.0/CHANGELOG.md)
