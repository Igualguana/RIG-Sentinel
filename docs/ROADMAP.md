# Roadmap

This roadmap expresses intent, not commitments. Priorities may change based on community
feedback. Nothing listed as planned or future is implemented unless marked otherwise.

## Editions

| | RIG Sentinel Community | RIG Sentinel Enterprise |
|---|---|---|
| Status | Available (this repository) | Future product — **not available, not offered for sale** |
| License | Apache License 2.0 | Commercial (planned) |
| Code location | This public repository | Separate, not part of this repository |

Community capabilities will not be removed to create paid features. Enterprise, if
built, is expected to be offered by RIG Industrial Technologies LLC as the proposed
commercial operator.

---

## Phase 1 — Community Scanner

**Status: implemented, release v0.1.0 in preparation.**

Delivered (Apache License 2.0, free):

- Static repository scanner (CLI)
- Heuristic identification of AI agent components
- AI provider detection (OpenAI, Anthropic, LangChain, CrewAI) and MCP server /
  configuration detection
- Identity and credential-reference analysis (names only), credential flow
- Capability detection and excessive / least-privilege indicators
- Shared credential references and shadow agents (approved inventory)
- Multi-agent relationship graph, risk propagation and possible attack paths
- Estimated blast radius (0–100)
- Advisory remediation and policy recommendations
- Terminal, JSON, offline HTML and SARIF 2.1.0 reports

Verified: 179 automated tests; CI on Ubuntu 24.04, Ubuntu 26.04 and macOS 15 Intel.

Planned Community follow-ups:

| Theme | Items |
|---|---|
| Precision | More regression fixtures from public repositories; fewer false positives |
| SARIF | Result locations on all platforms; verified GitHub code-scanning upload |
| CI usability | Opt-in exit codes / severity thresholds for gating; `--version` |
| Coverage | More providers and frameworks; JavaScript/TypeScript depth; more MCP config formats |
| Configuration | Configurable ignore lists and custom credential names |
| Packaging | PyPI distribution |
| Reports | Optional path redaction; diff-based scans for pull requests |

## Phase 2 — Runtime Permission Security

**Status: planned. Not implemented. Nothing in v0.1.0 enforces permissions at runtime.**

Areas under consideration:

- Runtime controls on agent tool calls and MCP actions
- Dynamic, context-aware permissions for agents
- Prevention of unauthorized actions (e.g. blocking or requiring approval for
  sensitive operations)

Which parts of Phase 2 will be part of Community and which part of Enterprise has not
been decided.

## Phase 3 — Enterprise Platform

**Status: future. Not implemented, not available, no pricing.**

Planned capabilities for RIG Sentinel Enterprise:

- Centralized dashboard
- Multi-organization management
- Continuous monitoring and auditing
- Runtime permission controls (building on Phase 2)
- Enterprise policy administration
- Integrations with corporate systems
- Centralized history and audit trail
- User and role management
- Enterprise reporting
- Support and professional services

These capabilities will be developed separately from the Community repository.
