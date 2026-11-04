# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — Unreleased (release candidate)

First public release of **RIG Sentinel Community**.

### Added

- `rig-sentinel scan <path>` CLI with terminal, JSON (`--json`), offline HTML (`--html`)
  and SARIF 2.1.0 (`--sarif`) output.
- Repository walker with supported file types, ignored directories and a 1 MB size limit.
- AI provider detection: OpenAI, Anthropic, LangChain, CrewAI.
- MCP detection: `mcpServers` JSON, `mcp.json`-style files, Python MCP SDK usage.
- Tool / capability detection: shell, filesystem write/delete, HTTP, e-mail.
- Identity and credential-reference discovery (names only) and agent ↔ identity linking.
- Heuristic agent detection with precision rules that exclude documentation, CI
  workflows and tests (Precision v1.2).
- Credential flow analysis (v3.1, intra- and inter-procedural for Python).
- Excessive privilege and least-privilege analysis.
- Shared credential reference detection, with explicit wording that a shared name does
  not prove a shared secret.
- Shadow agent detection against an approved inventory in `.rig-sentinel.toml`.
- Multi-agent identity graph and risk propagation analysis.
- Attack paths, blast radius (0–100 heuristic) and remediation recommendations.
- Advisory security policy generator.
- GitHub Actions CI on Ubuntu 24.04, Ubuntu 26.04 and macOS, generating HTML and SARIF
  artifacts.
- Apache License 2.0, NOTICE, Code of Conduct, contribution guide (code review rules,
  Apache-2.0 inbound=outbound contributions, no CLA), security policy with coordinated
  disclosure, issue and pull request templates, and documentation (installation, CLI
  reference, architecture, limitations, testing, detection-issue reporting, three-phase
  roadmap, Community vs Enterprise, Spanish overview, security audit).

### Known limitations

- SARIF results may lack file locations (always on Windows); GitHub code-scanning upload
  is not verified.
- Findings never change the exit code.
- macOS Apple Silicon CI validation pending at the time of writing.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

[Unreleased]: https://github.com/Igualguana/RIG-Sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Igualguana/RIG-Sentinel/releases/tag/v0.1.0
