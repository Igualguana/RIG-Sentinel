# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Not released. The policy engine below is development work (Genesis B2, milestone M1);
its API and schema may change before a release.

### Added

- **Genesis B2-M1 policy engine** (`rig_sentinel.policy`): a deterministic, advisory
  decision point for AI-agent tool requests that returns `ALLOW`, `DENY` or
  `REQUIRE_APPROVAL`. Standard library only, independent of the scanner and the CLI.
  Every decision record carries `"enforced": false`; nothing is blocked at runtime.
- **Policy API:** `load_policy_file`, `load_policy_bytes`, `load_policy_text`,
  `validate_policy`, `lint_policy`, `policy_sha256`, `check_policy_digest`,
  `PolicyEngine.evaluate`, `parse_request`, `parse_resource`, and the `DecisionRecord`
  type (`rig.decision/v1`, with `to_dict()`).
- **Policy validation:** strict TOML schema `rig.policy/v1` (unknown fields, wrong types
  and wrongly cased values rejected; all issues reported at once, without echoing
  values); default deny (`defaults.decision = "allow"` is rejected); deny overrides
  approval, which overrides allow, independent of rule order; tool registry with
  optional manifest digests; SHA-256 policy fingerprint with optional pinning.
- **Security hardening:**
  - Policies are rejected when a `deny` or `require_approval` rule on an `fs:`, `url:`,
    `db:` or `secret:` resource is nested inside an overlapping weaker rule or a
    `require_approval` default (`UNSAFE_PATH_CARVE_OUT`, `ALIAS_DOWNGRADE_RISK`), or
    when the same path prefix is spelled with different letter case
    (`PATH_CASE_CONFLICT`), because aliases of the protected name could bypass them.
  - ASCII-only identifiers and resources; Windows device names, overlong path segments,
    `..`, URL credentials, queries and percent-encoding are rejected.
  - Size, count and nesting limits on policies and requests; any `Exception` during
    evaluation returns `DENY`.
- **Tests:** 734 new tests (412 for the engine, 322 for hardening and limits); the full
  suite has 913 tests. Validated locally on Windows with Python 3.13; not yet run in CI.
- **Documentation:** `docs/POLICY_ENGINE.md`, `docs/THREAT_MODEL.md`, and updates to the
  README, architecture and testing documents.

### Known limitations

- **No enforcement.** Decisions are advisory until a trusted adapter (Genesis D, not
  implemented) refuses tool calls that are not `ALLOW`.
- **No authentication.** Agent identity, assurance, tool identity, resource and labels
  are asserted by the caller.
- **Names, not objects.** Symbolic links, junctions, hard links, mounts,
  time-of-check/time-of-use, sibling and cross-database or cross-name aliases on `db:` and
  `secret:`, and semantic aliases on `shell:` and `email:` are not detected.
- Approvals are described but not issued or verified; no audit log, secret redaction,
  policy signing, evaluation timeout or `rig-sentinel policy` CLI yet.
- "Everything except" policies on `fs:`, `url:`, `db:` and `secret:` resources cannot be
  written; use allowlists.

See [docs/POLICY_ENGINE.md](docs/POLICY_ENGINE.md#known-limitations-m1).

## [0.1.0] — 2026-11-04

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
- GitHub Actions CI with Python 3.13 on Ubuntu 24.04, Ubuntu 26.04 and macOS 15 Intel, plus
  macOS Apple Silicon ARM64 in a separate workflow; 179 tests passed on each platform for
  the release candidate, and on Windows. Each CI job
  generates HTML and SARIF artifacts.
- Apache License 2.0, NOTICE, Code of Conduct, contribution guide (code review rules,
  Apache-2.0 inbound=outbound contributions, no CLA), security policy with coordinated
  disclosure, issue and pull request templates, and documentation (installation, CLI
  reference, architecture, limitations, testing, detection-issue reporting, three-phase
  roadmap, Community vs Enterprise, Spanish overview, security audit).

### Known limitations

- SARIF 2.1.0 works as an export format, but integration with GitHub Code Scanning is not
  yet validated: results may lack file locations (always on Windows).
- Findings never change the exit code.
- Python 3.11 and 3.12 are declared supported but not yet exercised in CI.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

[Unreleased]: https://github.com/Igualguana/RIG-Sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Igualguana/RIG-Sentinel/releases/tag/v0.1.0
