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
  suite has 913 tests. Validated locally on Windows with Python 3.13, and in GitHub
  Actions for the Genesis B2-M1 pull request (Python 3.13: 913 passed on each of Ubuntu
  24.04, Ubuntu 26.04, macOS 15 Intel and macOS Apple Silicon). These results apply to
  the unreleased development branch, not to the v0.1.0 release. See
  [docs/TESTING.md](docs/TESTING.md#validation-status).
- **Documentation:** `docs/POLICY_ENGINE.md`, `docs/THREAT_MODEL.md`, and updates to the
  README, architecture and testing documents.
- **Audit foundation (Genesis B2-M2-B, in-memory only):** the new package `rig_sentinel.audit`.
  - **Events:** versioned, privacy-minimized `rig.audit-event/v2` events built from M1
    decision records, with fields grouped by provenance (audit, engine, caller claims).
  - **Keys:** HMAC-SHA-256 pseudonyms under a dedicated key (`K_ref`, never an unkeyed hash)
    and HMAC-authenticated envelopes under a separate key (`K_auth`).
  - **Validation and storage:** closed-schema validation, and a bounded `MemorySink` whose
    receipts are never stored inside events.
  - **Scope:** no persistence, ordering chain, key storage or enforcement yet. The policy
    package does not depend on it. See `docs/AUDIT.md`.
- **Audit privacy hardening (Genesis B2-P1, in-memory only):**
  - **Event schema `rig.audit-event/v3`**, selected explicitly with
    `AuditEventBuilder(..., event_schema=AUDIT_EVENT_SCHEMA_V3)`. `rig.audit-event/v2` remains
    the default and is unchanged. Separate parsers (`event_from_dict` for v2,
    `event_v3_from_dict` for v3) never reinterpret one version as the other.
  - **No plain-text actor or tool identities in v3:** `identity_mode` is `pseudonymized`
    (`agent_ref`, `tool_ref`, `manifest_ref` and `label_refs` are HMAC references under K_ref,
    with separate namespaces) or `omitted` (no K_ref: identities are left out, never written in
    clear). The tool manifest digest, which identifies the tool, is never copied into a v3
    event; v2 still records `manifest_sha256` unchanged.
  - **Omitted-label accounting:** in `omitted` mode, `omitted_labels_count` records exactly how
    many non-readable labels were dropped (0 when none; at most 32 minus the readable labels).
    It is `null` in `pseudonymized` mode and for requests that are not `consistent`.
  - **Readable label allowlist:** only `reviewed` and `untrusted_content_present` may appear
    as readable labels; deployments can narrow but not extend the set.
  - **Persistence privacy gate** `check_persistable`: a pure check, for a future persistent
    sink, that accepts only authenticated v3 envelopes whose canonical bytes re-parse
    identically and whose readable labels are allowed. It stores nothing.
  - v3 envelopes keep the M2-B digest and MAC construction unchanged (a temporary
    compatibility decision; per-version envelope domains are M2-C design work).
    Pseudonymized events remain linkable and are not anonymous, and the engine section keeps
    M1's unkeyed request digest. No persistent storage or runtime enforcement. See
    `docs/AUDIT.md`.
- **Privacy-safe audit projection (Genesis B2-P2, in-memory only):** the representation
  intended for future persistent storage, in the new module `rig_sentinel.audit.projection`.
  - **Projection** `rig.audit-projection/v1` sealed in `rig.audit-envelope/v2` (own digest and
    MAC domains, mandatory MAC). `project()` verifies a sealed v3 envelope (exact types, closed
    re-parse, K_auth) before transforming it. M1's unkeyed request digest, decision digest and
    approval request binding become HMAC references under a derived key K_eref (new key purpose
    `ENGINE_REF`), each in its own domain. Raw approver ids become keyed references, and the
    v3 event digest and MAC are never copied.
  - **Profiles:** `KEYED` (the default) needs the source's K_ref epoch; `UNLINKED` (no engine
    references) only by explicit selection and only for `no-ref-key` sources. There is never
    an automatic fallback.
  - **Persistence gate** `check_projection_persistable()`: pure, no I/O. It accepts only
    authentic projection envelopes that re-parse to identical bytes, pass a deep privacy scan
    and match an optional key epoch, and it returns the exact bytes to persist as a
    gate-issued `ValidatedProjection`. v1 envelopes (v2 and v3 events) are refused.
  - **Fidelity verification** `verify_projection_fidelity()` returns `MATCH`, `MISMATCH` or
    `NOT_VERIFIABLE` against an original M1 `DecisionRecord`. It proves neither provenance,
    execution nor enforcement.
  - `check_v3_projection_source` is a new alias for `check_persistable` (unchanged), which is
    now documented as a projection precondition rather than permission to persist.
  - M1, the v2/v3 events and `MemorySink` are unchanged. No persistent storage or runtime
    enforcement (M2-C, Genesis D). See `docs/AUDIT.md`.

### Security

- `DecisionRecord.error_type` now names an exception class only if it is one of Python's
  built-in `Exception` classes, matched by identity; any other class is recorded as
  `UnlistedError`. Previously, an exception class raised by a caller-supplied object
  (such as a custom mapping or clock) could place arbitrary text, including control
  characters, in `error_type`, and a class whose metaclass made `__name__` raise caused
  `evaluate()` to raise instead of returning `DENY / EVALUATION_ERROR`. Records for
  built-in exceptions and for normal requests are unchanged.

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
