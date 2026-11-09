# Architecture

This document describes the architecture of **RIG Sentinel Community v0.1.0** as
implemented in `src/rig_sentinel/`, followed by the longer-term target architecture.

## Design principles

- **Local and offline.** No network calls, no telemetry, no database.
- **Static.** Scanned code is parsed or pattern-matched, never imported or executed.
- **Zero runtime dependencies.** Standard library only (`ast`, `json`, `tomllib`, `html`, …).
- **Explainable findings.** Every finding carries evidence and, where relevant, a
  confidence level and an explicit statement of what it does not prove.

## Pipeline (v0.1.0)

```text
rig-sentinel scan <path>
        │
        ▼
┌───────────────────┐   ┌──────────────────┐
│ RepositoryWalker  │   │ ConfigLoader     │  .rig-sentinel.toml → approved_agents
│ repository.py     │   │ config.py        │
└────────┬──────────┘   └────────┬─────────┘
         │ supported files ≤ 1 MB│
         ▼                       │
┌─────────────────────────────── Detectors ─────────────────────────────────┐
│ ProviderDetector (providers.py)   OpenAI · Anthropic · LangChain · CrewAI │
│ MCPDetector      (mcp.py)         mcpServers · mcp.json · MCP SDK usage   │
│ ToolDetector     (tools.py)       shell · fs write/delete · HTTP · e-mail │
│ IdentityDetector (identity.py)    well-known credential names             │
│ AgentDetector    (agents.py)      heuristic agent candidates              │
│ Provider/MCP/Tool detectors use python_analysis.py (AST imports, calls)  │
└────────┬──────────────────────────────────────────────────────────────────┘
         ▼
┌─────────────────────────────── Analyzers ─────────────────────────────────┐
│ IdentityLinker          identity_linking.py   agent ↔ identity links      │
│ CredentialFlowAnalyzer  credential_flow.py    credential → capability     │
│ PrivilegeAnalyzer       privilege.py          excessive privilege         │
│ LeastPrivilegeAnalyzer  least_privilege.py    least-privilege gaps        │
│ SharedCredentialAnalyzer shared_credentials.py same credential *name*     │
│ ShadowAgentAnalyzer     shadow_agents.py      vs. approved inventory      │
│ MultiAgentGraphBuilder  multi_agent_graph.py  agents ↔ shared identities  │
│ RiskPropagationAnalyzer risk_propagation.py   modeled propagation         │
│ PolicyGenerator         policy_generator.py   advisory policies           │
│ ExposureReportBuilder   exposure_report.py → ExposureAnalyzer (exposure.py)│
│   ├─ permissions.py / graph.py   tool → permission → resource graph       │
│   ├─ attack_paths.py             path enumeration and severity            │
│   ├─ blast_radius.py             0–100 heuristic score                    │
│   └─ remediation.py              prioritized recommendations              │
└────────┬──────────────────────────────────────────────────────────────────┘
         ▼
┌─────────────── ScanReport (scanner.py) ───────────────┐
│ cli.report_to_dict → JSON payload                     │
└────────┬───────────────┬───────────────┬──────────────┘
         ▼               ▼               ▼
   Terminal (cli.py)  HTML (html_report.py)  SARIF 2.1.0 (sarif_report.py)
```

`RepositoryScanner` in `scanner.py` orchestrates the pipeline and returns an immutable
`ScanReport`. `cli.py` parses arguments, converts the report to a dictionary and hands it
to the selected reporter.

## Core data model

Findings are frozen dataclasses (`models.py` and each module's `*Finding` type). The
permission graph is an in-memory structure (`graph.py`) with node prefixes such as
`agent:`, `tool:`, `permission:` and `resource:`.

## Output safety

- HTML: every dynamic value is escaped with `html.escape(..., quote=True)`; the page sets
  a restrictive `Content-Security-Policy` and loads no external resources.
- SARIF: file URIs are only emitted for relative, forward-slash paths without `..`,
  control characters or drive letters.
- No reporter includes credential values; only names and file paths.

## Policy decision engine (Genesis B2-M1, unreleased)

`src/rig_sentinel/policy/` contains a policy engine that is in development and not part
of the v0.1.0 release. It is a **Policy Decision Point (PDP)**: given a validated policy
and a request, it returns `ALLOW`, `DENY` or `REQUIRE_APPROVAL`. It does not enforce
anything. Full reference: [POLICY_ENGINE.md](POLICY_ENGINE.md); threats and residual
risks: [THREAT_MODEL.md](THREAT_MODEL.md).

### Decision point and future enforcement point

| Component | Status | Responsibility |
|---|---|---|
| **Policy Decision Point** (`rig_sentinel.policy`) | Implemented (development) | Load and validate a policy; evaluate one request; return a `DecisionRecord` with `"enforced": false` |
| **Policy Enforcement Point** (adapter) | **Planned (Genesis D); does not exist** | Intercept a tool call, authenticate the caller, build the request, call the PDP, and invoke the tool only on `ALLOW` |

No runtime firewall, proxy or interception layer exists today. Until an enforcement
adapter exists, decisions are advisory.

### Separation from the scanner and the CLI

- The scanner and the CLI do not import `rig_sentinel.policy`, and the policy package
  imports neither of them (`tests/test_policy_isolation.py` checks this). The
  `rig-sentinel scan` command, its JSON keys and its SARIF rule IDs are unchanged.
- The engine never discovers policy files and never treats the scanner's advisory
  `security_policies` output as a policy. A policy is active only when a caller passes
  a validated `Policy` to `PolicyEngine`.
- The engine performs no file, network or database I/O during evaluation. Loading reads
  only the policy file the caller names.

### Request and decision flow

```text
policy.toml ──▶ loader ──▶ validation ──▶ Policy (frozen, canonical, sha256)
               size, UTF-8,  strict schema,          │
               TOML parse,   alias-safety checks     ▼
               digest pin                     PolicyEngine(policy, expected_policy_sha256)
                                               re-validates; mismatch → deny all
                                                     │
request (dict or AuthorizationRequest) ─────────────▶ evaluate()
  agent, tool, operation, resource, context           │
                                                      ├─ 1. engine state (policy, pin)
                                                      ├─ 2. request validation
                                                      ├─ 3. tool registry
                                                      ├─ 4. rules: deny > approval > allow
                                                      └─ 5. default (deny or approval)
                                                      ▼
                                              DecisionRecord (rig.decision/v1)
                                              decision, reason_code, rule ids,
                                              digests, "enforced": false
                                                      │
                                                      ▼
                         future adapter (Genesis D): invoke the tool only on ALLOW
```

Any `Exception` inside `evaluate()` returns `DENY / EVALUATION_ERROR`. An adapter must
also treat exceptions, timeouts, crashes and `REQUIRE_APPROVAL` as "do not invoke".

### Trust boundaries

| Boundary | Trusted | Not trusted |
|---|---|---|
| Policy file → loader | Loader and validator | File bytes on disk; a pinned SHA-256 detects substitution only if stored out of the attacker's reach |
| Caller → engine | Engine code | Request content. Identity, assurance, tool identity, resource and labels are **caller-asserted**; the engine validates their format but cannot authenticate them |
| Resource name → real object | A future adapter's identity verification | Path, URL, table and secret spellings; links, mounts and provider aliases |
| Agent output → adapter | Future adapter | Tool name, arguments and identity chosen by a model |

The full list (TB1–TB8) is in [THREAT_MODEL.md](THREAT_MODEL.md#trust-boundaries).

### Unsupported or ambiguous resource semantics

The engine compares **names**, not objects. It does not resolve symbolic links,
junctions, hard links, mounts, letter case on case-insensitive volumes, 8.3 short names,
database schemas, views, synonyms, cross-database names or secret-store API paths, and
it does not interpret `shell:` commands or `email:` subdomains. Inputs it cannot
interpret safely, such as Windows paths, `..`, non-ASCII names, URL queries and
percent-encoding, are rejected rather than normalized. Policies whose safety would
depend on recognizing aliases (nested carve-outs on `fs:`, `url:`, `db:` and `secret:`)
are rejected. Sibling and cross-database aliases remain open; see
[POLICY_ENGINE.md](POLICY_ENGINE.md#residual-alias-risks-that-static-validation-does-not-cover).

### Relationship to Genesis D adapters

Genesis D (runtime protection) is expected to provide the enforcement point. The
engine's adapter contract ([POLICY_ENGINE.md](POLICY_ENGINE.md#trust-boundary-and-adapter-security-contract))
lists what an adapter must add: authenticated context, mapping tool arguments to one
canonical resource, resolving the real object and checking both identifiers, acting on
the checked handle, failing closed, and leaving the agent no path around it. None of
this is implemented.

## Target architecture (beyond v0.1.0)

The long-term model generalizes the pipeline into:

| Layer | Responsibility |
|---|---|
| Discovery | Agents, MCP servers, SDK usage, manifests, workflows, tools, integrations |
| Normalization | Common entities: Agent, Identity, Tool, Permission, Resource, Data source, External destination, Control |
| Exposure graph | `Agent → Identity → Permission → Resource → Sensitive data → Egress` |
| Analysis | Excessive permissions, toxic combinations, attack paths, blast radius, ownership gaps, shadow agents |
| Remediation | Permission reductions, policy changes, human-approval requirements, configuration patches |
| Evidence | What was found, why it was scored, what changed |

v0.1.0 intentionally keeps a local CLI and in-memory graph until the domain model is
stable. See [ROADMAP.md](ROADMAP.md).

## Community and Enterprise boundary

- RIG Sentinel Community (this repository) is self-contained: it builds, tests and runs
  without any commercial component, and contains no license checks, telemetry or
  Enterprise feature flags.
- A future RIG Sentinel Enterprise product (Phase 3) is planned as a **separate**
  codebase that would consume Community as a dependency or through its JSON and SARIF
  outputs. No Enterprise code is part of this repository.
- The JSON report structure and SARIF rule IDs are therefore treated as public
  integration contracts; changes are documented in `CHANGELOG.md`.
- Runtime permission security (Phase 2) is planned only; nothing in v0.1.0 runs at
  agent runtime.
