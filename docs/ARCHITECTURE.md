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
