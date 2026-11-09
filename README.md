<div align="center">

# RIG Sentinel

**Open-source security scanner for AI agents, MCP servers, identities, permissions, and exposure risks.**

[![CI](https://github.com/Igualguana/RIG-Sentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Igualguana/RIG-Sentinel/actions/workflows/ci.yml)
[![macOS Apple Silicon](https://github.com/Igualguana/RIG-Sentinel/actions/workflows/ci-macos-arm64.yml/badge.svg?branch=main)](https://github.com/Igualguana/RIG-Sentinel/actions/workflows/ci-macos-arm64.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-informational)](CHANGELOG.md)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-8A2BE2)](docs/CLI_REFERENCE.md#sarif-output)

[Quick Start](#quick-start) ·
[Documentation](#documentation) ·
[Limitations](docs/LIMITATIONS.md) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md) ·
[Community vs Enterprise](#community-vs-enterprise) ·
[Español](docs/README_ES.md)

| Founder & Lead Maintainer | Commercial Operator (proposed) | Community License | Website |
|---|---|---|---|
| Randy Igualguana | RIG Industrial Technologies LLC | Apache License 2.0 | [rigindustrialusa.com](https://rigindustrialusa.com) |

</div>

---

## What is RIG Sentinel?

RIG Sentinel is an open-source, static security scanner for AI agent code. It reads a
source repository and builds a picture of the AI agents, MCP integrations, credentials
and capabilities it contains — then shows how those pieces connect, what an agent could
reach, and what to restrict first.

It runs locally, has **zero runtime dependencies**, never executes the code it scans, and
produces terminal, JSON, offline HTML and SARIF 2.1.0 reports.

## The problem it addresses

AI agents are becoming privileged workloads. They hold API keys, call MCP servers, run
shell commands, send HTTP requests and touch payment systems — often without an
inventory, an owner, or a review of what they could reach if something went wrong.

RIG Sentinel helps answer four questions from source code:

1. **What AI agents and MCP integrations exist here?**
2. **Which identities and credentials do they reference?**
3. **Which sensitive capabilities can they reach, and through which paths?**
4. **What should be restricted first to reduce exposure?**

> [!IMPORTANT]
> RIG Sentinel performs **static, heuristic analysis**. Its findings are indicators that
> warrant review — not confirmed vulnerabilities, not proof of credential sharing, and not
> evidence of compromise. Read [Limitations](docs/LIMITATIONS.md) before acting on results.

## Features (v0.1.0)

| Area | What RIG Sentinel detects |
|---|---|
| **AI providers** | OpenAI, Anthropic, LangChain and CrewAI usage via Python imports and configuration markers |
| **Agents** | Heuristic agent candidates that combine a provider with tools, identities or MCP signals; documentation, CI and test files are excluded |
| **MCP** | `mcpServers` blocks in JSON, `mcp.json` / `mcp-config.json` files, Python MCP SDK imports and `FastMCP` / `mcp.server.Server` usage |
| **Tools & capabilities** | Shell execution, filesystem write/delete, outbound HTTP and e-mail sending calls |
| **Identities & credentials** | References to well-known credential names (e.g. `OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`) — names only, never values |
| **Credential flow** | Intra- and inter-procedural tracking of credential variables to capabilities in Python |
| **Privilege** | Excessive privilege and least-privilege indicators per agent and identity |
| **Shared credential references** | Multiple agents referencing the same credential *name* |
| **Shadow agents** | Agents not listed in an approved inventory (`.rig-sentinel.toml`) |
| **Graphs & attack paths** | Agent → tool → permission → resource paths, multi-agent identity graph, risk propagation |
| **Blast radius** | A 0–100 heuristic exposure estimate per agent |
| **Remediation & policy** | Prioritized recommendations and **advisory** least-privilege policies |
| **Reports** | Terminal, JSON, self-contained offline HTML, SARIF 2.1.0 |

All of these features are part of RIG Sentinel Community and are free to use under
Apache License 2.0.

## Installation

**Requirements:** Python 3.11 or newer (CI and maintainer testing use Python 3.13), `pip`
and `venv`. RIG Sentinel v0.1.0 is installed from source; it is not yet on PyPI.

```bash
git clone https://github.com/Igualguana/RIG-Sentinel.git
cd RIG-Sentinel
python -m venv .venv
```

Activate the environment:

```bash
# Linux / macOS
source .venv/bin/activate
```

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

Install:

```bash
python -m pip install .
```

For development (editable install + pytest):

```bash
python -m pip install -e ".[dev]"
```

More options: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Quick Start

```bash
# Scan a repository and print a terminal report
rig-sentinel scan path/to/your-repo

# Write an offline HTML report
rig-sentinel scan path/to/your-repo --html rig-sentinel-report.html
```

### CLI

```text
Usage: rig-sentinel scan <path> [--json | --html <output.html> | --sarif <output.sarif>]
```

| Command | Result |
|---|---|
| `rig-sentinel scan <path>` | Human-readable terminal report |
| `rig-sentinel scan <path> --json` | JSON report on standard output |
| `rig-sentinel scan <path> --html report.html` | Self-contained offline HTML report |
| `rig-sentinel scan <path> --sarif report.sarif` | SARIF 2.1.0 report |
| `rig-sentinel --help` | Usage |

- `<path>` defaults to the current directory when omitted.
- Only one output format can be selected per run.
- The exit code is `0` after a successful scan **regardless of findings**, and `2` for
  usage errors. RIG Sentinel does not fail builds on its own.

Full reference: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).

### Approved agent inventory

Agents not listed in an approved inventory are reported as *shadow agents*. Declare
known agents in `.rig-sentinel.toml` at the root of the scanned repository:

```toml
approved_agents = ["billing_agent", "support_agent"]
```

## Reports and examples

The excerpts below are real output from scanning a small synthetic repository
(two Python agents using the OpenAI SDK and environment-variable credentials, plus an
`mcp.json`). They are abbreviated.

```text
SHARED CREDENTIALS
----------------------------------------------------
[MEDIUM]
Identity: OPENAI_API_KEY
Usage count: 2
Used by:
  - billing_agent
  - support_agent
Reason: Multiple agents or workloads reference the same credential identity name. This
does not establish that the underlying secret is shared or that the credential is exposed.

ATTACK PATHS
----------------------------------------------------
[CRITICAL]
agent:support_agent
  -> tool:shell
  -> permission:system.execute
  -> resource:host_system

RECOMMENDED REMEDIATION
----------------------------------------------------
[CRITICAL] Restrict shell execution
Tool: shell
Expected risk reduction: HIGH
Recommendation: Remove unrestricted shell execution where possible. If required, allow
only approved commands and execute them inside an isolated environment.

EXPOSURE SUMMARY
----------------------------------------------------
Critical agents:  0
High agents:      1
Medium agents:    0
Low agents:       1
Max blast radius: 47/100
```

| Format | Contents |
|---|---|
| **JSON** | Top-level keys `product`, `version`, `root`, `files_scanned`, `providers`, `mcp_findings`, `tools`, `identities`, `identity_links`, `credential_flows`, `privilege_findings`, `least_privilege_findings`, `shared_credential_findings`, `shadow_agent_findings`, `multi_agent_graph`, `risk_propagation_findings`, `security_policies`, `policy_count`, `agents`, `exposure` |
| **HTML** | One offline file, inline CSS, no JavaScript, restrictive Content-Security-Policy, all values escaped |
| **SARIF 2.1.0** | Rules `RIG001` Shadow agent, `RIG002` Shared credential reference, `RIG003` Excessive privilege, `RIG004` Sensitive agent capability; every result tagged `classification: static-indicator` |

## CI/CD integration

RIG Sentinel's own CI runs the scanner on every push and uploads the reports as build
artifacts. A minimal GitHub Actions job:

```yaml
jobs:
  rig-sentinel:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - name: Install RIG Sentinel
        run: python -m pip install "git+https://github.com/Igualguana/RIG-Sentinel.git@v0.1.0"
      - name: Scan
        run: |
          rig-sentinel scan . --sarif rig-sentinel.sarif
          rig-sentinel scan . --html rig-sentinel.html
      - uses: actions/upload-artifact@v6
        with:
          name: rig-sentinel-reports
          path: |
            rig-sentinel.sarif
            rig-sentinel.html
```

> [!NOTE]
> - The `@v0.1.0` reference works once the `v0.1.0` tag is published; until then use `@main`.
> - The scanner never fails the job based on findings. Add your own policy gate if you need one.
> - Uploading the SARIF file to **GitHub code scanning** is not yet a verified integration:
>   some results do not include a file location. See [Limitations](docs/LIMITATIONS.md#sarif).
> - For production pipelines, pin actions to full commit SHAs.

## Architecture

```text
 rig-sentinel scan <path>
          │
          ▼
 RepositoryWalker ──► Detectors ──────────────► Analyzers ──────────────► Reporters
 (filters, 1 MB       • ProviderDetector        • CredentialFlow           • Terminal
  size limit)         • MCPDetector             • Privilege / Least        • JSON
                      • ToolDetector              privilege                • HTML
                      • IdentityDetector        • SharedCredentials        • SARIF 2.1.0
                      • AgentDetector           • ShadowAgents
                                                • MultiAgentGraph
                                                • RiskPropagation
                                                • AttackPaths / BlastRadius
                                                • Remediation / PolicyGenerator
```

Everything runs in-process with an in-memory graph. No network calls, no database, no
code execution. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Platform status

| Platform | Status for v0.1.0 |
|---|---|
| Windows (Python 3.13) | ✅ 179 tests passed (maintainer machine) |
| Ubuntu 24.04 (Python 3.13) | ✅ 179 tests passed — GitHub Actions |
| Ubuntu 26.04 (Python 3.13) | ✅ 179 tests passed — GitHub Actions |
| macOS 15 Intel (Python 3.13) | ✅ 179 tests passed — GitHub Actions |
| macOS Apple Silicon ARM64 (Python 3.13) | ✅ 179 tests passed — GitHub Actions, [separate workflow](.github/workflows/ci-macos-arm64.yml) |
| Python 3.11 / 3.12 | Declared as supported; not yet exercised in CI |

GitHub Actions results are for the v0.1.0 release candidate on `main` (see the
[Actions history](https://github.com/Igualguana/RIG-Sentinel/actions)). Other operating systems, architectures and Python
versions have not been tested.

## Policy engine (Genesis B2-M1, unreleased)

> [!IMPORTANT]
> The policy engine is **in development and not part of the v0.1.0 release**. Its Python
> API and policy schema may change. It is an **advisory decision engine**: it decides
> whether a request should be allowed, but it does not block, execute or approve
> anything. Every decision record carries `"enforced": false`. Runtime enforcement
> adapters are planned (Genesis D) and do not exist yet.

`rig_sentinel.policy` is a deterministic decision point for AI-agent tool requests:
"agent *A* wants to perform operation *O* with tool *T* on resource *R*". It uses the
standard library only and is independent of the scanner and the CLI; the
`rig-sentinel scan` command is unchanged.

| Decision | Meaning |
|---|---|
| `ALLOW` | A rule permits the request and no deny or approval rule matches. |
| `DENY` | A deny rule matches, no rule matches (default deny), or the request, tool or policy is invalid (fail closed). |
| `REQUIRE_APPROVAL` | A rule requires human approval. Treat it as **not allowed**: approvals are not processed yet. |

- **Strict policy validation.** Policies are TOML (`rig.policy/v1`). Unknown fields,
  wrongly cased values, duplicate ids, rules that name unregistered tools and similar
  mistakes reject the whole policy, with every issue reported at once.
- **Default deny.** A request that no rule allows is denied. The default can be `deny` or
  `require_approval`; `allow` is rejected.
- **Deterministic decisions.** Rule order never matters: any matching `deny` wins, then
  `require_approval`, then `allow`. Any `Exception` during evaluation becomes `DENY`.
- **SHA-256 pinning.** `policy.sha256` fingerprints the policy's canonical content. Pass
  a reviewed value to `load_policy_file(..., expected_sha256=...)` or
  `PolicyEngine(..., expected_policy_sha256=...)` to refuse any other policy.
- **Conservative resource matching.** Resources (`fs:`, `db:`, `url:`, `secret:`,
  `shell:`, `email:`) are matched as exact, case-sensitive names; the only wildcards
  are `*` and a trailing `/**`. Ambiguous forms such as `..`, Windows paths, URL queries
  and non-ASCII names are rejected. Policies whose safety would depend on recognizing
  aliases (a narrow deny or approval rule inside a broader allow on `fs:`, `url:`, `db:`
  or `secret:`) are rejected. Prefer allowlists.

### Example

`policy.toml` (valid under the current validator):

```toml
schema_version = "rig.policy/v1"
policy_id      = "helpdesk-example"
policy_version = "2026.11.09-1"

[defaults]
decision = "deny"

[[tools]]
id            = "mcp://helpdesk/tickets.get"
operations    = ["read"]
resource_kind = "db"

[[tools]]
id            = "mcp://helpdesk/tickets.update"
operations    = ["database_write"]
resource_kind = "db"

[[approvers]]
id     = "oncall-lead"
scopes = ["approve-ticket-updates"]

[[rules]]
id         = "read-tickets"
effect     = "allow"
agents     = ["support-bot"]
tools      = ["mcp://helpdesk/tickets.get"]
operations = ["read"]
resources  = ["db:helpdesk/tickets"]

[[rules]]
id         = "approve-ticket-updates"
effect     = "require_approval"
agents     = ["support-bot"]
tools      = ["mcp://helpdesk/tickets.update"]
operations = ["database_write"]
resources  = ["db:helpdesk/tickets"]

[[rules]]
id         = "no-prod-ticket-updates"
effect     = "deny"
agents     = ["*"]
tools      = ["mcp://helpdesk/tickets.update"]
operations = ["database_write"]
resources  = ["db:helpdesk/tickets"]

[rules.conditions]
environment = ["prod"]
```

```python
from rig_sentinel.policy import PolicyEngine, load_policy_file

# Strict validation: raises PolicyLoadError or PolicyValidationError on any problem.
policy = load_policy_file("policy.toml")
print(policy.sha256)  # record this fingerprint when the policy is reviewed

# In practice, load the reviewed fingerprint from a location the agent cannot modify.
reviewed_sha256 = policy.sha256
engine = PolicyEngine(policy, expected_policy_sha256=reviewed_sha256)

record = engine.evaluate({
    "agent": {"id": "support-bot", "assurance": "authenticated"},
    "tool": {"id": "mcp://helpdesk/tickets.get"},
    "operation": "read",
    "resource": "db:helpdesk/tickets",
    "context": {"environment": "staging", "session_id": "s-1", "request_id": "r-1"},
})

print(record.decision.value, record.reason_code.value)  # ALLOW RULE_ALLOW
print(record.allowed, record.enforced)                  # True False
```

With the same policy and `support-bot` as the agent:

| Request | Decision | Reason code |
|---|---|---|
| `read` `db:helpdesk/tickets` with `tickets.get`, staging | `ALLOW` | `RULE_ALLOW` |
| `read` `db:helpdesk/users` with `tickets.get`, staging | `DENY` | `DEFAULT_DENY` |
| `database_write` `db:helpdesk/tickets` with `tickets.update`, staging | `REQUIRE_APPROVAL` | `RULE_REQUIRES_APPROVAL` |
| same, in `prod` | `DENY` | `RULE_DENY` |
| any request with the unregistered `mcp://helpdesk/tickets.delete` | `DENY` | `UNKNOWN_TOOL` |

`record.to_dict()` returns the full decision record (`rig.decision/v1`).

### Current security limitations

- **No enforcement.** Decisions are advisory until a trusted adapter refuses to run a
  tool unless the decision is `ALLOW`. Do not describe the engine as protecting a system.
- **No authentication.** Agent identity, assurance, tool identity, resource and context
  labels are supplied by the caller and are not verified.
- **Names, not objects.** The engine cannot tell whether two names refer to the same
  file, table or secret. Symbolic links, junctions, hard links, mounts, sibling or
  cross-database aliases, and changes between decision and use are not covered.
- **No prompt-injection detection, approval processing, audit log or policy signing.**

Details: [docs/POLICY_ENGINE.md](docs/POLICY_ENGINE.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Limitations

RIG Sentinel v0.1.0 is a **static analyzer**. In short:

- It reads files; it does not run code or observe runtime behavior.
- **Detected agents are heuristic candidates**, not a confirmed inventory.
- **A shared credential *reference* does not prove that agents share the same secret.**
  Two services reading `OPENAI_API_KEY` may be configured with different keys.
- **Attack paths are modeled possibilities**, not demonstrated exploits.
- **Blast radius is an estimate**, not a measured incident impact or breach probability.
- **Policies are advisory.** Nothing is enforced at runtime.
- Directories such as `tests/`, `examples/`, `fixtures/`, `vendor/` and `node_modules/` are
  skipped, and files larger than 1 MB are ignored.
- Deep analysis is Python-focused; other languages receive text-based detection only.
- **SARIF 2.1.0** works as an export format; GitHub Code Scanning integration is not yet validated.
- CI covers Python 3.13 only; Python 3.11 and 3.12 are declared but not yet tested.
- False positives and false negatives are expected.

Read the full list in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Contributing

Contributions are welcome — especially detection rules, false-positive and
false-negative reports, test fixtures and documentation.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report detection accuracy issues with the guide in
  [docs/DETECTION_ISSUES.md](docs/DETECTION_ISSUES.md).
- Testing conventions: [docs/TESTING.md](docs/TESTING.md).
- Contributions are accepted under the Apache License 2.0 (no CLA is required).

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Community vs Enterprise

| | **RIG Sentinel Community** | **RIG Sentinel Enterprise** |
|---|---|---|
| Status | Available — this repository | **Future product — not available** |
| License | Apache License 2.0 | Commercial (planned) |
| Price | Free | Not defined; not offered for sale |
| Scope | Everything listed in [Features](#features-v010): static scanning, agent/MCP/provider detection, identities and credential references, privilege analysis, graphs and attack paths, blast-radius estimates, advisory recommendations, CLI/JSON/HTML/SARIF reports | Planned: centralized dashboard, multi-organization management, continuous monitoring, runtime permission controls, enterprise policy administration, corporate integrations, centralized history and audit, users and roles, enterprise reporting, support and professional services |
| Use | Personal and commercial use, modification, redistribution, CI/CD integration — under Apache-2.0 terms | — |

Community features will not be removed to create paid features. Enterprise, if built,
will be developed as a separate product and is not included in this repository.

## Security and responsible disclosure

Please **do not** report vulnerabilities in public issues. Use GitHub private
vulnerability reporting as described in [SECURITY.md](SECURITY.md).

Reports generated by RIG Sentinel may contain repository paths and credential *names*;
review them before sharing. The pre-release security review is documented in
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

## Roadmap

| Phase | Status | Summary |
|---|---|---|
| **Phase 1 — Community Scanner** | Implemented, release in preparation | Everything in [Features](#features-v010) |
| **Phase 2 — Runtime Permission Security** | Planned — not implemented | Possible runtime controls, dynamic permissions, prevention of unauthorized actions |
| **Phase 3 — Enterprise Platform** | Future | Centralized management, multi-organization, continuous audit, integrations, commercial services |

Details: [docs/ROADMAP.md](docs/ROADMAP.md).

## Documentation

| Document | Description |
|---|---|
| [Installation](docs/INSTALLATION.md) | Install options for Windows, Linux and macOS |
| [CLI reference](docs/CLI_REFERENCE.md) | Commands, options, exit codes and output formats |
| [Architecture](docs/ARCHITECTURE.md) | Components and data flow |
| [Limitations](docs/LIMITATIONS.md) | Scope and interpretation of results |
| [Testing](docs/TESTING.md) | Test suite layout and conventions |
| [Policy engine](docs/POLICY_ENGINE.md) | Policy decision engine (Genesis B2-M1, unreleased): schema, decisions, limitations |
| [Threat model](docs/THREAT_MODEL.md) | Threats, trust boundaries and residual risks for the policy engine |
| [Detection issues](docs/DETECTION_ISSUES.md) | Reporting false positives and false negatives |
| [Roadmap](docs/ROADMAP.md) | Phases, Community and Enterprise direction |
| [Vision](docs/VISION.md) | Product vision |
| [Security audit](docs/SECURITY_AUDIT.md) | Pre-release audit for v0.1.0 |
| [Third-party provenance](docs/THIRD_PARTY_PROVENANCE.md) | Dependencies and code provenance review |
| [Changelog](CHANGELOG.md) | Release history |
| [Documentación en español](docs/README_ES.md) | Spanish overview |

## About RIG Sentinel

RIG Sentinel was founded and created by **Randy Igualguana**, who is also its lead
maintainer. RIG Industrial Technologies LLC is the proposed commercial operator for
future commercial products and services, including the planned RIG Sentinel Enterprise.

| | |
|---|---|
| **Founder, Creator & Lead Maintainer** | Randy Igualguana — [@Igualguana](https://github.com/Igualguana) |
| **Copyright** | © 2026 Randy Igualguana |
| **Proposed Commercial Operator** | RIG Industrial Technologies LLC (Industrial Technology · Cybersecurity · AI Security) — subject to a separate written license agreement |
| **Website** | <https://rigindustrialusa.com> |
| **Community License** | Apache License 2.0 |

## License

RIG Sentinel Community is licensed under the [Apache License, Version 2.0](LICENSE).
Copyright 2026 Randy Igualguana. See [NOTICE](NOTICE) for attribution.

The Apache License 2.0 grants its permissions to everyone. Any separate commercial
arrangement between the maintainer and RIG Industrial Technologies LLC does not limit the
rights that the Apache License 2.0 grants to users of RIG Sentinel Community.
