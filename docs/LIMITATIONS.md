# Limitations and Scope

RIG Sentinel v0.1.0 is a **static, heuristic** analyzer. This page explains what its
results mean and, just as importantly, what they do not mean.

## How to read the results

| Result | What it means | What it does **not** mean |
|---|---|---|
| **Detected agent** | A file combines signals (AI provider usage plus tools, credential references or MCP usage) that resemble an AI agent. It is a **heuristic candidate**. | That the file is a deployed agent, or that the inventory is complete. |
| **Identity / credential reference** | The source references a known credential *name* such as `OPENAI_API_KEY`. | That a secret value is present, valid, leaked or exposed. RIG Sentinel never reads or reports values. |
| **Shared credential reference** | Two or more agents reference the same credential **name**. | **That they use the same underlying secret.** Different environments, deployments or secret managers can bind the same variable name to different values. Verify before acting. |
| **Credential flow** | A credential variable appears to reach a capability in Python code. `unproven` means no supported capability binding was found. | Proof of data flow at runtime. |
| **Attack path** | A **modeled possibility**: agent → tool → permission → resource, derived from detected capabilities. | A demonstrated or exploitable vulnerability. |
| **Risk propagation** | A modeled relationship between agents that share identity references. Reports state `Confirmed lateral movement: No`. | Evidence of lateral movement. |
| **Blast radius (0–100)** | A **heuristic estimate** based on reachable resources and path severities. | A measured incident impact, a breach probability, or a confirmed incident. |
| **Shadow agent** | An agent candidate not listed in `.rig-sentinel.toml`. | That the agent is unauthorized or malicious. |
| **Security policy** | An **advisory** recommendation (`Enforcement: advisory`). | Runtime enforcement. RIG Sentinel blocks nothing. |
| **Severity (CRITICAL/HIGH/…)** | Relative prioritization for review. | A CVSS score or confirmed exploitability. |

## Analysis scope

- **Static only.** Code is parsed and pattern-matched; it is never imported or executed.
  Runtime configuration, secret managers, cloud IAM, network policies, container
  sandboxes and deployed permissions are not observed.
- **Python-focused depth.** Python files get AST-based analysis (imports, calls,
  credential flow). Other file types receive text and JSON based detection only.
- **Supported providers:** OpenAI, Anthropic, LangChain, CrewAI.
- **Supported credential names:** a fixed list of well-known names (OpenAI, Anthropic,
  Stripe, GitHub, AWS, Google, Azure, generic database credentials). Custom names are not
  recognized.
- **Supported capabilities:** shell execution, filesystem write/delete, outbound HTTP,
  e-mail sending.
- **MCP:** `mcpServers` JSON blocks, `mcp.json` / `mcp-config.json` / `mcp_config.json`
  files, Python MCP SDK imports, `FastMCP` and `mcp.server.Server`. Individual MCP server
  permissions and remote MCP endpoints are not evaluated.

## Files that are not scanned

- Directories named `tests`, `test`, `__tests__`, `fixtures`, `examples`, `vendor`,
  `node_modules`, `dist`, `build`, virtual environments and caches are skipped **anywhere
  in the tree**. Agents that live in such directories will not be reported.
- Files larger than 1 MB.
- File types outside the supported extension list (see [CLI_REFERENCE.md](CLI_REFERENCE.md#what-is-scanned)).

## Accuracy

False positives and false negatives are expected. Precision work in v0.1.0 includes
regression tests derived from reviewing public projects (OpenAI Agents SDK and the MCP
reference servers), for example excluding documentation, CI workflows and tests from
agent classification. These are regression fixtures, not a benchmark; no accuracy rate
is claimed.

## SARIF

- **SARIF 2.1.0 works as an export format** and output is valid SARIF 2.1.0.
- Results include a file location only when the path is relative and uses forward
  slashes. Scans on Windows produce results **without locations**, and some finding types
  never carry a location.
- Because GitHub code scanning expects result locations, **uploading RIG Sentinel SARIF to
  GitHub code scanning is not a verified integration in v0.1.0**. Use SARIF as a build
  artifact or with tools that accept location-less results.

## Platform validation

| Platform | Status |
|---|---|
| Windows, Python 3.13 | Validated (179 tests) |
| Ubuntu 24.04 / 26.04, Python 3.13 | Validated in GitHub Actions |
| macOS 15 Intel, Python 3.13 | Validated in GitHub Actions |
| **macOS Apple Silicon (`macos-latest`)** | **Pending validation.** The CI job has not yet been assigned a GitHub-hosted runner (runner capacity), so no result exists yet. This is not a known code failure; the package is pure Python with no native dependencies. Apple Silicon runs in a separate workflow (`ci-macos-arm64.yml`) with its own status badge. |
| Python 3.11 / 3.12 | Declared supported (`requires-python >= 3.11`) but not yet exercised in CI |

## CI behavior

- The exit code is `0` regardless of findings. RIG Sentinel never fails a pipeline on its
  own; gating must be implemented separately.
- A missing target directory produces a Python traceback and a non-zero exit code.

## Report privacy

- JSON and HTML reports include the **absolute path** of the scanned directory.
- Reports include file paths and credential **names**.
- Review and sanitize reports before attaching them to public issues.

## Not included in v0.1.0

- Runtime monitoring, permission firewall or enforcement (Phase 2 — planned, not
  implemented).
- SaaS / hosted service, dashboard or database.
- Cloud, identity-provider or SaaS connectors.
- Automatic remediation or pull-request generation.
- Enterprise features (Phase 3 — future, separate product, not part of this repository
  and not available).

See [ROADMAP.md](ROADMAP.md).
