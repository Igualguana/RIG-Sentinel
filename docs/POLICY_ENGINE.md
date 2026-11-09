# Policy & Authorization Engine (Genesis B2 — Milestone M1)

> **Status: pre-release, development branch only.** Not part of RIG Sentinel
> Community v0.1.0. The API and schema may change before release.

The policy engine is a **deterministic decision point** for AI-agent tool requests.
Given a validated policy and a request ("agent *A* wants to perform operation *O* with
tool *T* on resource *R*"), it returns one of three decisions:

| Decision | Meaning for an enforcement adapter |
|---|---|
| `ALLOW` | The policy permits the request. |
| `DENY` | The policy forbids the request, or something was wrong (fail closed). |
| `REQUIRE_APPROVAL` | The policy requires a human approval. **Treat as not allowed.** |

## What this engine is — and is not

| It **is** | It is **not** |
|---|---|
| A pure function: `(policy, request, clock) → decision record` | A firewall, proxy or runtime monitor |
| Deterministic, order-independent and fail-closed | A prompt-injection or behavior detector |
| Independent of the scanner, the CLI and any MCP SDK | An authenticator (it trusts the adapter's identity claims) |
| A library a trusted adapter can call before invoking a tool | Something that blocks, executes or approves anything itself |

Every decision record contains **`"enforced": false`**. A decision only has an effect if a
separate, trusted **enforcement adapter** checks it *before* invoking a tool and refuses to
invoke the tool unless the decision is `ALLOW`. No such adapter exists yet; adapters are
planned for Genesis D (runtime protection). Until then, decisions are **advisory**, like
the `Enforcement: advisory` policies that the v0.1.0 scanner prints.

The engine also never activates policies on its own: it does not search for policy files,
and it does not accept the scanner's advisory `SecurityPolicy` output as a policy.

## Architecture (M1)

```text
policy.toml ──▶ loader.py ──▶ validation.py ──▶ Policy (frozen, canonical, sha256)
 (bytes)        size/UTF-8      strict schema              │
                TOML parse      every issue reported       ▼
                digest pin                          engine.py: PolicyEngine
                                                     re-validates the policy,
request (dict or AuthorizationRequest) ───────────▶  evaluate(request) ──▶ DecisionRecord
                                                     (never raises; no I/O)
```

| Module | Responsibility |
|---|---|
| `policy/model.py` | Enums (`Decision`, `Effect`, `OperationClass`, `Assurance`, `Environment`), request types, policy types, `parse_request` |
| `policy/identifiers.py` | Identifier and tool-id grammars |
| `policy/resources.py` | Resource parsing and canonicalization |
| `policy/matching.py` | Pattern parsing, rule compilation and matching |
| `policy/schema.py` | Schema version, allowed fields, limits, issue codes |
| `policy/validation.py` | `validate_policy`, `lint_policy`, `policy_sha256` |
| `policy/loader.py` | `load_policy_file` / `_bytes` / `_text`, `check_policy_digest` |
| `policy/canonical.py` | Canonical JSON and domain-separated SHA-256 digests |
| `policy/engine.py` | `PolicyEngine.evaluate` |
| `policy/decision.py` | `DecisionRecord`, `ApprovalRequirement` |
| `policy/reasons.py` | `ReasonCode` |
| `policy/errors.py` | Exceptions and `PolicyIssue` |

Standard library only; no new dependencies. Python 3.11+ syntax, validated on 3.13.

## Quick start

```python
from rig_sentinel.policy import PolicyEngine, load_policy_file

policy = load_policy_file("policy.toml")            # raises on any problem
engine = PolicyEngine(policy, expected_policy_sha256=policy.sha256)

record = engine.evaluate({
    "agent": {"id": "support-bot", "assurance": "authenticated"},
    "tool": {"id": "mcp://helpdesk/tickets.get"},
    "operation": "read",
    "resource": "db:helpdesk/tickets",
    "context": {"environment": "staging", "session_id": "s-1", "request_id": "r-1"},
})

if record.allowed:          # True only for ALLOW
    ...                     # a future enforcement adapter would invoke the tool here
```

## Policy schema (`rig.policy/v1`)

Policies are TOML. Every table rejects unknown fields. Types are strict (a TOML boolean
is not an integer; dates are not strings).

```toml
schema_version = "rig.policy/v1"     # required; only this value is accepted
policy_id      = "acme-support"      # required; identifier
policy_version = "2026.11.09-1"      # required; 1-64 chars of [A-Za-z0-9._+-]
description    = "optional, single line, ≤ 1024 chars"

[defaults]                           # optional
decision             = "deny"        # "deny" (default) or "require_approval"; "allow" is rejected
approval_ttl_seconds = 300           # 30-3600, default 300

[[tools]]                            # the tool registry
id              = "mcp://helpdesk/tickets.get"   # required; <mcp|local>://<server>/<tool>
operations      = ["read"]                       # required; operation classes this tool performs
protected       = true                           # optional, default true
resource_kind   = "db"                           # optional; requests must use this resource kind
manifest_sha256 = "<64 lowercase hex>"           # optional; pins the tool definition
description     = "..."

[[approvers]]
id     = "oncall-lead"                           # identifier
scopes = ["approve-ticket-updates"]              # rule ids, or ["*"]

[[rules]]
id          = "read-tickets"                     # unique identifier
effect      = "allow"                            # "allow" | "deny" | "require_approval"
agents      = ["support-bot"]                    # identifiers, or ["*"]
tools       = ["mcp://helpdesk/tickets.get"]     # tool ids, "<scheme>://<server>/*", or ["*"]
operations  = ["read"]                           # operation classes, or ["*"]
resources   = ["db:helpdesk/tickets"]            # resources, "<prefix>/**", or ["*"]
description = "..."

[rules.conditions]                               # optional; all listed conditions must hold
environment   = ["dev", "staging"]               # dev | staging | prod
min_assurance = "authenticated"                  # asserted | authenticated
labels_all    = ["reviewed"]                     # request must carry all of these labels
labels_none   = ["untrusted_content_present"]    # request must carry none of these labels
```

### Identifiers

Agent, policy, rule, approver, label, session and request ids use
`[a-z0-9][a-z0-9._-]{0,127}`: lowercase ASCII only. Uppercase, whitespace and non-ASCII
(including look-alike characters) are rejected, never normalized.

Tool ids are fully qualified: `mcp://<server>/<tool>` or `local://<namespace>/<tool>`.
Rules never match bare tool names, so `send` on one server cannot inherit a rule written
for another server.

### Operation classes

`read`, `write`, `delete`, `execute`, `network`, `external_send`, `financial`,
`database_write`, `credential_access`, `admin`. The first seven match the capability
categories reported by the v0.1.0 scanner. Every class except `read` is *protected*.

### Validation guarantees

- The whole policy is rejected if any issue is found; all issues are reported at once,
  with field paths such as `rules[2].effect` and **without echoing raw values**.
- Rejected: unknown fields anywhere (for example `priority`, `override`, `enforcement`),
  unsupported or wrongly-cased values (`"Allow"`), `defaults.decision = "allow"`,
  duplicate rule/tool/approver ids, duplicate patterns (also after normalization), `*`
  mixed with other entries, rules that reference unregistered tools,
  `require_approval` rules without an approver in scope, conflicting label conditions,
  and size/count limits (256 KiB, 1000 rules, 500 tools, 64 patterns per field).
- Loader: UTF-8 only (no BOM), malformed TOML rejected, nesting-depth errors rejected.
- `lint_policy()` returns non-blocking warnings: `BROAD_ALLOW` (all agents and all tools),
  `HIGH_RISK_ALLOW` (execute/financial/credential/admin), `UNUSED_TOOL`,
  `UNPROTECTED_WRITE_TOOL`.

### Policy fingerprint and pinning

`policy.sha256` is the SHA-256 of the policy's canonical JSON (fields sorted; rules,
tools, approvers and patterns sorted; patterns normalized), prefixed with the domain tag
`rig.policy/v1`. Comments, whitespace and rule order do not change it; any semantic
change, including descriptions and `policy_version`, does.

Pin it with `load_policy_file(path, expected_sha256=...)` (raises
`PolicyDigestMismatchError`) and/or `PolicyEngine(policy, expected_policy_sha256=...)`
(every request is denied with `POLICY_DIGEST_MISMATCH`). The engine recomputes the
digest itself, so an altered `Policy.sha256` attribute has no effect.

## Supported resource formats

Resources are `<kind>:<value>`. The engine parses and canonicalizes them itself. All
resources must be visible ASCII with no whitespace or control characters, at most 2048
characters.

| Kind | Form | Canonicalization | Rejected |
|---|---|---|---|
| `fs` | `fs:/abs/path` | `//` and `.` collapsed, trailing `/` removed | relative paths, leading `//`, `..`, `\`, `%`, `:`, segments ending in `.`, wildcards |
| `db` | `db:<database>[/<table>]` | — | uppercase, more than two parts |
| `url` | `url:http(s)://host[:port][/path]` | host lowercased, default port removed, path as `fs` | credentials (`@`), query, fragment, `%`, `\`, other schemes, IPv6, numeric/hex host names like `1.2.3` or `0x7f000001` |
| `shell` | `shell:<command-name>` | — | paths, arguments, whitespace |
| `email` | `email:<domain>` | lowercased | IP literals |
| `secret` | `secret:<name>[/<name>…]` | — | uppercase, more than 16 parts |
| `none` | `none:` | — | any value |

Resource patterns in rules: `*`, an exact resource, or a hierarchical prefix ending in
`/**` (`fs`, `db`, `url`, `secret` only). A prefix matches the prefix itself and anything
below it **at segment boundaries**: `fs:/srv/data/**` matches `fs:/srv/data` and
`fs:/srv/data/a/b`, but not `fs:/srv/database`. No other wildcards or regular expressions
exist.

## Decision precedence

Evaluation runs in this fixed order; the first step that produces a decision wins.

1. **Engine state.** No valid policy → `DENY / POLICY_UNAVAILABLE`. Pin mismatch →
   `DENY / POLICY_DIGEST_MISMATCH`.
2. **Request validation**, in order: identity (`MISSING_IDENTITY`, `INVALID_IDENTITY`),
   tool id (`INVALID_TOOL_ID`), operation (`UNKNOWN_OPERATION`), resource
   (`INVALID_RESOURCE`), anything else (`INVALID_REQUEST`) → `DENY`.
3. **Tool registry.** Tool not registered → `DENY / UNKNOWN_TOOL` (even if a rule says
   `tools = ["*"]`). Pinned manifest missing or different → `TOOL_MANIFEST_MISMATCH`.
   Operation not declared for the tool → `OPERATION_NOT_DECLARED`. Resource kind differs
   from the tool's `resource_kind` → `RESOURCE_KIND_MISMATCH`.
4. **Rules (deny-overrides).** All matching rules are collected:
   - any `deny` → `DENY / RULE_DENY`
   - else any `require_approval` → `REQUIRE_APPROVAL / RULE_REQUIRES_APPROVAL`
   - else any `allow` → `ALLOW / RULE_ALLOW`
   - else the default: `DENY / DEFAULT_DENY` or
     `REQUIRE_APPROVAL / DEFAULT_REQUIRE_APPROVAL`.

Rule order in the file never matters, and rules have no priority field. A narrow `deny`
always beats a broad `allow`; an approval requirement always beats an `allow`; nothing
beats a `deny`. To make an exception, write a narrower deny, not a broader allow.

### Fail-closed semantics

- `PolicyEngine.evaluate()` never raises `Exception`. Any unexpected error (a failing
  clock, a hostile mapping, an internal bug) returns `DENY / EVALUATION_ERROR` with
  `error_type` set to the exception class name only. The message is never recorded,
  because it may contain request data.
- If even building that record fails, a pre-built `DENY` record is returned.
- Requests are copied once and fully re-validated, including typed
  `AuthorizationRequest` objects, so mutating the input during or after evaluation has
  no effect.
- The policy passed to `PolicyEngine` is re-validated; a tampered `Policy` object
  results in deny-all.
- `BaseException` (`KeyboardInterrupt`, `SystemExit`) propagates. **Adapters must treat
  anything other than a returned `ALLOW` record as "do not invoke".**

## Decision record (`rig.decision/v1`)

```json
{
  "record_schema": "rig.decision/v1",
  "decision": "REQUIRE_APPROVAL",
  "reason_code": "RULE_REQUIRES_APPROVAL",
  "deciding_rule_ids": ["approve-ticket-updates"],
  "matched_rule_ids": ["approve-ticket-updates"],
  "policy_id": "acme-support-agents",
  "policy_version": "2026.11.09-1",
  "policy_sha256": "a78a…",
  "schema_version": "rig.policy/v1",
  "engine_version": "genesis-b2-m1",
  "request_digest": "1aa3…",
  "evaluated_at": "2026-11-09T15:04:05.123456Z",
  "protected": true,
  "approval": {
    "eligible_approvers": ["oncall-lead"],
    "request_binding_sha256": "cf43…",
    "ttl_seconds": 300
  },
  "error_type": null,
  "enforced": false,
  "decision_digest": "f699…"
}
```

- `deciding_rule_ids` are the rules with the winning effect; `matched_rule_ids` are all
  matching rules. Both are sorted.
- `request_digest` is the SHA-256 of the canonical request. Spelling variants of the same
  request, such as label order or `fs:/a//b`, produce the same digest.
- `decision_digest` covers every other field. With a fixed clock, the same policy and
  request always produce a byte-identical record.
- `approval` describes what an approval would have to bind to (agent, tool, operation,
  canonical resource, environment, session, policy digest). **M1 does not issue, verify
  or consume approvals**, so no approval can turn a decision into `ALLOW` yet.

## Examples

These use the baseline policy in `tests/policy_fixtures.py`.

| Request | Decision | Reason | Deciding rule(s) |
|---|---|---|---|
| `support-bot` reads `db:helpdesk/tickets` in staging (authenticated) | `ALLOW` | `RULE_ALLOW` | `read-tickets` |
| same, in `prod` | `DENY` | `DEFAULT_DENY` | — |
| same, with `assurance = asserted` | `DENY` | `DEFAULT_DENY` | — |
| `support-bot` updates a ticket (`database_write`) | `REQUIRE_APPROVAL` | `RULE_REQUIRES_APPROVAL` | `approve-ticket-updates` |
| `support-bot` e-mails `customer.example.com` (matched by an allow **and** an approval rule) | `REQUIRE_APPROVAL` | `RULE_REQUIRES_APPROVAL` | `approve-customer-mail` |
| same, with label `untrusted_content_present` | `DENY` | `RULE_DENY` | `tainted-no-egress` |
| `ops-bot` runs `shell:git` (allowed **and** denied) | `DENY` | `RULE_DENY` | `no-shell-anywhere` |
| `build-agent` writes `fs:/srv/workspace/.rig-sentinel/policy.toml` | `DENY` | `RULE_DENY` | `protect-policy-dir` |
| `build-agent` writes `fs:/srv/workspace/tmp/../.rig-sentinel/policy.toml` | `DENY` | `INVALID_RESOURCE` | — |
| `support-bot` calls unregistered `mcp://helpdesk/tickets.delete` | `DENY` | `UNKNOWN_TOOL` | — |
| `support-bot` asks the read-only tool for `database_write` | `DENY` | `OPERATION_NOT_DECLARED` | — |
| request without an agent | `DENY` | `MISSING_IDENTITY` | — |

## Known limitations (M1)

- **No enforcement.** Nothing is blocked unless a trusted adapter enforces decisions;
  adapters are Genesis D. Do not describe M1 as protecting a production system.
- **No prompt-injection detection.** The engine limits what *any* request can do to what
  the policy allows. A manipulated request that falls inside the allowed set is allowed.
  Context labels such as `untrusted_content_present` must come from a trusted source
  (Genesis C detectors or the adapter); the engine cannot verify them.
- **Identity is asserted by the caller.** `assurance` and `agent.id` are whatever the
  adapter supplies; authentication is outside the engine.
- **Lexical resource checks only.** No symlink, mount-point, case-folding or DNS
  resolution. Windows paths, non-ASCII paths, IPv6, URL queries and percent-encoded
  forms are rejected rather than interpreted. Adapters must invoke tools with the same
  canonical resource that was evaluated (time-of-check/time-of-use is a Genesis D
  concern).
- **Resource extraction is not defined.** Mapping a tool's arguments to a resource is
  the adapter's job (Genesis D).
- **Per-call decisions only.** Multi-step flows (read a secret, then send it out) need
  session or taint tracking (Genesis C/D).
- **Approvals are described, not processed.** Issuing, verifying, expiring and
  single-use consumption of approval grants is milestone M3.
- **No audit subsystem or secret redaction yet** (milestone M2). Decision records contain
  identifiers and canonical resources, which can be sensitive metadata.
- **No policy signing.** Digest pinning detects substitution only if the pinned value is
  stored somewhere the attacker cannot change.
- **No CLI.** `rig-sentinel policy …` commands and the scanner-to-policy draft generator
  are milestone M4. The existing `rig-sentinel scan` command is unchanged.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threat model and which Genesis phase owns
each residual risk.
