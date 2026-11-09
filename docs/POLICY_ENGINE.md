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
| Independent of the scanner, the CLI and any MCP SDK | An authenticator: it trusts the identity, assurance and context the caller supplies |
| A library a trusted adapter can call before invoking a tool | Something that blocks, executes or approves anything itself |
| A matcher of *names* (path and URL strings) | A resolver of *objects*: it cannot tell whether two paths are the same file |

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
                                                     (Exception → DENY; no I/O)
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
- Structure checks on hierarchical resources (`fs:`, `url:`, `db:`, `secret:`), which
  reject policies whose safety would depend on recognizing aliases (see
  [Alias safety](#alias-safety-hierarchical-resources)):
  - `PATH_CASE_CONFLICT`: the same prefix is spelled with different letter case in
    different places, for example `/srv/Data` and `/srv/data`. This can only happen for
    `fs:` and `url:`, because `db:` and `secret:` identifiers are lowercase-only.
  - `UNSAFE_PATH_CARVE_OUT`: a `deny` or `require_approval` rule protects a resource that
    lies strictly inside the resource pattern of an `allow` rule whose agents, tools and
    operations overlap with it.
  - `ALIAS_DOWNGRADE_RISK`: a `deny` rule protects a resource that lies strictly inside
    an overlapping `require_approval` rule, or denies an `fs:`/`url:`/`db:`/`secret:`
    resource while `defaults.decision = "require_approval"`. An alias would get
    REQUIRE_APPROVAL instead of DENY.

  The codes keep their `PATH` names for stability; they apply to all four kinds.

  These checks run after all per-field checks pass, so a policy with field errors
  reports those first.
- `lint_policy()` returns non-blocking warnings:
  - `BROAD_ALLOW`: an allow covering all agents and all tools.
  - `HIGH_RISK_ALLOW`: an allow covering execute, financial, credential or admin operations.
  - `UNUSED_TOOL`: a registered tool that no rule refers to.
  - `UNPROTECTED_WRITE_TOOL`: a non-read tool marked `protected = false`.

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
| `fs` | `fs:/abs/path` | `//` and `.` collapsed, trailing `/` removed | relative paths, leading `//` (UNC), `..`, `\`, `%`, `:` (drive letters, NTFS streams), segments ending in `.`, segments over 255 characters, Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, in any case, with or without an extension), wildcards |
| `db` | `db:<database>[/<table>]` | — | uppercase, more than two parts |
| `url` | `url:http(s)://host[:port][/path]` | host lowercased, default port removed, path as `fs`; scheme, host and port together form the URL's authority (`http://h`, `https://h` and `https://h:8443` are different authorities) | credentials (`@`), query, fragment, `%`, `\`, other schemes, IPv6, numeric/hex host names like `1.2.3` or `0x7f000001` |
| `shell` | `shell:<command-name>` | — | paths, arguments, whitespace |
| `email` | `email:<domain>` | lowercased | IP literals |
| `secret` | `secret:<name>[/<name>…]` | — | uppercase, more than 16 parts |
| `none` | `none:` | — | any value |

Resource patterns in rules: `*`, an exact resource, or a hierarchical prefix ending in
`/**` (`fs`, `db`, `url`, `secret` only). A prefix matches the prefix itself and anything
below it **at segment boundaries**: `fs:/srv/data/**` matches `fs:/srv/data` and
`fs:/srv/data/a/b`, but not `fs:/srv/database`. No other wildcards or regular expressions
exist.

### What an `fs:` identifier means in M1

An `fs:` resource is a **normalized absolute POSIX-style path string**: a name, not a
filesystem object. The engine never touches the filesystem and **cannot prove whether two
different identifiers refer to the same object**. Aliases it cannot see include:
- letter case on case-insensitive volumes (the NTFS and APFS defaults, though both can
  be case-sensitive)
- 8.3 short names on NTFS (`SECRE~1`, or any short name an administrator assigns, with
  or without `~`)
- symbolic links, junctions, hard links, bind mounts and mount points

Matching is **byte-for-byte and case-sensitive on every platform**. M1 does not fold case,
expand short names or resolve links, and it makes no claim about which filesystem a path
lives on. The same applies to `url:` paths, which some servers treat case-insensitively.

### What `db:` and `secret:` identifiers mean in M1

`db:<database>[/<table>]` and `secret:<name>[/<name>…]` are **opaque, lowercase ASCII
names**. The engine knows nothing about schemas, search paths, views, synonyms, database
links, identifier quoting, secret-engine mounts or API path layouts. Like `fs:`, it cannot
prove whether two identifiers refer to the same table or secret.

Providers can expose one object under several names. **The examples below are
provider-specific illustrations, not universal equivalences**, and the engine does not
treat any of them as equal:
- a database that resolves `public.salaries` and `salaries` to the same table (schema
  search path), or that accepts a cross-database name such as `crm.dbo.salaries` from
  another database;
- views and synonyms over a table, and case-folding of unquoted identifiers;
- a key-value secret engine that serves the same secret under its logical path and an API
  prefix such as `data/` (or exposes metadata under `metadata/`);
- secret-engine mount aliases, and stores whose names are case-insensitive.

### Alias safety: hierarchical resources

Since the engine compares names, the shape of a policy determines whether aliases fail
open or closed:

- **Allowlists fail closed.** With `allow fs:/srv/public/**`, any spelling the engine does
  not recognize (`fs:/srv/Secret/x`, `fs:/srv/SECRET~1/x`, even `fs:/srv/PUBLIC/x`)
  matches no allow and gets `DEFAULT_DENY`. A name alias cannot escape an allowed
  directory, because the allowed prefix is matched exactly and each aliased component
  resolves inside its parent directory. Links can, which is an adapter concern (below).
- **Carve-outs fail open.** With `allow fs:/**` plus `deny fs:/srv/secret/**`, the request
  `fs:/srv/Secret/key` matches the allow but not the deny, so it is **ALLOWED**, although
  on a case-insensitive volume it names the protected file (finding F-1).

- **The same holds for `db:` and `secret:`.** With `allow db:crm/**` plus
  `deny db:crm/salaries`, the request `db:crm/public.salaries` would be ALLOWED wherever
  the database resolves it to the same table. With `allow secret:kv/**` plus
  `deny secret:kv/app/key`, the request `secret:kv/data/app/key` would be ALLOWED wherever
  the store serves the same secret under that path.

M1 therefore rejects unsafe shapes instead of guessing filesystem, database or
secret-store semantics. The rule: on `fs:`, `url:`, `db:` and `secret:` resources, a rule may
not be nested **strictly inside** an overlapping rule, or the default, that has a
**weaker** effect (strength: deny > require_approval > allow). Nesting is evaluated
within one kind and one authority: for `url:` the scheme, host and port together, for
`db:` the database; `fs:` and `secret:` have a single authority. A `*` resource pattern
contains everything.

| Policy | Result |
|---|---|
| `allow fs:/**` + `deny fs:/srv/secret/**` (same agent/tool/operation) | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow *` + `deny fs:/srv/secret/**` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow fs:/srv/**` + `require_approval fs:/srv/secret/**` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow url:https://app.example.com/**` + `deny url:https://app.example.com/admin/**` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow *` + `deny url:https://admin.example.com/**` (host names have aliases too) | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `require_approval fs:/srv/**` + `deny fs:/srv/secret/**` | **rejected**: `ALIAS_DOWNGRADE_RISK` |
| `defaults.decision = "require_approval"` + `deny fs:/srv/secret/**` | **rejected**: `ALIAS_DOWNGRADE_RISK` |
| `allow fs:/srv/data/**` + `deny fs:/srv/Data/secret/**` | **rejected**: `PATH_CASE_CONFLICT` |
| `allow db:crm/**` + `deny db:crm/salaries` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow db:crm/**` + `require_approval db:crm/salaries` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `allow *` + `deny db:crm/**` (cross-database names) | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `require_approval db:crm/**` + `deny db:crm/salaries` | **rejected**: `ALIAS_DOWNGRADE_RISK` |
| `allow secret:kv/**` + `deny secret:kv/app/key` | **rejected**: `UNSAFE_PATH_CARVE_OUT` |
| `require_approval secret:kv/**` + `deny secret:kv/app/key` | **rejected**: `ALIAS_DOWNGRADE_RISK` |
| `defaults.decision = "require_approval"` + `deny db:…` or `deny secret:…` | **rejected**: `ALIAS_DOWNGRADE_RISK` |
| `allow fs:/srv/public/**` + `deny fs:/srv/secret/**` (siblings) | accepted |
| `allow fs:/srv/public/**` + `deny fs:/srv/**` (deny is broader) | accepted |
| `allow *` + `deny fs:/**`, or `deny fs:/**` under a `require_approval` default (every `fs:` alias is still under `fs:/**`) | accepted |
| `allow db:crm/orders` + `allow db:crm/customers` (explicit allowlist) | accepted |
| `allow secret:kv/app/api` + `deny secret:kv/app/key` (siblings) | accepted (see the residual gap below) |
| `allow db:crm/**` + `deny *` (deny on all resources) | accepted |
| `allow fs:/srv/secret/**` + `deny fs:/srv/secret` (exact name at the allowed prefix; not strictly nested) | accepted (see the residual risks below for `url:`) |
| allow, approval and deny rules for disjoint agents, tools or operations | accepted |

**Which root-wide denies are exempt.** Only `deny fs:/**` (the whole `fs:` namespace) and
deny rules with `resources = ["*"]`. No `db:`/`secret:`/`url:` pattern covers its whole kind:
every such pattern is scoped to one database, top-level secret name or host, and those
names have aliases too. To deny every database or secret for a tool, use
`resources = ["*"]`, scoped by agent, tool and operation.

Express the allowed set positively: list the directories, tables or secrets an agent may
use instead of granting a broad allow and subtracting exceptions. Rule `conditions` are
ignored by these checks, which assume the conditions can hold at the same time. Matching
semantics did not change: the checks only reject policies, with explicit error codes. No
opt-out exists.

**Compatibility consequences** (on every platform and with every provider):
- "Allow, or require approval for, everything under X except Y" cannot be written for
  `fs:`, `url:`, `db:` or `secret:` resources. This includes "all tables of a database
  except one" and "all secrets under a prefix except one".
- A policy with `defaults.decision = "require_approval"` cannot contain narrow
  `fs:`/`url:`/`db:`/`secret:` deny rules. Use the `deny` default, `deny fs:/**`, or a deny
  with `resources = ["*"]`.
- A policy may not mention the same `fs:`/`url:` path with different letter case.
- These policies are rejected with an explicit error. Earlier development builds accepted
  some of them; no released version did.

### Residual alias risks that static validation does not cover

The structure checks see **nesting within one kind and one authority**. They cannot see
an allow that is a *sibling* of a deny, or one under a different authority (database;
URL scheme, host or port; top-level secret name), that names an alias of the denied
resource. Recognizing that requires filesystem, server or provider semantics, which the
engine deliberately does not encode. This applies to every resource kind, `fs:` and
`url:` included.

**An identifier that matches an `allow` rule is ALLOWED, even if it names the same
underlying object as a resource that a `deny` rule protects under another identifier.**
The engine compares names; a deny protects only the names it matches. The following
policies are accepted, and the alias is **ALLOWED**:

| Policy (accepted) | Alias request that is ALLOWED | Why it can be the same object |
|---|---|---|
| `allow secret:kv/data/**` + `deny secret:kv/app/key` | `secret:kv/data/app/key` | Some key-value engines serve a secret under a `data/` API prefix |
| `allow db:other/**` + `deny db:crm/**` | `db:other/crm.dbo.salaries` | Some databases accept cross-database names |
| `allow *` + `deny shell:rm` (shell tool) | `shell:unlink` | A different command with the same effect |
| `allow *` + `deny email:rival.example.com` (mail tool) | `email:mail.rival.example.com` | Subdomains or other domains of the same recipient |
| `allow fs:/srv/SECRE~1/**` + `deny fs:/srv/secret/**` (siblings) | `fs:/srv/SECRE~1/key` | An 8.3 short name of the same directory on NTFS |
| `allow url:http://app.example.com/**` + `deny url:https://app.example.com/admin/**` | `url:http://app.example.com/admin/x` | Many servers serve the same content over `http` and `https`, or on another port |
| `allow url:https://www.app.example.com/**` + `deny url:https://app.example.com/admin/**` | `url:https://www.app.example.com/admin/x` | Host-name aliases (DNS names, IP addresses) can reach the same server |
| `allow url:https://app.example.com/admin/**` + `deny url:https://app.example.com/admin` (exact name at the allowed prefix) | `url:https://app.example.com/admin/index.html` | Many servers serve a default document for a directory path; whether `/admin` and `/admin/index.html` are the same resource depends on the server |

`tests/test_policy_hardening.py::test_known_alias_gaps_are_accepted_and_bypassable` pins
the first four rows, so they cannot be mistaken for guarantees. The `fs:` and `url:` rows
follow from the same name-only matching and are not pinned by a dedicated test; the
exact-name shape is pinned as accepted for `fs:` by
`test_alias_safe_shapes_are_accepted` ("deny of the allowed directory entry itself"). In
the same way, an explicit allow can always name an alias directly (a symlink path, a
view, a secret's API path).

**Safe policy:** for every resource kind, prefer **allowlists**, and do not rely on deny
rules to protect a resource that an allow could also reach under another name. For
`db:`, `secret:`, `shell:` and `email:`, use allowlists only. Under allowlists, an
alternate identifier that no allow names fails closed to `DEFAULT_DENY`
(`test_alternate_identifiers_fail_closed_under_db_secret_allowlists`); an alternate
identifier that an allow does name is ALLOWED.

**What would remain a trusted adapter's job (Genesis D, planned and not implemented):**
translating each request into the provider's canonical identity before evaluation:
- for databases, the fully qualified object from the live catalog, with views and
  synonyms resolved;
- for secret stores, the logical secret path, without API prefixes or mount aliases.

The adapter also refuses requests it cannot canonicalize.

**Narrowest further engine-side alternative (not implemented; for review):** reject any
`db:`/`secret:` deny or approval rule that shares a database (for `db:`) or a top-level secret
name (for `secret:`) with an overlapping allow, not only when nested. That would also reject
the two sibling rows above, at the cost of rejecting sibling allow/deny pairs, whose deny
is already redundant under default-deny. Cross-database and cross-name aliases would
still require the adapter.

**The `~` character is still accepted.** Rejecting it would not remove short-name aliases,
since administrators can assign short names without `~`, and would break common POSIX
names such as `notes~` or `~user` URL paths. With carve-outs rejected, a `~` alias that no
allow rule names gets `DEFAULT_DENY`; a `~` alias that an allow rule names (for example a
sibling `allow fs:/srv/SECRE~1/**`, see the table above) is ALLOWED.

### Unicode

Resources, identifiers, tool ids, labels and policy patterns are **ASCII-only**. Non-ASCII
input is rejected, never normalized. NFC and NFD forms, look-alike letters (Cyrillic `а`,
Greek `ο`), full-width forms, zero-width and bidirectional control characters, the BOM,
no-break spaces, and characters whose case mapping produces ASCII (`K` KELVIN SIGN → `k`,
`ſ` → `S`) all produce `DENY` (`INVALID_IDENTITY`, `INVALID_TOOL_ID`, `INVALID_RESOURCE`,
`INVALID_REQUEST` or `UNKNOWN_OPERATION`) for requests, and a validation error for
policies. Policy and rule `description` fields may contain printable Unicode, since they
are never matched.

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

### Fail-closed semantics (exact boundary)

What is guaranteed, and covered by tests:

- Any **`Exception` subclass** raised inside `PolicyEngine.evaluate()` returns
  `DENY / EVALUATION_ERROR`. This covers a failing clock, a hostile mapping, an internal
  bug, `RecursionError` and `MemoryError`. `error_type` holds the name of the exception
  class only if that class is one of Python's built-in `Exception` classes; any other
  class is recorded as `UnlistedError`. The class is matched by identity, so its name,
  metaclass and comparison methods are never used, and caller-supplied objects cannot
  place text in the record or make `evaluate()` raise. The message is never recorded,
  because it may contain request data.
- If building that error record also fails, a `DENY` record built at import time is
  returned.
- Requests are copied once and fully re-validated, including typed
  `AuthorizationRequest` objects, so mutating the input during or after evaluation has
  no effect.
- The policy passed to `PolicyEngine` is re-validated. A tampered `Policy` object, or any
  `Exception` during construction, results in deny-all (`POLICY_UNAVAILABLE`).

What is **not** guaranteed:

- `BaseException` subclasses that are not `Exception` (`KeyboardInterrupt`, `SystemExit`,
  `GeneratorExit`) propagate out of `evaluate()`; no record is returned.
- Real memory exhaustion can fail again while the error record is being built, the
  process can be killed (OOM killer, signals, crashes), and a hostile callable such as a
  custom clock or `Mapping` can block forever. In these cases there is no decision at
  all.
- **Adapters must treat anything other than a returned `ALLOW` record (an exception, a
  timeout, a crash, `DENY` or `REQUIRE_APPROVAL`) as "do not invoke".** A timeout has to
  be enforced by the adapter, for example by running evaluation in a separate process;
  `tomllib` parsing and `evaluate()` cannot be interrupted from inside the same thread.

### Size limits and denial of service

Policies are trusted operator input, but loading is still bounded:
- 256 KiB per policy; at most 1000 rules, 500 tools, 100 approvers and 64 patterns per
  field; 1024-character descriptions.
- Size is checked before parsing. Excessive nesting is rejected (`RecursionError` is
  turned into `PolicyLoadError`). Every unknown key is reported, but the exception
  message summarizes at most 10 issues.
- The path-structure checks use a prefix tree. Their cost is linear in the number of path
  segments, plus at most one scope comparison per (restrictive rule, allow rule) pair.
- Requests are bounded too: 2048-character resources, 32 labels, 128-character
  identifiers. Evaluation cost is at most rules × (tool patterns + resource patterns).

`tests/test_policy_limits.py` exercises the worst cases within these limits. There is
**no timeout**; see the adapter requirement above.

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
| `build-agent` writes `fs:/srv/workspace/src/main.py` | `ALLOW` | `RULE_ALLOW` | `write-workspace` |
| `build-agent` writes `fs:/srv/workspace/.rig-sentinel/policy.toml` | `DENY` | `RULE_DENY` | `protect-policy-dir` |
| `build-agent` writes `fs:/srv/workspace/tmp/../.rig-sentinel/policy.toml` | `DENY` | `INVALID_RESOURCE` | — |
| `support-bot` calls unregistered `mcp://helpdesk/tickets.delete` | `DENY` | `UNKNOWN_TOOL` | — |
| `support-bot` asks the read-only tool for `database_write` | `DENY` | `OPERATION_NOT_DECLARED` | — |
| request without an agent | `DENY` | `MISSING_IDENTITY` | — |

## Trust boundary and adapter security contract

The engine evaluates what it is told. Everything in a request is **caller-asserted**:
`agent.id`, `assurance`, `tool.id`, `manifest_sha256`, `resource`, `environment`, session
and request ids, and `labels`. The engine has no credential inputs; requests containing
fields such as `token` or `signature` are rejected as `INVALID_REQUEST`. It performs no
authentication, signature checks or mTLS. `assurance = "authenticated"` is a label the
caller sets, not something the engine verified.

A future enforcement adapter (Genesis D) must therefore provide the trust the engine
lacks. These requirements are design inputs for Genesis D; **none is implemented in M1**:

1. **Authenticated context.** Derive `agent.id` and `assurance` from the adapter's own
   authentication of the calling process or session, never from model output. Derive
   `tool.id` and `manifest_sha256` from the adapter's own connection to the tool server.
   Set `labels` only from trusted detectors.
2. **Resource extraction.** Map tool arguments to exactly one canonical resource per
   protected operation; refuse the call if that is ambiguous.
3. **Resource identity verification.** Before invoking a filesystem tool, resolve the
   requested path to the real object with OS facilities, without following links outside
   policy, and obtain the object's canonical path. Re-evaluate the policy for that
   resolved path. Proceed only if **both** the requested and the resolved identifiers are
   `ALLOW`. Hard links cannot be detected from a path at all; they need storage-level
   controls such as permissions or dedicated volumes.
4. **No time-of-check/time-of-use gap.** Operate on the handle that was resolved and
   checked; never reopen by name.
5. **Fail closed.** Invoke a tool only after receiving an `ALLOW` record from this
   evaluation. Treat exceptions, timeouts, crashes, `DENY` and `REQUIRE_APPROVAL` as "do not
   invoke". Run evaluation where a timeout can actually be enforced.
6. **No bypass.** The agent must have no other path to the tool or its credentials.

## Known limitations (M1)

- **No enforcement.** Nothing is blocked unless a trusted adapter enforces decisions;
  adapters are Genesis D. Do not describe M1 as protecting a production system.
- **No prompt-injection detection.** The engine limits what *any* request can do to what
  the policy allows. A manipulated request that falls inside the allowed set is allowed.
  Context labels such as `untrusted_content_present` must come from a trusted source
  (Genesis C detectors or the adapter); the engine cannot verify them.
- **No authentication.** Identity, assurance, tool identity, resource and labels are
  caller-asserted (see the trust boundary above).
- **Names, not objects.** Matching is lexical and case-sensitive. The engine cannot detect
  aliases: case-insensitive lookup, 8.3 short names, symbolic links, junctions, hard
  links, bind mounts, URL paths that a server treats case-insensitively, host-name
  aliases, schema-qualified or cross-database table names, views, synonyms, or alternate
  secret-store paths.
  - Policy-shape checks reject policies in which a deny or approval rule on `fs:`, `url:`,
    `db:` or `secret:` is **nested** inside an overlapping weaker rule or default.
  - They do not cover **sibling or cross-authority** aliases on any of these kinds (for
    `url:`, the authority is the scheme, host and port), or an exact-name deny at the
    same path as a prefix allow (see the residual table above). An alias that an allow
    rule matches is ALLOWED.
  - They do not protect allowlists against **links** or provider aliases that point
    outside the allowed set. That requires the adapter's resource identity verification.
- **Rejected rather than interpreted.** Windows paths, non-ASCII paths, IPv6, URL queries
  and percent-encoded forms are rejected. Some valid names are rejected too: Windows
  device names such as `con.txt`, and path segments longer than 255 characters.
- **No "everything except" policies on hierarchical resources.** Because carve-outs and
  downgrades are rejected, broad allows or approvals with exceptions on `fs:`, `url:`, `db:`
  or `secret:` resources cannot be expressed.
- **`shell:` and `email:` carve-outs are accepted but not alias-safe**, and neither are
  sibling or cross-authority patterns on `fs:`, `url:`, `db:` or `secret:` (see above).
  Use allowlists.

### Which guarantees belong to M1, and which depend on Genesis D

| Guarantee | M1 (this engine) | Would require Genesis D (planned adapter; not implemented) |
|---|---|---|
| Decision is deterministic, order-independent, default-deny | ✅ tested | — |
| `Exception` during evaluation → DENY | ✅ tested | Treat no-decision (crash, timeout, `BaseException`) as "do not invoke" |
| A policy is rejected when a deny/approval rule on `fs:`/`url:`/`db:`/`secret:` is nested in an overlapping weaker rule or default | ✅ tested | — |
| A request naming an alias of a protected `fs:` or `url:` resource is not allowed | ⚠️ **Partial, not guaranteed.** An alias that no allow rule matches gets `DEFAULT_DENY`. An alias that an allow rule matches (a sibling or cross-authority allow; for `url:` another scheme, host or port; a server's default document under an exact-name deny) is **ALLOWED**, even though a deny protects the same object under another name | **Links, junctions, hard links, mounts**: resolve the real object, check both identifiers, act on the checked handle. Server and host aliases: canonical URL identity |
| Same for `db:` and `secret:` | ⚠️ **Partial.** Nested carve-outs are rejected; ❌ sibling or cross-database/cross-name aliases are ALLOWED | Canonical provider identity (fully qualified table, logical secret path) |
| Same for `shell:` and `email:` | ❌ allowlist-only guidance | Semantic controls (sandboxing, recipient verification) |
| Identity, assurance, tool identity and labels are genuine | ❌ caller-asserted | Authenticated context |
| No time-of-check/time-of-use gap | ❌ out of scope | Operate on the checked handle |
| A decision is actually enforced | ❌ `enforced: false` | Adapter enforcement, no bypass path |

### Other limitations

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
