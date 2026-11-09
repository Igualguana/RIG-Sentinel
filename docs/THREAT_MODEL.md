# Threat Model — Policy & Authorization Engine

> **Scope:** the Genesis B policy engine (`rig_sentinel.policy`). **Status:** milestone M1
> with B2-M1 security hardening, development branch. This document states what the engine
> does and does not protect against. An authorization engine **cannot by itself** detect
> prompt injection, authenticate an agent, identify the filesystem object behind a path,
> or stop a tool call that bypasses it.

Phase key: **B** policy engine · **C** behavior and manipulation detection · **D** runtime
protection and enforcement adapters · **E** attack simulation and verification ·
**F** product and UX. "M1/M2/M3/M4" are Genesis B milestones.

## Trust boundaries

| ID | Boundary | Trusted side | Untrusted side |
|---|---|---|---|
| TB1 | Agent/LLM output → enforcement adapter | Adapter | Tool name, arguments and identity chosen by the model |
| TB2 | Adapter → engine (in-process call) | Engine code | Request content (validated on entry). Identity, assurance, tool identity, resource and labels are **caller-asserted**; the engine cannot authenticate them. |
| TB3 | Policy file → loader | Loader and validator | File bytes on disk |
| TB4 | Approver → approval verifier | Verifier (M3) | Approval grants presented with requests |
| TB5 | Engine/adapter → audit sink | Redactor (M2) | Log storage and its readers |
| TB6 | MCP server → registry/adapter | Policy registry, pinned digests | Tool manifests, descriptions and outputs |
| TB7 | Scanned repository → scanner (v0.1.0) | Scanner | Repository content |
| TB8 | Resource name → real object | Adapter's resource identity verification and provider canonicalization (D) | Path, URL, table and secret-path spelling; filesystem, server, database and secret-store alias behavior |

## Threats

| # | Threat | Scenario | Boundary | Control (status) | Tests | Residual risk | Phase |
|---|---|---|---|---|---|---|---|
| T1 | Unauthorized MCP tool execution | Agent calls a tool no rule allows | TB1/TB2 | Default deny; unregistered tool → `UNKNOWN_TOOL` before rules (**M1**) | `test_policy_engine.py` default-deny and unknown-tool cases | A call that never reaches an adapter is not stopped | B (decision), D (enforcement) |
| T2 | Excessive permissions | `agents=*`, `tools=*` allow | TB3 | Lint `BROAD_ALLOW`/`HIGH_RISK_ALLOW`; deny-overrides allows narrowing (**M1**) | `test_policy_validation.py` lint tests | Humans can still approve broad policies | B, F |
| T3 | Prompt injection causing tool misuse | Injected text tells the agent to e-mail data | TB1 | Engine bounds impact to the allowed set; rules can deny egress when a trusted label such as `untrusted_content_present` is present (**M1**). **No detection.** | `test_deny_overrides_require_approval`, `test_context_labels_are_caller_asserted` | Injected requests inside the allowed set are allowed; an adapter that omits the label disables label rules | C (detect), B (bound), E (verify) |
| T4 | Tool impersonation / name spoofing | `send` on another server, `mcp://gmai1/send`, look-alike characters, changed tool description | TB6 | Fully qualified ids, ASCII-only grammar, registry membership, `manifest_sha256` pin (**M1**) | `test_spoofed_tool_ids`, `test_lookalike_tools_are_unknown`, `test_manifest_pinning`, Unicode tests | The adapter must report the server identity and manifest digest honestly | B, D |
| T5a | Lexical resource manipulation | `..` traversal, `/srv/data2` vs `/srv/data/**`, `user@host` URLs, percent-encoding, device names, mixed separators | TB1/TB2 | Engine-side canonicalization; segment-boundary prefixes; ambiguous forms rejected (**M1**) | `test_policy_resources.py`, `test_policy_matching.py`, `test_ambiguous_fs_identifiers_are_rejected` | — | B |
| T5b | **Alias bypass of path rules (F-1)** | `deny fs:/srv/secret/**` carved out of `allow fs:/**` (alias → ALLOW) or out of `require_approval fs:/**` or a `require_approval` default (alias → REQUIRE_APPROVAL); request `fs:/srv/Secret/key` or `fs:/srv/SECRET~1/key` | TB8 | Blocking policy-shape constraints on `fs:`/`url:`: `UNSAFE_PATH_CARVE_OUT`, `ALIAS_DOWNGRADE_RISK`, `PATH_CASE_CONFLICT`. Allowlists fail closed for name aliases (**M1 hardening**) | `test_policy_hardening.py` F-1 and downgrade sections | **Partially mitigated.** Links (symlinks, junctions, hard links, mounts) inside an allowed directory can still reach outside objects; time-of-check/time-of-use. The engine cannot prove object identity. | B (policy shape), **D** (resource identity verification) |
| T5d | Alias bypass of `db:`/`secret:` rules | `allow db:crm/**` + `deny db:crm/salaries`; request `db:crm/public.salaries` (schema-qualified name). `allow secret:kv/**` + `deny secret:kv/app/key`; request `secret:kv/data/app/key` (a key-value engine's API path). These examples are provider-specific, not universal. | TB8 | Same blocking structure checks as `fs:`/`url:` (`UNSAFE_PATH_CARVE_OUT`, `ALIAS_DOWNGRADE_RISK`): no deny/approval rule may be nested in an overlapping weaker rule or default. No provider canonicalization (**M1 hardening**) | `test_reported_db_alias_case_is_rejected`, `test_reported_secret_alias_case_is_rejected`, `test_db_and_secret_unsafe_shapes_are_rejected`, `test_alternate_identifiers_fail_closed_under_db_secret_allowlists` | **Partially mitigated.** Sibling and cross-authority aliases are accepted and bypassable (`allow secret:kv/data/**` + `deny secret:kv/app/key`; `allow db:other/**` + `deny db:crm/**` via `db:other/crm.dbo.salaries`), pinned by `test_known_alias_gaps_are_accepted_and_bypassable`. Views, synonyms and mounts are invisible. | B (nesting), **D** (canonical provider identity) |
| T5e | Semantic alias of `shell:`/`email:` rules | `deny shell:rm` while `shell:unlink` is allowed; `deny email:rival.example.com` while a subdomain is allowed | TB8 | **None in the engine** (aliases are semantic, not structural). Guidance: allowlists only | `test_known_alias_gaps_are_accepted_and_bypassable` | **Open** | D (sandboxing, recipient verification) |
| T5c | Unicode confusables / normalization | NFC vs NFD, Cyrillic look-alikes, zero-width, bidi controls, case mappings to ASCII | TB1/TB2 | ASCII-only identifiers and resources; no normalization (**M1**) | `test_policy_hardening.py` Unicode sections | Non-ASCII names cannot be expressed at all | B |
| T6 | Unauthorized database writes | Read tool asked for `database_write` | TB1 | Registry declares operations per tool → `OPERATION_NOT_DECLARED` (**M1**) | `test_privilege_escalation_via_operation_relabel` | SQL inside an allowed read tool is not parsed | B, D (read-only credentials) |
| T7 | Unauthorized shell execution | `execute` on `shell:bash` | TB1 | `execute` is protected; deny rules override allows; lint warns (**M1**) | `test_deny_overrides_allow` | Argument injection inside an allowed command; deny lists of commands are incomplete by nature | B, D (sandbox) |
| T8 | Sensitive-data exfiltration | Read a secret, then send it out | TB1 | Per-call rules on `external_send`/`network` with resource allowlists; approval for egress (**M1**) | mail and fetch cases in `test_policy_engine.py` | Multi-step flows; covert channels via allowed destinations | B, C, D |
| T9 | Privilege escalation | Relabel operation, claim another agent id, edit the policy through an allowed write | TB1–TB3 | Undeclared operation denied; no rule priority; allowlist the writable paths so the policy directory is never inside an allow (**M1**) | `test_deny_overrides_overlapping_allow_on_same_path`, operation relabel test | An adapter that forwards agent-claimed identity (`test_assurance_is_taken_from_the_request_not_verified`) | B, D |
| T10 | Policy tampering / substitution | Swap in a permissive policy, or a malformed one hoping for fail-open | TB3 | Strict validation, whole-policy rejection, SHA-256 fingerprint and pin, engine re-validation (**M1**) | `test_policy_loader.py`, `test_digest_pin_mismatch_denies_everything`, tampering tests | Attacker who controls both the file and the pin; no signing yet | B, D |
| T11 | Approval replay | Reuse an approval for another call or resource | TB4 | M1 computes a request-bound `request_binding_sha256`; grant verification, expiry and single-use are **M3** | `test_approval_binding_is_request_specific` | Approvals cannot be granted at all in M1 | B (M3), D, F |
| T12 | Missing or forged identities | No agent, empty id, look-alike id, `*` as id, self-asserted `authenticated` | TB1/TB2 | Missing → `MISSING_IDENTITY`; strict grammar → `INVALID_IDENTITY`; `min_assurance` conditions (**M1**). **No authentication**: assurance is a caller-supplied label | `test_missing_identity`, `test_forged_or_invalid_identity`, `test_assurance_is_taken_from_the_request_not_verified`, `test_requests_carry_no_credential_fields` | Forgery at the source is invisible to the engine | B, **D** (authenticated context) |
| T13 | Enforcement bypass | Agent calls the tool directly, or the adapter ignores decisions | outside B | `enforced: false` in every record; documented adapter contract | `test_policy_isolation.py` (engine never executes) | **Not solvable in Genesis B** | D, E |
| T14 | Fail-open conditions | Exception, empty policy, unknown enum, hostile input | TB2/TB3 | `Exception` → DENY; default `allow` impossible; pre-built fallback deny (**M1**) | `test_exception_subclasses_become_deny`, clock and hostile-mapping tests, fuzz test | `BaseException`, process death, real OOM and blocking callables produce **no decision**; adapters must treat that as "do not invoke" (`test_base_exceptions_propagate`) | B, D, E |
| T15 | Secret exposure in logs | Secrets in arguments or exception messages | TB5 | Records hold no tool arguments; exception messages never recorded; validation issues never echo values (**M1**). Redaction and audit events are **M2** | `test_validation_errors_do_not_echo_values`, `test_exception_in_matcher_fails_closed` | Canonical resources and ids can be sensitive metadata | B (M2) |
| T16 | Availability (policy or request DoS) | Huge, deeply nested or combinatorial policy; oversized request | TB2/TB3 | Size, count and depth limits checked before or during parsing; linear path analysis (**M1 hardening**) | `test_policy_limits.py` | No timeout exists inside the engine; a slow or hostile caller-supplied clock or mapping can block | B, D (process isolation) |

## Adapter contract (normative for Genesis D)

See [POLICY_ENGINE.md › Trust boundary and adapter security contract](POLICY_ENGINE.md#trust-boundary-and-adapter-security-contract).
In short:
1. Derive identity and context from the adapter's own authentication.
2. Map tool arguments to exactly one canonical resource.
3. Resolve that resource to the real object, and require `ALLOW` for both the requested
   and the resolved identifier.
4. Operate on the checked handle.
5. Invoke only on a returned `ALLOW`.
6. Allow no bypass path to the tool or its credentials.
