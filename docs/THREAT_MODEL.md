# Threat Model — Policy & Authorization Engine

> **Scope:** the Genesis B policy engine (`rig_sentinel.policy`). **Status:** milestone M1,
> development branch. This document states what the engine does and does not protect
> against. An authorization engine **cannot by itself** detect prompt injection, prove an
> agent's identity, or stop a tool call that bypasses it.

Phase key: **B** policy engine · **C** behavior and manipulation detection · **D** runtime
protection and enforcement adapters · **E** attack simulation and verification ·
**F** product and UX. "M1/M2/M3/M4" are Genesis B milestones.

## Trust boundaries

| ID | Boundary | Trusted side | Untrusted side |
|---|---|---|---|
| TB1 | Agent/LLM output → enforcement adapter | Adapter | Tool name, arguments and identity chosen by the model |
| TB2 | Adapter → engine (in-process call) | Engine code | Request content (validated on entry) |
| TB3 | Policy file → loader | Loader and validator | File bytes on disk |
| TB4 | Approver → approval verifier | Verifier (M3) | Approval grants presented with requests |
| TB5 | Engine/adapter → audit sink | Redactor (M2) | Log storage and its readers |
| TB6 | MCP server → registry/adapter | Policy registry, pinned digests | Tool manifests, descriptions and outputs |
| TB7 | Scanned repository → scanner (v0.1.0) | Scanner | Repository content |

## Threats

| # | Threat | Scenario | Boundary | Control (status) | Tests | Residual risk | Phase |
|---|---|---|---|---|---|---|---|
| T1 | Unauthorized MCP tool execution | Agent calls a tool no rule allows | TB1/TB2 | Default deny; unregistered tool → `UNKNOWN_TOOL` before rules (**M1**) | `test_policy_engine.py` default-deny and unknown-tool cases | A call that never reaches an adapter is not stopped | B (decision), D (enforcement) |
| T2 | Excessive permissions | `agents=*`, `tools=*` allow | TB3 | Lint `BROAD_ALLOW`/`HIGH_RISK_ALLOW`; deny-overrides allows narrowing (**M1**) | `test_policy_validation.py` lint tests | Humans can still approve broad policies | B, F |
| T3 | Prompt injection causing tool misuse | Injected text tells the agent to e-mail data | TB1 | Engine bounds impact to the allowed set; rules can deny egress when a trusted label such as `untrusted_content_present` is present (**M1**). **No detection.** | `test_deny_overrides_require_approval` | Injected requests inside the allowed set are allowed | C (detect), B (bound), E (verify) |
| T4 | Tool impersonation / name spoofing | `send` on another server, `mcp://gmai1/send`, look-alike characters, changed tool description | TB6 | Fully qualified ids, ASCII-only grammar, registry membership, `manifest_sha256` pin (**M1**) | `test_spoofed_tool_ids`, `test_lookalike_tools_are_unknown`, `test_manifest_pinning` | Adapter must report the server identity and manifest digest honestly | B, D |
| T5 | Resource manipulation | `..` traversal, `/srv/data2` vs `/srv/data/**`, `user@host` URLs, encodings | TB1/TB2 | Engine-side canonicalization; segment-boundary prefixes; ambiguous forms rejected (**M1**) | `test_policy_resources.py`, `test_policy_matching.py`, traversal tests | Symlinks and time-of-check/time-of-use at the real filesystem | B (lexical), D |
| T6 | Unauthorized database writes | Read tool asked for `database_write` | TB1 | Registry declares operations per tool → `OPERATION_NOT_DECLARED` (**M1**) | `test_privilege_escalation_via_operation_relabel` | SQL inside an allowed read tool is not parsed | B, D (read-only credentials) |
| T7 | Unauthorized shell execution | `execute` on `shell:bash` | TB1 | `execute` is protected; deny rules override allows; lint warns (**M1**) | `test_deny_overrides_allow` | Argument injection inside an allowed command | B, D (sandbox) |
| T8 | Sensitive-data exfiltration | Read a secret, then send it out | TB1 | Per-call rules on `external_send`/`network` with resource allowlists; approval for egress (**M1**) | mail and fetch cases in `test_policy_engine.py` | Multi-step flows; covert channels via allowed destinations | B, C, D |
| T9 | Privilege escalation | Relabel operation, claim another agent id, edit the policy through an allowed write | TB1–TB3 | Undeclared operation denied; no rule priority; deny-protect the policy path (**M1**) | `test_narrow_deny_overrides_broad_allow`, operation relabel test | Adapter that forwards agent-claimed identity | B, D |
| T10 | Policy tampering / substitution | Swap in a permissive policy, or a malformed one hoping for fail-open | TB3 | Strict validation, whole-policy rejection, SHA-256 fingerprint and pin, engine re-validation (**M1**) | `test_policy_loader.py`, `test_digest_pin_mismatch_denies_everything`, tampering tests | Attacker who controls both the file and the pin; no signing yet | B, D |
| T11 | Approval replay | Reuse an approval for another call or resource | TB4 | M1 computes a request-bound `request_binding_sha256`; grant verification, expiry and single-use are **M3** | `test_approval_binding_is_request_specific` | Approvals cannot be granted at all in M1 | B (M3), D, F |
| T12 | Missing or forged identities | No agent, empty id, look-alike id, `*` as id | TB1/TB2 | Missing → `MISSING_IDENTITY`; strict grammar → `INVALID_IDENTITY`; `min_assurance` conditions (**M1**) | `test_missing_identity`, `test_forged_or_invalid_identity` | Forgery at the source is invisible to the engine | B, D |
| T13 | Enforcement bypass | Agent calls the tool directly, or the adapter ignores decisions | outside B | `enforced: false` in every record; documented adapter contract | `test_policy_isolation.py` (engine never executes) | **Not solvable in Genesis B** | D, E |
| T14 | Fail-open conditions | Exception, empty policy, unknown enum, hostile input | TB2/TB3 | `evaluate()` never raises; default `allow` impossible; pre-built fallback deny (**M1**) | `test_exception_in_matcher_fails_closed`, clock and hostile-mapping tests, fuzz test | Adapter bugs that treat errors as allow | B, D, E |
| T15 | Secret exposure in logs | Secrets in arguments or exception messages | TB5 | Records hold no tool arguments; exception messages never recorded; validation issues never echo values (**M1**). Redaction and audit events are **M2** | `test_validation_errors_do_not_echo_values`, `test_exception_in_matcher_fails_closed` | Canonical resources and ids can be sensitive metadata | B (M2) |

## Adapter contract (normative for Genesis D)

1. Call `evaluate` before every protected tool call.
2. Invoke the tool **only** when `record.allowed` is true. Treat `DENY`,
   `REQUIRE_APPROVAL`, exceptions and timeouts as "not executed".
3. Invoke the tool with arguments that correspond to the evaluated canonical resource.
4. Set `agent.id` and `assurance` from the adapter's own authentication, never from the
   model's output.
5. Make sure the agent has no other path to the tool or its credentials.
