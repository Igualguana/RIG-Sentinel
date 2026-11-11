# Testing

## Running the tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The suite uses only `pytest` (installed by the `dev` extra) and the standard library. It
needs no network access and no credentials.

Current suite on the Genesis B2-P1 development branch: **1,480 tests** in 58 test
modules under `tests/`, plus the shared helpers `tests/policy_fixtures.py` and
`tests/audit_fixtures.py` (not test modules):

| Group | Modules | Tests |
|---|---|---|
| Scanner and CLI tests from v0.1.0 | 36 | 179 |
| Policy engine, Genesis B2-M1 | 11 | 412 |
| Policy engine hardening and limits | 2 | 322 |
| Policy engine `error_type` hardening (M1-H1) | 1 | 100 |
| Audit foundation, Genesis B2-M2-B | 6 | 290 |
| Audit privacy hardening, Genesis B2-P1 (`test_audit_p1_privacy.py`) | 1 | 110 |
| B2-P1 security review remediation (`test_audit_p1_remediation.py`) | 1 | 67 |
| **Total** | **58** | **1,480** |

The v0.1.0 release had 179 tests; the others test the unreleased policy engine and audit
foundation. `main` currently has 1,303 tests, everything except the B2-P1 privacy hardening.

To run only the audit tests (M2-B and B2-P1):

```bash
python -m pytest -q tests/test_audit_*.py
```

To run only the policy engine tests:

```bash
python -m pytest -q \
  tests/test_policy_canonical.py tests/test_policy_determinism.py \
  tests/test_policy_engine.py tests/test_policy_engine_adversarial.py \
  tests/test_policy_identifiers.py tests/test_policy_isolation.py \
  tests/test_policy_loader.py tests/test_policy_matching.py tests/test_policy_model.py \
  tests/test_policy_resources.py tests/test_policy_validation.py \
  tests/test_policy_hardening.py tests/test_policy_limits.py
```

A `tests/test_policy_*.py` glob is not equivalent: `test_policy_generator.py`,
`test_policy_integration.py` and `test_policy_cli_integration.py` test the v0.1.0
scanner's advisory policy generator, not the policy engine.

To make any warning fail the run, add `-W error::Warning`.

## Validation status

**Previously validated in CI** (Python 3.13):

| Where | Scope | Result |
|---|---|---|
| GitHub Actions (Ubuntu 24.04, Ubuntu 26.04, macOS 15 Intel, macOS Apple Silicon) | v0.1.0 (179 tests) | Passed for the v0.1.0 release candidate |
| GitHub Actions, Ubuntu 24.04 (x86_64, Python 3.13) | Genesis B2-M1 pull request (913 tests) | 913 passed |
| GitHub Actions, Ubuntu 26.04 (x86_64, Python 3.13) | Genesis B2-M1 pull request (913 tests) | 913 passed |
| GitHub Actions, macOS 15 Intel (x86_64, Python 3.13) | Genesis B2-M1 pull request (913 tests) | 913 passed |
| GitHub Actions, macOS Apple Silicon (arm64, Python 3.13) | Genesis B2-M1 pull request (913 tests) | 913 passed |

The four GitHub Actions results above are from the pull-request validation of the
unreleased Genesis B2-M1 development branch at commit `9f0f59f`, tested as merged with
`main` (workflow runs 42678818798 and 42678819046). They are not results for the v0.1.0
release, which contains only the 179 scanner and CLI tests. In CI, each job also ran the
CLI, generated the HTML and SARIF reports and validated the SARIF 2.1.0 output. CI runs
`python -m pytest -q` without `-W error::Warning`.

The M1-H1 `error_type` hardening was validated the same way: **1,013 passed** on each of
the four platforms for its pull request (commit `b8583cc` merged with `main`, workflow runs
42703580034 and 42703579962) and again on `main` after the merge (commit `7654020`, workflow
runs 42871476503 and 42871476496).

The M2-B audit foundation was validated the same way after its merge: **1,303 passed** on
each of the four platforms on `main` (commit `9c9b364`).

**Genesis B2-M2-B audit foundation, local validation before its pull request:**

| Where | Scope | Result |
|---|---|---|
| Local, Windows 11 (x64), Python 3.13.2 | Full suite (1,303 tests) from a clean, non-editable install in a fresh virtual environment, with `-W error::Warning` | 1,303 passed, 0 failed, 0 skipped, 0 warnings |
| Same environment | The 1,013 tests that predate the audit foundation | 1,013 passed |
| Same environment | Audit foundation tests (`tests/test_audit_*.py`) | 290 passed |

**Genesis B2-P1 privacy hardening, local only (not yet run in CI):**

| Where | Scope | Result |
|---|---|---|
| Local, Windows 11 (x64), Python 3.13.2 | Full suite (1,480 tests) from a clean, non-editable install in a fresh virtual environment, with `-W error::Warning` | 1,480 passed, 0 failed, 0 skipped, 0 warnings |
| Same environment | The 1,303 tests that predate B2-P1 (unchanged files) | 1,303 passed |
| Same environment | B2-P1 tests (`tests/test_audit_p1_privacy.py`) | 110 passed |
| Same environment | B2-P1 security review remediation tests (`tests/test_audit_p1_remediation.py`) | 67 passed |
| Local mutation check | 41 targeted B2-P1 mutations (gate, builder, v3 model, parsers, manifest privacy, omitted-label accounting) and the 20 earlier M2-B mutations, each applied to a scratch copy of `src/` | All 61 detected by the audit tests |

**Not yet tested:**
- the B2-P1 privacy hardening in GitHub Actions on Linux or macOS;
- Python 3.11 and 3.12 for any part of the suite. They are declared as supported but are
  exercised neither by CI nor by the local validation above.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request to `main` with Python 3.13
on Ubuntu 24.04, Ubuntu 26.04 and macOS 15 Intel. The same steps run on macOS Apple Silicon
in a separate workflow, `.github/workflows/ci-macos-arm64.yml`, so that hosted-runner
capacity delays do not mark the main workflow as failed; it has its own status badge.
Each job:

1. Installs the package with `pip install -e ".[dev]"`.
2. Runs `python -m pytest -q`.
3. Runs `rig-sentinel --help`.
4. Scans the repository itself and generates HTML and SARIF reports.
5. Checks that the SARIF file reports version `2.1.0` and at least one run.
6. Uploads the reports as build artifacts (retained 14 days).

## Test layout

Tests mirror the modules in `src/rig_sentinel/` and `src/rig_sentinel/policy/`:

| Area | Test modules |
|---|---|
| File discovery and configuration | `test_repository.py`, `test_config.py` |
| Python AST helpers | `test_python_analysis.py` |
| Detectors | `test_providers.py`, `test_mcp.py`, `test_tools.py`, `test_identity.py`, `test_agents.py` |
| Identity and credentials | `test_identity_linking.py`, `test_credential_flow.py`, `test_credential_flow_v3.py`, `test_credential_flow_v31.py`, `test_shared_credentials.py`, `test_shared_credential_precision.py` |
| Privilege | `test_privilege.py`, `test_least_privilege.py`, `test_permissions.py` |
| Graphs and exposure | `test_graph.py`, `test_multi_agent_graph.py`, `test_attack_paths.py`, `test_blast_radius.py`, `test_exposure.py`, `test_exposure_report.py`, `test_risk_propagation.py` |
| Remediation and policy | `test_remediation.py`, `test_policy_generator.py`, `test_policy_integration.py`, `test_policy_cli_integration.py`, `test_shadow_agents.py` |
| Policy engine: model, grammar and resources | `test_policy_model.py`, `test_policy_identifiers.py`, `test_policy_resources.py`, `test_policy_matching.py` |
| Policy engine: loading, validation and digests | `test_policy_loader.py`, `test_policy_validation.py`, `test_policy_canonical.py` |
| Policy engine: decisions | `test_policy_engine.py`, `test_policy_engine_adversarial.py`, `test_policy_determinism.py` |
| Policy engine: isolation from the scanner, CLI and I/O | `test_policy_isolation.py` |
| Policy engine: hardening and limits | `test_policy_hardening.py` (aliases, carve-outs, Unicode, trust boundary, fail-closed boundary), `test_policy_limits.py` (size and worst-case inputs), `test_policy_error_type_hardening.py` (untrusted exception classes) |
| Audit foundation | `test_audit_keys_and_chain.py` (keys, digests, HMAC known answers), `test_audit_events.py` (schema, tampering, limits), `test_audit_builder.py` (provenance, privacy, canaries), `test_audit_builder_hardening.py` (record snapshot, exception boundaries, redaction bound), `test_audit_sinks.py` (`MemorySink`, receipts, concurrency), `test_audit_isolation.py` (no I/O, no dependency from the policy package), `test_audit_p1_privacy.py` (B2-P1: v2/v3 compatibility, identity modes, reference vectors and domain separation, label allowlist, canaries, persistence gate), `test_audit_p1_remediation.py` (B2-P1 security review fixes: manifest reference, omitted-label count, cross-version confusion) |
| Reports and CLI | `test_html_report.py`, `test_html_cli_integration.py`, `test_sarif_report.py`, `test_scan.py` |
| End to end | `test_scanner.py`, `test_models.py` |
| Precision regressions | `test_precision_external.py` |

## Conventions

- **Synthetic fixtures only.** Tests typically build small repositories in pytest's
  `tmp_path` and use placeholder credential names without values and `example.com` addresses.
- **Positive and negative cases.** Every new detection rule needs at least one test that
  must be flagged and one that must not.
- **Precision regressions.** `test_precision_external.py` encodes false-positive patterns
  observed while reviewing public projects (for example, documentation, CI workflow and
  test files must not be classified as agents). These tests contain synthetic
  reproductions; no external code is downloaded or executed.
- **No external code execution.** Tests never import or run code from scanned
  repositories.
- **Do not delete or weaken tests** to make a change pass. If expected behavior
  genuinely changes, explain why in the pull request.
- **Report formats.** Changes to JSON, HTML or SARIF output need tests covering the new
  structure and escaping/sanitization behavior.
- **Policy engine.** Policy tests build policies from TOML text, mostly from the baseline
  policy in `tests/policy_fixtures.py`, and use a fixed clock so decision records are
  reproducible. Known residual risks are pinned by tests that assert the current
  behavior (for example `test_known_alias_gaps_are_accepted_and_bypassable`); a change
  that closes one must update that test and the documentation together.

## Manual verification before a release

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for clean-install, CLI and output-format
checks.
