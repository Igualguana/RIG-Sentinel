# Testing

## Running the tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The suite uses only `pytest` (installed by the `dev` extra) and the standard library. It
needs no network access and no credentials.

Current suite, including the unreleased policy engine: **913 tests** in 49 test modules
under `tests/`, plus the shared helper `tests/policy_fixtures.py` (not a test module):

| Group | Modules | Tests |
|---|---|---|
| Scanner and CLI tests from v0.1.0 | 36 | 179 |
| Policy engine, Genesis B2-M1 | 11 | 412 |
| Policy engine hardening and limits | 2 | 322 |
| **Total** | **49** | **913** |

The v0.1.0 release had 179 tests; the other 734 test the unreleased policy engine.

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

| Where | Scope | Result |
|---|---|---|
| Local, Windows 11, Python 3.13.2 | Full suite (913 tests) from a clean, non-editable install in a fresh virtual environment, with `-W error::Warning` | 913 passed, 0 failed, 0 skipped, 0 warnings |
| GitHub Actions (Ubuntu 24.04, Ubuntu 26.04, macOS 15 Intel, macOS Apple Silicon) | v0.1.0 (179 tests) | Passed for the v0.1.0 release candidate |
| GitHub Actions | Policy engine (913 tests) | **Not yet run.** Linux and macOS results for the policy engine are unknown until CI runs on a pull request |

Python 3.11 and 3.12 are declared as supported but are not exercised by CI or by the local
validation above.

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
| Policy engine: hardening and limits | `test_policy_hardening.py` (aliases, carve-outs, Unicode, trust boundary, fail-closed boundary), `test_policy_limits.py` (size and worst-case inputs) |
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
