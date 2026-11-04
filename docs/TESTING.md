# Testing

## Running the tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The suite uses only `pytest` (installed by the `dev` extra) and the standard library. It
needs no network access and no credentials.

Current suite: **179 tests** (as of v0.1.0 preparation), in 36 test modules under
`tests/`.

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

Tests mirror the modules in `src/rig_sentinel/`:

| Area | Test modules |
|---|---|
| File discovery and configuration | `test_repository.py`, `test_config.py` |
| Python AST helpers | `test_python_analysis.py` |
| Detectors | `test_providers.py`, `test_mcp.py`, `test_tools.py`, `test_identity.py`, `test_agents.py` |
| Identity and credentials | `test_identity_linking.py`, `test_credential_flow.py`, `test_credential_flow_v3.py`, `test_credential_flow_v31.py`, `test_shared_credentials.py`, `test_shared_credential_precision.py` |
| Privilege | `test_privilege.py`, `test_least_privilege.py`, `test_permissions.py` |
| Graphs and exposure | `test_graph.py`, `test_multi_agent_graph.py`, `test_attack_paths.py`, `test_blast_radius.py`, `test_exposure.py`, `test_exposure_report.py`, `test_risk_propagation.py` |
| Remediation and policy | `test_remediation.py`, `test_policy_generator.py`, `test_policy_integration.py`, `test_policy_cli_integration.py`, `test_shadow_agents.py` |
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

## Manual verification before a release

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for clean-install, CLI and output-format
checks.
