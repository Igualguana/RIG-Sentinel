# Reporting False Positives and False Negatives

RIG Sentinel is a static, heuristic analyzer, so accuracy reports are among the most
valuable contributions. This guide explains how to report them so they can be reproduced
and turned into regression tests.

## Definitions

| Term | Meaning in RIG Sentinel |
|---|---|
| **False positive** | Something was reported that should not have been (e.g. a documentation file detected as an agent, a capability attributed to the wrong agent). |
| **False negative** | Something relevant was missed (e.g. an agent using a supported provider and a shell tool was not detected). |
| **Misclassification** | Detected, but with the wrong severity, confidence, provider or category. |

### Not a false positive

Some findings are correct even if no real problem exists, because they report
*indicators*, not confirmed issues:

- **Shared credential reference** — two agents referencing `OPENAI_API_KEY` is reported
  even if they use different secret values. The finding itself states this is not proof
  of a shared secret.
- **Shadow agent** — any detected agent not listed in `.rig-sentinel.toml` is reported.
  Add approved agents to the inventory.
- **Attack path / blast radius** — modeled possibilities based on detected capabilities.

If you think the *wording* of such a finding is misleading, that is still a useful
report — choose "Wrong severity or classification".

### Out of scope by design

- Files in skipped directories (`tests/`, `examples/`, `fixtures/`, `vendor/`, …) and
  files over 1 MB. See [LIMITATIONS.md](LIMITATIONS.md).
- Unsupported providers, credential names or languages — please file these as feature
  requests.

## How to report

1. **Reproduce with synthetic code.** Reduce the case to the smallest set of files that
   shows the behavior. Never paste real secrets, proprietary code or customer data.
2. **Run the scan with JSON output** to capture the exact finding:

   ```bash
   rig-sentinel scan path/to/minimal-sample --json > result.json
   ```

3. **Open an issue** with the *False positive / false negative* template and include:
   - The type (false positive, false negative, misclassification) and area.
   - The minimal sample (file names and contents).
   - The relevant, sanitized part of the output.
   - What you expected and why.
   - RIG Sentinel version or commit, OS and Python version.

Sanitize before posting: the JSON `root` field contains the absolute path of the scanned
directory.

## What happens next

- A maintainer reproduces the case.
- Confirmed cases become regression tests (positive or negative) in `tests/` — see
  [TESTING.md](TESTING.md).
- Fixes are noted in `CHANGELOG.md`.

You are welcome to submit the fix yourself; include the regression test in the same pull
request.
