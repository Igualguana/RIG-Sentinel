# Release Checklist — v0.1.0

Status legend: ✅ done (verified on 2026-11-04 during release preparation) ·
⬜ pending · 🔒 requires owner approval.

A release is ready only when every item is checked — passing tests alone are not enough.

## 1. Code and tests

- ✅ `python -m pytest -q` — 179 passed (Windows, Python 3.13.2)
- ✅ `git diff --check` — clean
- ✅ No detection, scoring or output-format code changed during release preparation
- ⬜ CI green on the release commit (after the preparation commit is pushed)

## 2. Clean installation

- ✅ Fresh virtual environment, `pip install ".[dev]"` (non-editable) succeeds with
  `setuptools>=77`; metadata shows `License-Expression: Apache-2.0` and bundles
  `LICENSE` and `NOTICE`
- ✅ Test suite passes against the clean, non-editable install (179 passed)
- ⬜ Clean install from the published tag: `pip install "git+https://github.com/Igualguana/RIG-Sentinel.git@v0.1.0"`
  on Windows and Linux

## 3. CLI

- ✅ `rig-sentinel --help` → usage, exit 0
- ✅ `rig-sentinel` without arguments → usage on stderr, exit 2
- ✅ Conflicting formats (`--json --sarif x`) → error, exit 2
- ✅ `python -m rig_sentinel.cli --help` works
- ✅ Terminal scan of a synthetic sample repository completes

## 4. Output formats (synthetic sample repository)

- ✅ JSON parses; top-level keys match `docs/CLI_REFERENCE.md`
- ✅ HTML generated; values escaped; CSP present; no external resources
- ✅ SARIF: `version == "2.1.0"`, one run, rules `RIG001`–`RIG004`
- ⬜ SARIF validated with a SARIF-aware tool (e.g. Microsoft SARIF Multitool) — optional
- ✅ SARIF documented as an export format; GitHub Code Scanning integration not yet
  validated (audit M-1 remains open for a future release)

## 5. Platforms

- ✅ Windows — Python 3.13 (maintainer machine)
- ✅ Ubuntu 24.04 — GitHub Actions, commit `6f3cdf5`
- ✅ Ubuntu 26.04 — GitHub Actions, commit `6f3cdf5`
- ✅ macOS 15 Intel — GitHub Actions, commit `6f3cdf5` (run 41875200637)
- ✅ Ubuntu 24.04, Ubuntu 26.04, macOS 15 Intel — 179 passed on commit `b0f7e24`
  (run 41894175520)
- ✅ Ubuntu 24.04, Ubuntu 26.04, macOS 15 Intel — 179 passed on commit `2fd5f2e`
  (run 41896617740)
- ✅ macOS Apple Silicon ARM64 — 179 passed on commit `2fd5f2e` (run 41896617670,
  separate workflow `ci-macos-arm64.yml`)
- ⬜ Python 3.11 / 3.12 — declared supported, not yet run in CI

## 6. Security

- ✅ Pre-release audit: `docs/SECURITY_AUDIT.md` — 0 Blocker, 0 High
- ⬜ 🔒 Enable private vulnerability reporting (required by `SECURITY.md`)
- ⬜ 🔒 Enable secret scanning + push protection, Dependabot, CodeQL after going public
- ⬜ 🔒 Pin GitHub Actions to commit SHAs (audit M-2) — optional for v0.1.0

## 7. License

- ✅ `LICENSE` — official Apache-2.0 text, SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
- ✅ `pyproject.toml` — `license = "Apache-2.0"`, `license-files = ["LICENSE", "NOTICE"]`
- ✅ No third-party code with other licenses identified (reasonable review, see
  `docs/THIRD_PARTY_PROVENANCE.md`; no comparison against public code corpora)
- ✅ Ownership confirmed by the owner (2026-11-04); `NOTICE` finalized as
  `Copyright 2026 Randy Igualguana`
- ✅ RIG Industrial Technologies LLC described as "proposed commercial operator, subject to
  a separate written license agreement" (owner-approved wording, 2026-11-04)
- ✅ Founder / maintainer / company identity added to README, Spanish README, NOTICE and
  `pyproject.toml` (names only, no personal e-mail)

## 8. Documentation

- ✅ README rewritten; commands verified against `pyproject.toml` and the CLI
- ✅ SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG
- ✅ docs: INSTALLATION, CLI_REFERENCE, ARCHITECTURE, LIMITATIONS, ROADMAP (three phases),
  README_ES, TESTING, DETECTION_ISSUES, SECURITY_AUDIT, GITHUB_SETUP, RELEASE_NOTES_v0.1.0
- ✅ Community vs Enterprise documented; Enterprise presented only as a future product
  (no pricing, not for sale, no Enterprise code in the repository)
- ✅ Legal working drafts kept outside the repository (not published)
- ✅ Issue templates and pull request template
- ⬜ 🔒 Dedicated contact for Code of Conduct reports (currently: maintainer profile)
- ⬜ Update the macOS line in `RELEASE_NOTES_v0.1.0.md` and set the release date in `CHANGELOG.md`

## 9. Publishing procedure (owner only — not performed during preparation)

1. 🔒 Review the working-tree changes and commit them:

   ```bash
   git add -A
   git commit -m "docs: prepare RIG Sentinel Community v0.1.0 open-source release"
   ```

2. 🔒 Push and wait for CI to pass on all required jobs:

   ```bash
   git push origin main
   gh run watch
   ```

3. Set the release date in `CHANGELOG.md` (`## [0.1.0] — YYYY-MM-DD`), commit and push.
4. 🔒 Create an annotated (optionally signed) tag on the verified commit:

   ```bash
   git tag -a v0.1.0 -m "RIG Sentinel Community v0.1.0"
   # or signed: git tag -s v0.1.0 -m "RIG Sentinel Community v0.1.0"
   git push origin v0.1.0
   ```

5. 🔒 Build distributions and checksums (optional but recommended):

   ```bash
   python -m pip install build
   python -m build
   sha256sum dist/* > dist/SHA256SUMS.txt
   ```

6. 🔒 Create the GitHub Release from the tag (start as draft, review, then publish):

   ```bash
   gh release create v0.1.0 --draft --title "RIG Sentinel Community v0.1.0" \
     --notes-file docs/RELEASE_NOTES_v0.1.0.md dist/*
   ```

7. 🔒 Change repository visibility to public (see `docs/GITHUB_SETUP.md` §8) — before or
   after publishing the release, as the owner prefers.
8. Verify the release: clean install from the tag on Windows and Linux; badges render;
   links in README resolve.
