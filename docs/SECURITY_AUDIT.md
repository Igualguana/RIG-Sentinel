# Pre-Release Security Audit — RIG Sentinel Community v0.1.0

| Item | Value |
|---|---|
| Audit date | 2026-11-04 |
| Audited commit | `fix: improve agent precision and shared credential risk classification` (tree `8376946518`; `main`, 25 commits, 78 tracked files) |
| Scope | Working tree, full Git history (all refs), packaging, CI configuration, report output safety |
| Method | Local, offline review. No code or candidate secrets were sent to external services. No third-party repository code was executed. |
| Result | **PASS WITH WARNINGS — no Blocker findings** |

> This audit is a point-in-time maintainer review, not an independent third-party
> security assessment. It does not certify the absence of vulnerabilities.

## 1. Summary

| Severity | Count | Release impact |
|---|---|---|
| Blocker | 0 | — |
| High | 0 | — |
| Medium | 3 | Fix or accept before / shortly after v0.1.0 |
| Low | 6 | Track as issues |
| Informational | 7 | Documented |

No real secrets, tokens, passwords, private keys, certificates or `.env` files were
found in the current tree or anywhere in Git history.

The one pre-existing release blocker — **no open-source license** — was resolved in
this preparation by adding the official Apache License 2.0 text (`LICENSE`, SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, matching the
canonical file at apache.org) and a `NOTICE` file. The copyright holder in `NOTICE` is
Randy Igualguana (founder), confirmed by the owner on 2026-11-04, with RIG Industrial
Technologies LLC as the proposed commercial operator under a separate license (see §6).

## 2. Methodology

| Check | How it was performed |
|---|---|
| Secrets in history | Custom offline scanner over **every blob reachable from every ref** (`git rev-list --objects --all`). Patterns: AWS access keys, GitHub tokens/PATs, OpenAI/Anthropic keys, Google API keys, Slack tokens, Stripe live keys, PEM private-key headers, JWTs, credentials embedded in connection strings, generic `password/secret/token/api_key = "<literal>"` assignments. Only path + pattern type was recorded; values were never printed. |
| Sensitive files | Every path ever added to history checked for `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, logs, backups, scan outputs (`*.sarif`, `*.html`, `*.json`). |
| Personal data | Search for e-mail addresses, Windows user profile paths, POSIX home paths and local project paths in all blobs. |
| Deleted content | `git log --diff-filter=D` review of every deleted file. |
| Refs | Branches, remotes, tags, stash (`git for-each-ref`, `git stash list`). |
| Dependencies | `pyproject.toml` review; runtime and build dependencies enumerated. |
| CI | `.github/workflows/ci.yml` reviewed for permissions, triggers, credential persistence, action pinning. |
| Report safety | Source review of `html_report.py`, `sarif_report.py`, `identity.py`, `credential_flow.py`, `repository.py`; HTML/JSON/SARIF generated from a sanitized synthetic sample repository and inspected. |
| Code execution surface | Search of `src/` for `subprocess`, `os.system`, `eval`, `exec`, `pickle`, unsafe YAML, network clients. |

Tools such as gitleaks, trufflehog, detect-secrets and pip-audit were **not installed**
on the audit machine; they were not downloaded for this audit. Running gitleaks in CI
is recommended (see §7).

## 3. Findings

### Blocker

None.

### High

None.

### Medium

**M-1 — SARIF results frequently lack `locations` (affects GitHub code scanning upload)**
- Path: `src/rig_sentinel/sarif_report.py` (`_result`, `_safe_relative_path`)
- Observation: `_safe_relative_path` intentionally rejects any path containing `\` or `:`.
  On Windows, scanner paths use backslashes, so **all** results are emitted without a
  `locations` array (verified: 0 of 6 results on a Windows scan of the sample repo).
  Some finding types (for example shared credential references) never carry a file path
  on any platform.
- Risk: GitHub code scanning requires a location for each result; uploads via
  `github/codeql-action/upload-sarif` may be rejected or results may not be displayed.
  The SARIF file is still valid SARIF 2.1.0 and CI validates `version` and `runs`.
- Recommendation (requires approval — output-format change): normalize separators to
  `/` before the safety check and attach a repository-level location when no file is
  known. Until then, document SARIF as an artifact, not as a verified code-scanning feed.

**M-2 — GitHub Actions are pinned to mutable major-version tags**
- Path: `.github/workflows/ci.yml` (`actions/checkout@v6`, `actions/setup-python@v6`,
  `actions/upload-artifact@v6`)
- Risk: a compromised or retagged upstream action would run in CI. Impact is limited
  because the workflow has `permissions: contents: read`, `persist-credentials: false`
  and uses no secrets.
- Recommendation: pin each action to a full commit SHA (with the tag in a comment) and
  let Dependabot update the pins.

**M-3 — No automated secret or dependency scanning in CI**
- Path: `.github/` (no `dependabot.yml`, no secret-scanning or CodeQL workflow)
- Risk: future commits could introduce secrets or vulnerable dependencies unnoticed.
- Recommendation: enable GitHub secret scanning + push protection, Dependabot (for
  `github-actions` and `pip`) and CodeQL for Python once the repository is public
  (see `docs/GITHUB_SETUP.md`).

### Low

**L-1 — Build artifacts in Git history expose a local directory path**
- Paths: `src/rig_sentinel/__pycache__/*.pyc`, `tests/__pycache__/*.pyc` and
  `src/rig_sentinel.egg-info/*`, added in `48aff79` and removed in `c18a812`.
- Content: compiled bytecode embeds the absolute build path
  (`D:\project\RIG-Sentinel-v0.1-starter\RIG-Sentinel\...`). No user name, no secrets,
  no credentials. `PKG-INFO` contains only package metadata.
- Recommendation: acceptable to publish as-is. Rewriting history (e.g. `git filter-repo`)
  is **not** recommended solely for this; it would change every commit hash.

**L-2 — Test fixture contains a local path string**
- Path: `tests/test_html_report.py` line 9 (`"root": "D:/project/RIG-Sentinel-Lab"`).
- Risk: cosmetic disclosure of a directory name. No action required; may be replaced
  with a neutral path in a future change.

**L-3 — Reports include the absolute scanned path and credential variable names**
- Paths: `cli.py` (`report_to_dict` → `root`), HTML header, JSON output.
- Risk: sharing reports publicly can disclose local directory layout, repository names
  and the names of credential environment variables. Values are not included (see I-3).
- Recommendation: documented in `SECURITY.md` and `docs/LIMITATIONS.md`; consider an
  optional path-redaction flag in a future release.

**L-4 — Unhandled exception for a non-existent scan path**
- Path: `src/rig_sentinel/repository.py` (`RepositoryWalker.walk`) via `cli.main`.
- Observation: `rig-sentinel scan <missing-dir>` prints a Python traceback instead of a
  concise error (non-zero exit). No security impact; usability issue.
- Recommendation: catch `FileNotFoundError`/`NotADirectoryError` in the CLI (behavior
  change, requires approval).

**L-5 — File symlinks inside a scanned repository are followed**
- Path: `src/rig_sentinel/repository.py` (`rglob` + `is_file`).
- Risk: a symlinked file pointing outside the scanned tree is read (subject to the 1 MB
  size limit and supported extensions). Only detection metadata (names, file paths) is
  reported, so content disclosure through reports is limited.
- Recommendation: optionally skip symlinks that resolve outside the scan root.

**L-6 — Build backend version range is open-ended**
- Path: `pyproject.toml` (`setuptools>=77`).
- Risk: future setuptools releases could change build behavior. Low impact because the
  package has zero runtime dependencies.
- Recommendation: acceptable; optionally add an upper bound when publishing to PyPI.

### Informational

**I-1 — Zero runtime dependencies.** `dependencies = []`; only `pytest` (dev extra) and
`setuptools` (build) are used. Supply-chain surface is minimal.

**I-2 — No code-execution primitives in the scanner.** `subprocess`, `os.system`,
`requests` appear in `src/rig_sentinel/tools.py` only as **string patterns to detect**,
not as calls. The scanner does not import or execute scanned code (it uses `ast` and
text matching).

**I-3 — Credential values are not emitted.** Identity, credential-flow and shared-credential
evidence contain variable/identity *names* only (e.g. `credential reference: OPENAI_API_KEY`).
The scanner reads `.env` files to find names; values are not copied into findings.

**I-4 — HTML report hardening.** All dynamic values are passed through
`html.escape(..., quote=True)`; the report sets
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` and loads no
external resources or scripts.

**I-5 — CI follows least privilege.** `permissions: contents: read`,
`persist-credentials: false`, no secrets, no `pull_request_target`, artifacts retained
14 days.

**I-6 — Test fixtures use placeholder names only.** Credential identifiers such as
`OPENAI_API_KEY`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN` and the e-mail addresses
`customer@example.com` / `user@example.com` (reserved domain) appear in tests; no values.

**I-7 — Author identity in commit metadata.** All commits are authored by Randy
Igualguana. Before publication, the author/committer/tagger e-mail in the history was
changed from a personal address to the project address `opensource@rigindustrialusa.com`
(names, dates, messages and file contents unchanged; commit IDs changed). The audit
results above apply to the same file trees.

## 4. Tracked files and `.gitignore`

- 78 tracked files: source (`src/rig_sentinel`, 30 modules), tests (37 files),
  documentation, CI workflow, `pyproject.toml`, `.gitignore`.
- No tracked `.env`, certificate, key, log, backup or generated report files.
- Ignored but present locally (not tracked, not published): `.venv/`, `.venv-1/`,
  `.pytest_cache/`, `__pycache__/`, `src/rig_sentinel.egg-info/`.
- `.gitignore` covers Python caches, virtual environments, packaging output, coverage,
  IDE folders and `.env*` (with `.env.example` / `.env.sample` allowed).
- Suggested additions (not applied): generated report names such as `*.sarif` and
  `rig-sentinel*.html` to avoid accidentally committing scan output.

## 5. Git history

- Refs: `refs/heads/main`, `refs/remotes/origin/main` (same commit). No tags, no stash.
- Deleted files: only the `__pycache__` / `egg-info` artifacts listed in L-1.
- No secret patterns matched in any historical blob.

## 6. Licensing review

- `LICENSE`: official Apache License 2.0 text, unmodified (checksum above).
- `NOTICE`: `Copyright 2026 Randy Igualguana`. On 2026-11-04 the owner confirmed that
  he personally owns the rights to RIG Sentinel to the extent legally applicable, that he
  developed it independently, and that to his knowledge no employer, client, contractor
  or LLC agreement assigns ownership to another party. This is the owner's
  representation; it was not independently verified by legal review. Git history is
  consistent with it (all 25 commits authored by the founder, no external contributors).
- Proposed commercial operator: RIG Industrial Technologies LLC, under a separate written
  license that is not yet drafted in final form or signed. Such a license cannot narrow
  the permissions Apache-2.0 grants to Community users. Legal working drafts are kept
  outside the public repository.
- No third-party source code, vendored files or files under other licenses were found.
  The detailed provenance review is in [THIRD_PARTY_PROVENANCE.md](THIRD_PARTY_PROVENANCE.md).
  The Contributor Covenant 2.1 text used in `CODE_OF_CONDUCT.md` is licensed CC BY 4.0
  and is attributed in that file.
- No Enterprise or private modules exist in this repository.

## 7. Recommendations before / after publication

1. ✅ Copyright holder confirmed by the owner and `NOTICE` finalized. Optional: legal
   review of AI-assisted authorship questions before commercial licensing.
2. Enable private vulnerability reporting before switching visibility to public.
3. Enable secret scanning with push protection, Dependabot alerts/updates and CodeQL.
4. Pin GitHub Actions to commit SHAs (M-2).
5. Decide on the SARIF location fix (M-1) before advertising GitHub code-scanning
   integration.
6. Optionally add gitleaks to CI for defense in depth.

## 8. Audit verdict

**No Blocker or High findings.** The repository is suitable for public release from a
secrets and history standpoint, subject to the owner approvals listed in §7.
