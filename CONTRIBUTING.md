# Contributing to RIG Sentinel

Thank you for helping improve RIG Sentinel. Contributions of all sizes are welcome:
bug reports, false-positive and false-negative reports, detection rules, tests and
documentation.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security issues

Do **not** open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a false positive or false negative** — see
  [docs/DETECTION_ISSUES.md](docs/DETECTION_ISSUES.md) and use the issue template.
- **Fix a bug** — open an issue first unless the fix is trivial.
- **Add detection coverage** — new providers, tools, credential names or MCP formats.
- **Improve documentation.**

## Development setup

```bash
git clone https://github.com/Igualguana/RIG-Sentinel.git
cd RIG-Sentinel
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

Test conventions are described in [docs/TESTING.md](docs/TESTING.md); the code layout in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Pull request guidelines

1. Branch from `main` and keep changes focused — one logical change per pull request.
2. **Add tests** for new or changed detection logic, including a negative case
   (something that must *not* be flagged).
3. Run `python -m pytest -q` and `git diff --check` before pushing.
4. Preserve compatibility of the CLI, the JSON report structure and SARIF rule IDs. If a
   change is unavoidable, call it out explicitly in the PR description and in
   `CHANGELOG.md`.
5. Describe the false-positive / false-negative impact of detection changes.
6. Keep language in findings accurate: findings are **indicators**, not confirmed
   vulnerabilities. Do not claim credential sharing, exploitability or enforcement that
   the analysis cannot prove.
7. Fill in the pull request template.

## Code review rules

Every pull request is reviewed by a maintainer before merging. Reviewers check:

| Area | Expectation |
|---|---|
| CI | All required GitHub Actions jobs pass |
| Tests | New behavior is covered by positive and negative tests; no existing test is removed or weakened to make a change pass |
| Detection quality | False-positive and false-negative impact is explained; precision regressions are justified |
| Compatibility | CLI options, JSON keys and SARIF rule IDs unchanged, or the change is documented |
| Safety | Scanned code is never imported or executed; no network calls; credential **values** never appear in output |
| Report security | HTML output stays escaped and script-free; SARIF paths stay relative and sanitized |
| Dependencies | No new runtime dependencies without prior discussion in an issue |
| Data hygiene | No real secrets, customer code or personal data in code, tests or fixtures |
| Wording | Findings and docs stay accurate about what static analysis can and cannot show |
| Docs | User-visible changes update README/docs and `CHANGELOG.md` |

Maintainers may request changes, ask for the change to be split, or decline changes
that do not fit the project's scope. Decisions are explained in the pull request.

## Test data rules

- Never commit real secrets, tokens, customer code or personal data.
- Use placeholder credential **names** (e.g. `OPENAI_API_KEY`) without values, and
  reserved domains such as `example.com`.
- Do not add code copied from third-party repositories unless its license is compatible
  with Apache-2.0 and the required attribution is added to `NOTICE`.

## Licensing of contributions

RIG Sentinel Community is licensed under the [Apache License 2.0](LICENSE).

- Unless you explicitly state otherwise, any contribution you intentionally submit for
  inclusion is licensed under the Apache License 2.0, as described in Section 5 of the
  license ("inbound = outbound").
- **No Contributor License Agreement (CLA) is required.** You keep the copyright in your
  contributions.
- Contributor attribution is preserved through Git history and pull requests; copyright
  notices you add to files are not removed.
- Only submit work you have the right to contribute (for example, check whether your
  employer has rights in code you write).
- If the contribution policy changes in the future, the change will be announced in this
  file before it takes effect.
