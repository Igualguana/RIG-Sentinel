# Third-Party Components and Code Provenance Review

| Item | Value |
|---|---|
| Review date | 2026-11-04 |
| Scope | All tracked source (`src/rig_sentinel/`, 30 modules) and tests (`tests/`, 36 modules), plus `pyproject.toml`, CI workflow and documentation added for v0.1.0 |
| Result | **No third-party source code, vendored code or snippets with attribution obligations were identified** |

> This is the result of a reasonable, good-faith review using the methods described
> below. It is not a guarantee of absolute originality: no review can rule out every
> similarity to existing public code. If you believe any part of RIG Sentinel
> reproduces third-party code, please open an issue or contact the maintainer as
> described in [SECURITY.md](../SECURITY.md).

## 1. Libraries used through imports (not embedded)

| Component | Used by | How | License | Redistributed? |
|---|---|---|---|---|
| Python standard library (`ast`, `dataclasses`, `html`, `json`, `pathlib`, `re`, `sys`, `tomllib`, `typing`, `urllib`, `types`, `__future__`) | Source and tests | `import` | PSF License (part of Python) | No |
| `pytest` | Tests only (`dev` extra) | `import`, installed separately | MIT | No |
| `setuptools` | Build only (`build-system.requires`) | Build backend, installed by pip | MIT | No |

RIG Sentinel has **no runtime dependencies** (`dependencies = []`). No third-party
package is bundled in the wheel or source distribution; both were built and inspected
during release preparation and contain only RIG Sentinel modules, `LICENSE`, `NOTICE`
and metadata.

## 2. Code or text incorporated directly

| Item | Location | Origin | License / obligation | Status |
|---|---|---|---|---|
| Apache License 2.0 text | `LICENSE` | Apache Software Foundation | Must be included verbatim (it is; SHA-256 matches apache.org) | ✅ |
| Contributor Covenant 2.1 | `CODE_OF_CONDUCT.md` | contributor-covenant.org | CC BY 4.0 — attribution required | ✅ Attribution section retained |
| Third-party source code | — | — | — | None identified |

## 3. Elements that follow public conventions (not copied code)

These are names, formats or facts defined by others. Using them does not incorporate
third-party source code:

- **SARIF 2.1.0** output structure (OASIS standard) and the schema URL
  `https://json.schemastore.org/sarif-2.1.0.json`.
- **Credential variable names** such as `OPENAI_API_KEY`, `GITHUB_TOKEN`,
  `AWS_SECRET_ACCESS_KEY` — public naming conventions used as detection keys.
- **API and module names** used as detection patterns (e.g. `subprocess.run`,
  `requests.post`, `openai`, `langchain`, `crewai`, `mcp.server.Server`, `FastMCP`,
  `mcpServers`) — identifiers matched as strings, not code from those projects.
- **Precision regression tests** (`tests/test_precision_external.py`) were informed by
  reviewing public repositories (OpenAI Agents SDK, MCP reference servers). They contain
  only synthetic file paths and project-authored assertions; no code from those
  repositories is included, downloaded or executed.

## 4. Review method

1. **Import analysis** — every `import` / `from … import` in `src/` and `tests/` parsed
   with Python's `ast` and classified as standard library, first-party or third-party.
2. **Marker search** — case-insensitive search for copyright notices, `(c)`/`©`, SPDX
   identifiers, license names (MIT, BSD, GPL, Apache, MPL), "all rights reserved",
   author tags, and phrases such as "copied", "adapted", "based on", "taken from",
   "derived from", "ported from", Stack Overflow / Stack Exchange / gist links.
3. **URL inventory** — all URLs in source, tests and configuration (only project URLs,
   the SARIF schema URL and `example.com` placeholders were found).
4. **Vendoring check** — no `vendor/`, `third_party/`, `_vendor/`, minified or bundled
   files in the repository or Git history.
5. **Consistency check** — uniform conventions across all 30 source modules (every
   module except `__init__.py` uses `from __future__ import annotations`; 100% of
   functions have return-type annotations); no identical multi-line blocks shared
   across modules; non-ASCII characters limited to project UI symbols (`—`, `→`).
6. **Git history** — all 25 commits authored by the project founder; no merged pull
   requests or external contributors as of commit `6f3cdf5`.
7. **Distribution check** — built wheel and sdist inspected for unexpected files.

### Not performed

- Comparison against large public code corpora (e.g. code search services or
  license-scanning SaaS). This would require sending source code to an external
  service and was not done without the owner's approval.
- Automated license scanners (e.g. ScanCode Toolkit) were not run; they can be added
  in a later review.

## 5. Ongoing policy

- New third-party code may only be added with a compatible license and the required
  attribution in `NOTICE` (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- Contributors must only submit work they have the right to contribute.
- This document is updated when third-party components are added.
