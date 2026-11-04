# RIG Sentinel — Phase 1 release candidate

RIG Sentinel scans repositories for AI agent references, MCP integrations, sensitive tools, credential references, possible permission relationships, attack paths, and advisory remediation.

Current modes: terminal, JSON (`--json`), offline HTML (`--html output.html`), and SARIF 2.1.0 (`--sarif output.sarif`).

**Limitations:** static analysis only; false positives and false negatives are expected. A shared credential name is not proof of sharing an underlying secret. Blast Radius is a heuristic exposure score, not a breach probability. Policy Generator is advisory only. There is no runtime permission firewall or SaaS in Phase 1.

Read `docs/PHASE1_INSTALL.md`, `docs/PHASE1_RELEASE_CHECKLIST.md`, `SECURITY.md`, and `CONTRIBUTING.md`.

This is a release candidate until the checklist is satisfied. Decide on and publish an open-source license before calling the repository open source.
