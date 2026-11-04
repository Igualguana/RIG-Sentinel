# RIG Sentinel Phase 1 release checklist

## Automated gates
- [ ] Windows: existing 149 tests plus new SARIF tests pass
- [ ] Linux GitHub Actions CI passes on `push` and `pull_request`
- [ ] Terminal/JSON/HTML/SARIF outputs generate on a sanitized sample repo
- [ ] SARIF artifact downloads and validates with a SARIF-aware tool

## Security validation
- [ ] Test clean, positive and adversarial fixtures; record false positives and misses
- [ ] Run on at least two permission-approved external repositories, using no production credentials
- [ ] Review output for secret leakage, source disclosure, HTML injection and path manipulation
- [ ] Audit package dependencies and release artifacts

## Documentation and publication
- [ ] Confirm README installation and CLI docs
- [ ] Confirm copyright holder and choose/approve an open-source LICENSE (do not publish without one)
- [ ] Review SECURITY.md and enable a private vulnerability reporting method
- [ ] Confirm CONTRIBUTING.md and examples
- [ ] Tag a tested version, publish release notes, attach checksums
- [ ] Verify clean installation from release in fresh Windows and Linux virtual environments

Phase 1 is complete only when all gates above are reviewed and checked, not solely when tests pass.
