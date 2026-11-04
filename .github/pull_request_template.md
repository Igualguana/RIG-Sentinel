## Summary

<!-- What does this change do, and why? Link related issues (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix
- [ ] Detection rule / precision change
- [ ] New feature
- [ ] Documentation
- [ ] CI / build

## Detection impact

<!-- For detection changes: what new true positives, and what false-positive or
false-negative risk does this introduce? Include positive and negative test cases. -->

## Compatibility

- [ ] CLI options unchanged (or change documented)
- [ ] JSON report keys unchanged (or change documented)
- [ ] SARIF rule IDs unchanged (or change documented)

## Checklist

- [ ] `python -m pytest -q` passes locally
- [ ] `git diff --check` reports no problems
- [ ] Tests added or updated for changed behavior
- [ ] No real secrets, credentials, customer code or personal data in code, tests or fixtures
- [ ] Findings wording stays accurate (indicators, not confirmed vulnerabilities)
- [ ] `CHANGELOG.md` updated if user-visible
