# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1.0 | ❌ |

RIG Sentinel is early-stage software. Only the latest release receives security fixes.
No long-term support commitment is made at this stage.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions or pull requests.**

Report privately through **GitHub private vulnerability reporting**:
<https://github.com/Igualguana/RIG-Sentinel/security/advisories/new>

If you cannot use GitHub, e-mail **security@rigindustrialusa.com** instead.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, using synthetic data.
- Affected version or commit.
- Any suggested fix.

Do **not** include real secrets, credentials, customer code or personal data in a report.

### Responsible (coordinated) disclosure

RIG Sentinel follows coordinated disclosure:

1. You report privately through GitHub private vulnerability reporting.
2. The maintainer acknowledges the report as soon as practical and assesses it.
3. If confirmed, a fix is prepared privately (a temporary private fork may be used) and
   a release is published.
4. A GitHub Security Advisory is published with the fix, crediting the reporter if they
   wish.
5. Please keep details confidential until the advisory is published, or until you and
   the maintainer agree on a disclosure date.

This is a small, volunteer-maintained project: response times are best effort and no
service-level commitment is made. If you believe a report has been missed, follow up
through the same private channel.

Please test only against code and systems you own or are authorized to test, and use
synthetic data.

## Scope

In scope — issues in RIG Sentinel itself, for example:

- Code execution or file writes outside the requested output path while scanning
  untrusted repositories.
- Injection in HTML or SARIF reports.
- Credential values leaking into reports.
- Crashes or resource exhaustion triggered by crafted repositories.

Out of scope:

- Findings that RIG Sentinel reports *about a scanned repository* — those are the tool's
  normal output.
- False positives or false negatives in detection — please open a regular issue using the
  *False positive / false negative* template.

## Using RIG Sentinel safely

- RIG Sentinel is a **static analyzer**. It does not block agent behavior, enforce
  policies, or prove that credentials are shared or exposed.
- Reports contain the absolute scanned path, file paths and credential **names**. Review
  JSON, HTML and SARIF output before sharing it publicly.
- Never put real secrets in test fixtures or issue reproductions.

See also [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
