# GitHub Repository Setup — Proposal

Proposed settings for `Igualguana/RIG-Sentinel` ahead of the v0.1.0 public launch.
**Nothing here has been applied.** Each item requires the owner's approval.

Current state (read-only check, 2026-11-04): visibility **private**, Issues enabled,
Discussions disabled, no topics, no license detected, default branch `main`.

## 1. About section

**Description** (current text is long and mentions remediation features beyond v0.1.0):

> Open-source security scanner for AI agents, MCP servers, identities, permissions, and exposure risks.

**Public identity** (as presented in the README):

| | |
|---|---|
| Founder & Lead Maintainer | Randy Igualguana |
| Commercial Operator (proposed) | RIG Industrial Technologies LLC |
| Community License | Apache License 2.0 |
| Website | https://rigindustrialusa.com |

**Website:** `https://rigindustrialusa.com` (RIG Industrial Technologies LLC). Alternative:
`https://github.com/Igualguana/RIG-Sentinel#readme` if a project-specific page is preferred.

The founder's GitHub profile (`Igualguana`) already owns the repository. If the project is
later transferred to a GitHub organization for RIG Industrial Technologies LLC, GitHub
redirects old URLs, but README links and `pyproject.toml` URLs should be updated.

Enable "Releases" in the sidebar; disable "Packages" and "Deployments" unless used.

## 2. Topics

All topics below were confirmed to exist on GitHub (each is already used by other
public repositories). Recommended set (14 of the 20 allowed):

| Topic | Reason |
|---|---|
| `ai-security` | Primary category |
| `agent-security` | Primary category |
| `ai-agents` | Audience discovery |
| `mcp` | MCP ecosystem |
| `model-context-protocol` | Full name, widely used |
| `mcp-security` | Niche, high relevance |
| `llm-security` | Adjacent audience |
| `appsec` | Security audience |
| `devsecops` | CI/CD integration audience |
| `security-scanner` | What the tool is |
| `static-analysis` | How it works |
| `sarif` | Output format integration |
| `python` | Implementation language |
| `cybersecurity` | Broad category |

Not recommended: `open-source` (adds no discovery value for an already-public repo).

Command (after approval):

```bash
gh repo edit Igualguana/RIG-Sentinel \
  --homepage "https://rigindustrialusa.com" \
  --description "Open-source security scanner for AI agents, MCP servers, identities, permissions, and exposure risks." \
  --add-topic ai-security,agent-security,ai-agents,mcp,model-context-protocol,mcp-security,llm-security,appsec,devsecops,security-scanner,static-analysis,sarif,python,cybersecurity
```

## 3. Social preview (Open Graph image)

- Size **1280 × 640 px** (minimum 640 × 320), PNG, under 1 MB.
- Content: project name, one-line value proposition, and a simple graph motif
  (agent → tool → resource). Keep text inside the central safe area.
- Do not include fabricated metrics, customer logos or screenshots of reports that were
  not generated from real (synthetic) scan data.
- Upload in *Settings → General → Social preview*.

## 4. Issues and pull requests

- Keep Issues enabled. Templates are in `.github/ISSUE_TEMPLATE/` (bug report,
  false positive / false negative, feature request; blank issues disabled; security
  link to private reporting).
- Create labels: `bug`, `enhancement`, `triage`, `detection-accuracy`, `documentation`,
  `good first issue`, `help wanted`.
- Pull requests: enable "Allow squash merging" only (or squash + rebase), "Always suggest
  updating pull request branches", and "Automatically delete head branches".

## 5. Discussions

Recommended **on** at launch with categories: Announcements (maintainer-only),
Q&A, Ideas, Show and tell. Point general questions there to keep Issues actionable.

## 6. Branch protection / ruleset for `main`

- Require a pull request before merging (1 approval once there are other maintainers;
  0 while solo, but keep the PR requirement).
- Require status checks: `Python 3.13 / ubuntu-24.04`, `Python 3.13 / ubuntu-26.04`,
  `Python 3.13 / macos-15-intel`. Do **not** require the Apple Silicon workflow until it
  runs reliably (`macos-latest` has had runner-capacity delays).
- Require branches to be up to date before merging.
- Require conversation resolution.
- Block force pushes and deletions.
- Optionally require signed commits.
- Add a tag ruleset protecting `v*` tags from deletion and update.

## 7. Security features

| Feature | Recommendation |
|---|---|
| Private vulnerability reporting | **Enable before going public** — `SECURITY.md` links to it. |
| Secret scanning + push protection | Enable (free for public repositories). |
| Dependabot alerts | Enable. |
| Dependabot version updates | Add `.github/dependabot.yml` for `github-actions` and `pip` (proposal below). |
| CodeQL (Python) | Recommended. Compatible: pure-Python project, no build step. Use default setup in *Settings → Code security*. |
| Action pinning | Pin workflow actions to commit SHAs (audit finding M-2). |
| Workflow permissions | Set the repository default `GITHUB_TOKEN` permission to read-only. |

Proposed `.github/dependabot.yml` (not added; awaiting approval):

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

## 8. Visibility change (owner action)

Only after the [release checklist](RELEASE_CHECKLIST.md) is complete:

1. Re-run a final secret scan on `main`.
2. Enable private vulnerability reporting.
3. *Settings → General → Danger Zone → Change visibility → Public*.
4. Immediately enable secret scanning, push protection, Dependabot and CodeQL.
5. Apply branch protection.
