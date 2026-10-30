# RIG Sentinel

**RIG Sentinel is an open-source Agent Exposure Management platform that discovers AI agents, maps their permissions and data access, identifies attack paths and blast radius, and helps organizations automatically reduce excessive agent privileges.**

## Vision

RIG Sentinel helps organizations answer four questions:

1. What AI agents, MCP servers, AI-enabled applications, tools, and automations exist?
2. What identities, permissions, APIs, databases, files, SaaS services, and sensitive data can they access?
3. What attack paths and blast radius would exist if one of those agents were compromised or misconfigured?
4. What permissions or controls should be changed to reduce exposure with the least operational impact?

## Core workflow

DISCOVER -> MAP -> ANALYZE -> REMEDIATE -> PROVE

## Initial MVP

The first release focuses on repository-based discovery and static posture analysis:

- Detect agent manifests and AI integrations.
- Detect MCP configuration and MCP servers.
- Detect high-risk tools and permissions.
- Detect references to secrets and sensitive resources.
- Build a simple resource/permission graph.
- Calculate an initial exposure score.
- Produce JSON and terminal reports.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -e .
rig-sentinel scan .
```

## Project status

Early development / architecture phase.
