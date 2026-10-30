# Initial Architecture

## Components

### Discovery Engine
Finds AI agents, MCP servers, AI SDK usage, agent manifests, workflows, tools, and integrations.

### Normalization Layer
Converts discovered assets into a common model:

- Agent
- Identity
- Tool
- Permission
- Resource
- Data source
- External destination
- Control

### Exposure Graph
Stores relationships such as:

Agent -> Identity -> Permission -> Resource -> Sensitive Data -> Egress Path

### Analysis Engine
Calculates:

- Excessive permissions
- Dangerous permission combinations
- Attack paths
- Blast radius
- Ownership gaps
- Shadow agents
- Exposure score

### Remediation Engine
Produces:

- Suggested permission reductions
- Policy changes
- Human-approval requirements
- Generated configuration patches
- Future pull requests

### Evidence Layer
Tracks what was discovered, what changed, why a risk was scored, and what remediation was applied.

## MVP architecture

For v0.1 use a local CLI and in-memory graph representation. Avoid a database and web dashboard until the domain model is stable.
