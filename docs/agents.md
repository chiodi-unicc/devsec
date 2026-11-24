---
title: Use with coding agents
nav_order: 3
---

# Use with coding agents

Give an agent a way to check its own changes and fix what it introduced.
{: .fs-5 .fw-300 }

## Connect with MCP

devsec includes an [MCP](https://modelcontextprotocol.io) server. It runs over stdio, in
the repository the agent is working in.

**Claude Code**

```sh
claude mcp add devsec -- npx -y devsec mcp
```

Add `-s user` to make it available in every project. Check the connection with `/mcp`.

**Other MCP clients**

Configure a stdio server with the command `npx` and the arguments `-y devsec mcp`.
For clients configured with JSON:

```json
{
  "mcpServers": {
    "devsec": { "command": "npx", "args": ["-y", "devsec", "mcp"] }
  }
}
```

## Tools

| Tool | Use |
|------|-----|
| `devsec_scan` | Scan the working tree (or a commit). Returns the summary and the new findings. |
| `devsec_findings` | Page through and filter findings of a scan: by file, rule, verdict, new. |
| `devsec_finding` | Full detail of one finding, including the scanner's original result. |
| `devsec_doctor` | Check the scanners are installed. |
| `devsec_setup` | Install the pinned scanners. |
| `devsec_ui` | Open the [dashboard](dashboard) for the user. |

Parameters are listed in the [MCP reference](reference/mcp).

## Without MCP

Agents that run shell commands can use the CLI directly. The output is the same JSON:

```sh
devsec scan --quiet
devsec findings --file src/api/
devsec finding <id>
```

## What the agent sees

The result is kept small so it does not fill the agent's context:

- Only findings the policy flags.
- With uncommitted changes, only **new** findings: those the change introduced.
- At most 20 findings (`limit`). If there are more, a per-rule summary and the exact
  call to fetch the next page.
- A one-line `summary` that states both sides, so a pass is not read as "the
  repository is clean":
  `pass: no new findings (5 existing deny, 9 existing warn from HEAD, not counted)`

On a large project (Django, 532,000 lines, 612 flagged findings), a one-file change
returns about 10 KB with the 6 new findings, instead of a 400 KB report.

## Suggested instructions

Add to the project's `CLAUDE.md` or `AGENTS.md`:

```markdown
## Security checks
- After changing code or dependencies, run `devsec_scan` (or `devsec scan --quiet`).
- Fix every new `deny` finding before finishing. Do not silence rules.
- If a finding is a false positive, say so and leave it for a human to add an exception.
- Use `devsec_finding <id>` only when the summary is not enough to fix it.
```
