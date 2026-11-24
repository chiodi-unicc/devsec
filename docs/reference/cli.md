---
title: CLI
parent: Reference
nav_order: 1
---

# CLI

```
devsec <command> [options]
```

## scan

Scan the working tree and print the findings the policy flags.

| Option | Description |
|--------|-------------|
| `--ref <commit>` | Scan a commit instead of the working tree |
| `--baseline <ref>` | Findings in `<ref>` count as existing; `none` to disable |
| `--only <a,b>` | Scanners to run: `semgrep`, `trivy-secrets`, `trivy-sca` |
| `--format json\|sarif` | Output format (default `json`). Both are written to `.devsec/runs/<runId>/` |
| `--limit <n>` | Findings to print (default 20) |
| `--all` | All flagged findings, not only new ones |
| `--full` | The complete report instead of the compact view |
| `--quiet` | No progress on stderr |

## findings

Page through and filter the findings of a scan (default: the latest full scan).

| Option | Description |
|--------|-------------|
| `--file <path>` | Findings under this path prefix |
| `--rule <text>` | Rule id contains this text |
| `--verdict deny\|warn` | Only this verdict |
| `--new` | Only new findings |
| `--offset <n>`, `--limit <n>` | Paging |
| `--run <runId>` | A specific scan |

## finding

```
devsec finding <id> [--run <runId>]
```

Full detail of one finding, including the scanner's original result. A unique prefix of
the id is enough.

## setup

Install the pinned scanners into `~/.devsec/tools` (or `$DEVSEC_TOOLS`).

| Option | Description |
|--------|-------------|
| `--force` | Reinstall even if present |
| `--no-db` | Skip downloading the Trivy vulnerability database |

## doctor

Show each scanner's version and location, and differences from the pinned versions.

## init

Write `devsec.json` and an editable copy of the default policy to `devsec/policy/`.

## ui

Start the [dashboard](../dashboard).

| Option | Description |
|--------|-------------|
| `--port <n>` | Preferred port (default 4321) |
| `--no-open` | Don't open the browser |
| `--stop` | Stop the dashboard for this repository |

## mcp

Start the MCP server on stdio. Used by MCP clients, not run by hand.

## clean

Remove snapshots and temporary files. `--all` removes `.devsec/` entirely.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Pass |
| 1 | The policy failed |
| 2 | Error |
