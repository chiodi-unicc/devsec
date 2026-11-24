---
title: MCP tools
parent: Reference
nav_order: 2
---

# MCP tools

All tools accept `path`: a directory inside the repository (default: the server's
working directory).

## devsec_scan

| Parameter | Description |
|-----------|-------------|
| `ref` | Commit to scan instead of the working tree |
| `scanners` | Restrict to these scanners |
| `baseline` | Ref whose findings count as existing, or `"none"` |
| `scope` | `new` (default with a baseline) or `all` |
| `limit` | Findings to include, 0–200 (default 20) |

Reports progress through MCP progress notifications.

## devsec_findings

| Parameter | Description |
|-----------|-------------|
| `run` | `runId` from `devsec_scan` (default: latest full scan) |
| `file` | Path prefix, e.g. `src/api/` |
| `rule` | Rule id contains this text |
| `verdict` | `deny` or `warn` |
| `new` | Only new findings |
| `offset`, `limit` | Paging (limit 1–200, default 20) |

## devsec_finding

| Parameter | Description |
|-----------|-------------|
| `id` | Finding id, or a unique prefix |
| `run` | `runId` (default: latest full scan) |

## devsec_doctor

No parameters besides `path`.

## devsec_setup

| Parameter | Description |
|-----------|-------------|
| `force` | Reinstall even if present |

## devsec_ui

| Parameter | Description |
|-----------|-------------|
| `open` | Open in the user's browser (default true) |
| `port` | Preferred port (default 4321) |
| `stop` | Stop the dashboard |
