---
title: Report format
parent: Reference
nav_order: 3
---

# Report format

The JSON printed by `devsec scan` and returned by `devsec_scan`.

| Field | Description |
|-------|-------------|
| `status` | `pass`, `fail` or `error` |
| `summary` | One line stating new and existing findings |
| `subject` | `tree` scanned, `head` commit, `dirty` (uncommitted changes) |
| `runId`, `run` | Scan id and its folder in `.devsec/runs/` |
| `scanners` | Scanners that ran |
| `baseline` | `ref`, `tree` and `runId` of the baseline scan, when there is one |
| `counts` | `found`, `flagged`, `deny`, `warn`, `dropped`, `new`, `newDeny` |
| `existing` | `deny` and `warn` counts already in the baseline |
| `errors` | Scanners that failed, with their message |
| `policy` | Results not tied to a finding, e.g. unused exceptions |
| `scope` | `new` or `all` |
| `byRule` | Findings grouped by rule, when not all are listed |
| `findings` | The findings listed (see below) |
| `more`, `next` | Findings not listed, and the call that fetches them |

## Finding

| Field | Description |
|-------|-------------|
| `id` | Stable id: rule, file and matched code; independent of line numbers |
| `verdict` | `deny` or `warn` |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `scanner` | `semgrep`, `trivy-secrets` or `trivy-sca` |
| `rule` | Scanner rule id, or CVE/GHSA id |
| `path`, `line` | Location, for code and secret findings |
| `package`, `fix` | Package and fixed version, for dependency findings |
| `message` | The scanner's message |
| `policy` | The policy rules that flagged it |
| `new` | Not present in the baseline |
