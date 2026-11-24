---
title: Results and baseline
nav_order: 4
---

# Results and baseline

How to read a scan result, and how devsec separates new findings from existing ones.
{: .fs-5 .fw-300 }

## Status

| Status | Meaning | Exit code |
|--------|---------|-----------|
| `pass` | No new `deny` findings. | 0 |
| `fail` | At least one new `deny` finding (or `warn`, with `"failOn": "warn"`). | 1 |
| `error` | A scanner or the policy failed to run. | 2 |

A scanner that fails is reported in `errors`; the others still run.

## Counts

```json
"counts": { "found": 16, "flagged": 14, "deny": 9, "warn": 5, "dropped": 2, "new": 1, "newDeny": 1 }
```

- `found`: everything the scanners reported.
- `flagged`: what the policy marked `deny` or `warn`.
- `dropped`: what the policy did not flag. Kept on disk, not shown.
- `new`, `newDeny`: flagged findings not present in the baseline.

## Baseline

A repository often has existing findings. Reporting all of them on every change
hides the one that matters. With a baseline, devsec scans the baseline commit as well
and marks each finding `new` or existing. Only new `deny` findings fail the scan.

| Situation | Baseline |
|-----------|----------|
| Uncommitted changes | `HEAD` (default) |
| Clean working tree | none: there is nothing to compare |
| `--baseline origin/main` or `"baseline": "origin/main"` | that commit, e.g. for a whole branch |
| `--baseline none` | none: every finding counts |

The baseline scan is cached per commit, so it costs time only once.

![A scan of uncommitted changes that passes: the Baseline step compared it with HEAD and found nothing new]({{ "/assets/dashboard-pass.png" | relative_url }})

Finding ids do not depend on line numbers (rule, file and matched code), so moving
code does not make a finding new.

{: .important }
For gates on the main branch or before a release, use `--baseline none`, so existing
findings fail too.

## Formats

| | Content |
|-|---------|
| JSON (default) | Compact view for agents and scripts. `--full` prints the whole report. |
| SARIF (`--format sarif`) | The scanners' own SARIF, with unflagged results removed. For code-scanning tools and IDEs. |

## Files

Each scan writes to `.devsec/runs/<runId>/` in the repository:

```
report.json, report.sarif   flagged findings
findings.json               all findings, before the policy
raw/                        the scanners' original output
sbom.cdx.json, sbom.spdx.json
policy/                     policy input and result
events.jsonl                progress, read by the dashboard
```

`.devsec/` contains its own `.gitignore`; it is never committed. Remove it with
`devsec clean --all`.
