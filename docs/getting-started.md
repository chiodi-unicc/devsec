---
title: Getting started
nav_order: 2
---

# Getting started

Install devsec, run a first scan and read the result. About ten minutes.
{: .fs-5 .fw-300 }

## Requirements

- macOS or Linux, on arm64 or x64
- Node.js 24 or later
- git
- Python 3.10 or later (Semgrep is installed into its own virtual environment)
- Internet access for the first setup and the first scan
- About 650 MB of disk for the scanners

## 1. Install

```sh
npm install -g devsec
```

Or run any command without installing: `npx devsec <command>`.

## 2. Install the scanners

```sh
devsec setup
```

This downloads pinned versions of Trivy, Syft and conftest, checks each against a
SHA-256 checksum, installs Semgrep into a virtual environment and downloads the Trivy
vulnerability database. Everything goes to `~/.devsec/tools`; nothing is installed
system-wide.

Check the result:

```sh
devsec doctor
```

Already have the tools installed? devsec uses them when they are on your `PATH`. `doctor`
reports any version that differs from the pinned one.

## 3. Scan

In any git repository:

```sh
devsec scan
```

Progress is printed to stderr, the result to stdout as JSON:

```console
devsec: scanning tree ea3bdc2bb0bf
  ✓ snapshot
  ✓ trivy-secrets 1 results
  ✓ sbom
  ✓ trivy-sca 8 results
  ✓ semgrep 6 results
  ✓ policy
  ✓ report 13 results
devsec: fail: 8 deny, 5 warn (no baseline: all findings count)
```

The first scan downloads Semgrep's rules and takes longer. Later scans of unchanged code
return from cache.

## 4. Read the result

Each finding has a **verdict** from the policy:

- `deny`: must be fixed (or given an exception). The scan fails.
- `warn`: reported, does not fail the scan.

Findings the policy does not flag are dropped from the output and only counted.

```json
{
  "id": "145a6dd9339054",
  "verdict": "deny",
  "severity": "high",
  "scanner": "trivy-sca",
  "rule": "CVE-2020-8203",
  "package": "lodash@4.17.15",
  "fix": "4.17.19",
  "message": "nodejs-lodash: prototype pollution in zipObjectDeep function",
  "policy": ["CVE-2020-8203 lodash@4.17.15, fixed in 4.17.19"]
}
```

For the full detail, including the scanner's original output:

```sh
devsec finding 145a6dd9339054
```

Exit codes: `0` pass, `1` the policy failed, `2` error.

## 5. Change something and scan again

With uncommitted changes, devsec compares against the last commit and reports only
what your change introduced:

```console
$ devsec scan --quiet
devsec: fail: 1 new deny, 0 new warn (8 existing deny, 5 existing warn from HEAD, not counted)
```

See [Results and baseline](results) for details.

## 6. Connect your coding agent

```sh
claude mcp add devsec -- npx -y devsec mcp
```

See [Use with coding agents](agents) for other clients and suggested instructions.

## Optional: pre-commit check

Block commits that introduce new `deny` findings. Save as `.git/hooks/pre-commit` and make
it executable (`chmod +x`):

```sh
#!/bin/sh
exec devsec scan --quiet --limit 5 >&2
```

{: .note }
The hook scans the working tree, including changes you have not staged.

## Optional: see it in the browser

```sh
devsec ui
```

See [Dashboard](dashboard).
