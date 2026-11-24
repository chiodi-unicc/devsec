---
title: Security and data
nav_order: 9
---

# Security and data

What devsec reads, what it stores and what goes over the network.
{: .fs-5 .fw-300 }

## Your code

- Code is scanned on your machine. devsec has no server and uploads nothing.
- Scan results are written to `.devsec/` inside the repository, which git ignores.
  The scanners' raw output there can include the matched code, including secrets.

## Network access

devsec itself sends no data. The scanners download what they need:

| When | What | From |
|------|------|------|
| `devsec setup` | Trivy, Syft, conftest | GitHub releases, verified against SHA-256 checksums in devsec's source |
| `devsec setup` | Semgrep, pinned version | PyPI |
| `devsec setup` and scans | Trivy vulnerability database, when out of date | Trivy's database registry |
| Scans | Semgrep registry rules (`p/default`, `p/secrets`) | semgrep.dev |

Downloading rules sends no code.

devsec turns off the scanners' own usage reporting and update checks on every run:

| Tool | Setting |
|------|---------|
| Semgrep | `--metrics=off`, `SEMGREP_ENABLE_VERSION_CHECK=0` |
| Trivy | `TRIVY_DISABLE_TELEMETRY=true`, `TRIVY_SKIP_VERSION_CHECK=true` |
| Syft | `SYFT_CHECK_FOR_APP_UPDATE=false` |

These settings do not change what the scanners find; the project's tests compare
devsec's results with running each tool directly.

## Supply chain

- Scanner versions are pinned in devsec's source; `devsec doctor` reports any
  difference from the pinned versions.
- Scanners are installed in `~/.devsec/tools`, not system-wide.
- Each run records the tool versions and the exact commands used.

## Dashboard

The dashboard listens on `127.0.0.1` only and rejects requests addressed to any other
host name, which prevents access from web pages through DNS rebinding.

## Scope

devsec gives fast feedback while code is written. It is not a control:

- It runs on a developer's machine and can be skipped or modified.
- It produces no attestations or signatures.
- It does not scan container images or running systems.

Keep your pipeline's security checks as the point of enforcement.
