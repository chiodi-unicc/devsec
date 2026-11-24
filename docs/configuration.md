---
title: Configuration
nav_order: 6
---

# Configuration

devsec works without configuration. To change the defaults, add `devsec.json` to the
repository root and commit it.
{: .fs-5 .fw-300 }

## Fields

| Field | Default | Description |
|-------|---------|-------------|
| `scanners` | all | Scanners to run: `semgrep`, `trivy-secrets`, `trivy-sca` |
| `semgrep.rulesets` | `["p/default", "p/secrets"]` | Semgrep `--config` values: registry packs or local rule files |
| `policy` | built-in | Directory of Rego policies, relative to the repository root |
| `exceptions` | `[]` | Accepted findings, see [Policy](policy#exceptions) |
| `failOn` | `"deny"` | `"warn"` also fails on warnings |
| `baseline` | `HEAD` when the tree has changes | A git ref whose findings count as existing, or `"none"` |
| `cacheTtlHours` | `24` | How long an identical scan is reused |

## Example

```json
{
  "scanners": ["semgrep", "trivy-secrets", "trivy-sca"],
  "semgrep": { "rulesets": ["p/default", "p/secrets", "rules/internal.yml"] },
  "policy": "devsec/policy",
  "baseline": "origin/main",
  "failOn": "deny",
  "cacheTtlHours": 24,
  "exceptions": []
}
```

## Scanner configuration

Each scanner also reads its own configuration files from the repository, as it would
when run directly: `.semgrepignore`, `trivy.yaml`, `.trivyignore`, `.syft.yaml`.
