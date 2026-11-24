---
title: Policy
nav_order: 5
---

# Policy

The policy decides which findings block, which warn and which are dropped.
{: .fs-5 .fw-300 }

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and evaluated with conftest, in the style used by [Conforma](https://conforma.dev).

## Default policy

| Rule | Verdict | Applies to |
|------|---------|------------|
| `secret` | deny | Any secret found by Trivy, and any finding tagged CWE-798 (hard-coded credentials) |
| `sast_high` | deny | Code findings of high or critical severity |
| `sca_fixable` | deny | Vulnerable dependencies of high or critical severity with a fixed version |
| `sca_unfixable` | warn | Vulnerable dependencies of high or critical severity without a fix |
| `medium` | warn | Medium severity findings, except secrets |
| `exception_unused` | warn | An exception that matches no finding |
| `exception_expired` | warn | An exception past its expiry date |

Everything else (low and informational findings) is dropped.

## Exceptions

Accept a finding temporarily, with a reason. Exceptions go in `devsec.json`:

```json
{
  "exceptions": [
    {
      "finding": "145a6dd9339054",
      "reason": "lodash upgrade scheduled with the framework update, ticket SEC-142",
      "expires": "2027-03-31"
    },
    {
      "rule": "javascript.browser.security.eval-detected.eval-detected",
      "path": "tools/repl.js",
      "reason": "developer-only REPL, not deployed",
      "expires": "2027-06-30"
    }
  ]
}
```

- Match by `finding` id, or by `rule` (optionally limited to one `path`).
- `reason` and `expires` (`YYYY-MM-DD`) are required.
- After the expiry date the finding is flagged again, with a warning about the expired
  exception.
- Exceptions that no longer match anything are reported, so they get cleaned up.

## Fail on warnings

```json
{ "failOn": "warn" }
```

## Custom policy

```sh
devsec init
```

writes `devsec.json` and a copy of the default policy to `devsec/policy/`. Edit the Rego
there; devsec uses that directory instead of the built-in policy. The policy is evaluated
on every scan, so a policy change takes effect without scanning again.

Rules are written as `deny` and `warn` sets in `package devsec`, each result carrying the
`finding_id` it applies to:

```rego
package devsec

import rego.v1

# METADATA
# title: No findings in payment code
# custom:
#   short_name: payments_strict
deny contains result if {
	some f in input.findings
	startswith(f.location.path, "src/payments/")
	result := {"code": "devsec.payments_strict", "msg": "finding in payment code", "finding_id": f.id}
}
```

The input contains `subject` (the scanned tree) and `findings`. Exceptions are available
as `data.exceptions`.
