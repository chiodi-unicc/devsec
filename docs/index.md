---
title: Home
layout: home
nav_order: 1
---

# devsec

Security checks for code changes, run locally before you commit.
{: .fs-6 .fw-300 }

{: .prototype }
devsec is a prototype under active development and testing. Commands, output and
configuration may change without notice. Do not rely on it as a security control.

[Get started](getting-started){: .btn .btn-primary .mr-2 }
[How it works](how-it-works){: .btn }

---

devsec runs the checks a DevSecOps pipeline runs (static analysis, secret detection,
dependency vulnerabilities) on your machine, applies a policy, and reports only what the
policy flags. It is built for coding agents: an agent can scan its own change, read a
short result and fix it, before the code reaches review or CI.

It complements your pipeline. It does not replace it.

## Why use it

**Feedback in seconds, not after a pipeline run.**
A change is checked against the last commit; only problems the change introduced are
reported. Repeat scans of the same code are cached.

**Your code stays on your machine.**
Scanning happens locally. There is no service to sign up to and nothing is uploaded.
See [Security and data](security).

**Established open-source tools, unchanged.**
[Semgrep](https://semgrep.dev), [Trivy](https://trivy.dev), [Syft](https://github.com/anchore/syft)
and [conftest](https://www.conftest.dev) do the work. devsec runs them, collects their
output and never alters what they find.

**Policy as code.**
What blocks and what warns is written in Rego. Exceptions need a reason and an expiry date.

## What it looks like

A developer adds a route that passes request input to a shell command:

```console
$ devsec scan
devsec: fail: 1 new deny, 0 new warn (8 existing deny, 5 existing warn from HEAD, not counted)
```

```json
{
  "id": "1829b74ef49b4b",
  "verdict": "deny",
  "severity": "high",
  "scanner": "semgrep",
  "rule": "javascript.lang.security.detect-child-process.detect-child-process",
  "path": "app.js",
  "line": 14,
  "message": "Detected calls to child_process from a function argument `req`. ...",
  "policy": ["high severity code finding"],
  "new": true
}
```

One finding, the one the change introduced. The existing findings are counted, not repeated.
