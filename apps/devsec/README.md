# devsec

Security checks for code changes, run locally before you commit.

> **Prototype.** devsec is under active development and testing. Commands, output and
> configuration may change without notice. Do not rely on it as a security control.

devsec runs the checks a DevSecOps pipeline runs (static analysis, secret detection,
dependency vulnerabilities) on your machine, applies a Rego policy, and reports only what
the policy flags. It is built for coding agents: an agent scans its own change, reads a
short result and fixes it before the code reaches review or CI. It complements your
pipeline; it does not replace it.

The scanning is done by [Semgrep](https://semgrep.dev), [Trivy](https://trivy.dev),
[Syft](https://github.com/anchore/syft) and [conftest](https://www.conftest.dev), unchanged.
Code stays on your machine.

## Quick start

Requires Node.js 24+, git and Python 3.10+, on macOS or Linux.

```sh
npm install -g devsec
devsec setup        # pinned, checksum-verified scanners in ~/.devsec/tools
devsec scan         # in any git repository
```

Connect a coding agent over MCP:

```sh
claude mcp add devsec -- npx -y devsec mcp
```

Open the live dashboard:

```sh
devsec ui
```

## Documentation

<https://chiodi-unicc.github.io/devsec/>

## Licence

Apache-2.0. See [LICENSE](LICENSE).
