# Changelog

devsec follows [semantic versioning](https://semver.org). While the version is 0.x, any
release may change commands, output or configuration.

## 0.1.0 (unreleased)

First public prototype.

- `devsec` package with the CLI, the MCP server (`devsec mcp`) and the dashboard (`devsec ui`).
- Scanners: Semgrep (code and secrets), Trivy (secrets, and dependencies from a Syft SBOM).
- Policy with conftest: built-in default, exceptions with expiry, custom Rego.
- Baseline: only findings introduced by uncommitted changes fail the scan.
- `devsec setup` installs pinned, checksum-verified scanners.
- Scanner usage data and update checks are turned off.
