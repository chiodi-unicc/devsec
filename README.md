# devsec

Local DevSec(Ops) for coding agents: run the security checks a DevSecOps pipeline would,
on your machine, against the exact code state, and get back only what the policy flags.

devsec **orchestrates** established open-source tools and never scans anything itself:

| step | tool | runs on |
| --- | --- | --- |
| SBOM | `syft scan dir:.` (CycloneDX + SPDX) | snapshot |
| SAST + secrets | `semgrep` (`p/default` + `p/secrets`, one process) | snapshot |
| secrets | `trivy fs --scanners secret` | snapshot |
| SCA | `trivy sbom` | the Syft SBOM (no second walk of the source) |
| policy | `conftest` (Rego, Conforma-style) | projected findings |

The **subject** is a git tree: the working tree (tracked + untracked, non-ignored files)
staged into a private index (your index is never touched), or `--ref <commit>`. It is
checked out with git's own plumbing into `.devsec/snapshots/<tree>/`, and every tool
runs there with `cwd` = snapshot root, so project tool configs apply as usual.
`scripts/equivalence.sh` proves results equal running each tool directly in the repo.

## Layout

```
packages/core   pure functions: projections, policy, reports, orchestration (no I/O)
packages/node   Node implementations of core's ports (exec, fs, watch), shared by the apps
apps/cli        devsec command
apps/mcp        MCP server (FastMCP, stdio)
apps/ui         devsec-ui: SolidJS UI + server, bundled into one npx-able file
```

Core workflows are curried: `scanWith(steps)(deps)(args)`. Core implements the steps and
exports `scan = scanWith(scanSteps)`; apps bind infrastructure with
`scan(nodeDeps(emit))` and call it with args. Only `emit` differs per app (stderr progress,
MCP progress notifications), so `exec`/`fs`/`now` live once in `@devsec/node`.

## Use

```sh
pnpm install && pnpm build
node apps/cli/dist/main.js setup           # pinned toolchain → ~/.devsec/tools (sha256-verified)

node apps/cli/dist/main.js doctor
node apps/cli/dist/main.js scan            # compact JSON: status, counts, byRule, new findings first
node apps/cli/dist/main.js findings --new  # page through the rest (--rule, --path, --verdict, --offset)
node apps/cli/dist/main.js scan --format sarif
node apps/cli/dist/main.js finding <id>    # full detail + the tool's raw result
node apps/cli/dist/main.js init            # devsec.json + editable policy in devsec/policy
node apps/cli/dist/main.js ui              # start/reuse the live UI in the background, open it
node apps/cli/dist/main.js ui --stop
npx /path/to/devsec/apps/ui                 # in a repo: live UI on http://127.0.0.1:4321
claude mcp add devsec -- node /path/to/devsec/apps/mcp/dist/main.js
```

Exit codes: 0 pass, 1 policy deny (or warn with `"failOn": "warn"`), 2 error.

## Baseline: new findings only

With uncommitted changes, findings are compared with `HEAD` (the same pipeline on HEAD's
tree, cached per tree): findings marked `new` are the ones the change introduced, and only
new deny findings fail the scan. Set `"baseline": "origin/main"` in `devsec.json` or pass
`--baseline <ref>` for branch-level baselines; `none` disables it. Finding ids are
line-independent (rule + path + matched text), so moving code doesn't make findings "new".

The agent gets a compact view (`byRule` + up to `--limit` findings, `next` to page);
`report.json` keeps everything. On Django (532k LOC, 612 flagged findings) a one-file
change returns ~10 KB with the 6 new findings, instead of a 400 KB report.

## Toolchain

`devsec setup` installs pinned versions into `~/.devsec/tools` (`$DEVSEC_TOOLS`):
trivy, syft and conftest from their GitHub releases, each archive checked against a
SHA-256 stored in `packages/core/src/setup/toolchain.ts`, and semgrep in its own Python
venv (needs python3 ≥ 3.10). devsec puts that directory first on PATH, so pinned tools win
and your own installs are the fallback. `devsec doctor` shows each tool's path and flags
versions that differ from the pinned ones.

## UI

`devsec-ui` serves the repository in the current folder (`-C <dir>` for another,
`--port`, `--open`). It watches `.devsec/runs` with `fs.watch` and pushes changes to the
browser over one server-sent-events stream, so scans started from the CLI or MCP show up
and progress live, with no polling. The package is a single bundled `dist/cli.js` plus the
static client, with no runtime dependencies:

```sh
devsec ui                                         # from the CLI (MCP: devsec_ui tool)
cd /path/to/repo && npx /path/to/devsec/apps/ui   # directly, local checkout
npx @devsec/ui                                    # directly, once published
```

`devsec ui` / `devsec_ui` start it detached (log: `.devsec/ui.log`, pid and url:
`.devsec/ui.json`), reuse it when it already serves this repository, and stop it with
`--stop` / `stop: true`. The launcher is chosen in `@devsec/node` (`uiRunner`):
`DEVSEC_UI_BIN`, else the local workspace build, else `npx --yes @devsec/ui`.

## .devsec (ignored by git via its own .gitignore)

```
snapshots/<tree>/        pinned source the tools scan
runs/<tree>-<key>/       run.json, events.jsonl, raw/ (verbatim tool output),
                         sbom.*.json, findings.json, policy/, report.json, report.sarif
latest -> runs/...
```

Note: `trivy fs .` or `syft dir:.` run by hand in the repo root will also walk into
`.devsec/` (they don't read `.gitignore`). Your CI never sees it, since it isn't committed.

## Development

```sh
pnpm test          # unit tests on recorded real tool output, policy via real conftest
pnpm typecheck
pnpm fixtures      # re-record tool output (after tool upgrades)
pnpm equivalence   # devsec vs direct tool runs must match
```

See `docs/optimisations.md` for deferred optimisations.
