---
title: Troubleshooting
nav_order: 11
---

# Troubleshooting

Start with `devsec doctor`: it shows each scanner's version and location.
{: .fs-5 .fw-300 }

**A scanner is missing.**
Run `devsec setup`. To use your own installation instead, put it on `PATH`; tools in
`~/.devsec/tools` take precedence.

**`devsec setup` fails on Semgrep.**
Semgrep needs Python 3.10 or later as `python3`. Check with `python3 --version`.

**The first scan is slow.**
Semgrep downloads its rules and Trivy its vulnerability database. Later scans reuse
them, and unchanged code is served from cache.

**Scans are slow on a large repository.**
Semgrep is the slowest step and uses all CPU cores. Limit the scanners with
`--only trivy-secrets,trivy-sca` for a quick check, or narrow Semgrep with
`.semgrepignore`.

**A scan reports `error`.**
The failing scanner and its message are in `errors`. The other scanners' results are still
reported. Raw output is in `.devsec/runs/<runId>/raw/`.

**A finding is a false positive.**
Add an [exception](policy#exceptions) with a reason and an expiry date.

**The dashboard port is taken.**
devsec picks the next free port and prints the address. Use `--port` to choose one.

**Disk usage.**
`devsec clean` removes snapshots and temporary files. `devsec clean --all` removes
`.devsec/` entirely.
