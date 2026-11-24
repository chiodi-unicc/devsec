# Optimisations backlog

Ideas found while building devsec, kept for a later pass. None are implemented.
Each one must keep the rule that devsec never changes what a tool finds.

## Report size

- **Prune unreferenced SARIF rule descriptors.** Semgrep's SARIF lists every rule in
  the configured rulesets (1,077 for `p/default` + `p/secrets`; 2.1 MB for 6 results).
  After filtering results, drop rule descriptors nothing references and remap
  `ruleIndex` where used. More than 50× smaller; kept results stay byte-identical.

## Finding identity

- **Line-independent ids.** Semgrep's `extra.fingerprint` needs a Semgrep login
  (`"requires login"` otherwise), so ids hash rule + exact span and change when code
  moves. Options: use the fingerprint when logged in; hash rule + path + matched text.

## Speed

- **Cache tool versions.** A fully cached scan takes ~1.2 s, mostly `semgrep --version`
  (~0.9 s, Python startup). Versions could be cached by binary path + mtime.
- **Reuse the SBOM across configs.** The SBOM depends only on the tree and the Syft
  version, but it sits in the run directory, so a semgrep ruleset change regenerates it.

## Agent context

- **Slimmer `devsec_finding` raw output.** The raw tool result is returned verbatim, so a
  Trivy CVE still carries ~20+ reference URLs plus CVSS vectors (~4 KB). An opt-in
  `fields` / `maxReferences` parameter could trim it for agents, as long as the default stays verbatim.

## Measured on a real repo (Django: 7,104 files, 532k LOC Python), M1 Ultra 20 cores

| step | cold |
| --- | --- |
| semgrep (p/default + p/secrets) | 18.2 s |
| syft SBOM | 1.6 s |
| snapshot (git checkout-index) | 1.0 s |
| tool versions | 1.0 s |
| trivy secrets / trivy SCA / policy / report | 0.4 / 0.06 / 0.05 / 0.14 s |
| **total** | **20.4 s** (cache hit: ~1.2 s) |

Semgrep alone by `--jobs`: 16 → 16.6 s / 638 MB, 8 → 17.2 s / 492 MB, 4 → 20.5 s / 420 MB,
2 → 27.8 s / 366 MB. Fixed cost (startup + fetch + parse 1,077 rules): 2.5 s / 304 MB.

Laptop-relevant follow-ups:
- **Semgrep CPU share:** cap `--jobs` (e.g. half the cores) and run tools at lower priority
  (`nice`). Neither changes results.
- **Semgrep registry rules are downloaded on every run** (2.6 MB). Cache the fetched pack
  (dated) and pass the local file. Same rules, works offline.
- **Changed files only:** semgrep cost is per file. Semgrep's own `--baseline-commit`
  (a native tool feature) could cut a typical edit's scan to roughly its 2.5 s fixed cost.
- **Agent context, not CPU, is the real limit on big repos:** Django's report is 606
  flagged findings, ~400 KB (~100k tokens); 162 come from one warn rule. Needs
  new-vs-baseline findings, per-rule grouping, and/or pagination.
- **Disk:** the Trivy DB is 1.7 GB in ~/Library/Caches/trivy; the tools take ~600 MB.
