/** Every path devsec uses, derived purely from the repo root. POSIX separators. */
const join = (...parts: readonly string[]): string => parts.join("/").replace(/\/{2,}/g, "/");

export const devsecDirName = ".devsec";

/** Run ids are `<12 hex of the tree>-<8 hex of the scan key>`; anything else is rejected (no path traversal). */
export const isRunId = (id: string): boolean => /^[0-9a-f]{12}-[0-9a-f]{8}$/.test(id);

export const workspaceLayout = (repoRoot: string) => {
  const root = join(repoRoot, devsecDirName);
  return {
    root,
    gitignore: join(root, ".gitignore"),
    tmp: join(root, "tmp"),
    subjectIndex: join(root, "tmp", "subject-index"),
    snapshots: join(root, "snapshots"),
    snapshot: (treeSha: string) => join(root, "snapshots", treeSha),
    snapshotIndex: (treeSha: string) => join(root, "tmp", `snapshot-index-${treeSha}`),
    runs: join(root, "runs"),
    latest: join(root, "latest"),
    uiJson: join(root, "ui.json"),
    uiLog: join(root, "ui.log"),
    defaultPolicy: join(root, "policy", "default"),
    /** Index: scan key → the run directory holding that scan's tool outputs. */
    scanIndex: (key: string) => join(root, "cache", "scans", `${key}.json`),
    run: (runId: string) => runLayout(join(root, "runs", runId)),
  };
};

export const runLayout = (dir: string) => ({
  dir,
  runJson: join(dir, "run.json"),
  events: join(dir, "events.jsonl"),
  raw: join(dir, "raw"),
  sbomDir: dir,
  findings: join(dir, "findings.json"),
  policyDir: join(dir, "policy"),
  policyInput: join(dir, "policy", "input.json"),
  policyData: join(dir, "policy", "data.json"),
  policyResult: join(dir, "policy", "result.json"),
  filteredDir: join(dir, "filtered"),
  reportJson: join(dir, "report.json"),
  reportSarif: join(dir, "report.sarif"),
});

export type WorkspaceLayout = ReturnType<typeof workspaceLayout>;
export type RunLayout = ReturnType<typeof runLayout>;

/** .devsec ignores itself, so the repository's own .gitignore is never edited. */
export const devsecGitignore = "*\n";
