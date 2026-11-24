/** What is scanned: a git tree, content-addressed. */
export type Subject = {
  readonly repoRoot: string;
  readonly treeSha: string;
  /** HEAD commit, if the repo has one. */
  readonly headSha?: string;
  /** true when the tree differs from HEAD's tree (uncommitted changes were scanned). */
  readonly dirty: boolean;
  /** The ref given with --ref, if any. */
  readonly ref?: string;
};
