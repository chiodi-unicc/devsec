import type { Command } from "../domain/command.js";

/** Git plumbing, as data. `GIT_INDEX_FILE` keeps the user's real index untouched. */
const git = (cwd: string, args: readonly string[], env?: Record<string, string>): Command => ({
  cmd: "git",
  args,
  cwd,
  ...(env ? { env } : {}),
});

export const gitToplevel = (cwd: string) => git(cwd, ["rev-parse", "--show-toplevel"]);
export const gitHead = (repo: string) => git(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]);
export const gitHeadTree = (repo: string) => git(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]);
export const gitRefCommit = (repo: string, ref: string) => git(repo, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
export const gitRefTree = (repo: string, ref: string) => git(repo, ["rev-parse", "--verify", "--quiet", `${ref}^{tree}`]);
export const gitIndexPath = (repo: string) => git(repo, ["rev-parse", "--path-format=absolute", "--git-path", "index"]);

/** Stage the whole working tree (tracked + untracked, honouring .gitignore) into a private index. */
export const gitAddAll = (repo: string, index: string) => git(repo, ["add", "--all", "."], { GIT_INDEX_FILE: index });
export const gitWriteTree = (repo: string, index: string) => git(repo, ["write-tree"], { GIT_INDEX_FILE: index });

/** Materialise a tree with git's own checkout (filters, eol) under `prefix` (relative to repo, ends with /). */
export const gitReadTree = (repo: string, index: string, tree: string) => git(repo, ["read-tree", tree], { GIT_INDEX_FILE: index });
export const gitCheckoutIndex = (repo: string, index: string, prefix: string) =>
  git(repo, ["checkout-index", "--all", "--force", `--prefix=${prefix}`], { GIT_INDEX_FILE: index });
