import { configFile, defaultConfig } from "../domain/config.js";
import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { ok, type Result } from "../fp/result.js";
import { defaultPolicyFiles } from "../policy/default-policy.js";
import { toJson } from "../scan/run-tool.js";
import { devsecGitignore, workspaceLayout } from "./layout.js";
import { repoRootOf } from "./repo.js";

export const initPolicyDir = "devsec/policy";

export type InitArgs = { readonly cwd: string };
export type InitResult = { readonly created: readonly string[]; readonly skipped: readonly string[] };
export type InitSteps = { readonly repoRoot: (deps: InfraDeps) => (cwd: string) => Promise<Result<string, DevsecError>> };

/** Write devsec.json and a copy of the default policy to customise. Never overwrites. */
export const initWith =
  (steps: InitSteps) =>
  (deps: InfraDeps) =>
  async (args: InitArgs): Promise<Result<InitResult, DevsecError>> => {
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const { exceptions: _, ...config } = defaultConfig;
    const files: Record<string, string> = {
      [configFile]: toJson({ ...config, policy: initPolicyDir, exceptions: [] }),
      ...Object.fromEntries(Object.entries(defaultPolicyFiles).map(([f, src]) => [`${initPolicyDir}/${f}`, src])),
    };
    const created: string[] = [];
    const skipped: string[] = [];
    for (const [rel, content] of Object.entries(files)) {
      const path = `${root.value}/${rel}`;
      if (await deps.fs.exists(path)) skipped.push(rel);
      else {
        await deps.fs.writeText(path, content);
        created.push(rel);
      }
    }
    const layout = workspaceLayout(root.value);
    await deps.fs.writeText(layout.gitignore, devsecGitignore);
    return ok({ created, skipped });
  };

export type CleanArgs = { readonly cwd: string; readonly all?: boolean };

/** Remove snapshots and temp files (or the whole .devsec with `all`). */
export const cleanWith =
  (steps: InitSteps) =>
  (deps: InfraDeps) =>
  async (args: CleanArgs): Promise<Result<readonly string[], DevsecError>> => {
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const layout = workspaceLayout(root.value);
    const targets = args.all ? [layout.root] : [layout.snapshots, layout.tmp];
    for (const t of targets) await deps.fs.rm(t);
    return ok(targets);
  };

const repoSteps: InitSteps = { repoRoot: (deps) => repoRootOf(deps) };
export const init = initWith(repoSteps);
export const clean = cleanWith(repoSteps);
