import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { err, ok, type Result } from "../fp/result.js";
import { gitToplevel } from "../subject/git.js";

export const repoRootOf =
  (deps: Pick<InfraDeps, "exec">) =>
  async (cwd: string): Promise<Result<string, DevsecError>> => {
    const out = await deps.exec(gitToplevel(cwd));
    if (out.code === 127) return err({ type: "tool-missing", tool: "git" });
    return out.code === 0 ? ok(out.stdout.trim()) : err({ type: "not-a-repo", path: cwd });
  };
