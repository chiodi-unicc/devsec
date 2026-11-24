import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { ok, type Result } from "../fp/result.js";
import { scanSteps } from "../scan/steps.js";
import type { ScanSteps, Versions } from "../scan/types.js";
import { requiredTools } from "../tools/versions.js";
import { pinnedVersions } from "../setup/toolchain.js";

export type DoctorArgs = { readonly cwd: string };
export type DoctorSteps = Pick<ScanSteps, "versions">;
export type ToolCheck = {
  readonly tool: string;
  readonly version?: string;
  readonly pinned?: string;
  /** Resolved executable; managed tools live under the toolchain directory. */
  readonly path?: string;
  readonly status: "ok" | "missing" | "version-differs";
};
export type DoctorReport = Versions & { readonly ok: boolean; readonly tools: readonly ToolCheck[]; readonly hint?: string };

export const doctorWith =
  (steps: DoctorSteps) =>
  (deps: InfraDeps) =>
  async (args: DoctorArgs): Promise<Result<DoctorReport, DevsecError>> => {
    const v = await steps.versions(deps)(args);
    if (!v.ok) return v;
    const tools = await Promise.all(
      requiredTools.map(async (tool): Promise<ToolCheck> => {
        const where = await deps.exec({ cmd: "sh", args: ["-c", `command -v ${tool}`], cwd: args.cwd });
        const path = where.code === 0 ? where.stdout.trim() : undefined;
        const version = v.value.found[tool];
        const pinned = pinnedVersions[tool];
        const status = version === undefined ? "missing" : pinned !== undefined && version !== pinned ? "version-differs" : "ok";
        return { tool, status, ...(version ? { version } : {}), ...(pinned ? { pinned } : {}), ...(path ? { path } : {}) };
      }),
    );
    const healthy = v.value.missing.length === 0;
    const differs = tools.some((t) => t.status === "version-differs");
    return ok({
      ...v.value,
      ok: healthy,
      tools,
      ...(!healthy || differs ? { hint: `run "devsec setup" to install the pinned toolchain${healthy ? " (results can differ between tool versions)" : ""}` } : {}),
    });
  };

export const doctor = doctorWith({ versions: scanSteps.versions });
