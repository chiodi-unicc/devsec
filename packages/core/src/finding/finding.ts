import type { DevsecError } from "../domain/errors.js";
import type { Finding } from "../domain/finding.js";
import type { InfraDeps } from "../deps.js";
import { arr, isRecord, rec, str } from "../fp/decode.js";
import { scanSteps } from "../scan/steps.js";
import { resolvePointer } from "../fp/json-pointer.js";
import { err, ok, type Result } from "../fp/result.js";
import type { AgentFinding } from "../report/json.js";
import { isRunId, workspaceLayout } from "../workspace/layout.js";
import { repoRootOf } from "../workspace/repo.js";

/** `runId` defaults to the latest run. */
export type FindingArgs = { readonly cwd: string; readonly id: string; readonly runId?: string };

export type FindingDetail = {
  /** The projection, without `references` (they are in `raw`, verbatim). */
  readonly finding: Omit<Finding, "references">;
  /** Present when the policy flagged it in the latest run. */
  readonly verdict?: AgentFinding["verdict"];
  readonly policy?: readonly string[];
  /** The tool's own result object, verbatim. */
  readonly raw: unknown;
  /** Set when the latest full scan is of a different tree than the current working tree. */
  readonly warning?: string;
};

export type FindingSteps = {
  readonly repoRoot: (deps: InfraDeps) => (cwd: string) => Promise<Result<string, DevsecError>>;
  /** The current working tree as a tree hash (same pinning as scan). */
  readonly currentTree: (deps: InfraDeps) => (cwd: string) => Promise<Result<string, DevsecError>>;
};

const parse = (text: string | undefined): unknown => {
  try {
    return text === undefined ? undefined : JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** Full detail for one finding of the latest run, including the verbatim tool result. Accepts an id prefix. */
export const findingWith =
  (steps: FindingSteps) =>
  (deps: InfraDeps) =>
  async (args: FindingArgs): Promise<Result<FindingDetail, DevsecError>> => {
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    if (args.runId !== undefined && !isRunId(args.runId)) return err({ type: "io", detail: `invalid run id "${args.runId}"` });
    const layout = workspaceLayout(root.value);
    const latest = args.runId ? layout.run(args.runId).dir : layout.latest;
    const findings = arr(parse(await deps.fs.readText(`${latest}/findings.json`))) as Finding[];
    if (findings.length === 0 && !(await deps.fs.exists(latest))) return err({ type: "io", detail: "no scan yet: run devsec scan" });
    const matches = findings.filter((f) => f.id.startsWith(args.id));
    const finding = matches[0];
    if (finding === undefined) return err({ type: "io", detail: `no finding ${args.id} in ${args.runId ? `run ${args.runId}` : "the latest run"}` });
    if (matches.length > 1) return err({ type: "io", detail: `id prefix ${args.id} is ambiguous` });

    const raw = resolvePointer(parse(await deps.fs.readText(`${latest}/raw/${finding.raw.file}`)), finding.raw.pointer);
    const reported = arr(rec(parse(await deps.fs.readText(`${latest}/report.json`)))["findings"]).find(
      (f) => isRecord(f) && f["id"] === finding.id,
    ) as AgentFinding | undefined;
    const { references: _references, ...projection } = finding;
    const warning = args.runId ? undefined : await staleWarning(steps, deps, args.cwd, parse(await deps.fs.readText(`${latest}/run.json`)));
    return ok({ finding: projection, ...(warning ? { warning } : {}), ...(reported ? { verdict: reported.verdict, policy: reported.policy } : {}), raw });
  };

const staleWarning = async (steps: FindingSteps, deps: InfraDeps, cwd: string, runJson: unknown): Promise<string | undefined> => {
  const scanned = str(rec(rec(runJson)["subject"])["treeSha"]);
  const current = await steps.currentTree(deps)(cwd);
  if (scanned === undefined || !current.ok || current.value === scanned) return undefined;
  return `the latest full scan is of tree ${scanned.slice(0, 12)}, but the working tree is now ${current.value.slice(0, 12)}: finding ids may be out of date, run devsec_scan again`;
};

export const finding = findingWith({
  repoRoot: (deps) => repoRootOf(deps),
  currentTree: (deps) => async (cwd) => {
    const s = await scanSteps.subject(deps)({ cwd });
    return s.ok ? ok(s.value.treeSha) : s;
  },
});
