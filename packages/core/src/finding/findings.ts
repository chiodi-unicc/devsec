import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { err, ok, type Result } from "../fp/result.js";
import type { AgentReport } from "../report/json.js";
import { nextFindingsCall, pageFindings, type FindingsPage, type FindingsQuery } from "../report/view.js";
import { isRunId, workspaceLayout } from "../workspace/layout.js";
import { repoRootOf } from "../workspace/repo.js";

export type FindingsArgs = FindingsQuery & { readonly cwd: string; readonly runId?: string };
export type FindingsResult = FindingsPage & { readonly runId: string; readonly next?: string; readonly note?: string };
export type FindingsSteps = { readonly repoRoot: (deps: InfraDeps) => (cwd: string) => Promise<Result<string, DevsecError>> };

/** Page through a run's flagged findings (default: the latest full scan). */
export const findingsWith =
  (steps: FindingsSteps) =>
  (deps: InfraDeps) =>
  async (args: FindingsArgs): Promise<Result<FindingsResult, DevsecError>> => {
    if (args.runId !== undefined && !isRunId(args.runId)) return err({ type: "io", detail: `invalid run id "${args.runId}"` });
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const layout = workspaceLayout(root.value);
    const dir = args.runId ? layout.run(args.runId).dir : layout.latest;
    const text = await deps.fs.readText(`${dir}/report.json`);
    if (text === undefined) return err({ type: "io", detail: args.runId ? `no report for run ${args.runId}` : "no scan yet: run devsec scan" });
    let report: AgentReport;
    try {
      report = JSON.parse(text) as AgentReport;
    } catch {
      return err({ type: "io", detail: `unreadable report in ${dir}` });
    }
    const { cwd: _cwd, runId: _runId, ...asked } = args;
    // Without a baseline nothing is "new": fall back to all flagged findings and say so (like devsec_scan's scope).
    const noBaseline = asked.new === true && report.baseline === undefined;
    const { new: _new, ...withoutNew } = asked;
    const query: FindingsQuery = noBaseline ? withoutNew : asked;
    const page = pageFindings(report.findings, query);
    const { offset: _o, limit: _l, ...filters } = query;
    return ok({
      runId: report.runId,
      ...page,
      ...(noBaseline
        ? { note: "this run has no baseline (no uncommitted changes, no commits, or baseline: none), so nothing is marked new; showing all flagged findings" }
        : {}),
      ...(page.more > 0
        ? { next: nextFindingsCall(report.runId, { ...filters, ...(query.limit !== undefined ? { limit: query.limit } : {}) }, page.offset + page.findings.length) }
        : {}),
    });
  };

export const findings = findingsWith({ repoRoot: (deps) => repoRootOf(deps) });
