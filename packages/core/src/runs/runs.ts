import type { DevsecError } from "../domain/errors.js";
import type { DevsecEvent } from "../domain/events.js";
import { foldEvents, type RunState } from "../domain/run-state.js";
import type { InfraDeps } from "../deps.js";
import { isRecord, rec, str } from "../fp/decode.js";
import { err, ok, type Result } from "../fp/result.js";
import type { PolicyResult } from "../policy/conftest.js";
import { parseConftest } from "../policy/conftest.js";
import type { AgentReport } from "../report/json.js";
import { isRunId, workspaceLayout } from "../workspace/layout.js";
import type { StepCommand } from "../scan/scan.js";
import { repoRootOf } from "../workspace/repo.js";

/** Pure: events.jsonl text → events (incomplete trailing line ignored). */
export const parseEvents = (text: string): DevsecEvent[] =>
  text.split("\n").flatMap((line) => {
    if (!line.trim()) return [];
    try {
      const e: unknown = JSON.parse(line);
      return isRecord(e) && typeof e["type"] === "string" ? [e as DevsecEvent] : [];
    } catch {
      return [];
    }
  });

export type RunSummary = RunState & { readonly runId: string; readonly counts?: AgentReport["counts"] };

/** From run.json, once the run has finished. */
export type RunMeta = {
  readonly tools: Readonly<Record<string, string>>;
  readonly commands: readonly StepCommand[];
  readonly scanners: readonly string[];
  readonly dir: string;
};

export type RunDetail = {
  readonly runId: string;
  readonly meta?: RunMeta;
  readonly state: RunState;
  readonly events: readonly DevsecEvent[];
  readonly report?: AgentReport;
  readonly policy: { readonly dir: string; readonly files: Readonly<Record<string, string>>; readonly result?: PolicyResult };
};

export type RunsSteps = { readonly repoRoot: (deps: InfraDeps) => (cwd: string) => Promise<Result<string, DevsecError>> };

const parse = (text: string | undefined): unknown => {
  try {
    return text === undefined ? undefined : JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** The state of a run: its events folded (works for in-progress runs too). */
const loadEvents = (deps: InfraDeps) => async (dir: string) => parseEvents((await deps.fs.readText(`${dir}/events.jsonl`)) ?? "");

/** All runs, newest first. */
export const listRunsWith =
  (steps: RunsSteps) =>
  (deps: InfraDeps) =>
  async (args: { readonly cwd: string }): Promise<Result<RunSummary[], DevsecError>> => {
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const layout = workspaceLayout(root.value);
    const ids = (await deps.fs.exists(layout.runs)) ? await deps.fs.readdir(layout.runs) : [];
    const runs = await Promise.all(
      ids.map(async (runId): Promise<RunSummary> => {
        const run = layout.run(runId);
        const state = foldEvents(await loadEvents(deps)(run.dir));
        const report = parse(await deps.fs.readText(run.reportJson)) as AgentReport | undefined;
        return { ...state, runId, ...(state.status !== "running" && report?.counts ? { counts: report.counts } : {}) };
      }),
    );
    return ok(runs.sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0)));
  };

/** One run: folded state, events, report and the policy it was judged with. */
export const readRunWith =
  (steps: RunsSteps) =>
  (deps: InfraDeps) =>
  async (args: { readonly cwd: string; readonly runId: string }): Promise<Result<RunDetail, DevsecError>> => {
    if (!isRunId(args.runId)) return err({ type: "io", detail: `invalid run id "${args.runId}"` });
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const layout = workspaceLayout(root.value);
    const run = layout.run(args.runId);
    const events = await loadEvents(deps)(run.dir);
    const state = foldEvents(events);
    const runJson = rec(parse(await deps.fs.readText(run.runJson)));
    const customPolicy = str(rec(runJson["config"])["policy"]);
    const dir = customPolicy ? `${root.value}/${customPolicy}` : layout.defaultPolicy;
    const names = (await deps.fs.exists(dir)) ? (await deps.fs.readdir(dir)).filter((f) => f.endsWith(".rego")) : [];
    const files = Object.fromEntries(await Promise.all(names.map(async (n) => [n, (await deps.fs.readText(`${dir}/${n}`)) ?? ""] as const)));
    const resultText = await deps.fs.readText(run.policyResult);
    const result = resultText === undefined ? undefined : parseConftest(resultText);
    const report = state.status === "running" ? undefined : (parse(await deps.fs.readText(run.reportJson)) as AgentReport | undefined);
    const meta: RunMeta | undefined = isRecord(runJson["tools"])
      ? {
          tools: runJson["tools"] as Record<string, string>,
          commands: (Array.isArray(runJson["commands"]) ? runJson["commands"] : []).filter(
            (c): c is StepCommand => isRecord(c) && typeof c["step"] === "string" && isRecord(c["command"]),
          ),
          scanners: Array.isArray(runJson["scanners"]) ? (runJson["scanners"] as string[]) : [],
          dir: run.dir,
        }
      : undefined;
    return ok({
      runId: args.runId,
      ...(meta ? { meta } : {}),
      state,
      events,
      ...(report ? { report } : {}),
      policy: { dir: customPolicy ?? `.devsec/policy/default`, files, ...(result?.ok ? { result: result.value } : {}) },
    });
  };

const runsSteps: RunsSteps = { repoRoot: (deps) => repoRootOf(deps) };
export const listRuns = listRunsWith(runsSteps);
export const readRun = readRunWith(runsSteps);
