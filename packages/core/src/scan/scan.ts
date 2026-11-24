import type { DevsecError } from "../domain/errors.js";
import { describeError } from "../domain/errors.js";
import type { DevsecEvent, StepId, StepStatus } from "../domain/events.js";
import type { Finding, ScannerId } from "../domain/finding.js";
import { foldEvents } from "../domain/run-state.js";
import { canonicalJson, hash } from "../fp/hash.js";
import { err, ok, type Result } from "../fp/result.js";
import { conftestCommand, judge } from "../policy/conftest.js";
import type { Command } from "../domain/command.js";
import { semgrepCommand } from "../tools/semgrep.js";
import { syftCommand, sbomCycloneDx } from "../tools/syft.js";
import { trivyScaCommand, trivySecretsCommand } from "../tools/trivy.js";
import type { ToolName } from "../tools/versions.js";
import type { Subject } from "../domain/subject.js";
import type { BaselineInfo } from "../report/json.js";
import { workspaceLayout, type RunLayout } from "../workspace/layout.js";
import { toJson } from "./run-tool.js";
import { scanSteps } from "./steps.js";
import type { ScanArgs, ScanDeps, ScanOutcome, ScanSteps } from "./types.js";

/** Tools a scan needs, given the enabled scanners. Syft and conftest always run (SBOM, policy). */
export const neededTools = (scanners: readonly ScannerId[]): ToolName[] => [
  "git",
  "syft",
  "conftest",
  ...(scanners.includes("semgrep") ? (["semgrep"] as const) : []),
  ...(scanners.some((s) => s.startsWith("trivy")) ? (["trivy"] as const) : []),
];

/**
 * Version of devsec's projection of tool output into findings (ids, fields). Bump it whenever
 * that changes, so cached findings from an older devsec are never mixed with new ones.
 */
export const findingsSchema = 2;

/** Everything that determines the cached findings. Policy and exceptions are deliberately excluded. */
export const scanKey = (a: {
  readonly treeSha: string;
  readonly scanners: readonly ScannerId[];
  readonly rulesets: readonly string[];
  readonly versions: Readonly<Record<string, string>>;
}): string => hash(canonicalJson({ ...a, findingsSchema }));

export const runIdOf = (treeSha: string, key: string): string => `${treeSha.slice(0, 12)}-${key.slice(0, 8)}`;

/**
 * Pure: which ref is the baseline. Explicit argument, then devsec.json, then the default:
 * HEAD when scanning uncommitted changes (so an agent sees what it introduced). "none" disables.
 */
export const resolveBaseline = (arg: string | undefined, configured: string | undefined, s: Subject): string | undefined => {
  const chosen = arg ?? configured;
  if (chosen !== undefined) return chosen === "none" ? undefined : chosen;
  return s.dirty && s.ref === undefined && s.headSha !== undefined ? "HEAD" : undefined;
};

export type StepCommand = { readonly step: StepId; readonly command: Command };

/** The exact tool commands of a run, by step, recorded in run.json. */
export const plannedCommands = (a: {
  readonly snapshot: string;
  readonly run: RunLayout;
  readonly scanners: readonly ScannerId[];
  readonly rulesets: readonly string[];
  readonly policyDir: string;
}): StepCommand[] => {
  const { snapshot, run, scanners, rulesets } = a;
  return [
    { step: "sbom", command: syftCommand({ cwd: snapshot, outDir: run.sbomDir }) },
    ...(scanners.includes("semgrep") ? [{ step: "semgrep" as const, command: semgrepCommand({ cwd: snapshot, rulesets, rawDir: run.raw }) }] : []),
    ...(scanners.includes("trivy-secrets") ? [{ step: "trivy-secrets" as const, command: trivySecretsCommand({ cwd: snapshot, rawDir: run.raw }) }] : []),
    ...(scanners.includes("trivy-sca")
      ? [{ step: "trivy-sca" as const, command: trivyScaCommand({ cwd: snapshot, rawDir: run.raw, sbom: `${run.sbomDir}/${sbomCycloneDx}` }) }]
      : []),
    { step: "policy", command: conftestCommand({ cwd: run.dir, policyDir: a.policyDir, dataFile: run.policyData, inputFile: run.policyInput }) },
  ];
};

/**
 * scan = scanWith(steps)(deps)(args).
 * Pins the subject, runs the tools in parallel (SCA after the SBOM), applies the policy,
 * writes everything under .devsec/runs/<runId>/ and returns the agent report.
 */
export const scanWith =
  (steps: ScanSteps) =>
  (deps: ScanDeps) =>
  async (args: ScanArgs): Promise<Result<ScanOutcome, DevsecError>> => {
    // Events are buffered until the run directory is known, then appended to events.jsonl live.
    const events: DevsecEvent[] = [];
    let eventsFile: string | undefined;
    const record = async (e: DevsecEvent) => {
      events.push(e);
      deps.emit(e);
      if (eventsFile) await deps.fs.appendText(eventsFile, `${JSON.stringify(e)}\n`);
    };

    /** Run one step, emitting started/finished; thrown errors (e.g. fs) become `io` errors. */
    const step = async <T>(
      id: StepId,
      thunk: () => Promise<Result<T, DevsecError>>,
      count?: (t: T) => number,
    ): Promise<Result<T, DevsecError>> => {
      await record({ type: "step.started", at: deps.now(), step: id });
      let r: Result<T, DevsecError>;
      try {
        r = await thunk();
      } catch (e) {
        r = err({ type: "io", detail: `${id}: ${e instanceof Error ? e.message : String(e)}` });
      }
      const findings = r.ok && count ? count(r.value) : undefined;
      await record({
        type: "step.finished",
        at: deps.now(),
        step: id,
        status: r.ok ? "ok" : "failed",
        ...(r.ok ? {} : { error: describeError(r.error) }),
        ...(findings !== undefined ? { findings } : {}),
      });
      return r;
    };
    const mark = (id: StepId, status: StepStatus) =>
      record({ type: "step.started", at: deps.now(), step: id }).then(() =>
        record({ type: "step.finished", at: deps.now(), step: id, status }),
      );

    const [versions, subject] = await Promise.all([
      step("versions", () => steps.versions(deps)({ cwd: args.cwd })),
      step("subject", () => steps.subject(deps)(args.ref !== undefined ? { cwd: args.cwd, ref: args.ref } : { cwd: args.cwd })),
    ]);
    if (!subject.ok) return subject;
    if (!versions.ok) return versions;
    const s = subject.value;

    const config = await step("config", () => steps.config(deps)({ repoRoot: s.repoRoot }));
    if (!config.ok) return config;
    const c = config.value;
    const scanners = args.scanners ? c.scanners.filter((x) => args.scanners?.includes(x)) : c.scanners;

    const missing = neededTools(scanners).filter((t) => versions.value.missing.includes(t));
    if (missing[0] !== undefined) return err({ type: "tool-missing", tool: missing.join(", ") });

    const key = scanKey({ treeSha: s.treeSha, scanners, rulesets: c.semgrep.rulesets, versions: versions.value.found });
    const layout = workspaceLayout(s.repoRoot);
    const runId = runIdOf(s.treeSha, key);
    const run = layout.run(runId);

    await deps.fs.mkdir(run.dir);
    await deps.fs.rm(run.events);
    for (const e of events) await deps.fs.appendText(run.events, `${JSON.stringify(e)}\n`);
    eventsFile = run.events;
    await record({ type: "run.started", at: deps.now(), runId, subject: s, ...(args.purpose ? { purpose: args.purpose } : {}) });

    const cached = await step("cache", () => steps.cache(deps)({ run, key, ttlHours: c.cacheTtlHours }));
    let findings: readonly Finding[] = [];
    const errors: string[] = [];
    let snapshotDir = layout.snapshot(s.treeSha);

    if (cached.ok && cached.value) {
      findings = cached.value.findings;
      for (const id of ["snapshot", "sbom", "semgrep", "trivy-secrets", "trivy-sca"] as const) await mark(id, "cached");
    } else {
      const snap = await step("snapshot", () => steps.snapshot(deps)({ subject: s, layout }));
      if (!snap.ok) return snap;
      snapshotDir = snap.value;
      const input = { snapshot: snap.value, run };
      const count = (fs: Finding[]) => fs.length;
      const skip = (id: StepId) => mark(id, "skipped").then(() => ok<Finding[]>([]));

      const sbom = step("sbom", () => steps.sbom(deps)(input));
      const results = await Promise.all([
        scanners.includes("semgrep")
          ? step("semgrep", () => steps.semgrep(deps)({ ...input, rulesets: c.semgrep.rulesets }), count)
          : skip("semgrep"),
        scanners.includes("trivy-secrets") ? step("trivy-secrets", () => steps.trivySecrets(deps)(input), count) : skip("trivy-secrets"),
        sbom.then((b) =>
          !scanners.includes("trivy-sca") || !b.ok
            ? skip("trivy-sca")
            : step("trivy-sca", () => steps.trivySca(deps)({ ...input, sbom: b.value }), count),
        ),
        sbom.then((b) => (b.ok ? ok<Finding[]>([]) : b)),
      ]);
      for (const r of results) if (!r.ok) errors.push(describeError(r.error));
      findings = results.flatMap((r) => (r.ok ? r.value : []));
      await steps.saveScan(deps)({ run, key, findings, complete: errors.length === 0 });
    }

    // Baseline: same pipeline on the baseline tree (cached per tree), progress silenced.
    const baselineRef = args.purpose ? undefined : resolveBaseline(args.baseline, c.baseline, s);
    let baseline: BaselineInfo | undefined;
    if (baselineRef === undefined) {
      await mark("baseline", "skipped");
    } else {
      const b = await step("baseline", async () => {
        // Same tree as the subject: nothing can be new, and a nested scan would reuse this run's directory.
        const target = await steps.subject(deps)({ cwd: s.repoRoot, ref: baselineRef });
        if (!target.ok) return target;
        if (target.value.treeSha === s.treeSha) {
          return ok<BaselineInfo>({ ref: baselineRef, tree: s.treeSha, ids: new Set(findings.map((f) => f.id)) });
        }
        const r = await scanWith(steps)({ ...deps, emit: () => {} })({
          cwd: s.repoRoot,
          ref: baselineRef,
          scanners,
          purpose: "baseline",
        });
        if (!r.ok) return r;
        return ok<BaselineInfo>({
          ref: baselineRef,
          tree: r.value.report.subject.tree,
          runId: r.value.report.runId,
          ids: new Set(r.value.findings.map((f) => f.id)),
        });
      });
      if (!b.ok) return b;
      baseline = b.value;
    }

    const partial = !c.scanners.every((x) => scanners.includes(x));
    const policy = await step("policy", () => steps.policy(deps)({ subject: s, findings, config: c, layout, run, partial }));
    if (!policy.ok) errors.push(describeError(policy.error));
    const judgement = policy.ok ? judge(findings, policy.value) : { flagged: [], general: { deny: [], warn: [] }, dropped: findings.length };

    const report = await step(
      "report",
      () => steps.report(deps)({ subject: s, runId, run, scanners, judgement, errors, failOn: c.failOn, ...(baseline ? { baseline } : {}) }),
      (r) => r.findings.length,
    );
    if (!report.ok) return report;

    // Only a full, non-baseline scan becomes "latest"; partial and baseline scans keep their own run id.
    const full = c.scanners.every((x) => scanners.includes(x)) && args.purpose === undefined;
    if (full) await deps.fs.symlink(`runs/${runId}`, layout.latest);
    await record({ type: "run.finished", at: deps.now(), status: report.value.status });
    await deps.fs.writeText(
      run.runJson,
      toJson({
        ...foldEvents(events),
        tools: versions.value.found,
        config: c,
        scanners,
        commands: plannedCommands({
          snapshot: snapshotDir,
          run,
          scanners,
          rulesets: c.semgrep.rulesets,
          policyDir: c.policy ? `${s.repoRoot}/${c.policy}` : layout.defaultPolicy,
        }),
      }),
    );

    return ok({ report: report.value, findings, runDir: run.dir, reportJson: run.reportJson, reportSarif: run.reportSarif });
  };

export const scan = scanWith(scanSteps);
