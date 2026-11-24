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
import { clearScanOutputs, scanSteps } from "./steps.js";
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

/**
 * A run is one judgement: the scan (key) plus what it is compared with and why it ran.
 * Same scan, different baseline → different run (each keeps its own report); the tool
 * outputs are shared through the scan cache.
 */
export const runIdOf = (treeSha: string, key: string, baselineTree?: string, purpose?: string): string =>
  `${treeSha.slice(0, 12)}-${hash(canonicalJson({ key, baseline: baselineTree ?? null, purpose: purpose ?? null })).slice(0, 8)}`;

/**
 * Pure: which ref is the baseline. Explicit argument, then devsec.json, then the default:
 * HEAD when scanning uncommitted changes (so an agent sees what it introduced). "none" disables.
 */
export const resolveBaseline = (arg: string | undefined, configured: string | undefined, s: Subject): string | undefined =>
  baselineDecision(arg, configured, s).ref;

/** Pure: the baseline ref, or why there is none (shown on the skipped Baseline step). */
export const baselineDecision = (
  arg: string | undefined,
  configured: string | undefined,
  s: Subject,
  purpose?: "baseline",
): { readonly ref: string } | { readonly ref?: undefined; readonly reason: string } => {
  if (purpose === "baseline") return { reason: "this run is itself the baseline for another scan" };
  if (arg === "none") return { reason: "baseline: none (from --baseline)" };
  if (arg !== undefined) return { ref: arg };
  if (configured === "none") return { reason: 'baseline: none (from devsec.json)' };
  if (configured !== undefined) return { ref: configured };
  if (s.ref !== undefined) return { reason: `scanning --ref ${s.ref}: no baseline by default (pass --baseline to compare)` };
  if (s.headSha === undefined) return { reason: "the repository has no commits yet, so there is no HEAD to compare with" };
  if (!s.dirty) return { reason: "no uncommitted changes: the working tree is HEAD, so nothing can be new" };
  return { ref: "HEAD" };
};

/** Pure: why a scanner step did not run. */
export const scannerSkipReason = (id: ScannerId, configured: readonly ScannerId[], ran: readonly ScannerId[]): string =>
  configured.includes(id) ? `not requested: this scan ran only ${ran.join(", ")}` : "disabled in devsec.json (scanners)";

/** Pure: "3m ago"-style age for reasons. */
export const formatAge = (ms: number): string => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${Math.round(s / 3600)}h`;
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
    type StepInfo = { readonly findings?: number; readonly reason?: string; readonly cache?: { hit: boolean; from?: string; scannedAt?: number } };
    const step = async <T>(
      id: StepId,
      thunk: () => Promise<Result<T, DevsecError>>,
      count?: (t: T) => number,
      info?: (t: T) => StepInfo,
    ): Promise<Result<T, DevsecError>> => {
      await record({ type: "step.started", at: deps.now(), step: id });
      let r: Result<T, DevsecError>;
      try {
        r = await thunk();
      } catch (e) {
        r = err({ type: "io", detail: `${id}: ${e instanceof Error ? e.message : String(e)}` });
      }
      const findings = r.ok && count ? count(r.value) : undefined;
      const extra = r.ok && info ? info(r.value) : {};
      await record({
        type: "step.finished",
        at: deps.now(),
        step: id,
        status: r.ok ? "ok" : "failed",
        ...(r.ok ? {} : { error: describeError(r.error) }),
        ...(findings !== undefined ? { findings } : {}),
        ...extra,
      });
      return r;
    };
    const mark = (id: StepId, status: StepStatus, reason?: string) =>
      record({ type: "step.started", at: deps.now(), step: id }).then(() =>
        record({ type: "step.finished", at: deps.now(), step: id, status, ...(reason ? { reason } : {}) }),
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

    // Which tree the findings are compared with is part of the run's identity, so resolve it first.
    const decision = baselineDecision(args.baseline, c.baseline, s, args.purpose);
    const baselineRef = decision.ref;
    let baselineTree: string | undefined;
    if (baselineRef !== undefined) {
      const target = await steps.subject(deps)({ cwd: s.repoRoot, ref: baselineRef });
      if (!target.ok) return target;
      baselineTree = target.value.treeSha;
    }
    const runId = runIdOf(s.treeSha, key, baselineTree, args.purpose);
    const run = layout.run(runId);

    await deps.fs.mkdir(run.dir);
    await deps.fs.rm(run.events);
    for (const e of events) await deps.fs.appendText(run.events, `${JSON.stringify(e)}\n`);
    eventsFile = run.events;
    await record({ type: "run.started", at: deps.now(), runId, subject: s, ...(args.purpose ? { purpose: args.purpose } : {}) });

    const cached = await step("cache", () => steps.cache(deps)({ run, layout, key, ttlHours: c.cacheTtlHours }), undefined, (hit) =>
      hit
        ? {
            cache: { hit: true, from: hit.sourceRunId, scannedAt: hit.scannedAt },
            reason: `hit: reusing the scan from ${hit.sourceRunId === runId ? "this run" : `run ${hit.sourceRunId}`} (${formatAge(deps.now() - hit.scannedAt)} ago)`,
          }
        : { cache: { hit: false }, reason: `miss: no identical scan within the ${c.cacheTtlHours}h TTL, running the tools` },
    );
    let findings: readonly Finding[] = [];
    const errors: string[] = [];
    let snapshotDir = layout.snapshot(s.treeSha);

    const skipReason = (id: ScannerId) => scannerSkipReason(id, c.scanners, scanners);
    if (cached.ok && cached.value) {
      findings = cached.value.findings;
      const from = cached.value;
      const why = `reused from an identical scan ${formatAge(deps.now() - from.scannedAt)} ago${from.sourceRunId === runId ? "" : ` (run ${from.sourceRunId})`}`;
      for (const id of ["snapshot", "sbom"] as const) await mark(id, "cached", why);
      for (const id of ["semgrep", "trivy-secrets", "trivy-sca"] as const) {
        await (scanners.includes(id) ? mark(id, "cached", why) : mark(id, "skipped", skipReason(id)));
      }
    } else {
      await clearScanOutputs(deps)(run);
      const snap = await step("snapshot", () => steps.snapshot(deps)({ subject: s, layout }));
      if (!snap.ok) return snap;
      snapshotDir = snap.value;
      const input = { snapshot: snap.value, run };
      const count = (fs: Finding[]) => fs.length;
      const skip = (id: StepId, reason: string) => mark(id, "skipped", reason).then(() => ok<Finding[]>([]));

      const sbom = step("sbom", () => steps.sbom(deps)(input));
      const results = await Promise.all([
        scanners.includes("semgrep")
          ? step("semgrep", () => steps.semgrep(deps)({ ...input, rulesets: c.semgrep.rulesets }), count)
          : skip("semgrep", skipReason("semgrep")),
        scanners.includes("trivy-secrets")
          ? step("trivy-secrets", () => steps.trivySecrets(deps)(input), count)
          : skip("trivy-secrets", skipReason("trivy-secrets")),
        sbom.then((b) =>
          !scanners.includes("trivy-sca")
            ? skip("trivy-sca", skipReason("trivy-sca"))
            : !b.ok
              ? skip("trivy-sca", "needs the SBOM, which failed (see Syft SBOM)")
              : step("trivy-sca", () => steps.trivySca(deps)({ ...input, sbom: b.value }), count),
        ),
        sbom.then((b) => (b.ok ? ok<Finding[]>([]) : b)),
      ]);
      for (const r of results) if (!r.ok) errors.push(describeError(r.error));
      findings = results.flatMap((r) => (r.ok ? r.value : []));
      await steps.saveScan(deps)({ run, layout, key, findings, complete: errors.length === 0 });
    }

    // Baseline: same pipeline on the baseline tree (cached per tree), progress silenced.
    let baseline: BaselineInfo | undefined;
    if (baselineRef === undefined || baselineTree === undefined) {
      await mark("baseline", "skipped", decision.ref === undefined ? decision.reason : undefined);
    } else {
      const b = await step("baseline", async () => {
        // Same tree as the subject: nothing can be new.
        if (baselineTree === s.treeSha) {
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
      () => steps.report(deps)({ subject: s, runId, run, scanners, partial, judgement, errors, failOn: c.failOn, ...(baseline ? { baseline } : {}) }),
      (r) => r.findings.length,
    );
    if (!report.ok) return report;

    // Only a full scan of the working tree becomes "latest"; partial, --ref and baseline scans keep their own run id.
    const full = !partial && args.purpose === undefined && s.ref === undefined;
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
