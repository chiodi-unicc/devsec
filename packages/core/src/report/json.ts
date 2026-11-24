import type { Config } from "../domain/config.js";
import { severities, type Finding, type ScannerId } from "../domain/finding.js";
import type { Subject } from "../domain/subject.js";
import type { Judged, Judgement, Verdict, Violation } from "../policy/conftest.js";

/** One line per finding the agent should act on. Full detail: `devsec finding <id>`. */
export type AgentFinding = {
  readonly id: string;
  readonly verdict: Verdict;
  readonly severity: Finding["severity"];
  readonly scanner: ScannerId;
  readonly rule: string;
  readonly path?: string;
  readonly line?: number;
  readonly package?: string;
  readonly fix?: string;
  readonly message: string;
  readonly policy: readonly string[];
  /** With a baseline: true when the baseline did not have this finding. */
  readonly new?: boolean;
};

export type BaselineInfo = {
  readonly ref: string;
  readonly tree: string;
  readonly runId?: string;
  /** Ids of every finding in the baseline (before policy). */
  readonly ids: ReadonlySet<string>;
};

export type Status = "pass" | "fail" | "error";

export type AgentReport = {
  readonly status: Status;
  readonly subject: { readonly tree: string; readonly head?: string; readonly dirty: boolean };
  readonly runId: string;
  readonly run: string;
  /** Scanners this run used; a subset means a partial scan (it does not move .devsec/latest). */
  readonly scanners: readonly ScannerId[];
  /** With a baseline, only new findings decide the status; existing ones are still listed. */
  readonly baseline?: { readonly ref: string; readonly tree: string; readonly runId?: string };
  /** found = all tool findings = flagged (deny + warn) + dropped (no policy rule matched). new ⊆ flagged. */
  readonly counts: {
    readonly found: number;
    readonly flagged: number;
    readonly deny: number;
    readonly warn: number;
    readonly dropped: number;
    readonly new?: number;
    readonly newDeny?: number;
  };
  readonly errors: readonly string[];
  readonly policy: { readonly deny: readonly Violation[]; readonly warn: readonly Violation[] };
  readonly findings: readonly AgentFinding[];
};

const rank = (j: Judged): number =>
  (j.verdict === "deny" ? 0 : 10) + severities.indexOf(j.finding.severity);

const toAgentFinding = (baseline: BaselineInfo | undefined) => ({ finding: f, verdict, violations }: Judged): AgentFinding => ({
  id: f.id,
  verdict,
  severity: f.severity,
  scanner: f.scanner,
  rule: f.rule,
  ...(f.location ? { path: f.location.path, line: f.location.startLine } : {}),
  ...(f.package ? { package: `${f.package.name}@${f.package.version}` } : {}),
  ...(f.package?.fixedVersion ? { fix: f.package.fixedVersion } : {}),
  // semgrep's message explains the issue; trivy's title is the concise one (descriptions are long).
  message: f.scanner === "semgrep" ? f.message : f.title,
  policy: violations.map((v) => v.msg),
  ...(baseline ? { new: !baseline.ids.has(f.id) } : {}),
});

export const statusOf = (
  j: Judgement,
  failOn: Config["failOn"],
  errors: readonly string[],
  baseline?: BaselineInfo,
): Status => {
  if (errors.length > 0) return "error";
  const gating = baseline ? j.flagged.filter((f) => !baseline.ids.has(f.finding.id)) : j.flagged;
  const denies = j.general.deny.length + gating.filter((f) => f.verdict === "deny").length;
  const warns = j.general.warn.length + gating.filter((f) => f.verdict === "warn").length;
  return denies > 0 || (failOn === "warn" && warns > 0) ? "fail" : "pass";
};

export const agentReport = (a: {
  readonly subject: Subject;
  readonly runId: string;
  readonly runDir: string;
  readonly scanners: readonly ScannerId[];
  readonly judgement: Judgement;
  readonly errors: readonly string[];
  readonly failOn: Config["failOn"];
  readonly baseline?: BaselineInfo;
}): AgentReport => {
  const { judgement: j, baseline: b } = a;
  const isNew = (x: Judged) => (b ? !b.ids.has(x.finding.id) : false);
  const sorted = [...j.flagged].sort((x, y) => Number(isNew(y)) - Number(isNew(x)) || rank(x) - rank(y));
  const fresh = j.flagged.filter(isNew);
  return {
    status: statusOf(j, a.failOn, a.errors, b),
    subject: { tree: a.subject.treeSha, ...(a.subject.headSha ? { head: a.subject.headSha } : {}), dirty: a.subject.dirty },
    runId: a.runId,
    run: a.runDir,
    scanners: a.scanners,
    ...(b ? { baseline: { ref: b.ref, tree: b.tree, ...(b.runId ? { runId: b.runId } : {}) } } : {}),
    counts: {
      found: j.flagged.length + j.dropped,
      flagged: j.flagged.length,
      deny: j.flagged.filter((f) => f.verdict === "deny").length,
      warn: j.flagged.filter((f) => f.verdict === "warn").length,
      dropped: j.dropped,
      ...(b ? { new: fresh.length, newDeny: fresh.filter((f) => f.verdict === "deny").length } : {}),
    },
    errors: a.errors,
    policy: j.general,
    findings: sorted.map(toAgentFinding(b)),
  };
};
