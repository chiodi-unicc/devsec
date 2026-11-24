import { severities } from "../domain/finding.js";
import type { AgentFinding, AgentReport } from "./json.js";

/** One line per rule: what kinds of problems exist, without listing every instance. */
export type RuleGroup = {
  readonly rule: string;
  readonly scanner: AgentFinding["scanner"];
  readonly verdict: AgentFinding["verdict"];
  readonly severity: AgentFinding["severity"];
  readonly count: number;
  readonly new?: number;
};

export type ViewOptions = { readonly scope?: "new" | "all"; readonly limit?: number; readonly maxRules?: number };

/** The compact answer an agent gets from a scan; report.json keeps everything. */
export type AgentView = Omit<AgentReport, "findings"> & {
  readonly scope: "new" | "all";
  /** Only present when the findings list does not show everything flagged (cut off, or new-only scope). */
  readonly byRule?: readonly RuleGroup[];
  readonly otherRules?: number;
  readonly findings: readonly AgentFinding[];
  /** Findings in scope not shown; fetch them with devsec_findings / `devsec findings`. */
  readonly more: number;
  readonly next?: string;
};

const sevRank = (s: AgentFinding["severity"]) => severities.indexOf(s);

/** Pure: group flagged findings by rule (and verdict), most important first. */
export const groupByRule = (findings: readonly AgentFinding[]): RuleGroup[] => {
  const groups = new Map<string, { -readonly [K in keyof RuleGroup]: RuleGroup[K] }>();
  for (const f of findings) {
    const key = `${f.verdict}\u0000${f.rule}`;
    const g = groups.get(key) ?? { rule: f.rule, scanner: f.scanner, verdict: f.verdict, severity: f.severity, count: 0 };
    g.count += 1;
    if (sevRank(f.severity) < sevRank(g.severity)) g.severity = f.severity;
    if (f.new !== undefined) g.new = (g.new ?? 0) + (f.new ? 1 : 0);
    groups.set(key, g);
  }
  return [...groups.values()].sort(
    (a, b) =>
      (b.new ?? 0) - (a.new ?? 0) ||
      Number(a.verdict === "warn") - Number(b.verdict === "warn") ||
      sevRank(a.severity) - sevRank(b.severity) ||
      b.count - a.count,
  );
};

/** Pure: the agent's view of a report. With a baseline, defaults to new findings only. */
export const agentView = (report: AgentReport, opts: ViewOptions = {}): AgentView => {
  const scope = opts.scope ?? (report.baseline ? "new" : "all");
  const limit = opts.limit ?? 20;
  const maxRules = opts.maxRules ?? 25;
  const inScope = scope === "new" ? report.findings.filter((f) => f.new) : report.findings;
  const shown = inScope.slice(0, limit);
  const more = inScope.length - shown.length;
  const { findings: _all, ...rest } = report;
  const partial = shown.length < report.findings.length;
  const groups = partial ? groupByRule(report.findings) : [];
  return {
    ...rest,
    scope,
    ...(partial ? { byRule: groups.slice(0, maxRules) } : {}),
    ...(groups.length > maxRules ? { otherRules: groups.length - maxRules } : {}),
    findings: shown,
    more,
    ...(more > 0
      ? { next: nextFindingsCall(report.runId, scope === "new" ? { new: true } : {}, shown.length) }
      : {}),
  };
};

export type FindingsQuery = {
  readonly offset?: number;
  readonly limit?: number;
  readonly verdict?: AgentFinding["verdict"];
  /** Substring of the rule id. */
  readonly rule?: string;
  /** File path prefix (repository-relative). */
  readonly file?: string;
  /** Only findings the baseline did not have. */
  readonly new?: boolean;
};

export type FindingsPage = { readonly total: number; readonly offset: number; readonly findings: readonly AgentFinding[]; readonly more: number };

/** Pure: the devsec_findings call that fetches the next page. */
export const nextFindingsCall = (runId: string, q: FindingsQuery, nextOffset: number): string =>
  `devsec_findings ${JSON.stringify({ run: runId, ...q, offset: nextOffset })}`;

/** Pure: filter and page a report's flagged findings. */
export const pageFindings = (findings: readonly AgentFinding[], q: FindingsQuery): FindingsPage => {
  const matching = findings.filter(
    (f) =>
      (q.verdict === undefined || f.verdict === q.verdict) &&
      (q.rule === undefined || f.rule.includes(q.rule)) &&
      (q.file === undefined || (f.path ?? "").startsWith(q.file)) &&
      (q.new !== true || f.new === true),
  );
  const offset = Math.max(0, q.offset ?? 0);
  const page = matching.slice(offset, offset + (q.limit ?? 20));
  return { total: matching.length, offset, findings: page, more: Math.max(0, matching.length - offset - page.length) };
};
