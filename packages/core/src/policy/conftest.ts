import type { Command } from "../domain/command.js";
import type { Exception } from "../domain/config.js";
import type { Finding } from "../domain/finding.js";
import type { Subject } from "../domain/subject.js";
import { arr, isRecord, rec, str } from "../fp/decode.js";
import { err, ok, type Result } from "../fp/result.js";

/** `partial`: the scan ran only some scanners, so unmatched exceptions are not reported. */
export type PolicyInput = { readonly subject: Subject; readonly findings: readonly Finding[]; readonly partial: boolean };
export type PolicyData = { readonly exceptions: readonly Exception[] };

export const policyInput = (subject: Subject, findings: readonly Finding[], partial = false): PolicyInput => ({ subject, findings, partial });
export const policyData = (exceptions: readonly Exception[]): PolicyData => ({ exceptions });

export const conftestCommand = (a: {
  readonly cwd: string;
  readonly policyDir: string;
  readonly dataFile: string;
  readonly inputFile: string;
}): Command => ({
  cmd: "conftest",
  args: ["test", "--output", "json", "--no-color", "--namespace", "devsec", "--policy", a.policyDir, "--data", a.dataFile, a.inputFile],
  cwd: a.cwd,
});

export type Violation = { readonly code: string; readonly msg: string; readonly findingId?: string };
export type PolicyResult = { readonly deny: readonly Violation[]; readonly warn: readonly Violation[] };

const violations = (v: unknown): Violation[] =>
  arr(v).flatMap((x) => {
    if (!isRecord(x)) return [];
    const meta = rec(x["metadata"]);
    const findingId = str(meta["finding_id"]);
    return [{ code: str(meta["code"]) ?? str(meta["query"]) ?? "", msg: str(x["msg"]) ?? "", ...(findingId ? { findingId } : {}) }];
  });

/** conftest exits 1 when there are failures, so its JSON output, not the exit code, is the result. */
export const parseConftest = (stdout: string): Result<PolicyResult, string> => {
  let json: unknown;
  try {
    json = JSON.parse(stdout);
  } catch {
    return err(`conftest output is not JSON: ${stdout.slice(0, 200)}`);
  }
  if (!Array.isArray(json)) return err("conftest output is not an array");
  return ok({
    deny: json.flatMap((f) => violations(rec(f)["failures"])),
    warn: json.flatMap((f) => violations(rec(f)["warnings"])),
  });
};

export type Verdict = "deny" | "warn";
export type Judged = { readonly finding: Finding; readonly verdict: Verdict; readonly violations: readonly Violation[] };

export type Judgement = {
  /** Findings at least one policy rule flagged; deny wins over warn. */
  readonly flagged: readonly Judged[];
  /** Violations not tied to a finding (finding_id missing or unknown). */
  readonly general: { readonly deny: readonly Violation[]; readonly warn: readonly Violation[] };
  readonly dropped: number;
};

/** Pure: attach policy results to findings. Findings no rule flagged are dropped (only counted). */
export const judge = (findings: readonly Finding[], result: PolicyResult): Judgement => {
  const ids = new Set(findings.map((f) => f.id));
  const byFinding = (vs: readonly Violation[], id: string) => vs.filter((v) => v.findingId === id);
  const flagged = findings.flatMap((finding): Judged[] => {
    const deny = byFinding(result.deny, finding.id);
    const warn = byFinding(result.warn, finding.id);
    if (deny.length > 0) return [{ finding, verdict: "deny", violations: [...deny, ...warn] }];
    if (warn.length > 0) return [{ finding, verdict: "warn", violations: warn }];
    return [];
  });
  const general = (vs: readonly Violation[]) => vs.filter((v) => v.findingId === undefined || !ids.has(v.findingId));
  return {
    flagged,
    general: { deny: general(result.deny), warn: general(result.warn) },
    dropped: findings.length - flagged.length,
  };
};
