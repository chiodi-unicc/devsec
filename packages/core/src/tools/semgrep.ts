import type { Command } from "../domain/command.js";
import type { Finding, Location } from "../domain/finding.js";
import { arr, compact, isRecord, num, rec, str, strs } from "../fp/decode.js";
import { canonicalJson } from "../fp/hash.js";
import { fingerprints, snippetOf } from "./fingerprint.js";
import { err, ok, type Result } from "../fp/result.js";
import { mapSeverity } from "./severity.js";

export const semgrepRawJson = "semgrep.json";
export const semgrepRawSarif = "semgrep.sarif";

/**
 * One semgrep process for all rulesets: semgrep merges identical rules across configs itself.
 * `--no-git-ignore` is the single equivalence flag: the snapshot sits in the git-ignored
 * .devsec dir, so semgrep's git-based target selection would otherwise skip every file.
 * The snapshot already contains exactly the non-ignored files; .semgrepignore still applies.
 */
export const semgrepCommand = (a: {
  readonly cwd: string;
  readonly rulesets: readonly string[];
  readonly rawDir: string;
}): Command => ({
  cmd: "semgrep",
  args: [
    "scan",
    ...a.rulesets.flatMap((r) => ["--config", r]),
    "--metrics=off",
    "--quiet",
    "--no-git-ignore",
    `--json-output=${a.rawDir}/${semgrepRawJson}`,
    `--sarif-output=${a.rawDir}/${semgrepRawSarif}`,
    ".",
  ],
  cwd: a.cwd,
});

const locationOf = (r: Record<string, unknown>): Location | undefined => {
  const path = str(r["path"]);
  const start = rec(r["start"]);
  const end = rec(r["end"]);
  const startLine = num(start["line"]);
  if (path === undefined || startLine === undefined) return undefined;
  return compact({
    path,
    startLine,
    endLine: num(end["line"]),
    startColumn: num(start["col"]),
    endColumn: num(end["col"]),
  });
};

/** Identity of a semgrep result: rule + exact span. Shared by findings and SARIF results. */
export const semgrepKey = (rule: string, loc: Location | undefined): string =>
  canonicalJson([rule, loc?.path, loc?.startLine, loc?.startColumn, loc?.endLine, loc?.endColumn]);

/** Paths of all results, to load their source for fingerprints. */
export const semgrepResultPaths = (json: unknown): string[] =>
  [...new Set(arr(rec(json)["results"]).flatMap((r) => (str(rec(r)["path"]) ? [str(rec(r)["path"]) as string] : [])))];

/**
 * `source(path)` returns the scanned file's text (from the snapshot). It is only used for the
 * finding's identity: semgrep returns matched text only to logged-in users. Without it, the
 * identity falls back to the exact span.
 */
export const projectSemgrep = (json: unknown, source: (path: string) => string | undefined = () => undefined): Result<Finding[], string> => {
  if (!isRecord(json) || !Array.isArray(json["results"])) return err("missing results[]");
  const findings = arr(json["results"]).flatMap((r, i): Finding[] => {
      if (!isRecord(r)) return [];
      const rule = str(r["check_id"]);
      if (rule === undefined) return [];
      const extra = rec(r["extra"]);
      const meta = rec(extra["metadata"]);
      const toolSeverity = str(extra["severity"]) ?? "";
      const location = locationOf(r);
      return [
        compact({
          id: "",
          scanner: "semgrep" as const,
          rule,
          severity: mapSeverity(toolSeverity),
          toolSeverity,
          title: rule.split(".").at(-1) ?? rule,
          message: str(extra["message"]) ?? "",
          location,
          cwe: strs(meta["cwe"]),
          references: strs(meta["references"]),
          raw: { file: semgrepRawJson, pointer: `/results/${i}` },
        }),
      ];
    });
  const ids = fingerprints(
    findings.map((f) => {
      const text = f.location ? source(f.location.path) : undefined;
      return text !== undefined && f.location
        ? ["semgrep", f.rule, f.location.path, snippetOf(text, f.location.startLine, f.location.endLine ?? f.location.startLine)]
        : ["semgrep", semgrepKey(f.rule, f.location)];
    }),
  );
  return ok(findings.map((f, i) => ({ ...f, id: ids[i] ?? "" })));
};
