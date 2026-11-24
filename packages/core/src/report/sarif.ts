import type { Location } from "../domain/finding.js";
import { arr, compact, isRecord, num, rec, str, type Json } from "../fp/decode.js";

/** Location of a SARIF result, in the same shape as Finding.location. */
export const sarifLocation = (result: Json): Location | undefined => {
  const phys = rec(rec(arr(result["locations"])[0])["physicalLocation"]);
  const path = str(rec(phys["artifactLocation"])["uri"]);
  const region = rec(phys["region"]);
  const startLine = num(region["startLine"]);
  if (path === undefined || startLine === undefined) return undefined;
  return compact({
    path,
    startLine,
    endLine: num(region["endLine"]),
    startColumn: num(region["startColumn"]),
    endColumn: num(region["endColumn"]),
  });
};

/**
 * Keep only the results whose key is in `keep`, in a tool's own SARIF log.
 * Nothing else changes: kept results, rules and all other run data are untouched.
 */
export const filterSarif =
  (keyOf: (result: Json) => string) =>
  (keep: ReadonlySet<string>) =>
  (log: Json): Json => ({
    ...log,
    runs: arr(log["runs"]).map((run) =>
      isRecord(run) ? { ...run, results: arr(run["results"]).filter((r) => isRecord(r) && keep.has(keyOf(r))) } : run,
    ),
  });

/** Combine several tools' SARIF logs into one log with one run per tool. */
export const mergeSarif = (logs: readonly Json[]): Json => ({
  version: "2.1.0",
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  runs: logs.flatMap((l) => arr(l["runs"])),
});
