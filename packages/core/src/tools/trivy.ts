import type { Command } from "../domain/command.js";
import type { Finding } from "../domain/finding.js";
import { arr, compact, isRecord, num, rec, str, strs, type Json } from "../fp/decode.js";
import { canonicalJson, hash } from "../fp/hash.js";
import { err, ok, type Result } from "../fp/result.js";
import { mapSeverity } from "./severity.js";
import { fingerprints, normalizeSnippet } from "./fingerprint.js";

export const trivySecretsRaw = "trivy-secrets.json";
export const trivyScaRaw = "trivy-sca.json";

export const trivySecretsCommand = (a: { readonly cwd: string; readonly rawDir: string }): Command => ({
  cmd: "trivy",
  args: ["fs", "--quiet", "--scanners", "secret", "--format", "json", "--output", `${a.rawDir}/${trivySecretsRaw}`, "."],
  cwd: a.cwd,
});

/** SCA reads the Syft SBOM instead of walking the source again. */
export const trivyScaCommand = (a: { readonly cwd: string; readonly rawDir: string; readonly sbom: string }): Command => ({
  cmd: "trivy",
  args: ["sbom", "--quiet", "--format", "json", "--output", `${a.rawDir}/${trivyScaRaw}`, a.sbom],
  cwd: a.cwd,
});

/** Trivy writes its own SARIF from its own JSON (used after policy filtering). */
export const trivyConvertCommand = (a: { readonly cwd: string; readonly input: string; readonly output: string }): Command => ({
  cmd: "trivy",
  args: ["convert", "--quiet", "--format", "sarif", "--output", a.output, a.input],
  cwd: a.cwd,
});

export const trivyVersionCommand = (cwd: string): Command => ({
  cmd: "trivy",
  args: ["version", "--format", "json"],
  cwd,
});

type Item = { readonly result: Json; readonly item: Json; readonly pointer: string };

const items = (json: Json, key: "Secrets" | "Vulnerabilities"): Item[] =>
  arr(json["Results"]).flatMap((result, i) =>
    isRecord(result)
      ? arr(result[key]).flatMap((item, j) =>
          isRecord(item) ? [{ result, item, pointer: `/Results/${i}/${key}/${j}` }] : [],
        )
      : [],
  );

const checkReport = (json: unknown): Result<Json, string> =>
  isRecord(json) && json["SchemaVersion"] === 2 ? ok(json) : err("expected trivy JSON report with SchemaVersion 2");

export const projectTrivySecrets = (json: unknown): Result<Finding[], string> => {
  const report = checkReport(json);
  if (!report.ok) return report;
  const matches: string[] = [];
  const findings = items(report.value, "Secrets").flatMap(({ result, item, pointer }): Finding[] => {
      const rule = str(item["RuleID"]);
      const path = str(result["Target"]);
      const startLine = num(item["StartLine"]);
      if (rule === undefined || path === undefined || startLine === undefined) return [];
      const toolSeverity = str(item["Severity"]) ?? "";
      const location = compact({ path, startLine, endLine: num(item["EndLine"]) });
      matches.push(normalizeSnippet(str(item["Match"]) ?? ""));
      return [
        {
          id: "",
          scanner: "trivy-secrets",
          rule,
          severity: mapSeverity(toolSeverity),
          toolSeverity,
          title: str(item["Title"]) ?? rule,
          message: str(item["Title"]) ?? rule,
          location,
          cwe: [],
          references: [],
          raw: { file: trivySecretsRaw, pointer },
        },
      ];
    });
  // Identity: rule + path + trivy's own (redacted) matched line, so moving code keeps the id.
  const ids = fingerprints(findings.map((f, i) => ["trivy-secrets", f.rule, f.location?.path, matches[i]]));
  return ok(findings.map((f, i) => ({ ...f, id: ids[i] ?? "" })));
};

export const projectTrivyVulns = (json: unknown): Result<Finding[], string> => {
  const report = checkReport(json);
  if (!report.ok) return report;
  return ok(
    items(report.value, "Vulnerabilities").flatMap(({ item, pointer }): Finding[] => {
      const rule = str(item["VulnerabilityID"]);
      const name = str(item["PkgName"]);
      const version = str(item["InstalledVersion"]);
      if (rule === undefined || name === undefined || version === undefined) return [];
      const toolSeverity = str(item["Severity"]) ?? "";
      const pkg = compact({
        name,
        version,
        purl: str(rec(item["PkgIdentifier"])["PURL"]),
        fixedVersion: str(item["FixedVersion"]) || undefined,
      });
      const primary = str(item["PrimaryURL"]);
      return [
        {
          id: hash(canonicalJson(["trivy-sca", rule, pkg.purl ?? `${name}@${version}`])),
          scanner: "trivy-sca",
          rule,
          severity: mapSeverity(toolSeverity),
          toolSeverity,
          title: str(item["Title"]) ?? rule,
          message: str(item["Description"]) ?? "",
          package: pkg,
          cwe: strs(item["CweIDs"]),
          references: [...(primary ? [primary] : []), ...strs(item["References"])],
          raw: { file: trivyScaRaw, pointer },
        },
      ];
    }),
  );
};

/**
 * Remove Secrets / Vulnerabilities whose pointer is not in `keep`. Nothing else changes,
 * so `trivy convert` can then write the tool's own SARIF for just the kept results.
 */
export const filterTrivyReport =
  (keep: ReadonlySet<string>) =>
  (json: Json): Json => ({
    ...json,
    Results: arr(json["Results"]).map((result, i) => {
      if (!isRecord(result)) return result;
      const prune = (key: "Secrets" | "Vulnerabilities"): Json =>
        Array.isArray(result[key])
          ? { [key]: arr(result[key]).filter((_, j) => keep.has(`/Results/${i}/${key}/${j}`)) }
          : {};
      return { ...result, ...prune("Secrets"), ...prune("Vulnerabilities") };
    }),
  });
