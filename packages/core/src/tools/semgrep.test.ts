import { describe, expect, it } from "vitest";
import { filterSarif, sarifLocation } from "../report/sarif.js";
import { arr, rec, str, type Json } from "../fp/decode.js";
import { fixture } from "./fixtures.test-helper.js";
import { projectSemgrep, semgrepCommand, semgrepKey } from "./semgrep.js";

const json = fixture("semgrep.json");
const sarif = fixture("semgrep.sarif");
const sarifResults = () => arr(rec(arr(sarif["runs"])[0])["results"]) as Json[];
const keyOfSarif = (r: Json) => semgrepKey(str(r["ruleId"]) ?? "", sarifLocation(r));

describe("semgrep", () => {
  const findings = (() => {
    const r = projectSemgrep(json);
    if (!r.ok) throw new Error(r.error);
    return r.value;
  })();

  it("projects every result, copying tool fields", () => {
    expect(findings).toHaveLength(arr(json["results"]).length);
    const evalConcat = findings.find((f) => f.rule.endsWith("code-string-concat"));
    expect(evalConcat).toMatchObject({
      scanner: "semgrep",
      toolSeverity: "ERROR",
      severity: "high",
      location: { path: "app.js", startLine: 8 },
      raw: { file: "semgrep.json" },
    });
    expect(evalConcat?.cwe[0]).toMatch(/^CWE-95/);
  });

  it("gives every finding a unique, stable id", () => {
    expect(new Set(findings.map((f) => f.id)).size).toBe(findings.length);
    const again = projectSemgrep(json);
    expect(again.ok && again.value.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  });

  it("points raw refs at the verbatim result", () => {
    for (const f of findings) {
      const i = Number(f.raw.pointer.split("/").at(-1));
      expect(rec(arr(json["results"])[i])["check_id"]).toBe(f.rule);
    }
  });

  it("matches each finding to exactly one SARIF result", () => {
    const sarifKeys = sarifResults().map(keyOfSarif);
    for (const f of findings) {
      expect(sarifKeys.filter((k) => k === semgrepKey(f.rule, f.location))).toHaveLength(1);
    }
  });

  it("filters SARIF to kept results and changes nothing else", () => {
    const keep = findings.filter((f) => f.severity === "high").map((f) => semgrepKey(f.rule, f.location));
    const out = filterSarif(keyOfSarif)(new Set(keep))(sarif);
    const run = rec(arr(out["runs"])[0]);
    const kept = arr(run["results"]) as Json[];
    expect(kept).toHaveLength(keep.length);
    expect(kept).toEqual(sarifResults().filter((r) => keep.includes(keyOfSarif(r))));
    expect({ ...run, results: undefined }).toEqual({ ...rec(arr(sarif["runs"])[0]), results: undefined });
  });

  it("builds the command as data, with only output flags plus --no-git-ignore", () => {
    expect(semgrepCommand({ cwd: "/snap", rulesets: ["p/default", "p/secrets"], rawDir: "/run/raw" })).toEqual({
      cmd: "semgrep",
      args: [
        "scan",
        "--config", "p/default",
        "--config", "p/secrets",
        "--metrics=off",
        "--quiet",
        "--no-git-ignore",
        "--json-output=/run/raw/semgrep.json",
        "--sarif-output=/run/raw/semgrep.sarif",
        ".",
      ],
      cwd: "/snap",
    });
  });

  it("rejects non-semgrep input", () => {
    expect(projectSemgrep({ nope: true }).ok).toBe(false);
  });
});
