import { describe, expect, it } from "vitest";
import { arr, rec } from "../fp/decode.js";
import { fixture } from "./fixtures.test-helper.js";
import { filterTrivyReport, projectTrivySecrets, projectTrivyVulns } from "./trivy.js";

const secrets = fixture("trivy-secrets.json");
const sca = fixture("trivy-sca.json");
const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: string }): T => {
  if (!r.ok) throw new Error(r.error);
  return r.value;
};

describe("trivy secrets", () => {
  it("projects secrets with their file location", () => {
    const fs = unwrap(projectTrivySecrets(secrets));
    expect(fs).toEqual([
      expect.objectContaining({
        scanner: "trivy-secrets",
        rule: "github-pat",
        severity: "critical",
        toolSeverity: "CRITICAL",
        location: { path: "config.js", startLine: 3, endLine: 3 },
        raw: { file: "trivy-secrets.json", pointer: "/Results/1/Secrets/0" },
      }),
    ]);
  });
});

describe("trivy sca (from the syft SBOM)", () => {
  const vulns = unwrap(projectTrivyVulns(sca));

  it("projects every vulnerability with its package", () => {
    const total = arr(sca["Results"]).reduce<number>((n, r) => n + arr(rec(r)["Vulnerabilities"]).length, 0);
    expect(vulns).toHaveLength(total);
    for (const v of vulns) {
      expect(v.scanner).toBe("trivy-sca");
      expect(v.package?.purl).toMatch(/^pkg:npm\/(lodash|express)@/);
      expect(v.location).toBeUndefined();
    }
    expect(new Set(vulns.map((v) => v.id)).size).toBe(vulns.length);
  });

  it("filters the report by pointer and keeps everything else", () => {
    const keep = new Set([vulns[0]!.raw.pointer]);
    const out = filterTrivyReport(keep)(sca);
    const kept = unwrap(projectTrivyVulns(out));
    expect(kept).toHaveLength(1);
    expect(kept[0]!.id).toBe(vulns[0]!.id);
    expect({ ...out, Results: undefined }).toEqual({ ...sca, Results: undefined });
  });

  it("rejects non-trivy input", () => {
    expect(projectTrivyVulns({ SchemaVersion: 1 }).ok).toBe(false);
  });
});
