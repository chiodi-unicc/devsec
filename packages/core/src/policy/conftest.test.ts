import { describe, expect, it } from "vitest";
import type { Finding } from "../domain/finding.js";
import { judge, parseConftest } from "./conftest.js";

const finding = (id: string): Finding => ({
  id,
  scanner: "semgrep",
  rule: `r-${id}`,
  severity: "high",
  toolSeverity: "ERROR",
  title: id,
  message: id,
  cwe: [],
  references: [],
  raw: { file: "semgrep.json", pointer: "/results/0" },
});

// Verbatim shape of `conftest test --output json` (conftest 0.71).
const output = JSON.stringify([
  {
    filename: "input.json",
    namespace: "devsec",
    successes: 0,
    warnings: [{ msg: "medium", metadata: { code: "devsec.medium", finding_id: "c", query: "data.devsec.warn" } }],
    failures: [
      { msg: "high: a", metadata: { code: "devsec.high", finding_id: "a", query: "data.devsec.deny" } },
      { msg: "no secrets allowed", metadata: { query: "data.devsec.deny" } },
    ],
  },
]);

describe("conftest", () => {
  it("parses failures and warnings with their metadata", () => {
    const r = parseConftest(output);
    expect(r).toEqual({
      ok: true,
      value: {
        deny: [{ code: "devsec.high", msg: "high: a", findingId: "a" }, { code: "data.devsec.deny", msg: "no secrets allowed" }],
        warn: [{ code: "devsec.medium", msg: "medium", findingId: "c" }],
      },
    });
  });

  it("keeps only flagged findings, deny winning over warn", () => {
    const r = parseConftest(output);
    if (!r.ok) throw new Error(r.error);
    const j = judge(["a", "b", "c"].map(finding), r.value);
    expect(j.flagged.map((f) => [f.finding.id, f.verdict])).toEqual([["a", "deny"], ["c", "warn"]]);
    expect(j.dropped).toBe(1);
    expect(j.general.deny).toEqual([{ code: "data.devsec.deny", msg: "no secrets allowed" }]);
  });

  it("reports unparseable output", () => {
    expect(parseConftest("boom").ok).toBe(false);
  });
});
