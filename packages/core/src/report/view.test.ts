import { describe, expect, it } from "vitest";
import type { AgentFinding, AgentReport } from "./json.js";
import { agentView, groupByRule, pageFindings } from "./view.js";

const f = (id: string, rule: string, verdict: "deny" | "warn", isNew?: boolean, path = "a.py"): AgentFinding => ({
  id,
  verdict,
  severity: verdict === "deny" ? "high" : "medium",
  scanner: "semgrep",
  rule,
  path,
  line: 1,
  message: id,
  policy: [],
  ...(isNew !== undefined ? { new: isNew } : {}),
});

const report = (findings: AgentFinding[], baseline = false): AgentReport => ({
  status: "fail",
  runId: "r",
  run: "/r",
  scanners: ["semgrep"],
  subject: { tree: "t", dirty: true },
  ...(baseline ? { baseline: { ref: "HEAD", tree: "b" } } : {}),
  counts: { found: findings.length, flagged: findings.length, deny: 0, warn: 0, dropped: 0 },
  errors: [],
  policy: { deny: [], warn: [] },
  findings,
});

describe("agent view", () => {
  const many = Array.from({ length: 50 }, (_, i) => f(`w${i}`, "noisy-rule", "warn", i < 2));
  const all = [f("d1", "sqli", "deny", true), f("d2", "sqli", "deny", false), ...many];

  it("groups by rule, new and deny first", () => {
    expect(groupByRule(all).map((g) => [g.rule, g.verdict, g.count, g.new])).toEqual([
      ["noisy-rule", "warn", 50, 2],
      ["sqli", "deny", 2, 1],
    ]);
  });

  it("shows only new findings by default when there is a baseline, and how to get more", () => {
    const v = agentView(report(all, true), { limit: 2 });
    expect(v.scope).toBe("new");
    expect(v.findings.map((x) => x.id)).toEqual(["d1", "w0"]);
    expect(v.more).toBe(1);
    expect(v.next).toBe('devsec_findings {"run":"r","new":true,"offset":2}');
    expect(v.byRule?.length).toBe(2);
  });

  it("caps the list without a baseline", () => {
    const v = agentView(report(all), { limit: 20 });
    expect(v.scope).toBe("all");
    expect(v.findings).toHaveLength(20);
    expect(v.more).toBe(32);
    expect(JSON.stringify(v).length).toBeLessThan(JSON.stringify(report(all)).length / 2);
  });
});

describe("byRule", () => {
  it("is left out when the findings list already shows everything", () => {
    const few = [f("a", "r1", "deny"), f("b", "r2", "warn")];
    expect(agentView(report(few)).byRule).toBeUndefined();
    expect(agentView(report(few), { limit: 1 }).byRule?.length).toBe(2);
  });
});

describe("pageFindings", () => {
  const all = [f("a", "sqli", "deny", true, "src/x.py"), f("b", "xss", "warn", false, "src/y.py"), f("c", "sqli", "warn", false, "lib/z.py")];
  it("filters and pages", () => {
    expect(pageFindings(all, { rule: "sqli" }).findings.map((x) => x.id)).toEqual(["a", "c"]);
    expect(pageFindings(all, { file: "src/", verdict: "warn" }).findings.map((x) => x.id)).toEqual(["b"]);
    expect(pageFindings(all, { new: true }).total).toBe(1);
    expect(pageFindings(all, { offset: 1, limit: 1 })).toMatchObject({ total: 3, offset: 1, more: 1 });
  });
});
