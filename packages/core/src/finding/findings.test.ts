import { describe, expect, it } from "vitest";
import { ok } from "../fp/result.js";
import type { AgentFinding, AgentReport } from "../report/json.js";
import { memoryDeps } from "../scan/memory-deps.test-helper.js";
import { isRunId } from "../workspace/layout.js";
import { findingWith } from "./finding.js";
import { findingsWith } from "./findings.js";

const f = (id: string): AgentFinding => ({ id, verdict: "deny", severity: "high", scanner: "semgrep", rule: "r", path: "a.py", line: 1, message: id, policy: [] });
const report = (baseline: boolean): AgentReport => ({
  status: "fail",
  summary: "",
  runId: "aaaaaaaaaaaa-bbbbbbbb",
  run: "/x",
  scanners: ["semgrep"],
  subject: { tree: "t", dirty: false },
  ...(baseline ? { baseline: { ref: "HEAD", tree: "b" } } : {}),
  counts: { found: 5, flagged: 5, deny: 5, warn: 0, dropped: 0 },
  errors: [],
  policy: { deny: [], warn: [] },
  findings: ["1", "2", "3", "4", "5"].map(f),
});
const steps = { repoRoot: () => async () => ok("/repo") };

describe("devsec_findings", () => {
  it("falls back to all findings with a note when there is no baseline", async () => {
    const { deps, files } = memoryDeps();
    files.set("/repo/.devsec/latest/report.json", JSON.stringify(report(false)));
    const r = await findingsWith(steps)(deps)({ cwd: "/repo", new: true, limit: 2 });
    expect(r.ok && r.value.total).toBe(5);
    expect(r.ok && r.value.note).toMatch(/no baseline/);
  });

  it("gives the call for the next page, keeping filters", async () => {
    const { deps, files } = memoryDeps();
    files.set("/repo/.devsec/latest/report.json", JSON.stringify(report(true)));
    const r = await findingsWith(steps)(deps)({ cwd: "/repo", verdict: "deny", limit: 2 });
    expect(r.ok && r.value.next).toBe('devsec_findings {"run":"aaaaaaaaaaaa-bbbbbbbb","verdict":"deny","limit":2,"offset":2}');
    const last = await findingsWith(steps)(deps)({ cwd: "/repo", offset: 4, limit: 2 });
    expect(last.ok && last.value.next).toBeUndefined();
  });

  it("rejects run ids that are not run ids", async () => {
    const { deps } = memoryDeps();
    for (const runId of ["../../etc", "aaaaaaaaaaaa-bbbbbbbb/../x", ""]) {
      expect(isRunId(runId)).toBe(false);
      const r = await findingsWith(steps)(deps)({ cwd: "/repo", runId });
      expect(r.ok ? "" : r.error).toMatchObject({ type: "io", detail: expect.stringMatching(/invalid run id/) });
      const one = await findingWith({ ...steps, currentTree: () => async () => ok("t") })(deps)({ cwd: "/repo", id: "abcd", runId });
      expect(one.ok).toBe(false);
    }
  });
});
