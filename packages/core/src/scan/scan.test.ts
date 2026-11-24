import { describe, expect, it } from "vitest";
import { defaultConfig } from "../domain/config.js";
import type { DevsecEvent, StepId } from "../domain/events.js";
import type { Finding } from "../domain/finding.js";
import { foldEvents } from "../domain/run-state.js";
import { err, ok } from "../fp/result.js";
import { memoryDeps } from "./memory-deps.test-helper.js";
import { scanWith } from "./scan.js";
import { scanSteps } from "./steps.js";
import type { ScanSteps } from "./types.js";

const f = (id: string, scanner: Finding["scanner"], severity: Finding["severity"] = "high"): Finding => ({
  id,
  scanner,
  rule: `rule-${id}`,
  severity,
  toolSeverity: severity.toUpperCase(),
  title: id,
  message: id,
  cwe: [],
  references: [],
  raw: { file: `${scanner}.json`, pointer: "/0" },
});

const tick = () => new Promise((r) => setTimeout(r, 5));

/** Fake steps: no tools, deterministic results. Policy denies every high finding. */
const fakeSteps = (calls: string[], over: Partial<ScanSteps> = {}): ScanSteps => ({
  ...scanSteps,
  versions: () => async () => ok({ found: { git: "2", syft: "1", semgrep: "1", trivy: "0", conftest: "0" }, missing: [] }),
  subject: () => async () => ok({ repoRoot: "/repo", treeSha: "abcdef0123456789", headSha: "h", dirty: false }),
  config: () => async () => ok(defaultConfig),
  snapshot: () => async () => (calls.push("snapshot"), ok("/repo/.devsec/snapshots/abcdef0123456789")),
  sbom: () => async () => (calls.push("sbom"), await tick(), ok("/run/sbom.cdx.json")),
  semgrep: () => async () => (calls.push("semgrep"), await tick(), ok([f("s1", "semgrep"), f("s2", "semgrep", "low")])),
  trivySecrets: () => async () => (calls.push("trivy-secrets"), await tick(), ok([f("t1", "trivy-secrets")])),
  trivySca: () => async () => (calls.push("trivy-sca"), ok([f("v1", "trivy-sca")])),
  policy: () => async ({ findings }) =>
    ok({
      deny: findings.filter((x) => x.severity === "high").map((x) => ({ code: "c", msg: "m", findingId: x.id })),
      warn: [],
    }),
  report: (deps) => async (input) => {
    const { agentReport } = await import("../report/json.js");
    return ok(agentReport({ ...input, runDir: input.run.dir }));
  },
  ...over,
});

const timeline = (events: readonly DevsecEvent[]) =>
  events.flatMap((e) => (e.type === "step.started" || e.type === "step.finished" ? [`${e.type === "step.started" ? "+" : "-"}${e.step}`] : []));

describe("scanWith", () => {
  it("reports findings the baseline did not have as new, and gates only on those", async () => {
    const { deps, files } = memoryDeps();
    const steps = fakeSteps([], {
      // Working tree "work…" (dirty) vs HEAD "base…"; the working tree adds finding n1.
      subject: () => async (input) =>
        ok(
          input.ref === "HEAD"
            ? { repoRoot: "/repo", treeSha: "base000000000000", headSha: "h", dirty: false, ref: "HEAD" }
            : { repoRoot: "/repo", treeSha: "work000000000000", headSha: "h", dirty: true },
        ),
      semgrep: () => async ({ snapshot }) =>
        ok(snapshot.includes("work") ? [f("s1", "semgrep"), f("n1", "semgrep")] : [f("s1", "semgrep")]),
      snapshot: () => async ({ subject }) => ok(`/repo/.devsec/snapshots/${subject.treeSha}`),
    });
    const r = await scanWith(steps)(deps)({ cwd: "/repo" });
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const rep = r.value.report;
    expect(rep.baseline).toMatchObject({ ref: "HEAD", tree: "base000000000000" });
    expect(rep.findings.filter((x) => x.new).map((x) => x.id)).toEqual(["n1"]);
    expect(rep.counts.new).toBe(1);
    expect(rep.status).toBe("fail"); // n1 is a new deny
    // The baseline run never becomes latest.
    expect(files.get("@latest")).toBe(`runs/${rep.runId}`);

    // Without the new finding, existing denies alone do not fail the scan.
    const clean = fakeSteps([], { ...steps, semgrep: () => async () => ok([f("s1", "semgrep")]) });
    const r2 = await scanWith(clean)(memoryDeps().deps)({ cwd: "/repo" }); // fresh deps: no cached scan
    expect(r2.ok && [r2.value.report.status, r2.value.report.counts.deny, r2.value.report.counts.new]).toEqual(["pass", 3, 0]);

    // "none" disables the baseline.
    const r3 = await scanWith(steps)(deps)({ cwd: "/repo", baseline: "none" });
    expect(r3.ok && r3.value.report.baseline).toBeUndefined();
  });

  it("runs scanners in parallel and SCA after the SBOM, then reports policy-flagged findings", async () => {
    const { deps, events } = memoryDeps();
    const calls: string[] = [];
    const r = await scanWith(fakeSteps(calls))(deps)({ cwd: "/repo" });
    if (!r.ok) throw new Error(JSON.stringify(r.error));

    const t = timeline(events);
    const at = (s: string) => t.indexOf(s);
    // semgrep, trivy-secrets and sbom all start before any of them finishes
    expect(Math.max(at("+semgrep"), at("+trivy-secrets"), at("+sbom"))).toBeLessThan(
      Math.min(at("-semgrep"), at("-trivy-secrets"), at("-sbom")),
    );
    expect(at("+trivy-sca")).toBeGreaterThan(at("-sbom"));
    expect(at("+policy")).toBeGreaterThan(Math.max(at("-semgrep"), at("-trivy-secrets"), at("-trivy-sca")));

    expect(r.value.report.status).toBe("fail");
    expect(r.value.report.findings.map((x) => x.id).sort()).toEqual(["s1", "t1", "v1"]);
    expect(r.value.report.counts).toEqual({ found: 4, flagged: 3, deny: 3, warn: 0, dropped: 1 });
    expect(r.value.report.scanners).toEqual(["semgrep", "trivy-secrets", "trivy-sca"]);
    expect(r.value.runDir.endsWith(r.value.report.runId)).toBe(true);
    expect(r.value.runDir).toMatch(/^\/repo\/\.devsec\/runs\/abcdef012345-[0-9a-f]{8}$/);
  });

  it("writes events.jsonl in order and run.json from the folded events", async () => {
    const { deps, files, events } = memoryDeps();
    const r = await scanWith(fakeSteps([]))(deps)({ cwd: "/repo" });
    if (!r.ok) throw new Error("scan failed");
    const lines = (files.get(`${r.value.runDir}/events.jsonl`) ?? "").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines).toEqual(events);
    const runJson = JSON.parse(files.get(`${r.value.runDir}/run.json`) ?? "{}");
    expect(runJson).toMatchObject({ ...foldEvents(events), status: "fail" });
    expect(runJson.commands.map((c: { step: string; command: { cmd: string } }) => `${c.step}:${c.command.cmd}`)).toEqual([
      "sbom:syft",
      "semgrep:semgrep",
      "trivy-secrets:trivy",
      "trivy-sca:trivy",
      "policy:conftest",
    ]);
  });

  it("reuses a complete scan of the same tree within the TTL, re-evaluating only the policy", async () => {
    const m = memoryDeps();
    const calls: string[] = [];
    const steps = fakeSteps(calls);
    await scanWith(steps)(m.deps)({ cwd: "/repo" });
    calls.length = 0;
    m.events.length = 0;

    const again = await scanWith(steps)(m.deps)({ cwd: "/repo" });
    expect(calls).toEqual([]);
    const state = foldEvents(m.events);
    for (const s of ["snapshot", "sbom", "semgrep", "trivy-secrets", "trivy-sca"] as StepId[]) expect(state.steps[s]?.status).toBe("cached");
    expect(state.steps.policy?.status).toBe("ok");
    expect(again.ok && again.value.report.counts.deny).toBe(3);

    m.advance(25 * 3_600_000);
    await scanWith(steps)(m.deps)({ cwd: "/repo" });
    expect(calls).toContain("semgrep");
  });

  it("keeps other scanners' findings when one fails, reports status error and never caches", async () => {
    const { deps, files } = memoryDeps();
    const calls: string[] = [];
    const steps = fakeSteps(calls, {
      semgrep: () => async () => err({ type: "tool-failed", tool: "semgrep", code: 2, stderr: "boom" }),
    });
    const r = await scanWith(steps)(deps)({ cwd: "/repo" });
    if (!r.ok) throw new Error("scan failed");
    expect(r.value.report.status).toBe("error");
    expect(r.value.report.errors[0]).toMatch(/semgrep exited with 2: boom/);
    expect(r.value.report.findings.map((x) => x.id).sort()).toEqual(["t1", "v1"]);
    expect(JSON.parse(files.get(`${r.value.runDir}/scan.json`) ?? "{}").complete).toBe(false);
  });

  it("skips trivy-sca when the SBOM fails, and reports the SBOM error", async () => {
    const { deps, events } = memoryDeps();
    const steps = fakeSteps([], { sbom: () => async () => err({ type: "tool-failed", tool: "syft", code: 1, stderr: "x" }) });
    const r = await scanWith(steps)(deps)({ cwd: "/repo" });
    expect(foldEvents(events).steps["trivy-sca"]?.status).toBe("skipped");
    expect(r.ok && r.value.report.errors).toEqual([expect.stringMatching(/^syft/)]);
  });

  it("only runs the requested scanners, and a partial scan does not become latest", async () => {
    const { deps, files } = memoryDeps();
    const calls: string[] = [];
    const steps = fakeSteps(calls);
    const full = await scanWith(steps)(deps)({ cwd: "/repo" });
    const partial = await scanWith(steps)(deps)({ cwd: "/repo", scanners: ["trivy-secrets"] });
    expect(calls.filter((c) => c !== "snapshot" && c !== "sbom").sort()).toEqual(["semgrep", "trivy-sca", "trivy-secrets", "trivy-secrets"]);
    expect(partial.ok && partial.value.report.scanners).toEqual(["trivy-secrets"]);
    expect(full.ok && files.get("@latest")).toBe(`runs/${full.ok && full.value.report.runId}`);
  });

  it("fails fast when a needed tool is missing", async () => {
    const { deps } = memoryDeps();
    const steps = fakeSteps([], { versions: () => async () => ok({ found: {}, missing: ["semgrep"] }) });
    expect(await scanWith(steps)(deps)({ cwd: "/repo" })).toEqual({ ok: false, error: { type: "tool-missing", tool: "semgrep" } });
    expect((await scanWith(steps)(deps)({ cwd: "/repo", scanners: ["trivy-sca"] })).ok).toBe(true);
  });

  it("turns a throwing dependency into an error result", async () => {
    const { deps } = memoryDeps();
    const steps = fakeSteps([], {
      snapshot: () => async () => {
        throw new Error("disk full");
      },
    });
    const r = await scanWith(steps)(deps)({ cwd: "/repo" });
    expect(r).toEqual({ ok: false, error: { type: "io", detail: "snapshot: disk full" } });
  });
});
