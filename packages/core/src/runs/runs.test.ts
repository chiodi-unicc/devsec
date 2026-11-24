import { describe, expect, it } from "vitest";
import { ok } from "../fp/result.js";
import { memoryDeps } from "../scan/memory-deps.test-helper.js";
import { listRunsWith, parseEvents, readRunWith } from "./runs.js";

const steps = { repoRoot: () => async () => ok("/repo") };
const ev = (o: object) => `${JSON.stringify(o)}\n`;
const subject = { repoRoot: "/repo", treeSha: "t", dirty: false };

describe("runs", () => {
  it("parses events, ignoring a partially written last line", () => {
    expect(parseEvents(`${ev({ type: "step.started", at: 1, step: "sbom" })}{"type":"step.fin`)).toEqual([
      { type: "step.started", at: 1, step: "sbom" },
    ]);
  });

  it("lists finished and in-progress runs, newest first", async () => {
    const m = memoryDeps();
    const files = m.files;
    const deps = { ...m.deps, fs: { ...m.deps.fs, readdir: async () => ["a", "b"] } };
    files.set("/repo/.devsec/runs/a/events.jsonl", ev({ type: "run.started", at: 1, runId: "a", subject }) + ev({ type: "run.finished", at: 5, status: "pass" }));
    files.set("/repo/.devsec/runs/a/report.json", JSON.stringify({ counts: { total: 1, deny: 0, warn: 0, dropped: 1 } }));
    files.set("/repo/.devsec/runs/b/events.jsonl", ev({ type: "run.started", at: 9, runId: "b", subject }) + ev({ type: "step.started", at: 10, step: "semgrep" }));
    const r = await listRunsWith(steps)(deps)({ cwd: "/repo" });
    expect(r.ok && r.value.map((x) => [x.runId, x.status, x.counts?.dropped])).toEqual([
      ["b", "running", undefined],
      ["a", "pass", 1],
    ]);
  });

  it("reads a run with its policy files", async () => {
    const m = memoryDeps();
    const files = m.files;
    const deps = { ...m.deps, fs: { ...m.deps.fs, readdir: async () => ["devsec.rego", "notes.txt"] } };
    files.set("/repo/.devsec/runs/aaaaaaaaaaaa-bbbbbbbb/events.jsonl", ev({ type: "run.started", at: 1, runId: "aaaaaaaaaaaa-bbbbbbbb", subject }));
    files.set("/repo/.devsec/policy/default/devsec.rego", "package devsec");
    const r = await readRunWith(steps)(deps)({ cwd: "/repo", runId: "aaaaaaaaaaaa-bbbbbbbb" });
    expect(r.ok && r.value.policy).toEqual({ dir: ".devsec/policy/default", files: { "devsec.rego": "package devsec" } });
    expect(r.ok && r.value.state.status).toBe("running");
  });
});
