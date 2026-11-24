import { describe, expect, it } from "vitest";
import { resolvePointer } from "../fp/json-pointer.js";
import { durationMs, foldEvents } from "./run-state.js";

describe("foldEvents", () => {
  it("tracks steps from start to finish", () => {
    const s = foldEvents([
      { type: "run.started", at: 1, runId: "r", subject: { repoRoot: "/r", treeSha: "t", dirty: false } },
      { type: "step.started", at: 2, step: "semgrep" },
      { type: "step.started", at: 3, step: "sbom" },
      { type: "step.finished", at: 7, step: "semgrep", status: "ok", findings: 4 },
    ]);
    expect(s.status).toBe("running");
    expect(s.steps.semgrep).toEqual({ status: "ok", startedAt: 2, finishedAt: 7, findings: 4 });
    expect(s.steps.sbom?.status).toBe("running");
    expect(durationMs(s.steps.semgrep!)).toBe(5);
  });
});

describe("resolvePointer", () => {
  it("follows RFC 6901 pointers", () => {
    const doc = { Results: [{ "a/b": [1, { x: "y" }] }] };
    expect(resolvePointer(doc, "/Results/0/a~1b/1/x")).toBe("y");
    expect(resolvePointer(doc, "/Results/9")).toBeUndefined();
    expect(resolvePointer(doc, "")).toBe(doc);
  });
});
