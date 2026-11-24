import { describe, expect, it } from "vitest";
import { stepIds } from "./events.js";
import { stageState, stages, stepInfo } from "./steps-info.js";

const scan = stages[2]!;
const at = (startedAt: number, finishedAt: number | undefined, status: "ok" | "running" | "failed" | "cached" | "skipped") =>
  finishedAt === undefined ? { status, startedAt } : { status, startedAt, finishedAt };

describe("stages", () => {
  it("cover every step exactly once, each with a description", () => {
    expect(stages.flatMap((s) => s.lanes.flat()).sort()).toEqual([...stepIds].sort());
    for (const id of stepIds) expect(stepInfo[id].description.length).toBeGreaterThan(10);
  });

  it("aggregate step states into a stage state", () => {
    expect(stageState(scan, { steps: {} })).toEqual({ status: "pending" });
    expect(stageState(scan, { steps: { semgrep: at(0, 5, "ok") } }).status).toBe("running");
    expect(stageState(scan, { steps: { semgrep: at(0, 5, "ok"), sbom: at(0, undefined, "running") } }).status).toBe("running");
    expect(
      stageState(scan, {
        steps: { semgrep: at(10, 50, "ok"), "trivy-secrets": at(10, 20, "ok"), sbom: at(10, 30, "ok"), "trivy-sca": at(30, 35, "failed") },
      }),
    ).toEqual({ status: "failed", durationMs: 40 });
    expect(
      stageState(scan, {
        steps: { semgrep: at(1, 1, "cached"), "trivy-secrets": at(1, 1, "cached"), sbom: at(1, 1, "cached"), "trivy-sca": at(1, 1, "skipped") },
      }).status,
    ).toBe("cached");
  });
});
