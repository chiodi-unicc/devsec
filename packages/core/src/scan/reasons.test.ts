import { describe, expect, it } from "vitest";
import { baselineDecision, formatAge, scannerSkipReason } from "./scan.js";

const s = { repoRoot: "/r", treeSha: "t", headSha: "h", dirty: true };

describe("skip reasons", () => {
  it("explain every way the baseline can be absent", () => {
    expect(baselineDecision(undefined, undefined, s)).toEqual({ ref: "HEAD" });
    expect(baselineDecision(undefined, undefined, { ...s, dirty: false })).toMatchObject({ reason: expect.stringMatching(/no uncommitted changes/) });
    expect(baselineDecision(undefined, undefined, { repoRoot: "/r", treeSha: "t", dirty: true })).toMatchObject({ reason: expect.stringMatching(/no commits/) });
    expect(baselineDecision(undefined, undefined, { ...s, ref: "v1" })).toMatchObject({ reason: expect.stringMatching(/--ref v1/) });
    expect(baselineDecision("none", "origin/main", s)).toEqual({ reason: "baseline: none (from --baseline)" });
    expect(baselineDecision(undefined, "none", s)).toEqual({ reason: "baseline: none (from devsec.json)" });
    expect(baselineDecision(undefined, "origin/main", { ...s, dirty: false })).toEqual({ ref: "origin/main" });
    expect(baselineDecision(undefined, undefined, s, "baseline")).toMatchObject({ reason: expect.stringMatching(/itself the baseline/) });
  });

  it("explain why a scanner did not run", () => {
    expect(scannerSkipReason("semgrep", ["semgrep", "trivy-sca"], ["trivy-sca"])).toBe("not requested: this scan ran only trivy-sca");
    expect(scannerSkipReason("trivy-secrets", ["semgrep"], ["semgrep"])).toBe("disabled in devsec.json (scanners)");
    expect(formatAge(185_000)).toBe("3m");
  });
});
