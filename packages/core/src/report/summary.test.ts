import { describe, expect, it } from "vitest";
import { summarize } from "./json.js";

describe("summarize", () => {
  it("says what a status without a baseline counts", () => {
    expect(summarize({ status: "fail", errors: 0, deny: 5, warn: 9, newDeny: 0, newWarn: 0 })).toBe("fail: 5 deny, 9 warn (no baseline: all findings count)");
  });
  it("never lets a pass hide existing denies", () => {
    expect(
      summarize({ status: "pass", errors: 0, baselineRef: "HEAD", deny: 5, warn: 9, newDeny: 0, newWarn: 0, existing: { deny: 5, warn: 9 } }),
    ).toBe("pass: no new findings (5 existing deny, 9 existing warn from HEAD, not counted)");
    expect(
      summarize({ status: "pass", errors: 0, baselineRef: "origin/main", deny: 0, warn: 0, newDeny: 0, newWarn: 0, existing: { deny: 0, warn: 0 } }),
    ).toBe("pass: no new findings (nothing existing in origin/main)");
  });
  it("leads with scanner errors", () => {
    expect(summarize({ status: "error", errors: 1, deny: 0, warn: 0, newDeny: 0, newWarn: 0 })).toBe("error: 1 scanner error; 0 deny, 0 warn (no baseline: all findings count)");
  });
});
