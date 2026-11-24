import { describe, expect, it } from "vitest";
import { defaultConfig, parseConfig } from "./config.js";

import { describeError } from "./errors.js";

describe("describeError", () => {
  it("explains an unresolvable ref without blaming the config", () => {
    expect(describeError({ type: "bad-ref", ref: "HEAD", noCommits: true })).toBe('ref "HEAD" not found (the repository has no commits yet)');
    expect(describeError({ type: "bad-ref", ref: "v9", noCommits: false })).toBe('ref "v9" not found');
  });
});

describe("parseConfig", () => {
  it("defaults everything", () => {
    expect(parseConfig(undefined)).toEqual({ ok: true, value: defaultConfig });
    expect(parseConfig({})).toEqual({ ok: true, value: defaultConfig });
  });

  it("accepts a full config", () => {
    const r = parseConfig({
      scanners: ["semgrep"],
      semgrep: { rulesets: ["p/javascript"] },
      policy: "policy",
      failOn: "warn",
      cacheTtlHours: 0,
      exceptions: [{ rule: "CVE-1", reason: "not reachable", expires: "2027-01-01" }],
    });
    expect(r.ok && r.value).toMatchObject({ scanners: ["semgrep"], policy: "policy", failOn: "warn", cacheTtlHours: 0 });
  });

  it.each([
    [{ scanners: ["nope"] }, /unknown scanner/],
    [{ semgrep: { rulesets: [] } }, /rulesets/],
    [{ failOn: "maybe" }, /failOn/],
    [{ exceptions: [{ rule: "x", expires: "2027-01-01" }] }, /reason/],
    [{ exceptions: [{ rule: "x", reason: "r", expires: "soon" }] }, /YYYY-MM-DD/],
    [{ exceptions: [{ reason: "r", expires: "2027-01-01" }] }, /finding.*rule/],
  ])("rejects %j", (input, message) => {
    const r = parseConfig(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });
});
