// Runs the built-in Rego through the real conftest binary against projected fixtures.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Exception } from "../domain/config.js";
import type { Finding } from "../domain/finding.js";
import { fixture } from "../tools/fixtures.test-helper.js";
import { projectSemgrep } from "../tools/semgrep.js";
import { projectTrivySecrets, projectTrivyVulns } from "../tools/trivy.js";
import { conftestCommand, judge, parseConftest, policyData, policyInput } from "./conftest.js";
import { defaultPolicyFiles } from "./default-policy.js";

const hasConftest = spawnSync("conftest", ["--version"]).status === 0;

const findings: Finding[] = [
  ...[projectSemgrep(fixture("semgrep.json")), projectTrivySecrets(fixture("trivy-secrets.json")), projectTrivyVulns(fixture("trivy-sca.json"))].flatMap(
    (r) => (r.ok ? r.value : []),
  ),
];

const evaluate = (exceptions: Exception[] = [], partial = false) => {
  const dir = mkdtempSync(join(tmpdir(), "devsec-policy-"));
  mkdirSync(join(dir, "policy"));
  for (const [file, src] of Object.entries(defaultPolicyFiles)) writeFileSync(join(dir, "policy", file), src);
  const subject = { repoRoot: "/repo", treeSha: "t", dirty: false };
  writeFileSync(join(dir, "input.json"), JSON.stringify(policyInput(subject, findings, partial)));
  writeFileSync(join(dir, "data.json"), JSON.stringify(policyData(exceptions)));
  const cmd = conftestCommand({ cwd: dir, policyDir: "policy", dataFile: "data.json", inputFile: "input.json" });
  const out = spawnSync(cmd.cmd, cmd.args, { cwd: cmd.cwd, encoding: "utf8" });
  const parsed = parseConftest(out.stdout);
  if (!parsed.ok) throw new Error(`${parsed.error}\n${out.stderr}`);
  return judge(findings, parsed.value);
};

describe.skipIf(!hasConftest)("default policy (real conftest)", () => {
  it("is valid Rego", () => {
    expect(() => execFileSync("conftest", ["--version"])).not.toThrow();
  });

  it("denies secrets from both tools, high SAST and fixable high CVEs; drops low noise", () => {
    const j = evaluate();
    const denied = j.flagged.filter((f) => f.verdict === "deny").map((f) => f.finding);
    const deniedRules = denied.map((f) => f.rule.split(".").at(-1));

    expect(deniedRules).toContain("github-pat"); // trivy-secrets
    expect(deniedRules).toContain("detected-aws-access-key-id-value"); // semgrep p/secrets via CWE-798
    expect(deniedRules).toContain("code-string-concat"); // high SAST
    expect(denied.some((f) => f.scanner === "trivy-sca" && f.package?.fixedVersion)).toBe(true);
    expect(denied.filter((f) => f.scanner === "trivy-sca").every((f) => f.severity === "critical" || f.severity === "high")).toBe(true);

    const secretDeny = j.flagged.find((f) => f.finding.rule.endsWith("detected-aws-access-key-id-value"));
    expect(secretDeny?.violations.map((v) => v.code)).toEqual(["devsec.secret"]); // not double-reported as SAST

    const flaggedRules = j.flagged.map((f) => f.finding.rule);
    expect(flaggedRules.some((r) => r.endsWith("express-check-csurf-middleware-usage"))).toBe(false); // INFO → low → dropped
    expect(j.dropped).toBeGreaterThan(0);
  });

  it("warns about exceptions that match nothing, on full scans only", () => {
    const stale = { finding: "00000000000000", reason: "old id", expires: "2999-01-01" };
    const j = evaluate([stale]);
    expect(j.general.warn).toEqual([{ code: "devsec.exception_unused", msg: "exception matches no finding: finding 00000000000000 (old id)" }]);
    expect(evaluate([stale], true).general.warn).toEqual([]);
    const used = findings.find((x) => x.rule === "github-pat")!;
    expect(evaluate([{ finding: used.id, reason: "ok", expires: "2999-01-01" }]).general.warn).toEqual([]);
  });

  it("honours a valid exception and warns when it has expired", () => {
    const target = findings.find((f) => f.rule === "github-pat")!;
    const waived = evaluate([{ finding: target.id, reason: "test fixture", expires: "2999-01-01" }]);
    expect(waived.flagged.find((f) => f.finding.id === target.id)).toBeUndefined();

    const expired = evaluate([{ finding: target.id, reason: "test fixture", expires: "2000-01-01" }]);
    const j = expired.flagged.find((f) => f.finding.id === target.id);
    expect(j?.verdict).toBe("deny");
    expect(j?.violations.map((v) => v.code)).toContain("devsec.exception_expired");
  });
});
