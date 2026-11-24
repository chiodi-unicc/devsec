import { configFile, parseConfig } from "../domain/config.js";
import type { DevsecError } from "../domain/errors.js";
import type { Finding } from "../domain/finding.js";
import { arr, isRecord, num, rec, str, type Json } from "../fp/decode.js";
import { err, ok, type Result } from "../fp/result.js";
import { conftestCommand, parseConftest, policyData, policyInput } from "../policy/conftest.js";
import { defaultPolicyFiles } from "../policy/default-policy.js";
import { agentReport } from "../report/json.js";
import { filterSarif, mergeSarif, sarifLocation } from "../report/sarif.js";
import * as g from "../subject/git.js";
import { projectSemgrep, semgrepCommand, semgrepKey, semgrepRawJson, semgrepRawSarif, semgrepResultPaths } from "../tools/semgrep.js";
import { sbomCycloneDx, syftCommand } from "../tools/syft.js";
import {
  filterTrivyReport,
  projectTrivySecrets,
  projectTrivyVulns,
  trivyConvertCommand,
  trivyScaCommand,
  trivyScaRaw,
  trivySecretsCommand,
  trivySecretsRaw,
} from "../tools/trivy.js";
import { parseVersion, requiredTools, versionCommand, type ToolName, type ToolVersions } from "../tools/versions.js";
import { devsecGitignore, workspaceLayout } from "../workspace/layout.js";
import { parseJsonText, runTool, toJson } from "./run-tool.js";
import type { ScanSteps, Versions } from "./types.js";

const line = (s: string) => s.trim();

const versions: ScanSteps["versions"] = (deps) => async ({ cwd }) => {
  const results = await Promise.all(
    requiredTools.map(async (tool) => [tool, await deps.exec(versionCommand(tool, cwd))] as const),
  );
  const found: Record<string, string> = {};
  const missing: ToolName[] = [];
  for (const [tool, out] of results) {
    if (out.code !== 0) {
      missing.push(tool);
      continue;
    }
    const v = parseVersion(tool, out.stdout);
    found[tool] = v.version;
    if (v.trivyDb) found["trivyDb"] = v.trivyDb;
  }
  return ok<Versions>({ found: found as Partial<ToolVersions>, missing });
};

/** Pin the subject to a git tree. Also ensures .devsec exists and ignores itself. */
const subject: ScanSteps["subject"] = (deps) => async ({ cwd, ref }) => {
  const run = runTool(deps);
  const top = await run(g.gitToplevel(cwd));
  if (!top.ok) return top.error.type === "tool-missing" ? top : err({ type: "not-a-repo", path: cwd });
  const repoRoot = line(top.value.stdout);
  const layout = workspaceLayout(repoRoot);
  await deps.fs.mkdir(layout.tmp);
  await deps.fs.writeText(layout.gitignore, devsecGitignore);

  const head = await deps.exec(g.gitHead(repoRoot));
  const headSha = head.code === 0 ? line(head.stdout) : undefined;

  if (ref !== undefined) {
    const tree = await run(g.gitRefTree(repoRoot, ref));
    if (!tree.ok) return tree.error.type === "tool-missing" ? tree : err({ type: "bad-ref", ref, noCommits: headSha === undefined });
    const commit = await deps.exec(g.gitRefCommit(repoRoot, ref));
    return ok({
      repoRoot,
      treeSha: line(tree.value.stdout),
      ...(commit.code === 0 ? { headSha: line(commit.stdout) } : {}),
      dirty: false,
      ref,
    });
  }

  // Working tree: copy the real index (keeps git's stat cache, so this is fast), stage everything into the copy.
  const index = layout.subjectIndex;
  await deps.fs.rm(index);
  const realIndex = await run(g.gitIndexPath(repoRoot));
  if (realIndex.ok && (await deps.fs.exists(line(realIndex.value.stdout)))) {
    await deps.fs.copyFile(line(realIndex.value.stdout), index);
  }
  const added = await run(g.gitAddAll(repoRoot, index));
  if (!added.ok) return added;
  const tree = await run(g.gitWriteTree(repoRoot, index));
  if (!tree.ok) return tree;
  const treeSha = line(tree.value.stdout);
  const headTree = await deps.exec(g.gitHeadTree(repoRoot));
  return ok({
    repoRoot,
    treeSha,
    ...(headSha ? { headSha } : {}),
    dirty: headTree.code !== 0 || line(headTree.stdout) !== treeSha,
  });
};

const config: ScanSteps["config"] = (deps) => async ({ repoRoot }) => {
  const text = await deps.fs.readText(`${repoRoot}/${configFile}`);
  if (text === undefined) return parseConfig(undefined) as Result<never, never>;
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e) {
    return err({ type: "bad-config", detail: `${configFile} is not valid JSON: ${String(e)}` });
  }
  const parsed = parseConfig(json);
  return parsed.ok ? parsed : err({ type: "bad-config", detail: parsed.error });
};

const scanMeta = (dir: string) => `${dir}/scan.json`;

/** Reuse a complete earlier scan with the same key, within the TTL. */
const cache: ScanSteps["cache"] = (deps) => async ({ run, key, ttlHours }) => {
  const meta = rec(safeJson(await deps.fs.readText(scanMeta(run.dir))));
  const scannedAt = num(meta["scannedAt"]);
  if (meta["key"] !== key || meta["complete"] !== true || scannedAt === undefined) return ok(undefined);
  if (deps.now() - scannedAt > ttlHours * 3_600_000) return ok(undefined);
  const findings = safeJson(await deps.fs.readText(run.findings));
  return ok(Array.isArray(findings) ? { findings: findings as Finding[] } : undefined);
};

const safeJson = (text: string | undefined): unknown => {
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

const saveScan: ScanSteps["saveScan"] = (deps) => async ({ run, key, findings, complete }) => {
  await deps.fs.writeText(run.findings, toJson(findings));
  await deps.fs.writeText(scanMeta(run.dir), toJson({ key, complete, scannedAt: deps.now() }));
  return ok(undefined);
};

/** Materialise the tree with git's own checkout. Reused when already complete. */
const snapshot: ScanSteps["snapshot"] = (deps) => async ({ subject: s, layout }) => {
  const dir = layout.snapshot(s.treeSha);
  const done = `${dir}.done`;
  if (await deps.fs.exists(done)) return ok(dir);
  const run = runTool(deps);
  const index = layout.snapshotIndex(s.treeSha);
  await deps.fs.rm(dir);
  await deps.fs.rm(index);
  const read = await run(g.gitReadTree(s.repoRoot, index, s.treeSha));
  if (!read.ok) return read;
  const prefix = `${dir.slice(s.repoRoot.length + 1)}/`;
  const checkout = await run(g.gitCheckoutIndex(s.repoRoot, index, prefix));
  if (!checkout.ok) return checkout;
  await deps.fs.mkdir(dir); // an empty tree checks out nothing
  await deps.fs.rm(index);
  await deps.fs.writeText(done, `${deps.now()}\n`);
  return ok(dir);
};

const sbom: ScanSteps["sbom"] = (deps) => async ({ snapshot: cwd, run }) => {
  await deps.fs.mkdir(run.sbomDir);
  const out = await runTool(deps)(syftCommand({ cwd, outDir: run.sbomDir }));
  return out.ok ? ok(`${run.sbomDir}/${sbomCycloneDx}`) : out;
};

const project =
  (tool: string, projection: (json: unknown) => Result<Finding[], string>) =>
  (text: string | undefined): Result<Finding[], DevsecError> => {
    const json = parseJsonText(tool, text);
    if (!json.ok) return json;
    const r = projection(json.value);
    return r.ok ? r : err({ type: "bad-output", tool, detail: r.error });
  };

const semgrep: ScanSteps["semgrep"] = (deps) => async ({ snapshot: cwd, run, rulesets }) => {
  await deps.fs.mkdir(run.raw);
  // semgrep exits 0 with findings (no --error); 1 is only used with --error, 2+ are failures.
  const out = await runTool(deps)(semgrepCommand({ cwd, rulesets, rawDir: run.raw }), [0, 1]);
  if (!out.ok) {
    // With --quiet, semgrep reports fatal errors only in its JSON output's errors[].
    const reported = semgrepErrors(safeJson(await deps.fs.readText(`${run.raw}/${semgrepRawJson}`)));
    return out.error.type === "tool-failed" && reported ? err({ ...out.error, stderr: reported }) : out;
  }
  const text = await deps.fs.readText(`${run.raw}/${semgrepRawJson}`);
  const json = parseJsonText("semgrep", text);
  if (!json.ok) return json;
  // Matched files' text from the snapshot, for line-independent finding ids.
  const paths = semgrepResultPaths(json.value);
  const sources = new Map(await Promise.all(paths.map(async (p) => [p, await deps.fs.readText(`${cwd}/${p}`)] as const)));
  const r = projectSemgrep(json.value, (p) => sources.get(p));
  return r.ok ? r : err({ type: "bad-output", tool: "semgrep", detail: r.error });
};

const semgrepErrors = (json: unknown): string | undefined => {
  const messages = arr(rec(json)["errors"]).flatMap((e) => {
    const m = str(rec(e)["message"]);
    return m ? [m] : [];
  });
  return messages.length > 0 ? messages.join("\n") : undefined;
};

const trivySecrets: ScanSteps["trivySecrets"] = (deps) => async ({ snapshot: cwd, run }) => {
  await deps.fs.mkdir(run.raw);
  const out = await runTool(deps)(trivySecretsCommand({ cwd, rawDir: run.raw }));
  if (!out.ok) return out;
  return project("trivy", projectTrivySecrets)(await deps.fs.readText(`${run.raw}/${trivySecretsRaw}`));
};

const trivySca: ScanSteps["trivySca"] = (deps) => async ({ snapshot: cwd, run, sbom: sbomPath }) => {
  await deps.fs.mkdir(run.raw);
  const out = await runTool(deps)(trivyScaCommand({ cwd, rawDir: run.raw, sbom: sbomPath }));
  if (!out.ok) return out;
  return project("trivy", projectTrivyVulns)(await deps.fs.readText(`${run.raw}/${trivyScaRaw}`));
};

const policy: ScanSteps["policy"] = (deps) => async ({ subject: s, findings, config: c, layout, run, partial }) => {
  const policyDir = c.policy ? `${s.repoRoot}/${c.policy}` : layout.defaultPolicy;
  if (!c.policy) {
    for (const [file, src] of Object.entries(defaultPolicyFiles)) await deps.fs.writeText(`${policyDir}/${file}`, src);
  } else if (!(await deps.fs.exists(policyDir))) {
    return err({ type: "bad-config", detail: `policy directory not found: ${c.policy}` });
  }
  await deps.fs.writeText(run.policyInput, toJson(policyInput(s, findings, partial)));
  await deps.fs.writeText(run.policyData, toJson(policyData(c.exceptions)));
  // conftest: 0 = pass, 1 = failures, 2 = warnings with --fail-on-warn (unused); anything else is an error.
  const out = await runTool(deps)(
    conftestCommand({ cwd: run.dir, policyDir, dataFile: run.policyData, inputFile: run.policyInput }),
    [0, 1],
  );
  if (!out.ok) return out;
  const parsed = parseConftest(out.value.stdout);
  if (!parsed.ok) return err({ type: "bad-output", tool: "conftest", detail: parsed.error });
  await deps.fs.writeText(run.policyResult, out.value.stdout);
  return parsed;
};

const semgrepSarifKey = (r: Json) => semgrepKey(str(r["ruleId"]) ?? "", sarifLocation(r));

/** Report = agent JSON + SARIF made of each tool's own SARIF, keeping only flagged results. */
const report: ScanSteps["report"] = (deps) => async ({ subject: s, runId, run, scanners, judgement, errors, failOn, baseline }) => {
  const result = agentReport({ subject: s, runId, runDir: run.dir, scanners, judgement, errors, failOn, ...(baseline ? { baseline } : {}) });
  await deps.fs.writeText(run.reportJson, toJson(result));

  const flagged = judgement.flagged.map((j) => j.finding);
  const logs: Json[] = [];
  const semgrepSarif = safeJson(await deps.fs.readText(`${run.raw}/${semgrepRawSarif}`));
  if (isRecord(semgrepSarif)) {
    const keep = new Set(flagged.filter((f) => f.scanner === "semgrep").map((f) => semgrepKey(f.rule, f.location)));
    logs.push(filterSarif(semgrepSarifKey)(keep)(semgrepSarif));
  }
  for (const raw of [trivySecretsRaw, trivyScaRaw]) {
    const json = safeJson(await deps.fs.readText(`${run.raw}/${raw}`));
    if (!isRecord(json)) continue;
    const keep = new Set(flagged.filter((f) => f.raw.file === raw).map((f) => f.raw.pointer));
    const filteredJson = `${run.filteredDir}/${raw}`;
    const filteredSarif = filteredJson.replace(/\.json$/, ".sarif");
    await deps.fs.writeText(filteredJson, toJson(filterTrivyReport(keep)(json)));
    const out = await runTool(deps)(trivyConvertCommand({ cwd: run.dir, input: filteredJson, output: filteredSarif }));
    if (!out.ok) return out;
    const sarif = safeJson(await deps.fs.readText(filteredSarif));
    if (isRecord(sarif)) logs.push(sarif);
  }
  await deps.fs.writeText(run.reportSarif, toJson(mergeSarif(logs)));
  return ok(result);
};

export const scanSteps: ScanSteps = {
  versions,
  subject,
  config,
  cache,
  snapshot,
  sbom,
  semgrep,
  trivySecrets,
  trivySca,
  saveScan,
  policy,
  report,
};
