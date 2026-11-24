#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { agentView, clean, describeError, doctor, finding, findings, init, name, scan, scannerIds, setup, ui, type ScannerId } from "@devsec/core";
import { nodeDeps as deps, nodeSetupDeps, nodeUiDeps, silent, toolsDir } from "@devsec/node";
import { stderrProgress } from "./progress.js";

// Runtime shell: parse argv, bind deps, call core, print, set exit code. No domain logic here.

const usage = `usage: ${name} <command> [options]

commands:
  scan                 scan the working tree (or --ref), print policy-flagged findings
    --ref <commit>       scan a commit instead of the working tree
    --format json|sarif  stdout format (default json); both are written to .devsec/runs/<id>/
    --only <a,b>         scanners: ${scannerIds.join(", ")}
    --baseline <ref>     findings in <ref> count as existing; "none" to disable
                         (default: devsec.json "baseline", else HEAD when there are uncommitted changes)
    --limit <n>          findings to print (default 20; the rest: devsec findings)
    --all                print all flagged findings, not only new ones
    --full               print the complete report instead of the compact view
    --quiet              no progress on stderr
  findings             page through flagged findings of a run
    --offset <n> --limit <n> --verdict deny|warn --rule <text> --file <path prefix> --new
    --run <runId>        a specific run (default: latest full scan)
  finding <id>         full detail of a finding (tool's raw result included)
    --run <runId>        look in this run instead of the latest full scan
  doctor               check required tools (path, version vs pinned)
  setup                install the pinned toolchain into ~/.devsec/tools ($DEVSEC_TOOLS)
    --force              reinstall even if present
    --no-db              skip downloading the Trivy vulnerability database
  init                 write devsec.json and a customisable copy of the default policy
  clean [--all]        remove snapshots and temp files (--all: the whole .devsec)
  ui                   start the live UI in the background (or reuse it) and open it
    --port <n>           preferred port (default 4321, next free one if taken)
    --no-open            don't open the browser
    --stop               stop the UI started for this repository

global:
  -C <dir>             run as if started in <dir>
  -h, --help

exit codes: 0 pass, 1 policy failed, 2 error`;

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    help: { type: "boolean", short: "h" },
    C: { type: "string", short: "C" },
    ref: { type: "string" },
    format: { type: "string", default: "json" },
    only: { type: "string" },
    quiet: { type: "boolean" },
    all: { type: "boolean" },
    port: { type: "string" },
    open: { type: "boolean", default: true },
    stop: { type: "boolean" },
    force: { type: "boolean" },
    db: { type: "boolean", default: true },
    run: { type: "string" },
    baseline: { type: "string" },
    limit: { type: "string" },
    offset: { type: "string" },
    full: { type: "boolean" },
    verdict: { type: "string" },
    rule: { type: "string" },
    file: { type: "string" },
    new: { type: "boolean" },
  },
  allowNegative: true,
});

const cwd = values.C ?? process.cwd();
const print = (v: unknown) => process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
const fail = (msg: string, code = 2): number => {
  process.stderr.write(`${name}: ${msg}\n`);
  return code;
};

const parseScanners = (s: string | undefined): ScannerId[] | string | undefined => {
  if (s === undefined) return undefined;
  const list = s.split(",").map((x) => x.trim());
  const bad = list.find((x) => !(scannerIds as readonly string[]).includes(x));
  return bad ? `unknown scanner "${bad}"` : (list as ScannerId[]);
};

const commands: Record<string, () => Promise<number>> = {
  scan: async () => {
    if (values.format !== "json" && values.format !== "sarif") return fail(`--format must be json or sarif`);
    const scanners = parseScanners(values.only);
    if (typeof scanners === "string") return fail(scanners);
    const limit = values.limit === undefined ? undefined : Number(values.limit);
    if (limit !== undefined && !(Number.isInteger(limit) && limit >= 0)) return fail("--limit must be a non-negative number");
    const r = await scan(deps(values.quiet ? silent : stderrProgress))({
      cwd,
      ...(values.ref !== undefined ? { ref: values.ref } : {}),
      ...(scanners ? { scanners } : {}),
      ...(values.baseline !== undefined ? { baseline: values.baseline } : {}),
    });
    if (!r.ok) return fail(describeError(r.error));
    if (values.format === "sarif") process.stdout.write(await readFile(r.value.reportSarif, "utf8"));
    else if (values.full) print(r.value.report);
    else print(agentView(r.value.report, { ...(values.all ? { scope: "all" as const } : {}), ...(limit !== undefined ? { limit } : {}) }));
    return { pass: 0, fail: 1, error: 2 }[r.value.report.status];
  },
  finding: async () => {
    const id = positionals[1];
    if (!id) return fail("usage: devsec finding <id>");
    const r = await finding(deps())({ cwd, id, ...(values.run !== undefined ? { runId: values.run } : {}) });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return 0;
  },
  findings: async () => {
    const num = (v: string | undefined) => (v === undefined ? undefined : Number(v));
    if (values.verdict !== undefined && values.verdict !== "deny" && values.verdict !== "warn") return fail("--verdict must be deny or warn");
    const offset = num(values.offset);
    const limit = num(values.limit);
    const r = await findings(deps())({
      cwd,
      ...(values.run !== undefined ? { runId: values.run } : {}),
      ...(offset !== undefined ? { offset } : {}),
      ...(limit !== undefined ? { limit } : {}),
      ...(values.verdict !== undefined ? { verdict: values.verdict } : {}),
      ...(values.rule !== undefined ? { rule: values.rule } : {}),
      ...(values.file !== undefined ? { file: values.file } : {}),
      ...(values.new ? { new: true } : {}),
    });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return 0;
  },
  setup: async () => {
    const r = await setup(nodeSetupDeps((m) => process.stderr.write(`devsec setup: ${m}\n`)))({
      toolsDir: toolsDir(),
      os: process.platform,
      arch: process.arch,
      force: values.force ?? false,
      skipDb: values.db === false,
    });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return 0;
  },
  doctor: async () => {
    const r = await doctor(deps())({ cwd });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return r.value.ok ? 0 : 2;
  },
  init: async () => {
    const r = await init(deps())({ cwd });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return 0;
  },
  ui: async () => {
    const port = values.port === undefined ? undefined : Number(values.port);
    if (port !== undefined && !Number.isInteger(port)) return fail("--port must be a number");
    const r = await ui(nodeUiDeps())({ cwd, open: values.open ?? true, stop: values.stop ?? false, ...(port !== undefined ? { port } : {}) });
    if (!r.ok) return fail(describeError(r.error));
    print(r.value);
    return 0;
  },
  clean: async () => {
    const r = await clean(deps())({ cwd, all: values.all ?? false });
    if (!r.ok) return fail(describeError(r.error));
    print({ removed: r.value });
    return 0;
  },
};

const [command] = positionals;
const run = command ? commands[command] : undefined;
if (values.help || command === undefined) {
  console.log(usage);
} else if (!run) {
  process.exitCode = fail(`unknown command '${command}'\n${usage}`);
} else {
  process.exitCode = await run();
}
