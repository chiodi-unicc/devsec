#!/usr/bin/env node
import { FastMCP, UserError } from "fastmcp";
import { z } from "zod";
import { agentView, describeError, doctor, finding, findings, name, scan, scannerIds, setup, ui, type DevsecError, type Result } from "@devsec/core";
import { nodeDeps as deps, nodeSetupDeps, nodeUiDeps, toolsDir } from "@devsec/node";
import { progressEmitter } from "./progress.js";

// Runtime shell: bind deps, expose core functions as MCP tools. No domain logic here.

const server = new FastMCP({
  name,
  version: "0.0.0",
  instructions:
    "devsec runs local security scans (semgrep, trivy secrets, trivy SCA from a syft SBOM) on the git working tree " +
    "and returns only the findings the policy flags. Workflow: call devsec_scan after changing code. With uncommitted " +
    "changes, findings marked new are the ones your changes introduced (baseline: HEAD); fix new 'deny' findings first. " +
    "The scan result is compact: use devsec_findings to page or filter the rest (its `next` field is the follow-up call), " +
    "and devsec_finding for one finding's full detail including the scanner's raw result. If tools are missing or " +
    "versions differ (devsec_doctor), devsec_setup installs the pinned toolchain. devsec_ui opens a live view for the user. " +
    "In every tool, `path` is the repository directory (default: the server's working directory).",
});

const path = z.string().optional().describe("Directory inside the git repository to scan (default: the server's working directory)");
const cwdOf = (p: string | undefined) => p ?? process.cwd();

const unwrap = <T>(r: Result<T, DevsecError>): T => {
  if (!r.ok) throw new UserError(describeError(r.error));
  return r.value;
};

const json = (v: unknown) => JSON.stringify(v);

server.addTool({
  name: "devsec_scan",
  description:
    "Scan the working tree (or a commit with `ref`) and return a compact result: status pass|fail|error, summary " +
    "(one line; with a baseline it also states the existing findings that did not count), runId, existing, " +
    "counts (found = flagged + dropped; new = flagged findings the baseline did not have), byRule (one line per rule), " +
    "and up to `limit` findings (verdict deny|warn, severity, rule, path:line or package, fix, new). " +
    "With uncommitted changes the baseline defaults to HEAD, so findings marked new are the ones your changes introduced, " +
    "and only new deny findings fail the scan. Use devsec_findings to page through the rest (`next` shows the call). " +
    "Full reports and raw tool output are written under .devsec/runs/<id>/.",
  parameters: z.object({
    path,
    ref: z.string().optional().describe("Commit-ish to scan instead of the working tree"),
    scanners: z.array(z.enum(scannerIds)).optional().describe("Restrict to these scanners"),
    baseline: z.string().optional().describe('Ref whose findings count as existing (e.g. "origin/main"), or "none"'),
    scope: z.enum(["new", "all"]).optional().describe("Findings to list: new only (default with a baseline) or all flagged"),
    limit: z.number().int().min(0).max(200).optional().describe("Findings to include (default 20)"),
  }),
  annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false },
  execute: async (args, ctx) => {
    const r = unwrap(
      await scan(deps(progressEmitter(ctx.reportProgress)))({
        cwd: cwdOf(args.path),
        ...(args.ref !== undefined ? { ref: args.ref } : {}),
        ...(args.scanners ? { scanners: args.scanners } : {}),
        ...(args.baseline !== undefined ? { baseline: args.baseline } : {}),
      }),
    );
    return json(agentView(r.report, { ...(args.scope ? { scope: args.scope } : {}), ...(args.limit !== undefined ? { limit: args.limit } : {}) }));
  },
});

server.addTool({
  name: "devsec_finding",
  description:
    "Full detail of one finding, including the scanning tool's own result object. Looks in the latest full scan " +
    "unless `run` is given (use the runId from the devsec_scan result, e.g. after a partial scan).",
  parameters: z.object({
    id: z.string().min(4).describe("Finding id (or unique prefix) from devsec_scan"),
    run: z.string().optional().describe("runId from devsec_scan (default: latest full scan)"),
    path,
  }),
  annotations: { readOnlyHint: true },
  execute: async (args) =>
    json(unwrap(await finding(deps())({ cwd: cwdOf(args.path), id: args.id, ...(args.run !== undefined ? { runId: args.run } : {}) }))),
});

server.addTool({
  name: "devsec_findings",
  description: "Page through and filter the flagged findings of a scan (default: the latest full scan).",
  parameters: z.object({
    run: z.string().optional().describe("runId from devsec_scan"),
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(1).max(200).optional().describe("Default 20"),
    verdict: z.enum(["deny", "warn"]).optional(),
    rule: z.string().optional().describe("Substring of the rule id"),
    file: z.string().optional().describe("Repository-relative file path prefix, e.g. src/api/"),
    new: z.boolean().optional().describe("Only findings the baseline did not have"),
    path,
  }),
  annotations: { readOnlyHint: true },
  execute: async ({ run, path: repo, ...query }) =>
    json(
      unwrap(
        await findings(deps())({
          cwd: cwdOf(repo),
          ...(run !== undefined ? { runId: run } : {}),
          ...Object.fromEntries(Object.entries(query).filter(([, v]) => v !== undefined)),
        }),
      ),
    ),
});

server.addTool({
  name: "devsec_setup",
  description:
    "Install devsec's pinned toolchain (trivy, syft, conftest: downloaded and SHA-256 verified; semgrep: in its own Python venv) " +
    "into ~/.devsec/tools, and pre-download the Trivy vulnerability database. Takes about a minute the first time; " +
    "use when devsec_doctor reports missing tools or versions that differ.",
  parameters: z.object({ force: z.boolean().optional().describe("Reinstall even if present") }),
  annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: true },
  execute: async (args, ctx) =>
    json(
      unwrap(
        await setup(nodeSetupDeps((m) => ctx.log.info(m)))({
          toolsDir: toolsDir(),
          os: process.platform,
          arch: process.arch,
          force: args.force ?? false,
        }),
      ),
    ),
});

server.addTool({
  name: "devsec_doctor",
  description: "Check that the required tools (git, syft, semgrep, trivy, conftest) are installed, with versions.",
  parameters: z.object({ path }),
  annotations: { readOnlyHint: true },
  execute: async (args) => json(unwrap(await doctor(deps())({ cwd: cwdOf(args.path) }))),
});

server.addTool({
  name: "devsec_ui",
  description:
    "Start the live devsec UI for the repository in the background (or reuse the one already running) and return its URL. " +
    "It shows scans progressing, their findings and the policy, updating as scans run. Use stop: true to shut it down.",
  parameters: z.object({
    path,
    open: z.boolean().optional().describe("Open it in the user's browser (default true)"),
    port: z.number().int().min(1).max(65535).optional().describe("Preferred port (default 4321)"),
    stop: z.boolean().optional().describe("Stop the UI instead of starting it"),
  }),
  annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false },
  execute: async (args) =>
    json(
      unwrap(
        await ui(nodeUiDeps())({
          cwd: cwdOf(args.path),
          open: args.open ?? true,
          stop: args.stop ?? false,
          ...(args.port !== undefined ? { port: args.port } : {}),
        }),
      ),
    ),
});

await server.start({ transportType: "stdio" });
