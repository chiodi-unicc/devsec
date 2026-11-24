import type { Command } from "../domain/command.js";
import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { err, ok, type Result } from "../fp/result.js";
import { parseVersion } from "../tools/versions.js";
import { binaryTools, platformOf, semgrepTool, toolsLayout, type BinaryTool } from "./toolchain.js";

export type SetupDeps = Pick<InfraDeps, "exec" | "fs"> & {
  readonly fetchBytes: (url: string) => Promise<Uint8Array>;
  readonly sha256: (bytes: Uint8Array) => string;
  readonly writeBytes: (path: string, bytes: Uint8Array) => Promise<void>;
  readonly log: (message: string) => void;
};

export type SetupArgs = {
  /** Managed toolchain directory, e.g. ~/.devsec/tools. */
  readonly toolsDir: string;
  /** Operating system and CPU architecture, e.g. "darwin" + "arm64" (supplied by the app). */
  readonly os: string;
  readonly arch: string;
  /** Reinstall even when the pinned version is already present. */
  readonly force?: boolean;
  /** Skip pre-downloading Trivy's vulnerability database. */
  readonly skipDb?: boolean;
};

export type ToolOutcome = { readonly tool: string; readonly version: string; readonly status: "installed" | "present"; readonly path: string };
export type SetupResult = { readonly tools: readonly ToolOutcome[]; readonly trivyDb: "downloaded" | "skipped"; readonly bin: string };

const fail = (tool: string, detail: string): DevsecError => ({ type: "tool-failed", tool, code: 1, stderr: detail });

/** Version reported by a binary at `path`, or undefined. */
const installedVersion = async (deps: SetupDeps, tool: "trivy" | "syft" | "conftest" | "semgrep", path: string, cwd: string) => {
  if (!(await deps.fs.exists(path))) return undefined;
  const args = tool === "trivy" ? ["version", "--format", "json"] : tool === "syft" ? ["version", "--output", "json"] : ["--version"];
  const out = await deps.exec({ cmd: path, args, cwd });
  return out.code === 0 ? parseVersion(tool, out.stdout).version : undefined;
};

const run = async (deps: SetupDeps, tool: string, c: Command): Promise<Result<string, DevsecError>> => {
  const out = await deps.exec(c);
  return out.code === 0 ? ok(out.stdout) : err(fail(tool, out.stderr || out.stdout || `exit ${out.code}`));
};

const installBinary =
  (deps: SetupDeps, args: SetupArgs) =>
  async (tool: BinaryTool): Promise<Result<ToolOutcome, DevsecError>> => {
    const layout = toolsLayout(args.toolsDir);
    const target = layout.binary(tool.name);
    if (!args.force && (await installedVersion(deps, tool.name, target, args.toolsDir)) === tool.version) {
      return ok({ tool: tool.name, version: tool.version, status: "present", path: target });
    }
    const platform = platformOf(args.os, args.arch);
    if (!platform) return err(fail(tool.name, `unsupported platform ${args.os}-${args.arch}`));
    const asset = tool.assets[platform];
    deps.log(`downloading ${tool.name} ${tool.version} (${asset.file})`);
    const bytes = await deps.fetchBytes(tool.url(asset.file));
    const digest = deps.sha256(bytes);
    if (digest !== asset.sha256) {
      return err(fail(tool.name, `checksum mismatch for ${asset.file}: expected ${asset.sha256}, got ${digest}. Not installed.`));
    }
    const archive = `${layout.downloads}/${asset.file}`;
    const extractDir = `${layout.downloads}/${tool.name}-${tool.version}`;
    await deps.fs.rm(extractDir);
    await deps.fs.mkdir(extractDir);
    await deps.fs.mkdir(layout.bin);
    await deps.writeBytes(archive, bytes);
    const extracted = await run(deps, tool.name, { cmd: "tar", args: ["-xzf", archive, "-C", extractDir, tool.name], cwd: args.toolsDir });
    if (!extracted.ok) return extracted;
    const moved = await run(deps, tool.name, { cmd: "mv", args: ["-f", `${extractDir}/${tool.name}`, target], cwd: args.toolsDir });
    if (!moved.ok) return moved;
    await deps.fs.rm(extractDir);
    await deps.fs.rm(archive);
    const version = await installedVersion(deps, tool.name, target, args.toolsDir);
    if (version !== tool.version) return err(fail(tool.name, `installed binary reports version ${version ?? "none"}, expected ${tool.version}`));
    deps.log(`installed ${tool.name} ${version} (sha256 verified)`);
    return ok({ tool: tool.name, version, status: "installed", path: target });
  };

/** Pure: "Python 3.12.4" → [3, 12]. */
export const pythonVersion = (text: string): readonly [number, number] | undefined => {
  const m = /Python (\d+)\.(\d+)/.exec(text);
  return m ? [Number(m[1]), Number(m[2])] : undefined;
};

const installSemgrep = async (deps: SetupDeps, args: SetupArgs): Promise<Result<ToolOutcome, DevsecError>> => {
  const layout = toolsLayout(args.toolsDir);
  const target = layout.binary("semgrep");
  if (!args.force && (await installedVersion(deps, "semgrep", target, args.toolsDir)) === semgrepTool.version) {
    return ok({ tool: "semgrep", version: semgrepTool.version, status: "present", path: target });
  }
  const py = await deps.exec({ cmd: "python3", args: ["--version"], cwd: args.toolsDir });
  const v = pythonVersion(`${py.stdout}${py.stderr}`);
  const [maj, min] = semgrepTool.minPython;
  if (py.code !== 0 || !v || v[0] < maj || (v[0] === maj && v[1] < min)) {
    return err(fail("semgrep", `needs python3 >= ${maj}.${min} on PATH to install semgrep (found: ${v ? v.join(".") : "none"})`));
  }
  deps.log(`installing semgrep ${semgrepTool.version} into ${layout.semgrepVenv} (Python ${v.join(".")})`);
  await deps.fs.rm(layout.semgrepVenv);
  const venv = await run(deps, "semgrep", { cmd: "python3", args: ["-m", "venv", layout.semgrepVenv], cwd: args.toolsDir });
  if (!venv.ok) return venv;
  const pip = await run(deps, "semgrep", {
    cmd: `${layout.semgrepVenv}/bin/pip`,
    args: ["install", "--quiet", "--disable-pip-version-check", `semgrep==${semgrepTool.version}`],
    cwd: args.toolsDir,
  });
  if (!pip.ok) return pip;
  await deps.fs.mkdir(layout.bin);
  await deps.fs.symlink(`${layout.semgrepVenv}/bin/semgrep`, target);
  const version = await installedVersion(deps, "semgrep", target, args.toolsDir);
  if (version !== semgrepTool.version) return err(fail("semgrep", `installed semgrep reports ${version ?? "nothing"}`));
  deps.log(`installed semgrep ${version}`);
  return ok({ tool: "semgrep", version, status: "installed", path: target });
};

export type SetupSteps = {
  readonly binary: (deps: SetupDeps, args: SetupArgs) => (tool: BinaryTool) => Promise<Result<ToolOutcome, DevsecError>>;
  readonly semgrep: (deps: SetupDeps, args: SetupArgs) => Promise<Result<ToolOutcome, DevsecError>>;
};

/** Install the pinned toolchain into args.toolsDir (binaries verified against pinned SHA-256). */
export const setupWith =
  (steps: SetupSteps) =>
  (deps: SetupDeps) =>
  async (args: SetupArgs): Promise<Result<SetupResult, DevsecError>> => {
    const layout = toolsLayout(args.toolsDir);
    await deps.fs.mkdir(layout.bin);
    const results = await Promise.all([...binaryTools.map(steps.binary(deps, args)), steps.semgrep(deps, args)]);
    const tools: ToolOutcome[] = [];
    for (const r of results) {
      if (!r.ok) return r;
      tools.push(r.value);
    }
    if (args.skipDb) return ok({ tools, trivyDb: "skipped", bin: layout.bin });
    deps.log("downloading the Trivy vulnerability database");
    const db = await run(deps, "trivy", { cmd: layout.binary("trivy"), args: ["fs", "--quiet", "--download-db-only"], cwd: args.toolsDir });
    if (!db.ok) return db;
    return ok({ tools, trivyDb: "downloaded", bin: layout.bin });
  };

export const setup = setupWith({ binary: installBinary, semgrep: installSemgrep });
