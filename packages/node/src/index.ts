import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { closeSync, existsSync, openSync, watch as fsWatch } from "node:fs";
import { appendFile, copyFile, mkdir, readdir, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, toolsLayout, type Emit, type Exec, type Fs, type InfraDeps, type SetupDeps, type StartDetached, type UiDeps } from "@devsec/core";

/**
 * Node.js implementations of core's infrastructure ports, shared by every app.
 * Infrastructure only: apps bind these into core functions by partial application.
 */

/** The managed toolchain directory: $DEVSEC_TOOLS, else ~/.devsec/tools. */
export const toolsDir = (): string => process.env["DEVSEC_TOOLS"] ?? join(homedir(), ".devsec", "tools");

/** PATH with the managed tools first: devsec prefers its pinned tools and falls back to the user's. */
const toolPath = (): string => [toolsLayout(toolsDir()).bin, process.env["PATH"] ?? ""].join(delimiter);

export const exec: Exec = (c) =>
  new Promise((resolve) => {
    const env = { ...process.env, PATH: toolPath(), ...c.env };
    const child = spawn(c.cmd, [...c.args], { cwd: c.cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const errOut: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => errOut.push(d));
    child.on("error", (e: NodeJS.ErrnoException) => resolve({ code: e.code === "ENOENT" ? 127 : 126, stdout: "", stderr: e.message }));
    child.on("close", (code) =>
      resolve({ code: code ?? 1, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(errOut).toString("utf8") }),
    );
  });

const missing = (e: unknown) => (e as NodeJS.ErrnoException).code === "ENOENT";

export const fs: Fs = {
  readText: (p) => readFile(p, "utf8").catch((e) => (missing(e) ? undefined : Promise.reject(e))),
  writeText: async (p, d) => {
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, d);
  },
  appendText: async (p, d) => {
    await mkdir(dirname(p), { recursive: true });
    await appendFile(p, d);
  },
  mkdir: async (p) => void (await mkdir(p, { recursive: true })),
  rm: (p) => rm(p, { recursive: true, force: true }),
  exists: (p) => stat(p).then(() => true, () => false),
  readdir: (p) => readdir(p),
  copyFile: async (a, b) => {
    await mkdir(dirname(b), { recursive: true });
    await copyFile(a, b);
  },
  symlink: async (target, p) => {
    await unlink(p).catch(() => {});
    await symlink(target, p);
  },
};

export const silent: Emit = () => {};

/** Bind the Node implementations, with an app-specific `emit`. */
export const nodeDeps = (emit: Emit = silent): InfraDeps => ({ exec, fs, emit, now: Date.now });

/**
 * Watch a directory tree; `onChange` receives the changed path (relative to `dir`).
 * If `dir` does not exist yet, watches its closest existing ancestor until it appears.
 * Returns a function that stops watching.
 */
export const watchTree = (dir: string, onChange: (relativePath: string) => void): (() => void) => {
  let stopped = false;
  let close = () => {};
  const start = () => {
    if (stopped) return;
    try {
      const w = fsWatch(dir, { recursive: true }, (_event, file) => onChange(file?.toString() ?? ""));
      w.on("error", () => {
        w.close();
        setTimeout(start, 500);
      });
      close = () => w.close();
    } catch {
      // Not there yet: wait for the parent to change, then retry.
      try {
        const parent = fsWatch(dirname(dir), () => {
          parent.close();
          start();
        });
        close = () => parent.close();
      } catch {
        const t = setTimeout(start, 1000);
        close = () => clearTimeout(t);
      }
    }
  };
  start();
  return () => {
    stopped = true;
    close();
  };
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Spawn detached with output to `logFile`; resolve when `ready` appears in the log. */
export const startDetached: StartDetached = async (c, { logFile, ready, timeoutMs }) => {
  await mkdir(dirname(logFile), { recursive: true });
  const fd = openSync(logFile, "a");
  let exited: number | null | undefined;
  const child = spawn(c.cmd, [...c.args], { cwd: c.cwd, env: { ...process.env, PATH: toolPath(), ...c.env }, detached: true, stdio: ["ignore", fd, fd] });
  closeSync(fd);
  child.on("exit", (code) => (exited = code));
  child.on("error", () => (exited = 127));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const log = (await fs.readText(logFile)) ?? "";
    const match = ready.exec(log);
    if (match && child.pid !== undefined) {
      child.unref();
      return ok({ pid: child.pid, match: match[0] });
    }
    if (exited !== undefined) return err(`${c.cmd} exited with ${exited}: ${log.trim().split("\n").slice(-3).join(" | ")}`);
    await sleep(100);
  }
  child.kill();
  return err(`${c.cmd} did not become ready within ${timeoutMs}ms (log: ${logFile})`);
};

/** Ask a running devsec UI which repository it serves. */
export const probe = async (url: string): Promise<string | undefined> => {
  try {
    const res = await fetch(`${url}/api/repo`, { signal: AbortSignal.timeout(1000) });
    const body = (await res.json()) as { root?: unknown };
    return typeof body.root === "string" ? body.root : undefined;
  } catch {
    return undefined;
  }
};

export const kill = async (pid: number): Promise<void> => {
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // already gone
  }
};

export const openUrl = async (url: string): Promise<void> => {
  const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "explorer" : "xdg-open";
  spawn(opener, [url], { stdio: "ignore", detached: true }).unref();
};

/**
 * How to launch the UI: `DEVSEC_UI_BIN`, else the local workspace build.
 * No npx fallback until @devsec/ui is published under a name we own: `npx --yes` of an
 * unclaimed package name would run whatever someone else publishes there.
 */
export const uiRunner = (): readonly [string, ...string[]] | undefined => {
  const override = process.env["DEVSEC_UI_BIN"];
  if (override) return ["node", override];
  const local = fileURLToPath(new URL("../../../apps/ui/dist/cli.js", import.meta.url));
  return existsSync(local) ? ["node", local] : undefined;
};

/** Infra deps for the `ui` workflow. */
export const nodeUiDeps = (emit: Emit = silent): UiDeps => ({
  ...nodeDeps(emit),
  uiRunner: uiRunner(),
  startDetached,
  probe,
  kill,
  openUrl,
});

/** Infra deps for `devsec setup`. */
export const nodeSetupDeps = (log: (message: string) => void = () => {}): SetupDeps => ({
  exec,
  fs,
  fetchBytes: async (url) => {
    const res = await fetch(url, { redirect: "follow" });
    if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText} (${url})`);
    return new Uint8Array(await res.arrayBuffer());
  },
  sha256: (bytes) => createHash("sha256").update(bytes).digest("hex"),
  writeBytes: async (path, bytes) => {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  },
  log,
});
