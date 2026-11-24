import type { Command } from "../domain/command.js";
import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { num, rec, str } from "../fp/decode.js";
import { err, ok, type Result } from "../fp/result.js";
import { toJson } from "../scan/run-tool.js";
import { devsecGitignore, workspaceLayout } from "../workspace/layout.js";
import { repoRootOf } from "../workspace/repo.js";

/** Start a long-running command detached, logging to `logFile`; resolves once `ready` matches the log. */
export type StartDetached = (
  command: Command,
  options: { readonly logFile: string; readonly ready: RegExp; readonly timeoutMs: number },
) => Promise<Result<{ readonly pid: number; readonly match: string }, string>>;

/** The repository root a devsec UI at `url` serves, or undefined if nothing answers there. */
export type Probe = (url: string) => Promise<string | undefined>;

export type UiDeps = InfraDeps & {
  /** How to launch the UI server, e.g. [node, /…/devsec.js, "ui", "--serve"]; undefined when unavailable. */
  readonly uiRunner: readonly [string, ...string[]] | undefined;
  readonly startDetached: StartDetached;
  readonly probe: Probe;
  readonly kill: (pid: number) => Promise<void>;
  readonly openUrl: (url: string) => Promise<void>;
};

export type UiArgs = { readonly cwd: string; readonly port?: number; readonly open?: boolean; readonly stop?: boolean };

export type UiStatus =
  | { readonly status: "started" | "running"; readonly url: string; readonly pid: number; readonly log: string }
  | { readonly status: "stopped"; readonly pid: number }
  | { readonly status: "not-running" };

type UiState = { readonly pid: number; readonly url: string; readonly startedAt: number };

export const uiReady = /devsec-ui: (http:\/\/\S+)/;

/** Pure: the UI launch command (no --open: opening is done by the caller once it is ready). */
export const uiCommand = (runner: readonly [string, ...string[]], a: { readonly repoRoot: string; readonly port?: number }): Command => {
  const [cmd, ...pre] = runner;
  return { cmd, args: [...pre, "-C", a.repoRoot, ...(a.port !== undefined ? ["--port", String(a.port)] : [])], cwd: a.repoRoot };
};

const parseState = (text: string | undefined): UiState | undefined => {
  try {
    const j = rec(text === undefined ? undefined : JSON.parse(text));
    const pid = num(j["pid"]);
    const url = str(j["url"]);
    const startedAt = num(j["startedAt"]);
    return pid !== undefined && url !== undefined && startedAt !== undefined ? { pid, url, startedAt } : undefined;
  } catch {
    return undefined;
  }
};

export type UiSteps = { readonly repoRoot: (deps: UiDeps) => (cwd: string) => Promise<Result<string, DevsecError>> };

/**
 * Start (or reuse, or stop) the live UI for the repository. Reuse is only for a UI that
 * answers at the recorded url *and* serves this repository.
 */
export const uiWith =
  (steps: UiSteps) =>
  (deps: UiDeps) =>
  async (args: UiArgs): Promise<Result<UiStatus, DevsecError>> => {
    const root = await steps.repoRoot(deps)(args.cwd);
    if (!root.ok) return root;
    const layout = workspaceLayout(root.value);
    const recorded = parseState(await deps.fs.readText(layout.uiJson));
    const alive = recorded !== undefined && (await deps.probe(recorded.url)) === root.value;

    if (args.stop) {
      await deps.fs.rm(layout.uiJson);
      if (!recorded || !alive) return ok({ status: "not-running" });
      await deps.kill(recorded.pid);
      return ok({ status: "stopped", pid: recorded.pid });
    }

    if (recorded && alive) {
      if (args.open) await deps.openUrl(recorded.url);
      return ok({ status: "running", url: recorded.url, pid: recorded.pid, log: layout.uiLog });
    }

    if (deps.uiRunner === undefined) {
      return err({ type: "tool-missing", tool: "devsec ui (start it from the devsec executable)" });
    }
    await deps.fs.mkdir(layout.root);
    await deps.fs.writeText(layout.gitignore, devsecGitignore);
    await deps.fs.rm(layout.uiLog);
    const started = await deps.startDetached(
      uiCommand(deps.uiRunner, { repoRoot: root.value, ...(args.port !== undefined ? { port: args.port } : {}) }),
      { logFile: layout.uiLog, ready: uiReady, timeoutMs: 60_000 },
    );
    if (!started.ok) return err({ type: "tool-failed", tool: "devsec-ui", code: 1, stderr: started.error });
    const url = uiReady.exec(started.value.match)?.[1] ?? started.value.match;
    const state: UiState = { pid: started.value.pid, url, startedAt: deps.now() };
    await deps.fs.writeText(layout.uiJson, toJson(state));
    if (args.open) await deps.openUrl(url);
    return ok({ status: "started", url, pid: state.pid, log: layout.uiLog });
  };

export const ui = uiWith({ repoRoot: (deps) => repoRootOf(deps) });
