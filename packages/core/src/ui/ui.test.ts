import { describe, expect, it } from "vitest";
import { ok, err } from "../fp/result.js";
import { memoryDeps } from "../scan/memory-deps.test-helper.js";
import { uiCommand, uiWith, type UiDeps } from "./ui.js";

const steps = { repoRoot: () => async () => ok("/repo") };

const setup = (over: Partial<UiDeps> = {}) => {
  const m = memoryDeps();
  const calls: string[] = [];
  const deps: UiDeps = {
    ...m.deps,
    uiRunner: ["node", "/ui/cli.js"],
    startDetached: async (c) => (calls.push(`start ${c.cmd} ${c.args.join(" ")}`), ok({ pid: 42, match: "devsec-ui: http://127.0.0.1:4321  (repo: /repo)" })),
    probe: async () => undefined,
    kill: async (pid) => void calls.push(`kill ${pid}`),
    openUrl: async (url) => void calls.push(`open ${url}`),
    ...over,
  };
  return { deps, calls, files: m.files };
};

describe("ui", () => {
  it("builds the launch command from the runner", () => {
    expect(uiCommand(["npx", "--yes", "@devsec/ui"], { repoRoot: "/r", port: 5000 })).toEqual({
      cmd: "npx",
      args: ["--yes", "@devsec/ui", "-C", "/r", "--port", "5000"],
      cwd: "/r",
    });
  });

  it("starts the UI detached, records it, opens the browser", async () => {
    const { deps, calls, files } = setup();
    const r = await uiWith(steps)(deps)({ cwd: "/repo", open: true });
    expect(r).toEqual({ ok: true, value: { status: "started", url: "http://127.0.0.1:4321", pid: 42, log: "/repo/.devsec/ui.log" } });
    expect(calls).toEqual(["start node /ui/cli.js -C /repo", "open http://127.0.0.1:4321"]);
    expect(JSON.parse(files.get("/repo/.devsec/ui.json") ?? "{}")).toMatchObject({ pid: 42, url: "http://127.0.0.1:4321" });
    expect(files.get("/repo/.devsec/.gitignore")).toBe("*\n");
  });

  it("reuses a running UI only if it serves this repository", async () => {
    const running = setup({ probe: async () => "/repo" });
    running.files.set("/repo/.devsec/ui.json", JSON.stringify({ pid: 7, url: "http://127.0.0.1:4321", startedAt: 1 }));
    const r = await uiWith(steps)(running.deps)({ cwd: "/repo" });
    expect(r.ok && r.value.status).toBe("running");
    expect(running.calls).toEqual([]);

    const other = setup({ probe: async () => "/another-repo" });
    other.files.set("/repo/.devsec/ui.json", JSON.stringify({ pid: 7, url: "http://127.0.0.1:4321", startedAt: 1 }));
    const r2 = await uiWith(steps)(other.deps)({ cwd: "/repo" });
    expect(r2.ok && r2.value.status).toBe("started");
  });

  it("stops a running UI", async () => {
    const { deps, calls, files } = setup({ probe: async () => "/repo" });
    files.set("/repo/.devsec/ui.json", JSON.stringify({ pid: 7, url: "http://127.0.0.1:4321", startedAt: 1 }));
    expect(await uiWith(steps)(deps)({ cwd: "/repo", stop: true })).toEqual({ ok: true, value: { status: "stopped", pid: 7 } });
    expect(calls).toEqual(["kill 7"]);
    expect(files.has("/repo/.devsec/ui.json")).toBe(false);
    expect(await uiWith(steps)(deps)({ cwd: "/repo", stop: true })).toEqual({ ok: true, value: { status: "not-running" } });
  });

  it("refuses to start when no UI binary is available", async () => {
    const { deps, calls } = setup({ uiRunner: undefined });
    const r = await uiWith(steps)(deps)({ cwd: "/repo" });
    expect(r.ok ? r.value : r.error).toMatchObject({ type: "tool-missing" });
    expect(calls).toEqual([]);
  });

  it("reports a UI that fails to start", async () => {
    const { deps } = setup({ startDetached: async () => err("exited with 1") });
    const r = await uiWith(steps)(deps)({ cwd: "/repo" });
    expect(r.ok).toBe(false);
  });
});
