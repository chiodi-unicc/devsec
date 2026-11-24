import type { DevsecEvent } from "../domain/events.js";
import type { Fs, InfraDeps } from "../deps.js";

/** In-memory infrastructure for orchestration tests. */
export const memoryDeps = (start = 1_000_000) => {
  const files = new Map<string, string>();
  const events: DevsecEvent[] = [];
  let clock = start;
  const fs: Fs = {
    readText: async (p) => files.get(p.replace(/\/latest\//, `/${files.get("@latest") ?? "latest"}/`)),
    writeText: async (p, d) => void files.set(p, d),
    appendText: async (p, d) => void files.set(p, (files.get(p) ?? "") + d),
    mkdir: async () => {},
    rm: async (p) => {
      for (const k of [...files.keys()]) if (k === p || k.startsWith(`${p}/`)) files.delete(k);
    },
    exists: async (p) => [...files.keys()].some((k) => k === p || k.startsWith(`${p}/`)),
    readdir: async () => [],
    copyFile: async (a, b) => void files.set(b, files.get(a) ?? ""),
    symlink: async (target) => void files.set("@latest", target),
  };
  const deps: InfraDeps = {
    exec: async () => ({ code: 127, stdout: "", stderr: "not available in tests" }),
    fs,
    emit: (e) => void events.push(e),
    now: () => (clock += 10),
  };
  return { deps, files, events, advance: (ms: number) => void (clock += ms) };
};
