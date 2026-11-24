import { describe, expect, it } from "vitest";
import type { Command } from "../domain/command.js";
import { memoryDeps } from "../scan/memory-deps.test-helper.js";
import { pythonVersion, setup, type SetupDeps } from "./setup.js";
import { binaryTools, platformOf, semgrepTool } from "./toolchain.js";

const versionOut = (cmd: string): string => {
  const name = cmd.split("/").at(-1) ?? "";
  const t = binaryTools.find((b) => b.name === name);
  if (name === "trivy") return JSON.stringify({ Version: t?.version });
  if (name === "syft") return JSON.stringify({ version: t?.version });
  if (name === "conftest") return `Conftest: ${t?.version}`;
  if (name === "semgrep") return semgrepTool.version;
  return "";
};

/** Fake infra: downloads return `bytes`; sha256 is the identity on a marker string. */
const fake = (opts: { goodHashes: boolean; installed?: boolean }) => {
  const m = memoryDeps();
  const commands: string[] = [];
  const fetched: string[] = [];
  const deps: SetupDeps = {
    ...m.deps,
    exec: async (c: Command) => {
      commands.push([c.cmd, ...c.args].join(" "));
      if (c.cmd === "python3") return { code: 0, stdout: "Python 3.12.1", stderr: "" };
      if (c.args.includes("--version") || c.args[0] === "version") {
        const exists = opts.installed || m.files.has(`installed:${c.cmd}`);
        return exists ? { code: 0, stdout: versionOut(c.cmd), stderr: "" } : { code: 127, stdout: "", stderr: "" };
      }
      if (c.cmd === "mv") m.files.set(`installed:${c.args[2]}`, "1");
      if (c.args[0] === "install") m.files.set(`installed:/tools/bin/semgrep`, "1");
      return { code: 0, stdout: "", stderr: "" };
    },
    fs: { ...m.deps.fs, exists: async (p) => opts.installed || m.files.has(`installed:${p}`) || (await m.deps.fs.exists(p)) },
    fetchBytes: async (url) => (fetched.push(url), new TextEncoder().encode(url)),
    sha256: (bytes) => {
      const url = new TextDecoder().decode(bytes);
      const asset = binaryTools.flatMap((t) => Object.values(t.assets)).find((a) => url.endsWith(a.file));
      return opts.goodHashes ? (asset?.sha256 ?? "") : "0".repeat(64);
    },
    writeBytes: async () => {},
    log: () => {},
  };
  return { deps, commands, fetched };
};

describe("setup", () => {
  it("downloads each binary for the platform, verifies its sha256, installs semgrep in a venv, fetches the trivy DB", async () => {
    const { deps, commands, fetched } = fake({ goodHashes: true });
    const r = await setup(deps)({ toolsDir: "/tools", os: "darwin", arch: "arm64" });
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(fetched.map((u) => u.split("/").at(-1))).toEqual([
      "trivy_0.76.2_macOS-ARM64.tar.gz",
      "syft_1.57.2_darwin_arm64.tar.gz",
      "conftest_0.71.1_Darwin_arm64.tar.gz",
    ]);
    expect(r.value.tools.map((t) => [t.tool, t.status])).toEqual([
      ["trivy", "installed"],
      ["syft", "installed"],
      ["conftest", "installed"],
      ["semgrep", "installed"],
    ]);
    expect(commands).toContain(`/tools/semgrep-${semgrepTool.version}/bin/pip install --quiet --disable-pip-version-check semgrep==${semgrepTool.version}`);
    expect(commands).toContain("/tools/bin/trivy fs --quiet --download-db-only");
    expect(r.value.trivyDb).toBe("downloaded");
  });

  it("refuses an archive whose checksum does not match, and installs nothing from it", async () => {
    const { deps, commands } = fake({ goodHashes: false });
    const r = await setup(deps)({ toolsDir: "/tools", os: "linux", arch: "x64", skipDb: true });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatchObject({ type: "tool-failed", stderr: expect.stringMatching(/checksum mismatch/) });
    expect(commands.some((c) => c.startsWith("tar "))).toBe(false);
  });

  it("skips tools already at the pinned version", async () => {
    const { deps, fetched } = fake({ goodHashes: true, installed: true });
    const r = await setup(deps)({ toolsDir: "/tools", os: "darwin", arch: "arm64", skipDb: true });
    expect(r.ok && r.value.tools.every((t) => t.status === "present")).toBe(true);
    expect(fetched).toEqual([]);
  });

  it("rejects unsupported platforms and parses python versions", async () => {
    const { deps } = fake({ goodHashes: true });
    const r = await setup(deps)({ toolsDir: "/tools", os: "win32", arch: "x64", skipDb: true });
    expect(r.ok).toBe(false);
    expect(platformOf("linux", "arm64")).toBe("linux-arm64");
    expect(pythonVersion("Python 3.15.2")).toEqual([3, 15]);
  });

  it("pins a 64-hex sha256 for every platform of every tool", () => {
    for (const t of binaryTools) for (const a of Object.values(t.assets)) expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
