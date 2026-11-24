import type { Command } from "../domain/command.js";
import { isRecord, rec, str } from "../fp/decode.js";

export const requiredTools = ["git", "syft", "semgrep", "trivy", "conftest"] as const;
export type ToolName = (typeof requiredTools)[number];

export type ToolVersions = Readonly<Record<ToolName, string>> & { readonly trivyDb?: string };

export const versionCommand = (tool: ToolName, cwd: string): Command => {
  switch (tool) {
    case "git":
      return { cmd: "git", args: ["--version"], cwd };
    case "syft":
      return { cmd: "syft", args: ["version", "--output", "json"], cwd };
    case "semgrep":
      return { cmd: "semgrep", args: ["--version"], cwd };
    case "trivy":
      return { cmd: "trivy", args: ["version", "--format", "json"], cwd };
    case "conftest":
      return { cmd: "conftest", args: ["--version"], cwd };
  }
};

const parseJson = (s: string): unknown => {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
};

/** Version string from a tool's version output (plus Trivy's vulnerability DB timestamp). */
export const parseVersion = (tool: ToolName, stdout: string): { version: string; trivyDb?: string } => {
  const firstLine = stdout.trim().split("\n")[0] ?? "";
  switch (tool) {
    case "git":
      return { version: firstLine.replace(/^git version\s*/, "") };
    case "syft":
      return { version: str(rec(parseJson(stdout))["version"]) ?? firstLine };
    case "semgrep":
      return { version: firstLine };
    case "trivy": {
      const json = parseJson(stdout);
      const db = isRecord(json) ? str(rec(json["VulnerabilityDB"])["UpdatedAt"]) : undefined;
      return { version: str(rec(json)["Version"]) ?? firstLine, ...(db ? { trivyDb: db } : {}) };
    }
    case "conftest":
      return { version: firstLine.replace(/^Conftest:\s*/, "") };
  }
};

export const installHint = "devsec setup";
