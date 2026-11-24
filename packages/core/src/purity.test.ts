// Guard: core source (non-test) must stay free of I/O and platform imports.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL(".", import.meta.url));
const sources = (readdirSync(root, { recursive: true }) as string[]).filter(
  (f) => f.endsWith(".ts") && !f.includes(".test") && !f.includes("__fixtures__"),
);

describe("core purity", () => {
  it.each(sources)("%s imports no node: / platform modules", (file) => {
    const src = readFileSync(root + file, "utf8");
    expect(src).not.toMatch(/from\s+["'](node:|fs|path|child_process|os)["']/);
    expect(src).not.toMatch(/\bprocess\.(env|argv|cwd|exit|platform|stdout|stderr|stdin|pid|kill|on)\b/);
    expect(src).not.toMatch(/\brequire\(/);
  });
});
