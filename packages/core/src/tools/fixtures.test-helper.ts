// Test-only helper (excluded from the build via *.test.ts imports only).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`./__fixtures__/${name}`, import.meta.url)), "utf8"));
