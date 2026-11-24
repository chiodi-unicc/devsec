import { canonicalJson, hash } from "../fp/hash.js";

/**
 * Line-independent finding identity: tool + rule + path + the matched text (whitespace
 * normalised), plus an occurrence index for identical matches in the same file.
 * Moving code (edits above it) keeps the id; changing the matched code or renaming the
 * file gives a new one. Used for baselines and as the finding id.
 */
export const normalizeSnippet = (text: string): string =>
  text
    .split("\n")
    .map((l) => l.trim().replace(/\s+/g, " "))
    .filter(Boolean)
    .join("\n");

/** Lines [startLine, endLine] (1-based, inclusive) of `source`, normalised. */
export const snippetOf = (source: string, startLine: number, endLine: number): string =>
  normalizeSnippet(source.split("\n").slice(startLine - 1, endLine).join("\n"));

/** Pure: ids from identity parts, numbering repeats in order of appearance. */
export const fingerprints = (parts: readonly (readonly unknown[])[]): string[] => {
  const seen = new Map<string, number>();
  return parts.map((p) => {
    const key = canonicalJson(p);
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    return hash(canonicalJson([...p, n]));
  });
};
