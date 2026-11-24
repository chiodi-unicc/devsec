import { describe, expect, it } from "vitest";
import { fixture } from "./fixtures.test-helper.js";
import { fingerprints, snippetOf } from "./fingerprint.js";
import { projectSemgrep } from "./semgrep.js";
import { projectTrivySecrets } from "./trivy.js";

const appJs = `const express = require("express");
const _ = require("lodash");
const { GITHUB_TOKEN } = require("./config");

const app = express();

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.x)));
});

app.listen(3000);
`;

describe("fingerprints", () => {
  it("number identical matches", () => {
    const ids = fingerprints([["a"], ["b"], ["a"]]);
    expect(new Set(ids).size).toBe(3);
    expect(fingerprints([["a"], ["b"], ["a"]])).toEqual(ids);
  });

  it("normalise whitespace in snippets", () => {
    expect(snippetOf("a\n   x  =   1\n\nb", 2, 3)).toBe("x = 1");
  });
});

describe("semgrep ids are line-independent", () => {
  const json = fixture("semgrep.json") as { results: { path: string; start: { line: number }; end: { line: number } }[] };
  const idsFor = (j: unknown, source: string) => {
    const r = projectSemgrep(j, (p) => (p === "app.js" ? source : undefined));
    if (!r.ok) throw new Error(r.error);
    return r.value.filter((f) => f.location?.path === "app.js").map((f) => f.id);
  };

  it("keeps ids when code above the match moves", () => {
    const moved = structuredClone(json);
    for (const r of moved.results) if (r.path === "app.js") (r.start.line += 2), (r.end.line += 2);
    expect(idsFor(moved, `// new line\n// another\n${appJs}`)).toEqual(idsFor(json, appJs));
  });

  it("changes ids when the matched code changes", () => {
    expect(idsFor(json, appJs.replace("eval(req.query.x)", "eval(req.query.y)"))).not.toEqual(idsFor(json, appJs));
  });

  it("all ids are unique", () => {
    const r = projectSemgrep(json, (p) => (p === "app.js" ? appJs : "const AWS = 1;\nconst X = 2;\n"));
    expect(r.ok && new Set(r.value.map((f) => f.id)).size).toBe(r.ok && r.value.length);
  });
});

describe("trivy secret ids", () => {
  it("do not depend on the line number", () => {
    const json = fixture("trivy-secrets.json") as { Results: { Secrets?: { StartLine: number; EndLine: number }[] }[] };
    const a = projectTrivySecrets(json);
    const moved = structuredClone(json);
    for (const r of moved.Results) for (const s of r.Secrets ?? []) (s.StartLine += 10), (s.EndLine += 10);
    const b = projectTrivySecrets(moved);
    expect(a.ok && a.value.map((f) => f.id)).toEqual(b.ok && b.value.map((f) => f.id));
  });
});
