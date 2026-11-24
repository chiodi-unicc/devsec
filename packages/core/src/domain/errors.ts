export type DevsecError =
  | { readonly type: "tool-missing"; readonly tool: string }
  | { readonly type: "tool-failed"; readonly tool: string; readonly code: number; readonly stderr: string }
  | { readonly type: "bad-output"; readonly tool: string; readonly detail: string }
  | { readonly type: "bad-config"; readonly detail: string }
  | { readonly type: "not-a-repo"; readonly path: string }
  | { readonly type: "bad-ref"; readonly ref: string; readonly noCommits: boolean }
  | { readonly type: "io"; readonly detail: string };

export const describeError = (e: DevsecError): string => {
  switch (e.type) {
    case "tool-missing":
      return `${e.tool} not found on PATH (run: devsec doctor)`;
    case "tool-failed":
      return `${e.tool} exited with ${e.code}: ${e.stderr.trim().split("\n").slice(-3).join(" | ")}`;
    case "bad-output":
      return `${e.tool} produced unexpected output: ${e.detail}`;
    case "bad-config":
      return `invalid devsec.json: ${e.detail}`;
    case "bad-ref":
      return `ref "${e.ref}" not found${e.noCommits ? " (the repository has no commits yet)" : ""}`;
    case "not-a-repo":
      return `${e.path} is not inside a git repository`;
    case "io":
      return e.detail;
  }
};
