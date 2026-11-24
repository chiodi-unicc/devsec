import type { Subject } from "./subject.js";

export const stepIds = [
  "versions",
  "subject",
  "config",
  "cache",
  "snapshot",
  "sbom",
  "semgrep",
  "trivy-secrets",
  "trivy-sca",
  "baseline",
  "policy",
  "report",
] as const;
export type StepId = (typeof stepIds)[number];

export type StepStatus = "ok" | "cached" | "skipped" | "failed";

/** Progress stream: written to events.jsonl, sent as MCP progress, rendered by the UI. */
export type DevsecEvent =
  | {
      readonly type: "run.started";
      readonly at: number;
      readonly runId: string;
      readonly subject: Subject;
      /** Set when this run only provides the baseline for another scan. */
      readonly purpose?: "baseline";
    }
  | { readonly type: "step.started"; readonly at: number; readonly step: StepId }
  | {
      readonly type: "step.finished";
      readonly at: number;
      readonly step: StepId;
      readonly status: StepStatus;
      readonly error?: string;
      readonly findings?: number;
      /** Why a step was skipped or reused from the cache, in plain words. */
      readonly reason?: string;
      /** On the cache step: whether an identical scan was reused, and from which run. */
      readonly cache?: { readonly hit: boolean; readonly from?: string; readonly scannedAt?: number };
    }
  | { readonly type: "run.finished"; readonly at: number; readonly status: "pass" | "fail" | "error" };
