import type { StepId } from "./events.js";

/** Human description of each scan step (pure data, shared by the UI and any other renderer). */
export type StepInfo = {
  readonly label: string;
  readonly description: string;
  /** Tool whose version applies to this step (key of run.json `tools`). */
  readonly tool?: "git" | "syft" | "semgrep" | "trivy" | "conftest";
  /** Files the step writes, relative to the run directory. */
  readonly outputs?: readonly string[];
};

export const stepInfo: Readonly<Record<StepId, StepInfo>> = {
  versions: { label: "Tools", description: "Check that git, syft, semgrep, trivy and conftest are installed and record their versions." },
  subject: {
    label: "Subject",
    description: "Pin the code to scan as a git tree hash: the working tree (tracked + untracked, non-ignored files) or --ref.",
    tool: "git",
  },
  config: { label: "Config", description: "Read devsec.json (scanners, semgrep rulesets, policy, exceptions), or use the defaults." },
  cache: { label: "Cache", description: "Reuse an identical earlier scan (same tree, config and tool versions) within the TTL." },
  snapshot: {
    label: "Snapshot",
    description: "Check out the pinned tree into .devsec/snapshots/<tree> with git's own checkout; all tools scan this copy.",
    tool: "git",
  },
  semgrep: {
    label: "Semgrep",
    description: "Static analysis and secret rules (p/default + p/secrets) over the snapshot, in one process.",
    tool: "semgrep",
    outputs: ["raw/semgrep.json", "raw/semgrep.sarif"],
  },
  "trivy-secrets": {
    label: "Trivy secrets",
    description: "Trivy's secret scanner over the snapshot.",
    tool: "trivy",
    outputs: ["raw/trivy-secrets.json"],
  },
  sbom: {
    label: "Syft SBOM",
    description: "Catalogue the snapshot's dependencies into an SBOM (CycloneDX + SPDX).",
    tool: "syft",
    outputs: ["sbom.cdx.json", "sbom.spdx.json"],
  },
  "trivy-sca": {
    label: "Trivy SCA",
    description: "Find vulnerable dependencies from the SBOM (no second walk of the source).",
    tool: "trivy",
    outputs: ["raw/trivy-sca.json"],
  },
  baseline: {
    label: "Baseline",
    description:
      "Scan the baseline (default: HEAD when there are uncommitted changes) with the same pipeline, cached per tree, to tell new findings from existing ones.",
  },
  policy: {
    label: "Policy",
    description: "Evaluate the findings with conftest against the Rego policy; unflagged findings are dropped.",
    tool: "conftest",
    outputs: ["policy/input.json", "policy/data.json", "policy/result.json"],
  },
  report: {
    label: "Report",
    description: "Write the agent report and a SARIF file made of the tools' own SARIF, keeping only flagged results.",
    tool: "trivy",
    outputs: ["report.json", "report.sarif"],
  },
};

/** The scan as CI-style stages. Each stage holds lanes that run in parallel; a lane runs its steps in order. */
export type Stage = { readonly title: string; readonly lanes: readonly (readonly StepId[])[] };

export const stages: readonly Stage[] = [
  { title: "Prepare", lanes: [["versions"], ["subject"], ["config"], ["cache"]] },
  { title: "Snapshot", lanes: [["snapshot"]] },
  { title: "Scan (in parallel)", lanes: [["semgrep"], ["trivy-secrets"], ["sbom", "trivy-sca"]] },
  { title: "Baseline", lanes: [["baseline"]] },
  { title: "Policy", lanes: [["policy"]] },
  { title: "Report", lanes: [["report"]] },
];

export type DisplayStatus = "pending" | "running" | "ok" | "cached" | "skipped" | "failed";

/** Minimal view of run state needed here (avoids a cycle with run-state.ts). */
type StepsView = {
  readonly steps: Partial<Readonly<Record<StepId, { readonly status: Exclude<DisplayStatus, "pending">; readonly startedAt: number; readonly finishedAt?: number }>>>;
};

export const stepStatus = (s: StepsView, id: StepId): DisplayStatus => s.steps[id]?.status ?? "pending";

/** Pure: one status and duration for a whole stage, from its steps. */
export const stageState = (stage: Stage, s: StepsView): { readonly status: DisplayStatus; readonly durationMs?: number } => {
  const ids = stage.lanes.flat();
  const statuses = ids.map((id) => stepStatus(s, id));
  const started = ids.flatMap((id) => (s.steps[id] ? [s.steps[id]] : []));
  const status: DisplayStatus = statuses.includes("failed")
    ? "failed"
    : statuses.includes("running")
      ? "running"
      : statuses.every((x) => x === "pending")
        ? "pending"
        : statuses.includes("pending")
          ? "running"
          : statuses.every((x) => x === "cached" || x === "skipped")
            ? statuses.includes("cached") ? "cached" : "skipped"
            : "ok";
  const finished = started.every((x) => x?.finishedAt !== undefined) && started.length === ids.length;
  const durationMs = finished
    ? Math.max(...started.map((x) => x?.finishedAt ?? 0)) - Math.min(...started.map((x) => x?.startedAt ?? 0))
    : undefined;
  return durationMs === undefined ? { status } : { status, durationMs };
};
