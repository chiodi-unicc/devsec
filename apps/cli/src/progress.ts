import type { Emit } from "@devsec/core";

const icon = { ok: "✓", cached: "↺", skipped: "–", failed: "✗" } as const;

/** CLI-specific emit: progress on stderr (stdout is reserved for the report). */
export const stderrProgress: Emit = (e) => {
  if (e.type === "run.started") process.stderr.write(`devsec: scanning tree ${e.subject.treeSha.slice(0, 12)}${e.subject.dirty ? " (uncommitted changes)" : ""}\n`);
  if (e.type === "step.finished" && e.status !== "skipped") {
    const n = e.findings !== undefined ? ` ${e.findings} results` : "";
    process.stderr.write(`  ${icon[e.status]} ${e.step}${n}${e.error ? `: ${e.error}` : ""}\n`);
  }
};
