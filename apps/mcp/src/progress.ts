import { stepIds, type Emit } from "@devsec/core";

/** MCP-specific emit: step events → MCP progress notifications (one tick per finished step). */
export const progressEmitter =
  (report: (p: { progress: number; total: number; message: string }) => Promise<void>): Emit => {
    let done = 0;
    return (e) => {
      if (e.type !== "step.finished") return;
      done += 1;
      const n = e.findings !== undefined ? `: ${e.findings} results` : "";
      void report({ progress: done, total: stepIds.length, message: `${e.step} ${e.status}${n}${e.error ? ` (${e.error})` : ""}` }).catch(() => {});
    };
  };
