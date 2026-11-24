import type { RunSummary } from "@devsec/core";

/** Server → browser message on /api/stream, sent whenever .devsec/runs changes. */
export type StreamMessage = { readonly runs: readonly RunSummary[]; readonly changed: readonly string[] };
