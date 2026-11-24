import type { FindingDetail, RunDetail } from "@devsec/core";
import type { StreamMessage } from "../server/protocol.js";

/** Browser-side infrastructure: fetch + EventSource. Injected into the store. */
export type ClientDeps = {
  readonly getJson: <T>(path: string) => Promise<T>;
  readonly subscribe: <T>(path: string, onMessage: (m: T) => void) => () => void;
};

export const browserDeps: ClientDeps = {
  getJson: async <T,>(path: string) => {
    const res = await fetch(path);
    const body = (await res.json()) as T & { error?: string };
    if (!res.ok) throw new Error(body.error ?? res.statusText);
    return body;
  },
  // EventSource reconnects on its own if the server restarts.
  subscribe: <T,>(path: string, onMessage: (m: T) => void) => {
    const source = new EventSource(path);
    source.onmessage = (m) => onMessage(JSON.parse(m.data as string) as T);
    return () => source.close();
  },
};

export const api = (deps: ClientDeps) => ({
  repo: () => deps.getJson<{ root: string }>("/api/repo"),
  run: (id: string) => deps.getJson<RunDetail>(`/api/runs/${id}`),
  finding: (runId: string, id: string) => deps.getJson<FindingDetail>(`/api/runs/${runId}/findings/${id}`),
  stream: (onMessage: (m: StreamMessage) => void) => deps.subscribe<StreamMessage>("/api/stream", onMessage),
});

export type Api = ReturnType<typeof api>;
