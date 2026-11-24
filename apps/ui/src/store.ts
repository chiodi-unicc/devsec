import { foldEvents, type RunSummary } from "@devsec/core";
import { createEffect, createMemo, createResource, createSignal, onCleanup } from "solid-js";
import type { Api } from "./api.js";

/**
 * All UI state as signals, driven by the server's change stream (fs.watch on .devsec/runs).
 * Derived state is pure core functions over signals: foldEvents over the run's events.
 */
export const createStore = (api: Api) => {
  const [repo] = createResource(api.repo);
  const [runs, setRuns] = createSignal<readonly RunSummary[]>([]);
  const [pinned, setPinned] = createSignal<string>();
  // Follow the newest scan; baseline runs (HEAD scanned for comparison) are never auto-selected.
  const latest = createMemo(() => runs().find((r) => r.purpose !== "baseline")?.runId);
  const selected = createMemo(() => pinned() ?? latest());

  // Bumped whenever the selected run's files change → its detail is refetched.
  const [revision, setRevision] = createSignal(0);
  // A scan that starts while the page is open takes over the view, even if an older run was picked.
  const known = new Set<string>();
  let primed = false;
  const stop = api.stream((m) => {
    const started = m.runs.find((r) => r.status === "running" && r.purpose !== "baseline" && !known.has(r.runId));
    for (const r of m.runs) known.add(r.runId);
    if (primed && started) setPinned(undefined);
    primed = true;
    setRuns(m.runs);
    const id = selected();
    if (id && m.changed.includes(id)) setRevision((n) => n + 1);
  });
  onCleanup(stop);

  const source = createMemo(() => {
    const id = selected();
    return id ? { id, revision: revision() } : undefined;
  });
  const [detail] = createResource(source, (s) => api.run(s.id));
  // `latest` keeps showing the previous detail while the next one loads (no flicker during a scan).
  const current = () => detail.latest;
  const state = createMemo(() => foldEvents(current()?.events ?? []));
  /** Detail of the selected run has arrived (until then the folded state is empty, not "running"). */
  const loaded = () => current() !== undefined && current()?.runId === selected();

  // Tab title shows the selected run's state, visible from other tabs.
  createEffect(() => {
    const icon = { running: "⟳ scanning", pass: "✓ pass", fail: "✗ fail", error: "⚠ error" }[state().status];
    document.title = selected() && loaded() ? `${icon} · devsec` : "devsec";
  });

  return { repo, runs, selected, select: setPinned, follow: () => setPinned(undefined), following: () => pinned() === undefined, state, loaded, detail: current };
};

export type Store = ReturnType<typeof createStore>;
