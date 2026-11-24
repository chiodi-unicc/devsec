import { createEffect, createSignal, For, on, onCleanup, Show } from "solid-js";
import type { Store } from "../store.js";
import { ago, short } from "../format.js";

export const RunList = (props: { store: Store }) => {
  // Clock signal so relative times ("2m ago") stay current.
  const [now, setNow] = createSignal(Date.now());
  const timer = setInterval(() => setNow(Date.now()), 15_000);
  onCleanup(() => clearInterval(timer));
  createEffect(on(() => props.store.runs(), () => setNow(Date.now())));
  return (
  <nav class="runs" aria-label="Scan runs">
    <div class="runs-head">
      <h2>Runs</h2>
      <Show when={!props.store.following()}>
        <button class="link" onClick={() => props.store.follow()}>follow latest</button>
      </Show>
    </div>
    <Show when={props.store.runs().length > 0} fallback={<p class="muted pad">No scans yet. Run <code>devsec scan</code>.</p>}>
      <ul>
        <For each={props.store.runs()}>
          {(run) => (
            <li>
              <button
                class="run"
                classList={{ active: props.store.selected() === run.runId, baseline: run.purpose === "baseline" }}
                onClick={() => props.store.select(run.runId)}
              >
                <span class={`dot ${run.status}`} title={run.status} />
                <span class="run-main">
                  <code>{short(run.subject?.treeSha)}</code>
                  <Show when={run.subject?.dirty}><span class="tag">dirty</span></Show>
                  <Show when={run.purpose === "baseline"} fallback={<Show when={run.subject?.ref}><span class="tag">{run.subject?.ref}</span></Show>}>
                    <span class="tag" title="scanned as the baseline for another run">baseline {run.subject?.ref}</span>
                  </Show>
                </span>
                <span class="run-meta">
                  <Show when={run.counts} fallback={<span class="muted">{run.status}</span>}>
                    {(c) => (
                      <span title="deny / warn">
                        <span class="deny">{c().deny}</span> / <span class="warn">{c().warn}</span>
                      </span>
                    )}
                  </Show>
                  <span class="muted">{ago(run.startedAt, now())}</span>
                </span>
              </button>
            </li>
          )}
        </For>
      </ul>
    </Show>
  </nav>
);
};
