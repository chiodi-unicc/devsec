import { durationMs, type RunState } from "@devsec/core";
import { createMemo, createSignal, For, Match, Show, Switch } from "solid-js";
import { api as makeApi, browserDeps } from "./api.js";
import { Findings } from "./components/Findings.jsx";
import { Pipeline } from "./components/Pipeline.jsx";
import { Policy } from "./components/Policy.jsx";
import { RunList } from "./components/RunList.jsx";
import { ms, short } from "./format.js";
import { createStore } from "./store.js";

const total = (s: RunState) =>
  s.startedAt !== undefined && s.finishedAt !== undefined ? durationMs({ status: "ok", startedAt: s.startedAt, finishedAt: s.finishedAt }) : undefined;

export const App = () => {
  const api = makeApi(browserDeps);
  const store = createStore(api);
  const [tab, setTab] = createSignal<"findings" | "policy">("findings");
  const report = createMemo(() => store.detail()?.report);

  return (
    <div class="app">
      <header>
        <h1>devsec</h1>
        <span class="muted repo">{store.repo()?.root}</span>
      </header>
      <RunList store={store} />
      <main>
        <Show when={store.selected()} fallback={<p class="muted pad">Select a run.</p>}>
          {(runId) => (
            <>
              <div class="run-head">
                <span class={`status ${store.loaded() ? store.state().status : "pending"}`}>{store.loaded() ? store.state().status : "loading"}</span>
                <span>tree <code>{short(store.state().subject?.treeSha)}</code></span>
                <Show when={store.state().subject?.headSha}><span class="muted">HEAD <code>{short(store.state().subject?.headSha)}</code></span></Show>
                <Show when={store.state().subject?.dirty}><span class="tag">uncommitted changes</span></Show>
                <span class="muted">{ms(total(store.state()))}</span>
                <Show when={store.loaded() && report()}>{(r) => <span class="summary">{r().summary.replace(/^\w+: /, "")}</span>}</Show>
                <code class="muted run-id">{runId()}</code>
              </div>
              <Pipeline state={store.state()} meta={store.detail()?.meta} report={report()} />
              <Show when={report()?.errors.length}>
                <div class="errors"><For each={report()?.errors ?? []}>{(e) => <p>{e}</p>}</For></div>
              </Show>
              <div class="tabs" role="tablist">
                <button role="tab" aria-selected={tab() === "findings"} classList={{ on: tab() === "findings" }} onClick={() => setTab("findings")}>
                  Findings <Show when={report()}>{(r) => <span class="muted">({r().counts.dropped} dropped by policy)</span>}</Show>
                </button>
                <button role="tab" aria-selected={tab() === "policy"} classList={{ on: tab() === "policy" }} onClick={() => setTab("policy")}>Policy</button>
              </div>
              <Switch>
                <Match when={store.state().status === "running"}><p class="muted pad">Scanning…</p></Match>
                <Match when={tab() === "findings" && report()}>{(r) => <Findings findings={r().findings} runId={runId()} api={api} />}</Match>
                <Match when={tab() === "policy" && store.detail()}>{(d) => <Policy policy={d().policy} />}</Match>
              </Switch>
            </>
          )}
        </Show>
      </main>
    </div>
  );
};
