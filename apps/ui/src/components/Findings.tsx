import { severities, type AgentFinding, type FindingDetail } from "@devsec/core";
import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import type { Api } from "../api.js";

type Filter = "all" | "new" | "deny" | "warn";

const FindingRow = (props: { f: AgentFinding; runId: string; api: Api }) => {
  const [open, setOpen] = createSignal(false);
  const [detail] = createResource(
    () => (open() ? props.f.id : undefined),
    (id): Promise<FindingDetail> => props.api.finding(props.runId, id),
  );
  return (
    <>
      <tr class="finding" classList={{ open: open() }} onClick={() => setOpen(!open())}>
        <td>
          <span class={`badge ${props.f.verdict}`}>{props.f.verdict}</span>
          <Show when={props.f.new}><span class="badge new" title="not in the baseline">new</span></Show>
        </td>
        <td><span class={`sev ${props.f.severity}`}>{props.f.severity}</span></td>
        <td class="muted nowrap">{props.f.scanner}</td>
        <td class="where">
          <Show when={props.f.path} fallback={<code>{props.f.package}</code>}>
            <code>{props.f.path}:{props.f.line}</code>
          </Show>
          <Show when={props.f.fix}><span class="fix">fix: {props.f.fix}</span></Show>
        </td>
        <td>
          <div class="msg">{props.f.message}</div>
          <div class="rule muted"><code>{props.f.rule}</code></div>
        </td>
      </tr>
      <Show when={open()}>
        <tr class="detail">
          <td colspan="5">
            <ul class="policy-msgs"><For each={props.f.policy}>{(m) => <li>{m}</li>}</For></ul>
            <Show when={detail()} fallback={<p class="muted">loading…</p>}>
              {(d) => (
                <>
                  <p class="muted small">Raw tool result (<code>{d().finding.raw.file}{d().finding.raw.pointer}</code>):</p>
                  <pre>{JSON.stringify(d().raw, null, 2)}</pre>
                </>
              )}
            </Show>
          </td>
        </tr>
      </Show>
    </>
  );
};

export const Findings = (props: { findings: readonly AgentFinding[]; runId: string; api: Api }) => {
  const [picked, setFilter] = createSignal<Filter>();
  const matches = (f: AgentFinding, x: Filter) => x === "all" || (x === "new" ? f.new === true : f.verdict === x);
  const hasBaseline = createMemo(() => props.findings.some((f) => f.new !== undefined));
  // With a baseline, start on the findings the change introduced.
  const filter = () => picked() ?? (hasBaseline() ? "new" : "all");
  const shown = createMemo(() => props.findings.filter((f) => matches(f, filter())));
  const bySeverity = createMemo(() => severities.map((s) => [s, props.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0));
  return (
    <section>
      <div class="toolbar">
        <div class="seg" role="tablist">
          <For each={hasBaseline() ? (["new", "all", "deny", "warn"] as const) : (["all", "deny", "warn"] as const)}>
            {(f) => (
              <button role="tab" aria-selected={filter() === f} classList={{ on: filter() === f }} onClick={() => setFilter(f)}>
                {f} ({props.findings.filter((x) => matches(x, f)).length})
              </button>
            )}
          </For>
        </div>
        <div class="sevs"><For each={bySeverity()}>{([s, n]) => <span class={`sev ${s}`}>{n} {s}</span>}</For></div>
      </div>
      <Show
        when={shown().length > 0}
        fallback={
          <p class="muted pad">
            <Show when={filter() === "new" && props.findings.length > 0} fallback="Nothing flagged by the policy.">
              No new findings: the {props.findings.length} flagged finding{props.findings.length === 1 ? "" : "s"} already exist in the baseline.{" "}
              <button class="link" onClick={() => setFilter("all")}>Show them</button>
            </Show>
          </p>
        }
      >
        <div class="table-wrap">
          <table>
            <thead><tr><th>verdict</th><th>severity</th><th>scanner</th><th>where</th><th>finding</th></tr></thead>
            <tbody><For each={shown()}>{(f) => <FindingRow f={f} runId={props.runId} api={props.api} />}</For></tbody>
          </table>
        </div>
      </Show>
    </section>
  );
};
