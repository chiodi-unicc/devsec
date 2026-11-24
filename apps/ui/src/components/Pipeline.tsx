import {
  durationMs,
  stageState,
  stages,
  stepInfo,
  stepStatus,
  type AgentReport,
  type RunMeta,
  type RunState,
  type StepId,
} from "@devsec/core";
import { createEffect, createMemo, createSignal, For, on, onCleanup, Show, type Accessor } from "solid-js";
import { ms, short } from "../format.js";
import { StatusIcon } from "./StatusIcon.jsx";

type Props = { state: RunState; meta: RunMeta | undefined; report: AgentReport | undefined; now: Accessor<number> };

/** One-line summary of what a step produced, from live state plus run.json / report when available. */
const summary = (id: StepId, p: Props): string => {
  const s = p.state.steps[id];
  // A skipped or reused step explains itself: the reason is recorded by core when it decides.
  if (s?.reason && s.status === "skipped") return `skipped: ${s.reason}`;
  if (s?.reason && s.status === "cached") return s.reason;
  const subject = p.state.subject;
  switch (id) {
    case "versions":
      return p.meta ? ["git", "syft", "semgrep", "trivy", "conftest"].map((t) => `${t} ${p.meta?.tools[t] ?? "?"}`).join(" · ") : "";
    case "subject":
      return subject ? `tree ${short(subject.treeSha)}${subject.ref ? ` (ref ${subject.ref})` : subject.dirty ? " (uncommitted changes)" : ""}` : "";
    case "config":
      return p.meta ? `scanners: ${p.meta.scanners.join(", ")}` : "";
    case "cache":
      return s?.reason ?? (stepStatus(p.state, "semgrep") === "cached" ? "hit: reusing an identical scan" : s?.status === "ok" ? "miss: scanning" : "");
    case "snapshot":
      return subject ? `.devsec/snapshots/${short(subject.treeSha)}…` : "";
    case "baseline":
      return p.report?.baseline
        ? `${p.report.baseline.ref} (tree ${short(p.report.baseline.tree)}) · ${p.report.counts.new ?? 0} new`
        : s?.status === "skipped"
          ? "skipped: no baseline (all findings count)"
          : "";
    case "policy":
      return p.report ? `${p.report.counts.deny} deny · ${p.report.counts.warn} warn · ${p.report.counts.dropped} dropped` : "";
    case "report":
      return p.report ? `${p.report.counts.flagged} flagged findings` : "";
    default:
      return s?.findings !== undefined ? `${s.findings} result${s.findings === 1 ? "" : "s"}` : "";
  }
};

const commandLine = (c: { cmd: string; args: readonly string[] }) =>
  [c.cmd, ...c.args].map((a) => (/[\s"']/.test(a) ? JSON.stringify(a) : a)).join(" ");

/** Duration for finished steps, live elapsed time for running ones, nothing for cached / skipped / pending. */
const timeOf = (id: StepId, p: Props): string => {
  const s = p.state.steps[id];
  if (!s) return "";
  if (s.status === "running") return `${ms(Math.max(0, p.now() - s.startedAt))}…`;
  if (s.status === "cached" || s.status === "skipped") return "";
  return ms(durationMs(s));
};

const StepRow = (props: { id: StepId; p: Props; after?: boolean }) => {
  const info = () => stepInfo[props.id];
  const status = () => stepStatus(props.p.state, props.id);
  const step = () => props.p.state.steps[props.id];
  const [open, setOpen] = createSignal(false);
  const expanded = () => open() || status() === "failed";
  const command = () => props.p.meta?.commands.find((c) => c.step === props.id)?.command;
  const version = () => (info().tool ? props.p.meta?.tools[info().tool ?? ""] : undefined);

  return (
    <li class={`step-row ${status()}`} classList={{ after: props.after }}>
      <button class="step-line" aria-expanded={expanded()} onClick={() => setOpen(!open())}>
        <span class="step-icon">
          <Show when={props.after}><span class="flow" title="runs after the step above, using its output">↳</span></Show>
          <StatusIcon status={status()} />
        </span>
        <span class="step-label">{info().label}</span>
        <span class="step-summary" classList={{ reason: step()?.reason !== undefined }} title={step()?.reason ?? ""}>
          {summary(props.id, props.p)}
        </span>
        <span class="step-time">{timeOf(props.id, props.p)}</span>
        <span class="chev" aria-hidden="true">{expanded() ? "▾" : "▸"}</span>
      </button>
      <Show when={expanded()}>
        <div class="step-detail">
          <p>{info().description}</p>
          <Show when={step()?.error}><pre class="step-error">{step()?.error}</pre></Show>
          <dl>
            <dt>status</dt>
            <dd>{status()}</dd>
            <Show when={step()?.reason}>
              <dt>{status() === "skipped" ? "why skipped" : "why"}</dt>
              <dd class="why">{step()?.reason}</dd>
            </Show>
            <Show when={version()}>
              <dt>{info().tool}</dt>
              <dd>{version()}{info().tool === "trivy" && props.p.meta?.tools["trivyDb"] ? ` (vulnerability DB ${props.p.meta.tools["trivyDb"]?.slice(0, 10)})` : ""}</dd>
            </Show>
            <Show when={command()}>
              {(c) => (
                <>
                  <dt>command</dt>
                  <dd><code class="cmd">{commandLine(c())}</code><div class="muted small">in {c().cwd}</div></dd>
                </>
              )}
            </Show>
            <Show when={info().outputs && props.p.meta}>
              <dt>writes</dt>
              <dd><For each={info().outputs}>{(o) => <code class="out">{o}</code>}</For></dd>
            </Show>
          </dl>
        </div>
      </Show>
    </li>
  );
};

export const Pipeline = (props: Omit<Props, "now">) => {
  // Clock for live elapsed times; ticks only while the run is in progress.
  const [now, setNow] = createSignal(Date.now());
  const running = createMemo(() => props.state.status === "running");
  const timer = setInterval(() => running() && setNow(Date.now()), 250);
  onCleanup(() => clearInterval(timer));
  // Resync immediately when new events arrive, so elapsed times never lag behind them.
  createEffect(on(() => props.state, () => setNow(Date.now())));
  const p: Props = {
    get state() { return props.state; },
    get meta() { return props.meta; },
    get report() { return props.report; },
    now,
  };
  return (
  <ol class="pipeline" aria-label="Scan pipeline">
    <For each={stages}>
      {(stage, i) => {
        const st = () => stageState(stage, p.state);
        return (
          <li class={`stage ${st().status}`}>
            <div class="stage-head">
              <StatusIcon status={st().status} size={22} />
              <span class="stage-title"><span class="stage-num">{i() + 1}</span>{stage.title}</span>
              <span class="step-time">{st().status === "cached" || st().status === "skipped" ? "" : ms(st().durationMs)}</span>
            </div>
            <ul class="steps">
              <For each={stage.lanes}>
                {(lane) => <For each={lane}>{(id, j) => <StepRow id={id} p={p} after={j() > 0} />}</For>}
              </For>
            </ul>
          </li>
        );
      }}
    </For>
  </ol>
);
};
