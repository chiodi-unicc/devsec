import type { DisplayStatus } from "@devsec/core";
import { Match, Switch } from "solid-js";

const titles: Record<DisplayStatus, string> = {
  pending: "pending",
  running: "running",
  ok: "done",
  cached: "reused from cache",
  skipped: "skipped",
  failed: "failed",
};

/** One icon per status: spinner while running, check when done, cross when failed. */
export const StatusIcon = (props: { status: DisplayStatus; size?: number }) => (
  <svg
    class={`icon icon-${props.status}`}
    width={props.size ?? 18}
    height={props.size ?? 18}
    viewBox="0 0 20 20"
    role="img"
    aria-label={titles[props.status]}
  >
    <title>{titles[props.status]}</title>
    <Switch>
      <Match when={props.status === "running"}>
        <circle cx="10" cy="10" r="7.5" fill="none" stroke="currentColor" stroke-opacity="0.2" stroke-width="2.5" />
        <path d="M10 2.5a7.5 7.5 0 0 1 7.5 7.5" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" />
      </Match>
      <Match when={props.status === "ok"}>
        <circle cx="10" cy="10" r="9" fill="currentColor" />
        <path d="M6 10.3l2.6 2.6L14 7.5" fill="none" stroke="var(--on-status)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" />
      </Match>
      <Match when={props.status === "failed"}>
        <circle cx="10" cy="10" r="9" fill="currentColor" />
        <path d="M7 7l6 6M13 7l-6 6" fill="none" stroke="var(--on-status)" stroke-width="2.2" stroke-linecap="round" />
      </Match>
      <Match when={props.status === "cached"}>
        <circle cx="10" cy="10" r="8.5" fill="none" stroke="currentColor" stroke-width="1.6" />
        <path d="M6.5 10a3.5 3.5 0 1 0 1.2-2.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
        <path d="M6.2 5.6v2.3h2.3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
      </Match>
      <Match when={props.status === "skipped"}>
        <circle cx="10" cy="10" r="8.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2.5 2.5" />
        <path d="M6.5 10h7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
      </Match>
      <Match when={props.status === "pending"}>
        <circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="1.6" />
      </Match>
    </Switch>
  </svg>
);
