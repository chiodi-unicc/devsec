import type { RunDetail, Violation } from "@devsec/core";
import { createMemo, For, Show } from "solid-js";

const byCode = (vs: readonly Violation[]) =>
  Object.entries(vs.reduce<Record<string, number>>((acc, v) => ({ ...acc, [v.code]: (acc[v.code] ?? 0) + 1 }), {}));

export const Policy = (props: { policy: RunDetail["policy"] }) => {
  const deny = createMemo(() => byCode(props.policy.result?.deny ?? []));
  const warn = createMemo(() => byCode(props.policy.result?.warn ?? []));
  return (
    <section class="policy">
      <p class="muted">Evaluated with conftest from <code>{props.policy.dir}</code>.</p>
      <Show when={props.policy.result}>
        <div class="rules">
          <For each={deny()}>{([code, n]) => <span class="badge deny">{code} × {n}</span>}</For>
          <For each={warn()}>{([code, n]) => <span class="badge warn">{code} × {n}</span>}</For>
        </div>
      </Show>
      <For each={Object.entries(props.policy.files)}>
        {([name, src]) => (
          <details open>
            <summary><code>{name}</code></summary>
            <pre class="rego">{src}</pre>
          </details>
        )}
      </For>
    </section>
  );
};
