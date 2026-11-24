import type { DevsecEvent, StepId, StepStatus } from "./events.js";
import type { Subject } from "./subject.js";

export type StepState = {
  readonly status: "running" | StepStatus;
  readonly startedAt: number;
  readonly finishedAt?: number;
  readonly error?: string;
  readonly findings?: number;
};

export type RunState = {
  readonly runId?: string;
  readonly subject?: Subject;
  /** "baseline" when this run only provided the baseline for another scan. */
  readonly purpose?: "baseline";
  readonly startedAt?: number;
  readonly finishedAt?: number;
  readonly status: "running" | "pass" | "fail" | "error";
  readonly steps: Partial<Readonly<Record<StepId, StepState>>>;
};

export const initialRunState: RunState = { status: "running", steps: {} };

/** Pure reducer over the event stream. Shared by run.json, the CLI progress line and the UI. */
export const reduceEvent = (s: RunState, e: DevsecEvent): RunState => {
  switch (e.type) {
    case "run.started":
      return { ...s, runId: e.runId, subject: e.subject, startedAt: e.at, status: "running", ...(e.purpose ? { purpose: e.purpose } : {}) };
    case "step.started":
      return { ...s, steps: { ...s.steps, [e.step]: { status: "running", startedAt: e.at } } };
    case "step.finished": {
      const prev = s.steps[e.step];
      const step: StepState = {
        status: e.status,
        startedAt: prev?.startedAt ?? e.at,
        finishedAt: e.at,
        ...(e.error !== undefined ? { error: e.error } : {}),
        ...(e.findings !== undefined ? { findings: e.findings } : {}),
      };
      return { ...s, steps: { ...s.steps, [e.step]: step } };
    }
    case "run.finished":
      return { ...s, status: e.status, finishedAt: e.at };
  }
};

export const foldEvents = (events: readonly DevsecEvent[]): RunState => events.reduce(reduceEvent, initialRunState);

export const durationMs = (s: StepState): number | undefined =>
  s.finishedAt === undefined ? undefined : s.finishedAt - s.startedAt;
