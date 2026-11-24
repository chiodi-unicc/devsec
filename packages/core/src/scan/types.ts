import type { Config } from "../domain/config.js";
import type { DevsecError } from "../domain/errors.js";
import type { Finding, ScannerId } from "../domain/finding.js";
import type { Subject } from "../domain/subject.js";
import type { InfraDeps } from "../deps.js";
import type { Result } from "../fp/result.js";
import type { Judgement, PolicyResult } from "../policy/conftest.js";
import type { AgentReport, BaselineInfo } from "../report/json.js";
import type { ToolName, ToolVersions } from "../tools/versions.js";
import type { RunLayout, WorkspaceLayout } from "../workspace/layout.js";

export type ScanArgs = {
  /** Any directory inside the repository. */
  readonly cwd: string;
  /** Scan this commit-ish instead of the working tree. */
  readonly ref?: string;
  /** Restrict to these scanners (intersected with devsec.json). */
  readonly scanners?: readonly ScannerId[];
  /** Ref whose findings count as existing, or "none"; overrides devsec.json. */
  readonly baseline?: string;
  /** Internal: this scan only provides a baseline (no nested baseline, never becomes latest). */
  readonly purpose?: "baseline";
};

export type ScanDeps = InfraDeps;

/** A step: deps first (bound once by the app), then its input. */
export type Step<I, O> = (deps: ScanDeps) => (input: I) => Promise<Result<O, DevsecError>>;

export type Versions = { readonly found: Partial<ToolVersions>; readonly missing: readonly ToolName[] };

export type CachedScan = { readonly findings: readonly Finding[] };

export type ScanSteps = {
  readonly versions: Step<{ readonly cwd: string }, Versions>;
  readonly subject: Step<{ readonly cwd: string; readonly ref?: string }, Subject>;
  readonly config: Step<{ readonly repoRoot: string }, Config>;
  readonly cache: Step<{ readonly run: RunLayout; readonly key: string; readonly ttlHours: number }, CachedScan | undefined>;
  readonly snapshot: Step<{ readonly subject: Subject; readonly layout: WorkspaceLayout }, string>;
  readonly sbom: Step<{ readonly snapshot: string; readonly run: RunLayout }, string>;
  readonly semgrep: Step<{ readonly snapshot: string; readonly run: RunLayout; readonly rulesets: readonly string[] }, Finding[]>;
  readonly trivySecrets: Step<{ readonly snapshot: string; readonly run: RunLayout }, Finding[]>;
  readonly trivySca: Step<{ readonly snapshot: string; readonly run: RunLayout; readonly sbom: string }, Finding[]>;
  readonly saveScan: Step<{ readonly run: RunLayout; readonly key: string; readonly findings: readonly Finding[]; readonly complete: boolean }, void>;
  readonly policy: Step<
    {
      readonly subject: Subject;
      readonly findings: readonly Finding[];
      readonly config: Config;
      readonly layout: WorkspaceLayout;
      readonly run: RunLayout;
      readonly partial: boolean;
    },
    PolicyResult
  >;
  readonly report: Step<
    {
      readonly subject: Subject;
      readonly runId: string;
      readonly run: RunLayout;
      readonly scanners: readonly ScannerId[];
      readonly judgement: Judgement;
      readonly errors: readonly string[];
      readonly failOn: Config["failOn"];
      readonly baseline?: BaselineInfo;
    },
    AgentReport
  >;
};

export type ScanOutcome = {
  readonly report: AgentReport;
  /** All projected findings (before policy). */
  readonly findings: readonly Finding[];
  readonly runDir: string;
  readonly reportJson: string;
  readonly reportSarif: string;
};
