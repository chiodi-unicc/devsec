/** An external command described as data. Core builds these; apps execute them via `exec`. */
export type Command = {
  readonly cmd: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: Readonly<Record<string, string>>;
};

export type ExecOutput = { readonly code: number; readonly stdout: string; readonly stderr: string };

/**
 * Environment for every tool devsec runs: no usage data, no update checks. These settings
 * only stop the tools contacting their vendors; they do not change what the tools find.
 * Rule and vulnerability-database downloads are unaffected.
 */
export const toolEnv: Readonly<Record<string, string>> = {
  TRIVY_DISABLE_TELEMETRY: "true", // trivy: anonymous usage data to Aqua (on by default)
  TRIVY_SKIP_VERSION_CHECK: "true", // trivy: version and announcement notices
  SYFT_CHECK_FOR_APP_UPDATE: "false", // syft: update check
  SEMGREP_ENABLE_VERSION_CHECK: "0", // semgrep: update check (metrics are off via --metrics=off)
};
