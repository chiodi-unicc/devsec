export const severities = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof severities)[number];

export const scannerIds = ["semgrep", "trivy-secrets", "trivy-sca"] as const;
export type ScannerId = (typeof scannerIds)[number];

/**
 * A projection of one tool result, for the policy and the compact agent view.
 * Fields are copied from tool output, never inferred. `raw` points to the
 * verbatim result in the tool's own JSON output.
 */
export type Finding = {
  readonly id: string;
  readonly scanner: ScannerId;
  readonly rule: string;
  readonly severity: Severity;
  readonly toolSeverity: string;
  readonly title: string;
  readonly message: string;
  readonly location?: Location;
  readonly package?: Package;
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly raw: RawRef;
};

export type Location = {
  readonly path: string;
  readonly startLine: number;
  readonly endLine?: number;
  readonly startColumn?: number;
  readonly endColumn?: number;
};

export type Package = {
  readonly name: string;
  readonly version: string;
  readonly purl?: string;
  readonly fixedVersion?: string;
};

/** `file` is relative to the run's raw/ dir; `pointer` is an RFC 6901 JSON pointer. */
export type RawRef = { readonly file: string; readonly pointer: string };
