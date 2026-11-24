import { scannerIds, severities, type ScannerId, type Severity } from "./finding.js";
import { arr, compact, isRecord, num, rec, str, strs, type Json } from "../fp/decode.js";
import { err, ok, type Result } from "../fp/result.js";

/** Waiver for a finding (by id) or a rule (optionally limited to one path). Must justify and expire. */
export type Exception = {
  readonly finding?: string;
  readonly rule?: string;
  readonly path?: string;
  readonly reason: string;
  readonly expires: string; // YYYY-MM-DD
};

export type Config = {
  readonly scanners: readonly ScannerId[];
  readonly semgrep: { readonly rulesets: readonly string[] };
  /** Directory of Rego policies (package devsec), relative to the repo root. Default: built-in. */
  readonly policy?: string;
  readonly exceptions: readonly Exception[];
  /** Exit non-zero on: "deny" (default) or also "warn". */
  readonly failOn: "deny" | "warn";
  /** Reuse an identical scan for this long; bounds drift in unversioned semgrep registry packs. */
  readonly cacheTtlHours: number;
  /** Git ref whose findings count as existing (e.g. "origin/main"), or "none". Default: HEAD when the tree is dirty. */
  readonly baseline?: string;
};

export const defaultConfig: Config = {
  scanners: scannerIds,
  semgrep: { rulesets: ["p/default", "p/secrets"] },
  exceptions: [],
  failOn: "deny",
  cacheTtlHours: 24,
};

export const configFile = "devsec.json";

const date = /^\d{4}-\d{2}-\d{2}$/;

const parseException = (v: unknown, i: number): Result<Exception, string> => {
  if (!isRecord(v)) return err(`exceptions[${i}] must be an object`);
  const e = compact({
    finding: str(v["finding"]),
    rule: str(v["rule"]),
    path: str(v["path"]),
    reason: str(v["reason"]) ?? "",
    expires: str(v["expires"]) ?? "",
  });
  if (!e.finding && !e.rule) return err(`exceptions[${i}] needs "finding" or "rule"`);
  if (!e.reason.trim()) return err(`exceptions[${i}] needs a "reason"`);
  if (!date.test(e.expires)) return err(`exceptions[${i}].expires must be YYYY-MM-DD`);
  return ok(e);
};

/** Parse devsec.json (already JSON.parsed). Missing fields fall back to defaults. */
export const parseConfig = (json: unknown): Result<Config, string> => {
  if (json === undefined) return ok(defaultConfig);
  if (!isRecord(json)) return err("devsec.json must be a JSON object");
  const j: Json = json;

  const scanners = j["scanners"] === undefined ? defaultConfig.scanners : strs(j["scanners"]);
  const unknownScanner = scanners.find((s) => !(scannerIds as readonly string[]).includes(s));
  if (unknownScanner) return err(`unknown scanner "${unknownScanner}" (known: ${scannerIds.join(", ")})`);

  const semgrep = rec(j["semgrep"]);
  const rulesets = semgrep["rulesets"] === undefined ? defaultConfig.semgrep.rulesets : strs(semgrep["rulesets"]);
  if (rulesets.length === 0) return err("semgrep.rulesets must not be empty");

  const failOn = j["failOn"] ?? defaultConfig.failOn;
  if (failOn !== "deny" && failOn !== "warn") return err(`failOn must be "deny" or "warn"`);

  const ttl = j["cacheTtlHours"] === undefined ? defaultConfig.cacheTtlHours : num(j["cacheTtlHours"]);
  if (ttl === undefined || ttl < 0) return err("cacheTtlHours must be a non-negative number");

  const exceptions: Exception[] = [];
  for (const [i, v] of arr(j["exceptions"]).entries()) {
    const e = parseException(v, i);
    if (!e.ok) return e;
    exceptions.push(e.value);
  }

  const policy = str(j["policy"]);
  const baseline = j["baseline"] === undefined ? undefined : str(j["baseline"]);
  if (j["baseline"] !== undefined && !baseline) return err("baseline must be a git ref or \"none\"");
  return ok({
    ...(baseline ? { baseline } : {}),
    scanners: scanners as ScannerId[],
    semgrep: { rulesets },
    ...(policy ? { policy } : {}),
    exceptions,
    failOn,
    cacheTtlHours: ttl,
  });
};

export const isSeverity = (s: string): s is Severity => (severities as readonly string[]).includes(s);
