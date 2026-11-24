/** Minimal, dependency-free readers for untrusted JSON (tool output, config). */
export type Json = Record<string, unknown>;

export const isRecord = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
export const arr = (v: unknown): readonly unknown[] => (Array.isArray(v) ? v : []);
export const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
export const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
export const strs = (v: unknown): string[] => arr(v).flatMap((x) => (typeof x === "string" ? [x] : []));
export const rec = (v: unknown): Json => (isRecord(v) ? v : {});

/** Drop keys whose value is undefined (keeps exactOptionalPropertyTypes happy). */
export const compact = <T extends Json>(o: T): { [K in keyof T]: Exclude<T[K], undefined> } =>
  Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as never;
