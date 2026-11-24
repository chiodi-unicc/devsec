/** Errors as values: core never throws, runtimes decide what to do with failures. */
export type Result<T, E = string> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

export const map =
  <T, U>(f: (t: T) => U) =>
  <E>(r: Result<T, E>): Result<U, E> =>
    r.ok ? ok(f(r.value)) : r;

export const flatMap =
  <T, U, E>(f: (t: T) => Result<U, E>) =>
  (r: Result<T, E>): Result<U, E> =>
    r.ok ? f(r.value) : r;

export const all = <T, E>(rs: ReadonlyArray<Result<T, E>>): Result<T[], E> => {
  const out: T[] = [];
  for (const r of rs) {
    if (!r.ok) return r;
    out.push(r.value);
  }
  return ok(out);
};

export const mapErr =
  <E, F>(f: (e: E) => F) =>
  <T>(r: Result<T, E>): Result<T, F> =>
    r.ok ? r : err(f(r.error));
