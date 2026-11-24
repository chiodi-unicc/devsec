import { describe, expect, it } from "vitest";
import { err, flatMap, map, ok } from "./result.js";
import { pipe } from "./pipe.js";

describe("result", () => {
  it("maps ok values", () => {
    expect(pipe(ok(2), map((n: number) => n * 2))).toEqual(ok(4));
  });

  it("short-circuits on err", () => {
    const half = (n: number) => (n % 2 === 0 ? ok(n / 2) : err("odd"));
    expect(pipe(ok(3), flatMap(half))).toEqual(err("odd"));
  });
});
