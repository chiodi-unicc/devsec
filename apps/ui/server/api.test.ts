import { describe, expect, it } from "vitest";
import { isLoopbackHost } from "./api.js";

describe("isLoopbackHost (DNS rebinding guard)", () => {
  it.each(["127.0.0.1:4321", "localhost:4321", "LOCALHOST", "[::1]:4321", "127.0.0.1"])("allows %s", (h) => {
    expect(isLoopbackHost(h)).toBe(true);
  });
  it.each(["evil.example", "evil.example:4321", "127.0.0.1.evil.example", "[::2]:4321", "", undefined])("rejects %s", (h) => {
    expect(isLoopbackHost(h)).toBe(false);
  });
});
