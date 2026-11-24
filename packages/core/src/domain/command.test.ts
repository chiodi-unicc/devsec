import { describe, expect, it } from "vitest";
import { toolEnv } from "./command.js";

describe("toolEnv", () => {
  it("turns off vendor usage data and update checks for every tool", () => {
    expect(toolEnv).toEqual({
      TRIVY_DISABLE_TELEMETRY: "true",
      TRIVY_SKIP_VERSION_CHECK: "true",
      SYFT_CHECK_FOR_APP_UPDATE: "false",
      SEMGREP_ENABLE_VERSION_CHECK: "0",
    });
  });
});
