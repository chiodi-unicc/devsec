import type { Command, ExecOutput } from "../domain/command.js";
import type { DevsecError } from "../domain/errors.js";
import type { InfraDeps } from "../deps.js";
import { err, ok, type Result } from "../fp/result.js";

/** Exec a command; 127 → tool-missing, an exit code outside `okCodes` → tool-failed. */
export const runTool =
  (deps: Pick<InfraDeps, "exec">) =>
  async (command: Command, okCodes: readonly number[] = [0]): Promise<Result<ExecOutput, DevsecError>> => {
    const out = await deps.exec(command);
    if (out.code === 127) return err({ type: "tool-missing", tool: command.cmd });
    // Some tools (semgrep --quiet) report fatal errors on stdout; fall back to it when stderr is empty.
    if (!okCodes.includes(out.code)) {
      return err({ type: "tool-failed", tool: command.cmd, code: out.code, stderr: out.stderr.trim() ? out.stderr : out.stdout });
    }
    return ok(out);
  };

export const parseJsonText = (tool: string, text: string | undefined): Result<unknown, DevsecError> => {
  if (text === undefined) return err({ type: "bad-output", tool, detail: "output file missing" });
  try {
    return ok(JSON.parse(text));
  } catch (e) {
    return err({ type: "bad-output", tool, detail: `invalid JSON: ${String(e)}` });
  }
};

export const toJson = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
