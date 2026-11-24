/** An external command described as data. Core builds these; apps execute them via `exec`. */
export type Command = {
  readonly cmd: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: Readonly<Record<string, string>>;
};

export type ExecOutput = { readonly code: number; readonly stdout: string; readonly stderr: string };
