import type { Command, ExecOutput } from "./domain/command.js";
import type { DevsecEvent } from "./domain/events.js";

/**
 * Infrastructure dependencies. Apps implement these and bind them by partial
 * application; core never performs I/O on its own.
 */

/**
 * Run a command, merging `env` over the current environment. Never rejects: a
 * command that cannot be started (not on PATH) resolves with code 127.
 */
export type Exec = (command: Command) => Promise<ExecOutput>;

/** File system. Paths are absolute. Rejections are caught by core and become errors. */
export type Fs = {
  /** undefined when the file does not exist. */
  readonly readText: (path: string) => Promise<string | undefined>;
  /** Creates parent directories as needed. Replaces the file atomically (never rewrites it in place). */
  readonly writeText: (path: string, data: string) => Promise<void>;
  /** Creates parent directories as needed. */
  readonly appendText: (path: string, data: string) => Promise<void>;
  readonly mkdir: (path: string) => Promise<void>;
  /** Recursive, no error when missing. */
  readonly rm: (path: string) => Promise<void>;
  readonly exists: (path: string) => Promise<boolean>;
  readonly readdir: (path: string) => Promise<readonly string[]>;
  readonly copyFile: (from: string, to: string) => Promise<void>;
  /**
   * Share a file that is never modified in place: hard link, falling back to a copy (e.g. across
   * file systems). Safe because writeText replaces files (temp + rename) instead of rewriting them.
   */
  readonly linkFile: (from: string, to: string) => Promise<void>;
  /** Create or replace a symlink at `path` pointing to `target` (relative target allowed). */
  readonly symlink: (target: string, path: string) => Promise<void>;
};

export type Emit = (event: DevsecEvent) => void;

/** Milliseconds since epoch. */
export type Now = () => number;

export type InfraDeps = {
  readonly exec: Exec;
  readonly fs: Fs;
  readonly emit: Emit;
  readonly now: Now;
};
