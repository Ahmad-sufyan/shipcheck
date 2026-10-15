import { statSync } from 'node:fs';
import { delimiter, isAbsolute, join } from 'node:path';
import { execa } from 'execa';

/** External tools get two minutes; the runner extends tool-backed rules' timeouts to match. */
export const TOOL_TIMEOUT_MS = 120_000;

export interface ExecOptions {
  cwd: string;
  timeoutMs: number;
}

export interface ExecResult {
  /** null when the process never ran or was killed. */
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** The binary is not installed (not found on PATH). */
  missing: boolean;
}

/** Runs `command` with an argument array (never a shell string). Injected in tests to replay recorded output. */
export type ExecFn = (command: string, args: readonly string[], options: ExecOptions) => Promise<ExecResult>;

export interface ToolContext {
  exec: ExecFn;
  /** Skip adapters that need the network (vulnerability database lookups). */
  offline: boolean;
}

function isFile(path: string): boolean {
  return statSync(path, { throwIfNoEntry: false })?.isFile() ?? false;
}

/** Resolves a command on PATH (with PATHEXT on Windows), so a missing tool is detected without spawning a shell. */
export function findExecutable(command: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const extensions = process.platform === 'win32' ? ['', ...(env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').map((e) => e.toLowerCase())] : [''];
  const candidates = isAbsolute(command) ? [command] : (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean).map((dir) => join(dir, command));
  for (const base of candidates) {
    for (const extension of extensions) {
      if (isFile(base + extension)) return base + extension;
    }
  }
  return undefined;
}

export const defaultExec: ExecFn = async (command, args, { cwd, timeoutMs }) => {
  const resolved = findExecutable(command);
  if (!resolved) return { exitCode: null, stdout: '', stderr: '', timedOut: false, missing: true };
  const result = await execa(resolved, [...args], {
    cwd,
    timeout: timeoutMs,
    reject: false,
    shell: false,
    windowsHide: true,
    stripFinalNewline: false,
    maxBuffer: 64 * 1024 * 1024,
    env: { NO_COLOR: '1', FORCE_COLOR: '0' },
  });
  return {
    exitCode: typeof result.exitCode === 'number' ? result.exitCode : null,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    timedOut: result.timedOut === true,
    missing: false,
  };
};
