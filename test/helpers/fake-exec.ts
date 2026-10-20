import { readFileSync } from 'node:fs';
import { execa } from 'execa';
import type { ExecFn, ExecResult, ToolContext } from '../../src/adapters/exec.js';

export interface ExecCall {
  command: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
}

export type FakeResponse = Partial<ExecResult> | 'missing' | 'timeout';

/** Recorded tool output from test/tool-outputs/. */
export function recorded(name: string): string {
  return readFileSync(new URL(`../tool-outputs/${name}`, import.meta.url), 'utf8');
}

/** An exec that answers from `respond` (default: every binary is missing) and records each call. */
export function fakeExec(respond: (command: string, args: readonly string[]) => FakeResponse = () => 'missing'): { exec: ExecFn; calls: ExecCall[] } {
  const calls: ExecCall[] = [];
  const exec: ExecFn = async (command, args, { cwd, timeoutMs }) => {
    calls.push({ command, args: [...args], cwd, timeoutMs });
    const response = respond(command, args);
    if (response === 'missing') return { exitCode: null, stdout: '', stderr: '', timedOut: false, missing: true };
    if (response === 'timeout') return { exitCode: null, stdout: '', stderr: '', timedOut: true, missing: false };
    return { exitCode: 0, stdout: '', stderr: '', timedOut: false, missing: false, ...response };
  };
  return { exec, calls };
}

export function toolContext(exec: ExecFn, offline = false): ToolContext {
  return { exec, offline };
}

/**
 * For scans of real fixtures: git runs for real (tracked / ignored checks), every scanner reports as not
 * installed, so results never depend on what is installed on the machine or on the network.
 */
export const gitOnlyExec: ExecFn = async (command, args, { cwd, timeoutMs }) => {
  if (command !== 'git') return { exitCode: null, stdout: '', stderr: '', timedOut: false, missing: true };
  const result = await execa('git', [...args], { cwd, timeout: timeoutMs, reject: false, stripFinalNewline: false });
  return { exitCode: typeof result.exitCode === 'number' ? result.exitCode : null, stdout: String(result.stdout), stderr: String(result.stderr), timedOut: false, missing: false };
};
