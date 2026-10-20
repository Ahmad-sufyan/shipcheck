import { describe, expect, it } from 'vitest';
import { defaultExec, findExecutable, TOOL_TIMEOUT_MS } from '../../../src/adapters/exec.js';

const cwd = process.cwd();

describe('findExecutable', () => {
  it('resolves binaries on PATH and returns undefined for missing ones', () => {
    expect(findExecutable('node')).toMatch(/node(?:\.exe)?$/i);
    expect(findExecutable('definitely-not-a-binary-xyz')).toBeUndefined();
  });
});

describe('defaultExec', () => {
  it('uses a 120 s default timeout constant', () => {
    expect(TOOL_TIMEOUT_MS).toBe(120_000);
  });

  it('runs a command with an argument array and no shell', async () => {
    const result = await defaultExec('node', ['-e', 'console.log(process.argv[1])', 'a && echo injected; $(id)'], { cwd, timeoutMs: 10_000 });
    expect(result).toMatchObject({ exitCode: 0, missing: false, timedOut: false });
    expect(result.stdout.trim()).toBe('a && echo injected; $(id)');
  });

  it('returns non-zero exits instead of throwing', async () => {
    const result = await defaultExec('node', ['-e', 'console.log("{}"); process.exit(3)'], { cwd, timeoutMs: 10_000 });
    expect(result).toMatchObject({ exitCode: 3, stdout: '{}\n', missing: false });
  });

  it('reports timeouts', async () => {
    const result = await defaultExec('node', ['-e', 'setTimeout(() => {}, 10000)'], { cwd, timeoutMs: 200 });
    expect(result).toMatchObject({ timedOut: true, missing: false });
  });

  it('reports a missing binary without spawning anything', async () => {
    expect(await defaultExec('definitely-not-a-binary-xyz', ['--version'], { cwd, timeoutMs: 1000 })).toEqual({
      exitCode: null,
      stdout: '',
      stderr: '',
      timedOut: false,
      missing: true,
    });
  });
});
