import { describe, expect, it } from 'vitest';
import { gitIgnored, gitRepo, gitTracked } from '../../../src/adapters/git.js';
import { fakeExec, toolContext } from '../../helpers/fake-exec.js';

const ROOT = '/project';

describe('git adapter', () => {
  it('finds the scan root prefix inside a repository, once per scan', async () => {
    const { exec, calls } = fakeExec(() => ({ stdout: 'apps/web/\n' }));
    const tools = toolContext(exec);
    expect(await gitRepo(ROOT, tools)).toEqual({ prefix: 'apps/web/' });
    expect(await gitRepo(ROOT, tools)).toEqual({ prefix: 'apps/web/' });
    expect(calls).toEqual([expect.objectContaining({ command: 'git', args: ['rev-parse', '--show-prefix'], cwd: ROOT })]);
  });

  it('returns null outside a repository or without git', async () => {
    expect(await gitRepo(ROOT, toolContext(fakeExec(() => ({ exitCode: 128 })).exec))).toBeNull();
    expect(await gitRepo(ROOT, toolContext(fakeExec().exec))).toBeNull();
  });

  it('lists tracked and ignored paths with NUL-separated output', async () => {
    const { exec, calls } = fakeExec((_command, args) => (args[0] === 'ls-files' ? { stdout: '.env.local\0' } : { exitCode: 0, stdout: '.env\0' }));
    const tools = toolContext(exec);
    expect(await gitTracked(ROOT, tools, ['.env.local', '.env'])).toEqual(new Set(['.env.local']));
    expect(await gitIgnored(ROOT, tools, ['.env'])).toEqual(new Set(['.env']));
    expect(calls.map((c) => c.args)).toEqual([
      ['ls-files', '-z', '--', '.env.local', '.env'],
      ['check-ignore', '-z', '--', '.env'],
    ]);
  });

  it('treats check-ignore exit code 1 as "nothing ignored" and errors as unknown', async () => {
    expect(await gitIgnored(ROOT, toolContext(fakeExec(() => ({ exitCode: 1 })).exec), ['.env'])).toEqual(new Set());
    expect(await gitIgnored(ROOT, toolContext(fakeExec(() => ({ exitCode: 128 })).exec), ['.env'])).toBeNull();
  });
});
