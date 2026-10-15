import { describe, expect, it } from 'vitest';
import { gitStatus, isGitignored } from '../../../src/packs/nextjs-supabase/analysis/git-status.js';
import { fakeExec, toolContext } from '../../helpers/fake-exec.js';
import { memoryContext } from '../../helpers/memory-context.js';

describe('isGitignored', () => {
  it.each([
    [['.env*.local'], '.env.local', true],
    [['.env*.local'], '.env', false],
    [['.env*'], '.env.production', true],
    [['.env*', '!.env.example'], '.env.example', false],
    [['*.local'], 'apps/web/.env.local', true],
    [['/.env.local'], 'apps/web/.env.local', false],
    [['/.env.local'], '.env.local', true],
    [['config/'], 'config/.env', true],
    [['**/secrets/**'], 'a/secrets/b/.env', true],
    [['.env.local'], '.env.local.bak', false],
    [['.env?'], '.env1', true],
  ])('%j ignores %s: %s', (patterns, file, expected) => {
    expect(isGitignored(patterns, file)).toBe(expected);
  });
});

describe('gitStatus', () => {
  it('asks git when the project is a repository', async () => {
    const { exec, calls } = fakeExec((_command, args) => {
      if (args[0] === 'rev-parse') return { stdout: '\n' };
      if (args[0] === 'ls-files') return { stdout: '.env\0' };
      return { exitCode: 0, stdout: '.env.local\n' };
    });
    const ctx = memoryContext({ '.env': 'A=1', '.env.local': 'B=2', '.env.test.local': 'C=3' }, {}, { tools: toolContext(exec) });
    expect(Object.fromEntries(await gitStatus(ctx, ['.env', '.env.local', '.env.test.local']))).toEqual({
      '.env': { tracked: true, ignored: false },
      '.env.local': { tracked: false, ignored: true },
      '.env.test.local': { tracked: false, ignored: false },
    });
    expect(calls.at(-1)?.args).toEqual(['check-ignore', '--', '.env.local', '.env.test.local']);
  });

  it('falls back to the root .gitignore without git', async () => {
    const ctx = memoryContext({ '.gitignore': '# env\n.env*.local\n', '.env.local': 'B=2', '.env': 'A=1' }, {}, { tools: toolContext(fakeExec().exec) });
    expect(Object.fromEntries(await gitStatus(ctx, ['.env', '.env.local']))).toEqual({ '.env': { ignored: false }, '.env.local': { ignored: true } });
  });
});
