import { describe, expect, it } from 'vitest';
import { secret003 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-003-git-history.js';
import type { FakeResponse } from '../../helpers/fake-exec.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';
import { memoryContext } from '../../helpers/memory-context.js';

async function run(respond: (command: string, args: readonly string[]) => FakeResponse) {
  const { exec } = fakeExec(respond);
  const ctx = memoryContext({ 'lib/stripe.ts': 'export {}' }, {}, { tools: toolContext(exec) });
  const skipped: { check: string; reason: string }[] = [];
  ctx.skip = (check, reason) => skipped.push({ check, reason });
  return { findings: await rule.run(ctx), skipped };
}

const repository = (command: string, args: readonly string[]): FakeResponse => {
  if (command === 'git') return { stdout: '\n' };
  return { exitCode: 1, stdout: recorded(args[0] === 'git' ? 'gitleaks-git.json' : 'gitleaks-dir.json') };
};

describe('SECRET-003 Secret in git history', () => {
  it('reports history findings that are no longer in the working tree, without the secret', async () => {
    const { findings, skipped } = await run(repository);
    expect(skipped).toEqual([]);
    expect(findings).toEqual([
      {
        evidence: 'stripe-access-token in config/legacy-keys.ts:2, commit ed7ede7 (2026-09-30)',
        explanation: expect.stringContaining('commit ed7ede7'),
        source: 'tool:gitleaks',
      },
    ]);
  });

  it('skips with the reason when gitleaks is missing', async () => {
    const { findings, skipped } = await run((command) => (command === 'git' ? { stdout: '\n' } : 'missing'));
    expect(findings).toEqual([]);
    expect(skipped).toEqual([{ check: 'SECRET-003', reason: expect.stringMatching(/^gitleaks is not installed; install gitleaks/) }]);
  });

  it('skips outside a git repository', async () => {
    const { skipped } = await run((command) => (command === 'git' ? { exitCode: 128 } : { stdout: '[]' }));
    expect(skipped).toEqual([{ check: 'SECRET-003', reason: expect.stringContaining('not a git repository') }]);
  });

  it('does nothing when external tools are disabled', async () => {
    expect(await rule.run(memoryContext({}))).toEqual([]);
  });
});
