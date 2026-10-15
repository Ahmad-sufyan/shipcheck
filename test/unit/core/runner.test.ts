import { describe, expect, it } from 'vitest';
import { runRules } from '../../../src/core/runner.js';
import { memoryContext } from '../../helpers/context.js';
import { testRule } from '../../helpers/rules.js';

const nextApp = {
  'package.json': JSON.stringify({ dependencies: { next: '16.4.1' } }),
  'app/page.tsx': 'export default function Page() { return null }',
};

describe('runRules', () => {
  it('runs rules whose stacks are all detected and skips the rest', async () => {
    const ctx = memoryContext(nextApp);
    const outcome = await runRules(
      [
        testRule({ id: 'A-001', stacks: ['nextjs-app-router'], run: () => [{ evidence: 'a' }] }),
        testRule({ id: 'B-001', stacks: ['nextjs-app-router', 'supabase'], run: () => [{ evidence: 'b' }] }),
        testRule({ id: 'C-001', stacks: [], run: () => [{ evidence: 'c' }] }),
      ],
      ctx,
    );
    expect(outcome.runs.map((r) => [r.rule.id, r.findings.map((f) => f.evidence)])).toEqual([
      ['A-001', ['a']],
      ['C-001', ['c']],
    ]);
    expect(outcome.skipped).toEqual([{ check: 'B-001', reason: 'requires stack not detected: supabase' }]);
    expect(outcome.ruleErrors).toEqual([]);
  });

  it("skips rules set to 'off' and applies severity overrides", async () => {
    const ctx = memoryContext(nextApp, { rules: { 'A-001': 'off', 'B-001': 'critical' } });
    const outcome = await runRules(
      [
        testRule({ id: 'A-001', run: () => [{ evidence: 'a' }] }),
        testRule({ id: 'B-001', run: () => [{ evidence: 'b', severity: 'low' }, { evidence: 'c' }] }),
      ],
      ctx,
    );
    expect(outcome.skipped).toEqual([{ check: 'A-001', reason: 'disabled in config' }]);
    expect(outcome.runs[0]?.findings.map((f) => f.severity)).toEqual(['critical', 'critical']);
  });

  it('turns throws, rejections and bad return values into rule errors without stopping other rules', async () => {
    const ctx = memoryContext(nextApp);
    const outcome = await runRules(
      [
        testRule({
          id: 'A-001',
          run: () => {
            throw new Error('boom');
          },
        }),
        testRule({ id: 'B-001', run: async () => Promise.reject(new Error('async boom')) }),
        testRule({ id: 'C-001', run: () => 'nope' as never }),
        testRule({ id: 'D-001', run: () => [{ evidence: 'ok' }] }),
      ],
      ctx,
    );
    expect(outcome.ruleErrors).toEqual([
      { ruleId: 'A-001', message: 'boom' },
      { ruleId: 'B-001', message: 'async boom' },
      { ruleId: 'C-001', message: 'run() must return an array of findings' },
    ]);
    expect(outcome.runs.map((r) => r.rule.id)).toEqual(['D-001']);
  });

  it('times out slow rules', async () => {
    const ctx = memoryContext(nextApp);
    const outcome = await runRules([testRule({ id: 'A-001', run: () => new Promise(() => {}) })], ctx, { timeoutMs: 50 });
    expect(outcome.ruleErrors).toEqual([{ ruleId: 'A-001', message: 'timed out after 50 ms' }]);
  });

  it('lets a rule extend its own timeout', async () => {
    const ctx = memoryContext(nextApp);
    const slow = () => new Promise<[]>((resolve) => setTimeout(() => resolve([]), 120));
    const outcome = await runRules([testRule({ id: 'A-001', timeoutMs: 1000, run: slow }), testRule({ id: 'B-001', run: slow })], ctx, { timeoutMs: 50 });
    expect(outcome.ruleErrors).toEqual([{ ruleId: 'B-001', message: 'timed out after 50 ms' }]);
  });

  it('runs rules concurrently', async () => {
    const ctx = memoryContext(nextApp);
    let releaseA!: () => void;
    const bStarted = new Promise<void>((resolve) => (releaseA = resolve));
    const outcome = await runRules(
      [
        testRule({ id: 'A-001', run: async () => (await bStarted, [{ evidence: 'a' }]) }),
        testRule({ id: 'B-001', run: async () => (releaseA(), [{ evidence: 'b' }]) }),
      ],
      ctx,
      { timeoutMs: 2000 },
    );
    expect(outcome.ruleErrors).toEqual([]);
    expect(outcome.runs.map((r) => r.rule.id)).toEqual(['A-001', 'B-001']);
  });
});
