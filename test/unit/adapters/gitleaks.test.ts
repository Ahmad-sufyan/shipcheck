import { describe, expect, it } from 'vitest';
import { TOOL_TIMEOUT_MS } from '../../../src/adapters/exec.js';
import { gitleaksArgs, parseGitleaksReport, runGitleaks } from '../../../src/adapters/gitleaks.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';

const ROOT = '/project';
const KEY = 'sk_test_FAKEFAKEFAKEFAKEFAKEFAKE00';

describe('gitleaks adapter', () => {
  it('runs `gitleaks dir` with an argument array: JSON on stdout, redacted, no banner', async () => {
    const { exec, calls } = fakeExec(() => ({ stdout: '[]' }));
    expect(await runGitleaks(ROOT, 'dir', toolContext(exec))).toEqual({ ok: true, value: [] });
    expect(calls).toEqual([
      { command: 'gitleaks', args: ['dir', '.', '--report-format', 'json', '--report-path', '-', '--redact=100', '--no-banner', '--log-level', 'error'], cwd: ROOT, timeoutMs: TOOL_TIMEOUT_MS },
    ]);
  });

  it('treats exit code 1 with a JSON report as success', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 1, stdout: recorded('gitleaks-dir.json') }));
    const run = await runGitleaks(ROOT, 'dir', toolContext(exec));
    expect(run).toEqual({
      ok: true,
      value: [
        expect.objectContaining({ ruleId: 'stripe-access-token', file: '.env.local', startLine: 6 }),
        { ruleId: 'stripe-access-token', description: expect.stringContaining('Stripe'), file: 'lib/stripe.ts', startLine: 4, endLine: 4, startColumn: 35, endColumn: 69 },
      ],
    });
  });

  it('makes columns 1-based and inclusive: gitleaks reports them one too high after the first line', () => {
    // Real gitleaks 8.30 output for `KEY\nconst a = 1\nexport const k = 'KEY'\n`.
    const report = [
      { RuleID: 'stripe-access-token', File: 'lf.ts', StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 34 },
      { RuleID: 'stripe-access-token', File: 'lf.ts', StartLine: 3, EndLine: 3, StartColumn: 20, EndColumn: 54 },
    ];
    expect(parseGitleaksReport(report)?.map((l) => [l.startLine, l.startColumn, l.endColumn])).toEqual([
      [1, 1, 34],
      [3, 19, 53],
    ]);
  });

  it('never carries Match or Secret into the normalized leaks', () => {
    const leaks = parseGitleaksReport(JSON.parse(recorded('gitleaks-dir-unredacted.json')));
    expect(JSON.stringify(leaks)).not.toContain(KEY.slice(0, 8));
  });

  it('reports a missing binary as a skip with an install hint', async () => {
    const { exec } = fakeExec();
    expect(await runGitleaks(ROOT, 'dir', toolContext(exec))).toEqual({ ok: false, reason: expect.stringMatching(/^gitleaks is not installed; install gitleaks 8\.19 or newer: https:\/\/github\.com\/gitleaks/) });
  });

  it('reports a timeout as a skip', async () => {
    const { exec } = fakeExec(() => 'timeout');
    expect(await runGitleaks(ROOT, 'dir', toolContext(exec))).toEqual({ ok: false, reason: 'gitleaks timed out after 120 s' });
  });

  it('explains when gitleaks is too old for the dir/git commands', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 1, stderr: 'Error: unknown command "dir" for "gitleaks"\n' }));
    expect(await runGitleaks(ROOT, 'dir', toolContext(exec))).toEqual({ ok: false, reason: expect.stringContaining('older than 8.19') });
  });

  it('reports unparseable output with the first stderr line', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 126, stdout: 'not json', stderr: '\nfatal: config invalid\nmore' }));
    expect(await runGitleaks(ROOT, 'dir', toolContext(exec))).toEqual({ ok: false, reason: 'gitleaks failed (exit code 126): fatal: config invalid' });
  });

  it('scans history relative to the scan root inside a larger repository', async () => {
    const report = JSON.parse(recorded('gitleaks-git.json')) as { File: string }[];
    const nested = JSON.stringify([...report.map((leak) => ({ ...leak, File: `apps/web/${leak.File}` })), { ...report[0], File: 'apps/other/lib/stripe.ts' }]);
    const { exec, calls } = fakeExec((command) => (command === 'git' ? { stdout: 'apps/web/\n' } : { exitCode: 1, stdout: nested }));
    const run = await runGitleaks(ROOT, 'git', toolContext(exec));
    expect(calls.map((c) => [c.command, ...c.args].slice(0, 3).join(' '))).toEqual(['git rev-parse --show-prefix', 'gitleaks git .']);
    expect(run.ok && run.value.map((l) => `${l.file}:${l.startLine}@${l.commit?.slice(0, 7)}`)).toEqual(['config/legacy-keys.ts:2@ed7ede7', 'lib/stripe.ts:4@e3a2ff3']);
  });

  it('skips history scans outside a git repository', async () => {
    const { exec, calls } = fakeExec((command) => (command === 'git' ? { exitCode: 128, stderr: 'fatal: not a git repository' } : { stdout: '[]' }));
    expect(await runGitleaks(ROOT, 'git', toolContext(exec))).toEqual({ ok: false, reason: expect.stringContaining('not a git repository') });
    expect(calls.map((c) => c.command)).toEqual(['git']);
  });

  it('runs once per scan and mode', async () => {
    const { exec, calls } = fakeExec(() => ({ stdout: '[]' }));
    const tools = toolContext(exec);
    await Promise.all([runGitleaks(ROOT, 'dir', tools), runGitleaks(ROOT, 'dir', tools)]);
    expect(calls).toHaveLength(1);
  });

  it('normalizes Windows paths', () => {
    expect(parseGitleaksReport([{ RuleID: 'x', File: 'lib\\stripe.ts', StartLine: 1 }])).toEqual([expect.objectContaining({ file: 'lib/stripe.ts' })]);
    expect(parseGitleaksReport({ not: 'an array' })).toBeUndefined();
    expect(gitleaksArgs('git')[0]).toBe('git');
  });
});
