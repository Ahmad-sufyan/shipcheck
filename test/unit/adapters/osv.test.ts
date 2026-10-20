import { describe, expect, it } from 'vitest';
import { TOOL_TIMEOUT_MS } from '../../../src/adapters/exec.js';
import { parseOsvReport, runOsvScanner } from '../../../src/adapters/osv.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';

const ROOT = '/project';

describe('osv-scanner adapter', () => {
  it('scans the lockfile with `scan source --lockfile ... --format json`', async () => {
    const { exec, calls } = fakeExec(() => ({ stdout: '{"results":[]}' }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({ ok: true, value: [] });
    expect(calls).toEqual([{ command: 'osv-scanner', args: ['scan', 'source', '--lockfile', 'package-lock.json', '--format', 'json'], cwd: ROOT, timeoutMs: TOOL_TIMEOUT_MS }]);
  });

  it('normalizes the recorded report (exit code 1 = vulnerabilities found)', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 1, stdout: recorded('osv-scanner.json') }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({
      ok: true,
      value: [
        expect.objectContaining({ package: 'esbuild', version: '0.24.2', cvss: 5.3, severity: 'moderate', fixedVersions: ['0.25.0'], dev: true }),
        {
          package: 'next',
          version: '15.1.0',
          ids: ['GHSA-f82v-jwr5-mffw', 'CVE-2025-29927'],
          title: 'Authorization Bypass in Next.js Middleware',
          cvss: 9.1,
          severity: 'critical',
          url: 'https://github.com/advisories/GHSA-f82v-jwr5-mffw',
          fixedVersions: ['13.5.9', '14.2.25', '15.2.3', '12.3.5'],
          tool: 'osv-scanner',
        },
      ],
    });
  });

  it('leaves dev unknown when osv-scanner reports no dependency groups (production packages)', () => {
    const report = { results: [{ packages: [{ package: { name: 'a', version: '1.0.0', ecosystem: 'npm' }, groups: [{ ids: ['GHSA-1'], aliases: [], max_severity: '' }], vulnerabilities: [{ id: 'GHSA-1' }] }] }] };
    const withGroups = (dependency_groups: string[]) => ({ results: [{ packages: [{ ...report.results[0]!.packages[0]!, dependency_groups }] }] });
    expect(parseOsvReport(report)?.[0]?.dev).toBeUndefined();
    expect(parseOsvReport(withGroups(['dev']))?.[0]?.dev).toBe(true);
    expect(parseOsvReport(withGroups(['dev', 'optional']))?.[0]?.dev).toBe(false);
    expect(parseOsvReport(withGroups(['optional']))?.[0]?.dev).toBe(false);
  });

  it('treats exit code 128 (no packages found) as an empty result', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 128, stderr: 'No package sources found' }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({ ok: true, value: [] });
  });

  it('skips on errors, even with JSON output (exit code 127 when osv.dev cannot be reached)', async () => {
    const stderr = 'Starting filesystem walk for root: /\nError during extraction: (extracting as vulnmatch/osvdev) max retries exceeded\n';
    const { exec } = fakeExec(() => ({ exitCode: 127, stdout: '{\n  "results": []\n}\n', stderr }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({ ok: false, reason: 'osv-scanner failed (exit code 127)' });
  });

  it('skips with an install hint when the binary is missing, and on timeouts', async () => {
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(fakeExec().exec))).toEqual({ ok: false, reason: expect.stringMatching(/^osv-scanner is not installed; install osv-scanner v2/) });
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(fakeExec(() => 'timeout').exec))).toEqual({ ok: false, reason: 'osv-scanner timed out after 120 s' });
  });

  it('ignores other ecosystems and unexpected shapes', () => {
    expect(parseOsvReport({ results: [{ packages: [{ package: { name: 'requests', version: '1.0', ecosystem: 'PyPI' }, vulnerabilities: [{ id: 'PYSEC-1' }] }] }] })).toEqual([]);
    expect(parseOsvReport([])).toBeUndefined();
  });
});
