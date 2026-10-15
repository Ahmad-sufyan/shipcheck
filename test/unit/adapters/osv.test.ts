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
        {
          package: 'next',
          version: '15.1.0',
          ids: ['GHSA-f82v-jwr5-mffw', 'CVE-2025-29927'],
          title: 'Authorization Bypass in Next.js Middleware',
          cvss: 9.1,
          severity: 'critical',
          url: 'https://github.com/advisories/GHSA-f82v-jwr5-mffw',
          fixedVersions: ['13.5.9', '14.2.25', '15.2.3', '12.3.5'],
          dev: false,
          tool: 'osv-scanner',
        },
        expect.objectContaining({ package: 'esbuild', version: '0.24.2', cvss: 5.3, severity: 'moderate', fixedVersions: ['0.25.0'], dev: true }),
      ],
    });
  });

  it('treats exit code 128 (no packages found) as an empty result', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 128, stderr: 'No package sources found' }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({ ok: true, value: [] });
  });

  it('skips on errors, even with JSON output', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 129, stdout: '{"results":[]}' }));
    expect(await runOsvScanner(ROOT, 'package-lock.json', toolContext(exec))).toEqual({ ok: false, reason: 'osv-scanner failed (exit code 129)' });
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
