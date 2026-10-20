import { describe, expect, it } from 'vitest';
import { TOOL_TIMEOUT_MS } from '../../../src/adapters/exec.js';
import { findVulnerabilities } from '../../../src/adapters/index.js';
import { runPackageAudit } from '../../../src/adapters/npm-audit.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';

const ROOT = '/project';

describe('npm audit adapter', () => {
  it('runs `npm audit --json --package-lock-only` and normalizes advisories (exit code 1)', async () => {
    const { exec, calls } = fakeExec(() => ({ exitCode: 1, stdout: recorded('npm-audit.json') }));
    const run = await runPackageAudit(ROOT, 'npm', toolContext(exec));
    expect(calls).toEqual([{ command: 'npm', args: ['audit', '--json', '--package-lock-only'], cwd: ROOT, timeoutMs: TOOL_TIMEOUT_MS }]);
    expect(run).toEqual({
      ok: true,
      value: [
        expect.objectContaining({ package: 'esbuild', version: '', ids: ['GHSA-67mh-4wv8-2f99'], cvss: 5.3, severity: 'moderate', fixedVersions: [] }),
        {
          package: 'next',
          version: '',
          ids: ['GHSA-f82v-jwr5-mffw'],
          title: 'Authorization Bypass in Next.js Middleware',
          cvss: 9.1,
          severity: 'critical',
          url: 'https://github.com/advisories/GHSA-f82v-jwr5-mffw',
          fixedVersions: ['15.5.24'],
          tool: 'npm audit',
        },
      ],
    });
  });

  it('reports audit errors as skips', async () => {
    const { exec } = fakeExec(() => ({ exitCode: 1, stdout: '{"error":{"code":"ENOLOCK","summary":"This command requires an existing lockfile."}}' }));
    expect(await runPackageAudit(ROOT, 'npm', toolContext(exec))).toEqual({ ok: false, reason: 'npm audit failed: This command requires an existing lockfile.' });
  });
});

describe('pnpm audit adapter', () => {
  it('runs `pnpm audit --json` and keeps installed versions and dev flags', async () => {
    const { exec, calls } = fakeExec(() => ({ exitCode: 1, stdout: recorded('pnpm-audit.json') }));
    const run = await runPackageAudit(ROOT, 'pnpm', toolContext(exec));
    expect(calls[0]?.args).toEqual(['audit', '--json']);
    expect(run.ok && run.value.map((v) => `${v.package}@${v.version} ${v.ids[0]} ${v.severity} dev=${v.dev} fix=${v.fixedVersions.join()}`)).toEqual([
      'esbuild@0.24.2 GHSA-67mh-4wv8-2f99 moderate dev=true fix=0.25.0',
      'next@15.1.0 GHSA-f82v-jwr5-mffw critical dev=false fix=15.2.3',
    ]);
  });
});

describe('findVulnerabilities', () => {
  const lockfile = { kind: 'npm' as const, file: 'package-lock.json' };

  it('prefers osv-scanner', async () => {
    const { exec, calls } = fakeExec(() => ({ stdout: recorded('osv-scanner.json') }));
    const run = await findVulnerabilities(ROOT, lockfile, toolContext(exec));
    expect(run.ok && run.value.tool).toBe('osv-scanner');
    expect(calls.map((c) => c.command)).toEqual(['osv-scanner']);
  });

  it('falls back to npm audit when osv-scanner is missing', async () => {
    const { exec, calls } = fakeExec((command) => (command === 'npm' ? { exitCode: 1, stdout: recorded('npm-audit.json') } : 'missing'));
    const run = await findVulnerabilities(ROOT, lockfile, toolContext(exec));
    expect(run.ok && [run.value.tool, run.value.vulnerabilities.length]).toEqual(['npm audit', 2]);
    expect(calls.map((c) => c.command)).toEqual(['osv-scanner', 'npm']);
  });

  it('explains both failures when nothing works', async () => {
    const run = await findVulnerabilities(ROOT, { kind: 'pnpm', file: 'pnpm-lock.yaml' }, toolContext(fakeExec().exec));
    expect(run).toEqual({ ok: false, reason: expect.stringMatching(/^osv-scanner is not installed.*; pnpm is not installed/) });
  });

  it('has no fallback for yarn and bun', async () => {
    const run = await findVulnerabilities(ROOT, { kind: 'yarn', file: 'yarn.lock' }, toolContext(fakeExec().exec));
    expect(run).toEqual({ ok: false, reason: expect.stringContaining('no audit fallback for yarn lockfiles') });
  });
});
