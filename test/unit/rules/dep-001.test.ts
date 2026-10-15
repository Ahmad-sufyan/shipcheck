import { describe, expect, it } from 'vitest';
import { dep001 as rule } from '../../../src/packs/nextjs-supabase/rules/dep-001-vulnerable-dependency.js';
import type { FakeResponse } from '../../helpers/fake-exec.js';
import { fakeExec, recorded, toolContext } from '../../helpers/fake-exec.js';
import { lineOf, memoryContext } from '../../helpers/memory-context.js';
import { npmLockfile, packageJson } from '../../helpers/lockfiles.js';

const LOCK = npmLockfile({ 'node_modules/next': { version: '15.1.0' }, 'node_modules/esbuild': { version: '0.24.2', dev: true }, 'node_modules/vite': { version: '6.1.0', dev: true } });
const FILES = { 'package.json': packageJson({ next: '15.1.0' }, { devDependencies: { vite: '^6.1.0' } }), 'package-lock.json': LOCK };

async function run(respond: (command: string, args: readonly string[]) => FakeResponse, { offline = false, files = FILES }: { offline?: boolean; files?: Record<string, string> } = {}) {
  const { exec, calls } = fakeExec(respond);
  const ctx = memoryContext(files, {}, { tools: toolContext(exec, offline) });
  const skipped: { check: string; reason: string }[] = [];
  ctx.skip = (check, reason) => skipped.push({ check, reason });
  return { findings: await rule.run(ctx), skipped, calls };
}

describe('DEP-001 Known vulnerable dependency', () => {
  it('reports osv-scanner results with CVSS-based severity, one level lower for dev dependencies', async () => {
    const { findings, skipped } = await run(() => ({ exitCode: 1, stdout: recorded('osv-scanner.json') }));
    expect(skipped).toEqual([]);
    expect(findings).toEqual([
      {
        file: 'package-lock.json',
        line: lineOf(LOCK, '"node_modules/next"'),
        evidence: 'next@15.1.0: GHSA-f82v-jwr5-mffw (CVE-2025-29927) Authorization Bypass in Next.js Middleware',
        severity: 'critical',
        explanation: expect.stringContaining('CVSS 9.1'),
        fix: 'Upgrade next to 15.2.3 or later (https://github.com/advisories/GHSA-f82v-jwr5-mffw).',
        source: 'tool:osv',
      },
      expect.objectContaining({ line: lineOf(LOCK, '"node_modules/esbuild"'), severity: 'low', explanation: expect.stringContaining('development dependency') }),
    ]);
  });

  it('is skipped with --offline, without running anything', async () => {
    const { findings, skipped, calls } = await run(() => ({ stdout: recorded('osv-scanner.json') }), { offline: true });
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
    expect(skipped).toEqual([{ check: 'DEP-001', reason: expect.stringContaining('--offline') }]);
  });

  it('falls back to npm audit, taking versions from the lockfile', async () => {
    const { findings } = await run((command) => (command === 'npm' ? { exitCode: 1, stdout: recorded('npm-audit.json') } : 'missing'));
    expect(findings.map((f) => `${f.evidence} | ${f.severity} | ${f.source}`)).toEqual([
      'esbuild@0.24.2: GHSA-67mh-4wv8-2f99 esbuild enables any website to send any requests to the development server and read the response | low | tool:npm-audit',
      'next@15.1.0: GHSA-f82v-jwr5-mffw Authorization Bypass in Next.js Middleware | critical | tool:npm-audit',
    ]);
  });

  it('maps advisory labels when there is no CVSS score (pnpm audit)', async () => {
    const files = { 'package.json': packageJson({ next: '15.1.0' }), 'pnpm-lock.yaml': "lockfileVersion: '9.0'\n\npackages:\n\n  next@15.1.0:\n    resolution: {integrity: sha512-x}\n" };
    const { findings } = await run((command) => (command === 'pnpm' ? { exitCode: 1, stdout: recorded('pnpm-audit.json') } : 'missing'), { files });
    expect(findings.map((f) => `${f.file}:${f.line ?? '-'} ${f.severity}`)).toEqual(['pnpm-lock.yaml:- low', 'pnpm-lock.yaml:5 critical']);
  });

  it('records why it could not run', async () => {
    const { findings, skipped } = await run(() => 'missing');
    expect(findings).toEqual([]);
    expect(skipped).toEqual([{ check: 'DEP-001', reason: expect.stringMatching(/osv-scanner is not installed.*npm is not installed/) }]);
  });

  it('leaves projects without a lockfile to DEP-002', async () => {
    const { findings, calls } = await run(() => ({ stdout: '{}' }), { files: { 'package.json': packageJson({ next: '15.1.0' }) } });
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });
});
