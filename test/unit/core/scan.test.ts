import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ShipcheckError } from '../../../src/core/errors.js';
import { filterFindings, hasBlockingFindings, scan, VERSION } from '../../../src/core/scan.js';
import { ScanResultSchema } from '../../../src/schema.js';
import { tmpProject } from '../../helpers/context.js';
import { makeFinding, makeResult } from '../../helpers/results.js';
import { testRule } from '../../helpers/rules.js';

const project = {
  'package.json': JSON.stringify({ dependencies: { next: '16.4.1', '@supabase/supabase-js': '2.0.0' } }),
  'app/page.tsx': 'export default function Page() { return null }',
  'next.config.mjs': 'export default {\n  productionBrowserSourceMaps: true,\n}\n',
};

const rules = [
  testRule({
    id: 'A-001',
    severity: 'high',
    stacks: ['nextjs-app-router'],
    run: (ctx) => [{ file: ctx.nextConfig!.file, line: ctx.nextConfig!.objectLine, evidence: 'export default {' }],
  }),
  testRule({ id: 'B-001', stacks: ['cloudflare'] }),
];

describe('scan', () => {
  it('fails clearly for a missing path or a file', async () => {
    await expect(scan('does-not-exist-anywhere')).rejects.toThrow(ShipcheckError);
    await expect(scan('does-not-exist-anywhere')).rejects.toThrow(/Path does not exist: does-not-exist-anywhere/);
    const root = tmpProject({ 'a.txt': '' });
    await expect(scan(join(root, 'a.txt'))).rejects.toThrow(/Not a directory/);
  });

  it('returns a schema-valid result', async () => {
    const root = tmpProject(project);
    const result = await scan(root, { rules });
    expect(ScanResultSchema.parse(result)).toEqual(result);
    expect(result.tool).toEqual({ name: 'shipcheck', version: VERSION });
    expect(result.stack).toEqual(['nextjs-app-router', 'supabase']);
    expect(result.findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual(['A-001 next.config.mjs:1']);
    expect(result.skipped).toEqual([{ check: 'B-001', reason: 'requires stack not detected: cloudflare' }]);
    expect(result.score).toMatchObject({ value: 79, grade: 'C' });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('reports the version from package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });

  it('honours shipcheck.config.json in the scan root and an explicit --config file', async () => {
    const root = tmpProject({ ...project, 'shipcheck.config.json': '{"rules":{"A-001":"off"}}', 'other.json': '{"rules":{"A-001":"info"}}' });
    expect((await scan(root, { rules })).findings).toEqual([]);
    const explicit = await scan(root, { rules, configFile: join(root, 'other.json') });
    expect(explicit.findings.map((f) => f.severity)).toEqual(['info']);
  });

  it('filters displayed findings by minimum severity without touching the score', () => {
    const result = makeResult([makeFinding({ severity: 'high' }), makeFinding({ severity: 'low', ruleId: 'HTTP-006' })]);
    const filtered = filterFindings(result, 'medium');
    expect(filtered.findings.map((f) => f.severity)).toEqual(['high']);
    expect(filtered.score).toEqual(result.score);
    expect(filterFindings(result, 'info')).toBe(result);
  });

  it('decides whether findings should fail the run', () => {
    const result = makeResult([makeFinding({ severity: 'medium' }), makeFinding({ severity: 'critical', advisory: true, ruleId: 'X-001' })]);
    expect(hasBlockingFindings(result, 'medium')).toBe(true);
    expect(hasBlockingFindings(result, 'low')).toBe(true);
    expect(hasBlockingFindings(result, 'high')).toBe(false);
    expect(hasBlockingFindings(result, 'none')).toBe(false);
  });

  it('is deterministic apart from durationMs', async () => {
    const root = tmpProject(project);
    const strip = ({ durationMs: _d, ...rest }: Awaited<ReturnType<typeof scan>>) => rest;
    expect(strip(await scan(root, { rules }))).toEqual(strip(await scan(root, { rules })));
  });
});
