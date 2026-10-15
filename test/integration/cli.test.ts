import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultRegistry } from '../../src/packs/index.js';
import { ScanResultSchema } from '../../src/schema.js';
import { shipcheck } from '../helpers/cli.js';
import { tmpProject } from '../helpers/context.js';

const ANSI = /\x1b\[[0-9;]*m/;

/** Turns off every rule except `ids`, so later rules do not change what these CLI tests see. */
const only = (ids: string[], extra: Record<string, string> = {}) =>
  JSON.stringify({ rules: { ...Object.fromEntries(defaultRegistry().all().filter((r) => !ids.includes(r.id)).map((r) => [r.id, 'off'])), ...extra } });

/** One low (HTTP-006) and one medium (SECRET-006) finding. */
const leaky = {
  'shipcheck.config.json': only(['SECRET-006', 'HTTP-006']),
  'package.json': JSON.stringify({ dependencies: { next: '16.4.1' } }),
  'app/page.tsx': 'export default function Page() { return null }',
  'next.config.mjs': 'const nextConfig = {\n  productionBrowserSourceMaps: true,\n}\nexport default nextConfig\n',
};

const clean = { ...leaky, 'next.config.mjs': 'export default { poweredByHeader: false }\n' };

describe.concurrent('shipcheck CLI', () => {
  it('lists the scan command in --help', async () => {
    const { exitCode, stdout } = await shipcheck(['--help']);
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/scan \[options\] \[path\]/);
  });

  it('prints its version', async () => {
    const { exitCode, stdout } = await shipcheck(['--version']);
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('prints help and exits 2 without a command', async () => {
    const { exitCode, stderr } = await shipcheck([]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Usage: shipcheck');
  });

  it('writes schema-valid JSON to stdout', async () => {
    const { exitCode, stdout } = await shipcheck(['scan', tmpProject(leaky), '--format', 'json', '--fail-on', 'none']);
    expect(exitCode).toBe(0);
    const result = ScanResultSchema.parse(JSON.parse(stdout));
    expect(result.findings.map((f) => f.ruleId)).toEqual(['SECRET-006', 'HTTP-006']);
  });

  it('writes markdown and text', async () => {
    const root = tmpProject(leaky);
    expect((await shipcheck(['scan', root, '--format', 'md', '--fail-on', 'none'])).stdout).toMatch(/^# shipcheck report/);
    const text = await shipcheck(['scan', root, '--fail-on', 'none']);
    expect(text.stdout).toMatch(/MEDIUM\s+SECRET-006/);
    expect(text.stdout).not.toMatch(ANSI);
  });

  it('exits 1 only when a non-advisory finding is at or above --fail-on (default high)', async () => {
    const root = tmpProject(leaky);
    expect((await shipcheck(['scan', root])).exitCode).toBe(0);
    expect((await shipcheck(['scan', root, '--fail-on', 'medium'])).exitCode).toBe(1);
    expect((await shipcheck(['scan', root, '--fail-on', 'low'])).exitCode).toBe(1);
    expect((await shipcheck(['scan', tmpProject(clean), '--fail-on', 'low'])).exitCode).toBe(0);
  });

  it('treats --min-severity as a display filter only', async () => {
    const { exitCode, stdout } = await shipcheck(['scan', tmpProject(leaky), '--min-severity', 'medium', '--fail-on', 'low']);
    expect(exitCode).toBe(1);
    expect(stdout).toContain('SECRET-006');
    expect(stdout).not.toContain('HTTP-006');
  });

  it('writes the report to --out', async () => {
    const root = tmpProject(leaky);
    const out = join(root, 'reports', 'shipcheck.json');
    const { exitCode, stdout, stderr } = await shipcheck(['scan', root, '--format', 'json', '--out', out, '--fail-on', 'none']);
    expect(exitCode).toBe(0);
    expect(stdout).toBe('');
    expect(stderr).toContain('shipcheck.json');
    expect(existsSync(out)).toBe(true);
    expect(ScanResultSchema.parse(JSON.parse(readFileSync(out, 'utf8'))).findings).toHaveLength(2);
  });

  it('uses --config', async () => {
    const root = tmpProject({ ...leaky, 'strict.json': only(['SECRET-006', 'HTTP-006'], { 'HTTP-006': 'critical' }) });
    const { exitCode, stdout } = await shipcheck(['scan', root, '--config', join(root, 'strict.json'), '--format', 'json']);
    expect(exitCode).toBe(1);
    expect(JSON.parse(stdout).findings[0]).toMatchObject({ ruleId: 'HTTP-006', severity: 'critical' });
  });

  it('respects NO_COLOR and FORCE_COLOR', async () => {
    const root = tmpProject(leaky);
    expect((await shipcheck(['scan', root, '--fail-on', 'none'], { FORCE_COLOR: '1' })).stdout).toMatch(ANSI);
    expect((await shipcheck(['scan', root, '--fail-on', 'none'], { FORCE_COLOR: '1', NO_COLOR: '1' })).stdout).not.toMatch(ANSI);
  });

  it('reports HTTP-006 and SECRET-006 for fixtures/demo-app as schema-valid JSON', async () => {
    const { exitCode, stdout } = await shipcheck(['scan', 'fixtures/demo-app', '--format', 'json', '--fail-on', 'none']);
    expect(exitCode).toBe(0);
    const result = ScanResultSchema.parse(JSON.parse(stdout));
    expect(result.target.path).toBe('fixtures/demo-app');
    expect(result.findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual(expect.arrayContaining(['SECRET-006 next.config.mjs:9', 'HTTP-006 next.config.mjs:3']));
  });

  it('exits 0 for fixtures/clean-app with --fail-on low and 1 for fixtures/demo-app with --fail-on medium', async () => {
    expect((await shipcheck(['scan', 'fixtures/clean-app', '--fail-on', 'low'])).exitCode).toBe(0);
    expect((await shipcheck(['scan', 'fixtures/demo-app', '--fail-on', 'medium'])).exitCode).toBe(1);
  });

  it('produces identical JSON for repeated scans apart from durationMs', async () => {
    const [a, b] = await Promise.all([1, 2].map(() => shipcheck(['scan', 'fixtures/demo-app', '--format', 'json'])));
    const strip = (stdout: string) => ({ ...JSON.parse(stdout), durationMs: 0 });
    expect(strip(a!.stdout)).toEqual(strip(b!.stdout));
  });

  it.each([
    [['scan', 'does-not-exist'], /Path does not exist: does-not-exist/],
    [['scan', '.', '--format', 'xml'], /argument 'xml' is invalid/],
    [['scan', '.', '--fail-on', 'severe'], /argument 'severe' is invalid/],
    [['scan', '.', '--config', 'missing.json'], /Config file not found: missing\.json/],
    [['scan', '.', '--bogus'], /unknown option/],
  ])('exits 2 with a clear message for %j', async (args, message) => {
    const { exitCode, stderr, stdout } = await shipcheck(args);
    expect(exitCode).toBe(2);
    expect(stderr).toMatch(message);
    expect(stdout).toBe('');
  });
});
