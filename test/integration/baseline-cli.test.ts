import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { defaultRegistry } from '../../src/packs/index.js';
import { ScanResultSchema } from '../../src/schema.js';
import { shipcheck } from '../helpers/cli.js';
import { tmpProject } from '../helpers/context.js';
import { FAKE } from '../helpers/fake-secrets.js';

const DEMO = fileURLToPath(new URL('../../fixtures/demo-app', import.meta.url));

/** Only these rules run, so the project's findings stay predictable. */
const only = (ids: string[]) => JSON.stringify({ rules: Object.fromEntries(defaultRegistry().all().filter((r) => !ids.includes(r.id)).map((r) => [r.id, 'off'])) });

/** SECRET-006 (medium) and HTTP-006 (low) from next.config; SECRET-004 stays on for planted keys. */
const project = () =>
  tmpProject({
    'package.json': JSON.stringify({ name: 'app', private: true, dependencies: { next: '16.4.1' } }),
    'app/page.tsx': 'export default function Page() { return null }',
    'next.config.mjs': 'const nextConfig = {\n  productionBrowserSourceMaps: true,\n}\nexport default nextConfig\n',
    'shipcheck.config.json': only(['SECRET-006', 'HTTP-006', 'SECRET-004']),
  });

const json = (stdout: string) => ScanResultSchema.parse(JSON.parse(stdout));
const baselineOf = (root: string) => JSON.parse(readFileSync(join(root, '.shipcheck-baseline.json'), 'utf8')) as { entries: { id: string; reason: string; expires?: string }[] };

describe.concurrent('shipcheck baseline', { timeout: 120_000 }, () => {
  it('create accepts current findings: the re-scan passes, a new finding still fails', async () => {
    const root = project();
    expect((await shipcheck(['scan', root, '--offline', '--fail-on', 'low'])).exitCode).toBe(1);
    const create = await shipcheck(['baseline', 'create', root, '--offline', '--reason', 'initial', '--accepted-by', 'ci']);
    expect(create.exitCode).toBe(0);
    expect(create.stdout).toContain('Wrote 2 entries');
    expect(baselineOf(root).entries.map((e) => e.reason)).toEqual(['initial', 'initial']);

    const rescan = await shipcheck(['scan', root, '--offline', '--fail-on', 'low', '--format', 'json']);
    expect(rescan.exitCode).toBe(0);
    const result = json(rescan.stdout);
    expect(result.findings).toEqual([]);
    expect(result.suppressed.map((s) => [s.ruleId, s.reason]).sort()).toEqual([
      ['HTTP-006', 'initial'],
      ['SECRET-006', 'initial'],
    ]);
    expect(result.suppressedCount).toBe(2);
    expect(result.score.value).toBe(100);

    writeFileSync(join(root, 'lib.ts'), `export const stripe = '${FAKE.stripe}'\n`);
    const planted = await shipcheck(['scan', root, '--offline', '--fail-on', 'high', '--format', 'json']);
    expect(planted.exitCode).toBe(1);
    expect(json(planted.stdout).findings.map((f) => f.ruleId)).toEqual(['SECRET-004']);

    expect((await shipcheck(['scan', root, '--offline', '--fail-on', 'low', '--no-baseline'])).exitCode).toBe(1);
  });

  it('requires a reason', async () => {
    const root = project();
    const missing = await shipcheck(['baseline', 'create', root, '--offline']);
    expect(missing.exitCode).toBe(2);
    expect(missing.stderr).toContain("required option '--reason <text>' not specified");
    const blank = await shipcheck(['baseline', 'create', root, '--offline', '--reason', '   ']);
    expect(blank.exitCode).toBe(2);
    expect(blank.stderr).toContain('needs a reason');
  });

  it('rejects a baseline file with an entry that has no reason', async () => {
    const root = project();
    writeFileSync(join(root, '.shipcheck-baseline.json'), JSON.stringify({ version: 1, entries: [{ id: '0123456789abcdef', ruleId: 'X-001', file: null, createdAt: '2026-10-01' }] }));
    const { exitCode, stderr } = await shipcheck(['scan', root, '--offline']);
    expect(exitCode).toBe(2);
    expect(stderr).toMatch(/Invalid baseline .*\n.*entries\.0\.reason/);
  });

  it('stops honouring expired entries and warns', async () => {
    const root = project();
    await shipcheck(['baseline', 'create', root, '--offline', '--reason', 'initial']);
    const file = join(root, '.shipcheck-baseline.json');
    const baseline = baselineOf(root);
    baseline.entries[0]!.expires = '2020-01-31';
    writeFileSync(file, JSON.stringify(baseline));
    const { exitCode, stderr } = await shipcheck(['scan', root, '--offline', '--fail-on', 'low']);
    expect(exitCode).toBe(1);
    expect(stderr).toMatch(/shipcheck: warning: baseline entry [0-9a-f]{16} \(\S+\) expired on 2020-01-31/);
  });

  it('add accepts one finding by id with an expiry; prune drops entries that match nothing', async () => {
    const root = project();
    const ids = json((await shipcheck(['scan', root, '--offline', '--format', 'json'])).stdout).findings.map((f) => f.id);
    const add = await shipcheck(['baseline', 'add', ids[0]!, root, '--offline', '--reason', 'tracked in issue 12', '--expires', '2999-12-31']);
    expect(add.exitCode).toBe(0);
    expect(baselineOf(root).entries).toEqual([expect.objectContaining({ id: ids[0], reason: 'tracked in issue 12', expires: '2999-12-31' })]);
    expect((await shipcheck(['baseline', 'add', 'ffffffffffffffff', root, '--offline', '--reason', 'x'])).stderr).toContain('No current finding has the id ffffffffffffffff');

    writeFileSync(join(root, 'next.config.mjs'), 'export default { poweredByHeader: false }\n');
    const prune = await shipcheck(['baseline', 'prune', root, '--offline']);
    expect(prune.stdout).toContain('Removed 1 entry');
    expect(baselineOf(root).entries).toEqual([]);
  });

  it('honours shipcheck-ignore-next-line with a reason and warns without one', async () => {
    const root = project();
    writeFileSync(join(root, 'next.config.mjs'), 'const nextConfig = {\n  // shipcheck-ignore-next-line SECRET-006\n  productionBrowserSourceMaps: true,\n  poweredByHeader: false,\n}\nexport default nextConfig\n');
    const bare = await shipcheck(['scan', root, '--offline', '--format', 'json']);
    expect(json(bare.stdout).findings.map((f) => f.ruleId)).toEqual(['SECRET-006']);
    expect(bare.stderr).toContain('next.config.mjs:2: shipcheck-ignore-next-line without a reason is ignored');
    writeFileSync(join(root, 'next.config.mjs'), 'const nextConfig = {\n  // shipcheck-ignore-next-line SECRET-006: maps are uploaded to Sentry and deleted\n  productionBrowserSourceMaps: true,\n  poweredByHeader: false,\n}\nexport default nextConfig\n');
    const result = json((await shipcheck(['scan', root, '--offline', '--format', 'json'])).stdout);
    expect(result.findings).toEqual([]);
    expect(result.suppressed).toEqual([expect.objectContaining({ ruleId: 'SECRET-006', reason: 'maps are uploaded to Sentry and deleted' })]);
  });

  it('works on a copy of fixtures/demo-app: baseline, then only a planted bug fails', async () => {
    const root = tmpProject({});
    cpSync(DEMO, root, { recursive: true });
    expect((await shipcheck(['baseline', 'create', root, '--offline', '--reason', 'initial'])).exitCode).toBe(0);
    expect((await shipcheck(['scan', root, '--offline', '--fail-on', 'high'])).exitCode).toBe(0);
    writeFileSync(join(root, 'app/api/planted/route.ts'.replace('/route.ts', '.ts')), `export const key = '${FAKE.stripe}'\n`);
    const planted = await shipcheck(['scan', root, '--offline', '--fail-on', 'high', '--format', 'json']);
    expect(planted.exitCode).toBe(1);
    expect(json(planted.stdout).findings.map((f) => `${f.ruleId} ${f.file}`)).toEqual(['SECRET-004 app/api/planted.ts']);
  });
});
