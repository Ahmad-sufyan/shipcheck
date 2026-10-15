import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { buildContext } from '../../src/context/build-context.js';
import { loadUserConfig } from '../../src/context/user-config.js';
import { scan } from '../../src/core/scan.js';
import { defaultRegistry } from '../../src/packs/index.js';
import type { ScanResult } from '../../src/types.js';
import { gitOnlyExec } from '../helpers/fake-exec.js';
import { collectMarkers } from '../helpers/markers.js';

const CLEAN = fileURLToPath(new URL('../../fixtures/clean-app', import.meta.url));
const registry = defaultRegistry();
/** Checks that need gitleaks or the network; the test scan runs offline with no scanners installed. */
const TOOL_CHECKS = new Set(['DEP-001', 'SECRET-003', 'SECRET-004']);

let result: ScanResult;
beforeAll(async () => {
  result = await scan(CLEAN, { offline: true, exec: gitOnlyExec });
});

describe('fixtures/clean-app', () => {
  it('has no findings from registered rules', () => {
    expect(result.findings.filter((f) => registry.has(f.ruleId)).map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual([]);
  });

  it('scans without rule errors or skipped inputs, with a perfect score', () => {
    expect(result.ruleErrors).toEqual([]);
    expect(result.skipped.filter((s) => !TOOL_CHECKS.has(s.check))).toEqual([]);
    expect(result.stack).toEqual(['nextjs-app-router', 'supabase', 'vercel']);
    expect(result.score).toMatchObject({ value: 100, grade: 'A' });
  });

  it('contains no expectation markers', () => {
    expect(collectMarkers(CLEAN)).toEqual({ markers: [], project: [] });
  });

  it('exposes the Next.js structure to rules', async () => {
    const { ctx } = await buildContext(CLEAN, loadUserConfig(CLEAN).config);
    expect(ctx.next.middleware()).toEqual({ file: 'proxy.ts', matchers: ['/((?!_next/static|_next/image|favicon.ico).*)'] });
    expect(ctx.next.serverActions().map((a) => `${a.file} ${a.name}`)).toEqual([
      'app/account/security/actions.ts enrollTotp',
      'app/account/security/actions.ts verifyTotp',
    ]);
    expect(ctx.nextConfig).toMatchObject({ hasHeadersFn: true, options: { poweredByHeader: { value: false, dynamic: false } } });
  });
});
