import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { buildContext } from '../../src/context/build-context.js';
import { loadUserConfig } from '../../src/context/user-config.js';
import { scan } from '../../src/core/scan.js';
import { defaultRegistry } from '../../src/packs/index.js';
import type { Finding, ScanResult } from '../../src/types.js';
import { checkRuleAgainstExpectations, collectMarkers, expectedRuleIds, type Marker } from '../helpers/markers.js';

const DEMO = fileURLToPath(new URL('../../fixtures/demo-app', import.meta.url));
const expectations = collectMarkers(DEMO);
const registry = defaultRegistry();

const showMarker = (m: Marker) => `${m.file}:${m.line} [${m.ruleIds.join(', ')}]`;
const showFinding = (f: Finding) => `${f.ruleId} ${f.file ?? f.url ?? '(project)'}:${f.line ?? '-'} ${f.evidence}`;

let result: ScanResult;
beforeAll(async () => {
  result = await scan(DEMO);
});

describe('fixtures/demo-app', () => {
  it('scans cleanly with the expected stack', () => {
    expect(result.ruleErrors).toEqual([]);
    expect(result.stack).toEqual(['nextjs-app-router', 'supabase', 'vercel']);
  });

  it('only reports findings from registered rules', () => {
    expect(result.findings.filter((f) => !registry.has(f.ruleId)).map(showFinding)).toEqual([]);
  });

  for (const rule of registry.all()) {
    describe(rule.id, () => {
      it('matches every marker', () => {
        const check = checkRuleAgainstExpectations(rule.id, result.findings, expectations);
        expect(check.unmatchedMarkers.map(showMarker)).toEqual([]);
        expect(check.missingProjectFinding).toBe(false);
      });

      it('reports nothing unexpected', () => {
        const check = checkRuleAgainstExpectations(rule.id, result.findings, expectations);
        expect(check.unexpectedFindings.map(showFinding)).toEqual([]);
      });
    });
  }

  for (const ruleId of expectedRuleIds(expectations).filter((id) => !registry.has(id))) {
    it.todo(`${ruleId}: planted in fixtures/demo-app, rule not implemented yet`);
  }
});

describe('fixtures/demo-app context', () => {
  it('exposes the Next.js structure to rules', async () => {
    const { ctx, skipped } = await buildContext(DEMO, loadUserConfig(DEMO).config);
    expect(skipped).toEqual([]);
    expect(ctx.next.middleware()).toEqual({ file: 'proxy.ts', matchers: ['/dashboard/:path*'] });
    expect(ctx.next.routeHandlers().map((h) => `${h.method} ${h.routePath}`)).toEqual(expect.arrayContaining([
      'GET /api/admin/stats',
      'POST /api/admin/users',
      'GET /api/files',
      'GET /api/invoices/[id]',
      'POST /api/legacy',
      'POST /api/login',
      'POST /api/logout',
      'GET /api/oauth/start',
      'POST /api/password-reset',
      'GET /api/preview',
      'GET /api/search',
      'POST /api/settings',
      'GET /api/thumbnail',
      'POST /api/upload',
      'GET /auth/callback',
      'GET /go',
    ]));
    expect(ctx.next.serverActions()).toEqual([]);
    expect(['components/admin-client.tsx', 'components/admin-panel.tsx', 'components/token-store.ts'].every((f) => ctx.next.isClientFile(f))).toBe(true);
    expect(ctx.next.isClientFile('components/comment.tsx')).toBe(false);
    expect(ctx.nextConfig?.options.productionBrowserSourceMaps).toEqual({ value: true, line: 9, dynamic: false });
    expect(ctx.sqlMigrations.map((m) => m.file)).toEqual(['supabase/migrations/0001_init.sql', 'supabase/migrations/0002_storage.sql']);
  });
});
