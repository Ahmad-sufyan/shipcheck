import { describe, expect, it } from 'vitest';
import { renderText, shouldUseColor } from '../../../src/reporters/text.js';
import { makeFinding, makeResult } from '../../helpers/results.js';

const ANSI = /\x1b\[[0-9;]*m/;

describe('renderText', () => {
  const result = makeResult(
    [
      makeFinding({ ruleId: 'AUTHZ-001', title: 'Route without auth', category: 'authorization', severity: 'critical', file: 'app/api/admin/users/route.ts', line: 12, evidence: 'export async function POST(req: Request) {' }),
      makeFinding(),
      makeFinding({ ruleId: 'HTTP-006', title: 'X-Powered-By header enabled', severity: 'low', line: 2, evidence: 'const nextConfig = {', advisory: true }),
    ],
    { suppressedCount: 1, skipped: [{ check: 'B-001', reason: 'requires stack not detected: cloudflare' }], ruleErrors: [{ ruleId: 'X-001', message: 'boom' }] },
  );

  it('prints a compact, uncoloured report', () => {
    const out = renderText(result, { color: false });
    expect(out).not.toMatch(ANSI);
    expect(out).toContain('shipcheck 0.1.0');
    expect(out).toContain(`Score: ${result.score.value}/100 (${result.score.grade})`);
    expect(out).toMatch(/CRITICAL\s+AUTHZ-001\s+Route without auth/);
    expect(out).toContain('app/api/admin/users/route.ts:12');
    expect(out).toContain('> export async function POST(req: Request) {');
    expect(out).toContain('Fix: Remove `productionBrowserSourceMaps`.');
    expect(out).toContain('[advisory]');
    expect(out).toContain('3 findings: 1 critical, 0 high, 1 medium, 1 low, 0 info; 1 suppressed');
    expect(out).toContain('Skipped: B-001 (requires stack not detected: cloudflare)');
    expect(out).toContain('Rule errors: X-001: boom');
    expect(out.indexOf('AUTHZ-001')).toBeLessThan(out.indexOf('SECRET-006'));
  });

  it('colours severities when asked', () => {
    expect(renderText(result, { color: true })).toMatch(ANSI);
  });

  it('reports a clean result', () => {
    expect(renderText(makeResult(), { color: false })).toContain('No findings.');
  });
});

describe('shouldUseColor', () => {
  it('respects NO_COLOR, then FORCE_COLOR, then the TTY', () => {
    expect(shouldUseColor({}, true)).toBe(true);
    expect(shouldUseColor({}, false)).toBe(false);
    expect(shouldUseColor({ NO_COLOR: '1' }, true)).toBe(false);
    expect(shouldUseColor({ NO_COLOR: '' }, true)).toBe(true);
    expect(shouldUseColor({ FORCE_COLOR: '1' }, false)).toBe(true);
    expect(shouldUseColor({ FORCE_COLOR: '0' }, true)).toBe(false);
    expect(shouldUseColor({ NO_COLOR: '1', FORCE_COLOR: '1' }, true)).toBe(false);
  });
});
