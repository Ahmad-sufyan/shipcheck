import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { applyBaseline, baselineEntry, loadBaseline, pruneBaseline, type Baseline } from '../../../src/core/baseline.js';
import { ShipcheckError } from '../../../src/core/errors.js';
import { tmpProject } from '../../helpers/context.js';
import { makeFinding } from '../../helpers/results.js';

const a = makeFinding({ ruleId: 'SECRET-006', evidence: 'productionBrowserSourceMaps: true,' });
const b = makeFinding({ ruleId: 'HTTP-006', evidence: 'const nextConfig = {', line: 3, severity: 'low' });
const entry = (overrides: Partial<Baseline['entries'][number]> = {}) => ({ id: a.id, ruleId: a.ruleId, file: a.file, reason: 'accepted for the beta', createdAt: '2026-10-01', ...overrides });

function write(baseline: unknown): string {
  const root = tmpProject({});
  const file = join(root, '.shipcheck-baseline.json');
  writeFileSync(file, JSON.stringify(baseline));
  return file;
}

describe('loadBaseline', () => {
  it('reads a valid file', () => {
    expect(loadBaseline(write({ version: 1, entries: [entry({ acceptedBy: 'Ahmad', expires: '2027-01-01' })] }))).toEqual({
      version: 1,
      entries: [entry({ acceptedBy: 'Ahmad', expires: '2027-01-01' })],
    });
  });

  it.each([
    ['an entry without a reason', { version: 1, entries: [{ ...entry(), reason: undefined }] }, /entries\.0\.reason/],
    ['a blank reason', { version: 1, entries: [entry({ reason: '   ' })] }, /a reason is required/],
    ['a malformed expiry date', { version: 1, entries: [entry({ expires: 'next year' })] }, /entries\.0\.expires/],
    ['another version', { version: 2, entries: [] }, /version/],
  ])('rejects %s', (_name, baseline, message) => {
    expect(() => loadBaseline(write(baseline))).toThrow(ShipcheckError);
    expect(() => loadBaseline(write(baseline))).toThrow(message);
  });
});

describe('applyBaseline', () => {
  it('suppresses matching findings and lists them with their reason', () => {
    const { findings, suppressed, warnings } = applyBaseline([a, b], { version: 1, entries: [entry()] }, '2026-10-20');
    expect(findings).toEqual([b]);
    expect(suppressed).toEqual([{ id: a.id, ruleId: 'SECRET-006', reason: 'accepted for the beta' }]);
    expect(warnings).toEqual([]);
  });

  it('stops suppressing after the expiry date and warns', () => {
    const expired = applyBaseline([a], { version: 1, entries: [entry({ expires: '2026-10-19' })] }, '2026-10-20');
    expect(expired.findings).toEqual([a]);
    expect(expired.warnings).toEqual([`baseline entry ${a.id} (SECRET-006) expired on 2026-10-19 and no longer suppresses its finding`]);
    expect(applyBaseline([a], { version: 1, entries: [entry({ expires: '2026-10-20' })] }, '2026-10-20').findings).toEqual([]);
  });
});

describe('baselineEntry and pruneBaseline', () => {
  it('records a finding with today and an optional expiry', () => {
    expect(baselineEntry(a, { reason: 'initial', today: '2026-10-20', acceptedBy: 'ci', expires: '2027-01-31' })).toEqual({
      id: a.id,
      ruleId: 'SECRET-006',
      file: 'next.config.mjs',
      reason: 'initial',
      acceptedBy: 'ci',
      createdAt: '2026-10-20',
      expires: '2027-01-31',
    });
  });

  it('drops entries that match no current finding', () => {
    const baseline: Baseline = { version: 1, entries: [entry(), entry({ id: 'ffffffffffffffff', ruleId: 'OLD-001' })] };
    expect(pruneBaseline(baseline, [a, b])).toEqual({ baseline: { version: 1, entries: [entry()] }, removed: 1 });
  });
});
