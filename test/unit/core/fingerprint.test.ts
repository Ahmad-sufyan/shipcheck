import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../../src/core/fingerprint.js';

describe('fingerprint', () => {
  it('is the first 16 hex chars of sha256(ruleId|file|evidence)', () => {
    const expected = createHash('sha256').update('HTTP-006|next.config.mjs|const a = 1').digest('hex').slice(0, 16);
    expect(fingerprint({ ruleId: 'HTTP-006', file: 'next.config.mjs', evidence: 'const a = 1' })).toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{16}$/);
  });

  it('collapses whitespace in evidence', () => {
    const a = fingerprint({ ruleId: 'R-001', file: 'a.ts', evidence: 'foo(\n    bar,\t baz)' });
    const b = fingerprint({ ruleId: 'R-001', file: 'a.ts', evidence: 'foo( bar, baz)' });
    const c = fingerprint({ ruleId: 'R-001', file: 'a.ts', evidence: '  foo( bar, baz)  ' });
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('falls back to url, then to an empty location', () => {
    const viaUrl = createHash('sha256').update('LIVE-001|https://x.test/|hdr').digest('hex').slice(0, 16);
    expect(fingerprint({ ruleId: 'LIVE-001', file: null, url: 'https://x.test/', evidence: 'hdr' })).toBe(viaUrl);
    const empty = createHash('sha256').update('AUTH-012||none').digest('hex').slice(0, 16);
    expect(fingerprint({ ruleId: 'AUTH-012', evidence: 'none' })).toBe(empty);
  });

  it('differs by rule and by file', () => {
    const base = fingerprint({ ruleId: 'R-001', file: 'a.ts', evidence: 'x' });
    expect(fingerprint({ ruleId: 'R-002', file: 'a.ts', evidence: 'x' })).not.toBe(base);
    expect(fingerprint({ ruleId: 'R-001', file: 'b.ts', evidence: 'x' })).not.toBe(base);
  });
});
