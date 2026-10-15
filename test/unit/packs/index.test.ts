import { describe, expect, it } from 'vitest';
import { defaultRegistry, packs } from '../../../src/packs/index.js';

describe('packs', () => {
  it('registers the nextjs-supabase pack', () => {
    expect(packs.map((p) => p.id)).toEqual(['nextjs-supabase']);
  });

  it('builds a registry with every rule from Chunks 1 and 2, sorted and unique', () => {
    const range = (prefix: string, count: number) => Array.from({ length: count }, (_, i) => `${prefix}-${String(i + 1).padStart(3, '0')}`);
    const ids = defaultRegistry().all().map((r) => r.id);
    expect(ids).toEqual(expect.arrayContaining([...range('AUTH', 13), ...range('AUTHZ', 8), 'HTTP-006', ...range('INPUT', 12), 'SECRET-006']));
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(ids);
  });

  it('gives every rule complete documentation', () => {
    for (const rule of defaultRegistry().all()) {
      for (const field of ['description', 'explanation', 'fix', 'falsePositiveNote'] as const) {
        expect(rule[field].length, `${rule.id}.${field}`).toBeGreaterThan(20);
      }
    }
  });
});
