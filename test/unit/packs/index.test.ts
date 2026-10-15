import { describe, expect, it } from 'vitest';
import { defaultRegistry, packs } from '../../../src/packs/index.js';

describe('packs', () => {
  it('registers the nextjs-supabase pack', () => {
    expect(packs.map((p) => p.id)).toEqual(['nextjs-supabase']);
  });

  it('builds a registry with every pilot rule', () => {
    expect(defaultRegistry().all().map((r) => r.id)).toEqual(['HTTP-006', 'SECRET-006']);
  });

  it('gives every rule complete documentation', () => {
    for (const rule of defaultRegistry().all()) {
      for (const field of ['description', 'explanation', 'fix', 'falsePositiveNote'] as const) {
        expect(rule[field].length, `${rule.id}.${field}`).toBeGreaterThan(20);
      }
    }
  });
});
