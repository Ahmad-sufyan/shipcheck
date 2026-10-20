import { describe, expect, it } from 'vitest';
import { clientReachableModules, resolveImport } from '../../../src/packs/nextjs-supabase/analysis/import-graph.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

const tsconfig = JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['./*'], '~lib/*': ['lib/*'] } } });

describe('resolveImport', () => {
  const ctx = memoryContext({
    'tsconfig.json': `// comment\n${tsconfig}`,
    'components/a.tsx': '',
    'lib/billing.ts': '',
    'lib/utils/index.ts': '',
    'lib/esm.ts': '',
  });

  it.each([
    ['../lib/billing', 'lib/billing.ts'],
    ['@/lib/billing', 'lib/billing.ts'],
    ['~lib/billing', 'lib/billing.ts'],
    ['@/lib/utils', 'lib/utils/index.ts'],
    ['../lib/esm.js', 'lib/esm.ts'],
  ])('%s -> %s', (specifier, expected) => {
    expect(resolveImport(ctx, 'components/a.tsx', specifier)).toBe(expected);
  });

  it('does not resolve packages from node_modules or missing files', () => {
    expect(resolveImport(ctx, 'components/a.tsx', 'react')).toBeUndefined();
    expect(resolveImport(ctx, 'components/a.tsx', '@/lib/missing')).toBeUndefined();
  });
});

describe('clientReachableModules', () => {
  it('follows imports transitively from client files, recording the path', () => {
    const ctx = memoryContext({
      'tsconfig.json': tsconfig,
      'components/pricing.tsx': code("'use client'", "import { price } from '@/lib/billing'", "import type { Plan } from '@/lib/types'", "import { useState } from 'react'"),
      'lib/billing.ts': "import { stripe } from './stripe'\nexport const price = 1",
      'lib/stripe.ts': 'export const stripe = {}',
      'lib/types.ts': 'export type Plan = string',
      'lib/server-only-thing.ts': "import { stripe } from './stripe'",
      'app/page.tsx': "import { price } from '@/lib/billing'",
    });
    const reachable = clientReachableModules(ctx);
    expect([...reachable.keys()].sort()).toEqual(['components/pricing.tsx', 'lib/billing.ts', 'lib/stripe.ts']);
    expect(reachable.get('lib/stripe.ts')).toEqual(['components/pricing.tsx', 'lib/billing.ts', 'lib/stripe.ts']);
  });

  it('follows dynamic imports and re-exports', () => {
    const ctx = memoryContext({
      'components/a.tsx': "'use client'\nexport { b } from './b'\nconst c = () => import('./c')",
      'components/b.ts': 'export const b = 1',
      'components/c.ts': 'export const c = 1',
    });
    expect([...clientReachableModules(ctx).keys()].sort()).toEqual(['components/a.tsx', 'components/b.ts', 'components/c.ts']);
  });
});
