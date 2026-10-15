import { describe, expect, it } from 'vitest';
import { secret005 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-005-client-reachable-secret.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { code, runRule } from '../../helpers/memory-context.js';

const TSCONFIG = JSON.stringify({ compilerOptions: { paths: { '@/*': ['./*'] } } });
const client = (specifier: string) => code("'use client'", `import { PLANS } from '${specifier}'`, 'export function Pricing() { return PLANS.length }');
const billing = (...lines: string[]) => code("import Stripe from 'stripe'", ...lines, 'export const PLANS = []');

describe('SECRET-005 Server secret reachable from client code', () => {
  it('reports a non-public secret env var read in a module that client code imports', async () => {
    const findings = await runRule(rule, {
      'tsconfig.json': TSCONFIG,
      'components/pricing.tsx': client('@/lib/billing'),
      'lib/billing.ts': billing('const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)'),
    });
    expect(findings).toEqual([
      {
        file: 'lib/billing.ts',
        line: 2,
        evidence: 'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)',
        severity: 'medium',
        confidence: 'medium',
        explanation: expect.stringContaining('components/pricing.tsx → lib/billing.ts'),
      },
    ]);
  });

  it('reports a secret literal in a client-reachable module as critical, masked', async () => {
    const findings = await runRule(rule, { 'components/pricing.tsx': client('../lib/billing'), 'lib/billing.ts': billing(`const key = '${FAKE.stripe}'`) });
    expect(findings).toEqual([expect.objectContaining({ file: 'lib/billing.ts', line: 2, evidence: "const key = 'sk_t****'", confidence: 'high' })]);
    expect(findings[0]).not.toHaveProperty('severity');
  });

  it("is satisfied by import 'server-only'", async () => {
    const files = { 'components/pricing.tsx': client('../lib/billing'), 'lib/billing.ts': code("import 'server-only'", 'const key = process.env.STRIPE_SECRET_KEY', 'export const PLANS = []') };
    expect(await runRule(rule, files)).toEqual([]);
  });

  it('ignores public env vars, unreachable modules and the client entry itself', async () => {
    const files = {
      'components/pricing.tsx': code("'use client'", "import { PLANS } from '../lib/plans'", 'const t = process.env.API_TOKEN', 'export const x = PLANS'),
      'lib/plans.ts': code('export const url = process.env.NEXT_PUBLIC_SUPABASE_URL', 'export const PLANS = []'),
      'lib/server.ts': 'export const key = process.env.STRIPE_SECRET_KEY',
    };
    expect(await runRule(rule, files)).toEqual([]);
  });

  it('reports secrets in .next/static bundles from a local build', async () => {
    const bundle = `(()=>{var e={};e.k="${FAKE.stripe}";console.log(e)})();`;
    const findings = await runRule(rule, { '.next/static/chunks/app/page-abc123.js': bundle });
    expect(findings).toEqual([
      expect.objectContaining({ file: '.next/static/chunks/app/page-abc123.js', line: 1, column: bundle.indexOf('sk_') + 1, evidence: '(()=>{var e={};e.k="sk_t****";console.log(e)})();', confidence: 'high' }),
    ]);
  });
});
