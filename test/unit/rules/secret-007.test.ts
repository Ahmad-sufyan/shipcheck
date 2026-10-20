import { describe, expect, it } from 'vitest';
import { secret007 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-007-env-example-values.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { runRule } from '../../helpers/memory-context.js';

describe('SECRET-007 Real values in .env.example', () => {
  it('reports values that match a secret format, without the value', async () => {
    const findings = await runRule(rule, { '.env.example': `NEXT_PUBLIC_SUPABASE_URL=\nSTRIPE_SECRET_KEY=${FAKE.stripe}` });
    expect(findings).toEqual([{ file: '.env.example', line: 2, evidence: 'STRIPE_SECRET_KEY=<redacted>', confidence: 'high', explanation: expect.stringContaining('Stripe') }]);
  });

  it('reports long random values and database URLs with a password', async () => {
    const findings = await runRule(rule, {
      '.env.sample': 'SESSION_SECRET=q8Zr2Lm9Tv4Rp7Wn1BcY6kH3sJ0d\nDATABASE_URL=postgres://app:Xk29dLq7Vz@db.prod.internal:5432/app',
    });
    expect(findings.map((f) => `${f.line} ${f.confidence}`)).toEqual(['1 medium', '2 high']);
  });

  it('ignores placeholders, public URLs, public keys and local development defaults', async () => {
    const env = [
      'STRIPE_SECRET_KEY=your-stripe-secret-key',
      'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx',
      'SUPABASE_SERVICE_ROLE_KEY=<service-role-key>',
      'NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co',
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${FAKE.supabaseAnonJwt}`,
      `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${FAKE.stripePublishable}`,
      'DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres',
      'JWT_SECRET=changeme',
      'NODE_ENV=development',
    ].join('\n');
    expect(await runRule(rule, { '.env.example': env })).toEqual([]);
  });

  it('only looks at example files', async () => {
    expect(await runRule(rule, { '.env.local': `STRIPE_SECRET_KEY=${FAKE.stripe}` })).toEqual([]);
  });
});
