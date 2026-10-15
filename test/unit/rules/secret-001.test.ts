import { describe, expect, it } from 'vitest';
import { secret001 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-001-public-env-secret.js';
import { FAKE } from '../../helpers/fake-secrets.js';
import { runRule } from '../../helpers/memory-context.js';

describe('SECRET-001 Secret in a NEXT_PUBLIC_ variable', () => {
  it('reports a NEXT_PUBLIC_ variable holding a secret value, without the value', async () => {
    const findings = await runRule(rule, { '.env.local': `NEXT_PUBLIC_SITE_URL=http://localhost:3000\nNEXT_PUBLIC_STRIPE_SECRET_KEY=${FAKE.stripe}` });
    expect(findings).toEqual([{ file: '.env.local', line: 2, evidence: 'NEXT_PUBLIC_STRIPE_SECRET_KEY=<redacted>', confidence: 'high', explanation: expect.stringContaining('Stripe') }]);
    expect(JSON.stringify(findings)).not.toContain(FAKE.stripe.slice(4));
  });

  it('reports a secret value behind a harmless-looking name', async () => {
    expect(await runRule(rule, { '.env': `NEXT_PUBLIC_SUPABASE_ANON_KEY=${FAKE.supabaseServiceJwt}` })).toEqual([expect.objectContaining({ line: 1, confidence: 'high' })]);
  });

  it('reports secret-like names with medium confidence when the value does not prove it', async () => {
    expect(await runRule(rule, { '.env.example': 'NEXT_PUBLIC_OPENAI_API_KEY=\nNEXT_PUBLIC_ADMIN_PASSWORD=changeme' })).toEqual([
      { file: '.env.example', line: 1, evidence: 'NEXT_PUBLIC_OPENAI_API_KEY=', confidence: 'medium' },
      { file: '.env.example', line: 2, evidence: 'NEXT_PUBLIC_ADMIN_PASSWORD=<redacted>', confidence: 'medium' },
    ]);
  });

  it('ignores keys that are public by design', async () => {
    const env = [
      'NEXT_PUBLIC_SUPABASE_URL=https://fakefakefakefake.supabase.co',
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${FAKE.supabaseAnonJwt}`,
      `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${FAKE.supabasePublishable}`,
      `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${FAKE.stripePublishable}`,
      `NEXT_PUBLIC_STRIPE_KEY=${FAKE.stripePublishable}`,
      'NEXT_PUBLIC_MAPBOX_TOKEN=pk.FAKEFAKEFAKE',
      'NEXT_PUBLIC_FIREBASE_API_KEY=AIzaFAKEFAKEFAKE',
      'NEXT_PUBLIC_TURNSTILE_SITE_KEY=0x4AAAAAAAFAKE',
    ].join('\n');
    expect(await runRule(rule, { '.env.local': env })).toEqual([]);
  });

  it('leaves NEXT_PUBLIC_*SERVICE_ROLE* names to AUTHZ-007 and ignores server-only names', async () => {
    expect(await runRule(rule, { '.env.local': `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${FAKE.supabaseServiceJwt}\nSTRIPE_SECRET_KEY=${FAKE.stripe}` })).toEqual([]);
  });
});
