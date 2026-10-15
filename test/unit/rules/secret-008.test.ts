import { describe, expect, it } from 'vitest';
import { secret008 as rule } from '../../../src/packs/nextjs-supabase/rules/secret-008-env-validation.js';
import { code, runRule } from '../../helpers/memory-context.js';

const usesEnv = { 'lib/stripe.ts': 'export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)' };

describe('SECRET-008 No startup env validation', () => {
  it('reports once, without a file, when process.env is used but never validated', async () => {
    const findings = await runRule(rule, usesEnv);
    expect(findings).toEqual([{ evidence: expect.stringContaining('process.env') }]);
  });

  it.each([
    ['a zod parse of process.env', code("import { z } from 'zod'", 'export const env = z.object({ A: z.string() }).parse(process.env)')],
    ['a safeParse of process.env', 'const parsed = EnvSchema.safeParse(process.env)'],
    ['t3-env createEnv', "export const env = createEnv({ server: {}, client: {}, runtimeEnv: process.env })"],
    ['envalid cleanEnv', 'export const env = cleanEnv(process.env, { API_KEY: str() })'],
  ])('is satisfied by %s', async (_name, text) => {
    expect(await runRule(rule, { ...usesEnv, 'lib/env.ts': text })).toEqual([]);
  });

  it('is satisfied by an env validation package', async () => {
    expect(await runRule(rule, { ...usesEnv, 'package.json': JSON.stringify({ dependencies: { '@t3-oss/env-nextjs': '0.13.0' } }) })).toEqual([]);
  });

  it('ignores projects that read no environment variables', async () => {
    expect(await runRule(rule, { 'app/page.tsx': 'export default function Page() { return null }' })).toEqual([]);
  });
});
