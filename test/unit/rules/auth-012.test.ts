import { describe, expect, it } from 'vitest';
import { auth012 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-012-no-mfa.js';
import { runRule } from '../../helpers/memory-context.js';

const base = { 'app/api/login/route.ts': 'export async function POST() { await supabase.auth.signInWithPassword(creds) }' };

describe('AUTH-012 No MFA', () => {
  it('reports a project without any MFA usage, without a file', async () => {
    const findings = await runRule(rule, base);
    expect(findings).toHaveLength(1);
    expect(findings[0]).not.toHaveProperty('file');
    expect(findings[0]?.evidence).toMatch(/MFA/);
  });

  it.each([
    ['Supabase MFA enrollment', "await supabase.auth.mfa.enroll({ factorType: 'totp' })"],
    ['Supabase MFA challenge', 'await supabase.auth.mfa.challenge({ factorId })'],
    ['a TOTP library', "import { authenticator } from 'otplib'"],
    ['WebAuthn', "import { startRegistration } from '@simplewebauthn/browser'"],
  ])('is satisfied by %s', async (_name, line) => {
    expect(await runRule(rule, { ...base, 'app/account/security.ts': line })).toEqual([]);
  });

  it('ignores MFA mentions in tests only', async () => {
    expect(await runRule(rule, { ...base, 'tests/mfa.test.ts': "await supabase.auth.mfa.enroll({ factorType: 'totp' })" })).toHaveLength(1);
  });
});
