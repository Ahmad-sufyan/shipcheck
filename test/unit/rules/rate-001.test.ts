import { describe, expect, it } from 'vitest';
import { rate001 as rule } from '../../../src/packs/nextjs-supabase/rules/rate-001-sensitive-endpoint.js';
import { code, runRule } from '../../helpers/memory-context.js';

const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '  return Response.json({ ok: true })', '}');

describe('RATE-001 Sensitive endpoint without rate limit', () => {
  it('reports a sign-up handler that only proxies Supabase Auth, with low confidence', async () => {
    expect(await runRule(rule, { 'app/api/signup/route.ts': post('await supabase.auth.signUp({ email, password })') })).toEqual([
      { file: 'app/api/signup/route.ts', line: 1, evidence: 'export async function POST(request: Request) {', confidence: 'low' },
    ]);
  });

  it('reports OTP and magic-link handlers', async () => {
    expect(await runRule(rule, { 'app/api/otp/route.ts': post('await supabase.auth.verifyOtp({ email, token, type: "email" })', 'await pool.query("insert into logins (email) values ($1)", [email])') })).toEqual([
      expect.objectContaining({ line: 1 }),
    ]);
  });

  it('reports contact forms that send email as medium', async () => {
    const findings = await runRule(rule, { 'app/api/contact/route.ts': post("await resend.emails.send({ from: 'a', to: 'b', subject: 'c', text: 'd' })") });
    expect(findings).toEqual([expect.objectContaining({ severity: 'medium' })]);
  });

  it('ignores handlers with a rate limiter', async () => {
    expect(await runRule(rule, { 'app/api/signup/route.ts': post('if (!(await rateLimit(ip))) return new Response(null, { status: 429 })', 'await supabase.auth.signUp({ email, password })') })).toEqual([]);
  });

  it('leaves logins to AUTH-002 and ignores ordinary handlers', async () => {
    expect(await runRule(rule, { 'app/api/login/route.ts': post('await supabase.auth.signInWithPassword({ email, password })') })).toEqual([]);
    expect(await runRule(rule, { 'app/api/posts/route.ts': post("await supabase.from('posts').insert({ a: 1 })") })).toEqual([]);
  });
});
