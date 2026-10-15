import { describe, expect, it } from 'vitest';
import { auth002 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-002-login-rate-limit.js';
import { code, runRule } from '../../helpers/memory-context.js';

const login = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '  return Response.json({ ok: true })', '}');
const verify = 'const ok = await bcrypt.compare(password, user.password_hash)';

describe('AUTH-002 Login without brute-force protection', () => {
  it('reports a login route without a rate limiter', async () => {
    expect(await runRule(rule, { 'app/api/login/route.ts': login(verify) })).toEqual([{ file: 'app/api/login/route.ts', line: 1, evidence: 'export async function POST(request: Request) {' }]);
  });

  it('recognises login handlers by bcrypt.compare on other paths', async () => {
    expect(await runRule(rule, { 'app/api/session/route.ts': login(verify) })).toHaveLength(1);
  });

  it('reports a server action that only proxies Supabase Auth with low confidence', async () => {
    const action = code("'use server'", 'export async function signIn(formData: FormData) {', "  await supabase.auth.signInWithPassword({ email: String(formData.get('email')), password: String(formData.get('password')) })", '}');
    expect(await runRule(rule, { 'app/login/actions.ts': action })).toEqual([expect.objectContaining({ line: 2, confidence: 'low' })]);
  });

  it('ignores rate-limited login handlers', async () => {
    expect(await runRule(rule, { 'app/api/login/route.ts': login("if (!rateLimit(`login:${ip}`)) return new Response(null, { status: 429 })", verify) })).toEqual([]);
  });

  it('ignores handlers that are not logins', async () => {
    expect(await runRule(rule, { 'app/api/posts/route.ts': login("await supabase.from('posts').insert({ a: 1 })") })).toEqual([]);
  });
});
