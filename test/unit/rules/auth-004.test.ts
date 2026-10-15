import { describe, expect, it } from 'vitest';
import { auth004 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-004-insecure-cookie.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/login/route.ts';
const post = (...body: string[]) => code("import { cookies } from 'next/headers'", 'export async function POST(request: Request) {', '  const cookieStore = await cookies()', ...body.map((l) => `  ${l}`), '}');

describe('AUTH-004 Insecure session cookie', () => {
  it('reports a session cookie set without options', async () => {
    const findings = await runRule(rule, { [ROUTE]: post("cookieStore.set('session', sessionId)") });
    expect(findings).toEqual([expect.objectContaining({ file: ROUTE, line: 4, evidence: "cookieStore.set('session', sessionId)" })]);
    expect(findings[0]?.explanation).toMatch(/httpOnly.*secure.*sameSite/);
  });

  it('reports missing flags and long lifetimes', async () => {
    expect(await runRule(rule, { [ROUTE]: post("cookieStore.set('auth_token', t, { httpOnly: true })") })).toHaveLength(1);
    const long = post('const DAY = 60 * 60 * 24', "cookieStore.set('sid', t, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: DAY * 60 })");
    expect((await runRule(rule, { [ROUTE]: long }))[0]?.explanation).toMatch(/30 days/);
  });

  it('reports the object form on a response', async () => {
    const text = code('export async function POST() {', '  const res = NextResponse.json({ ok: true })', "  res.cookies.set({ name: 'jwt', value: t, secure: true })", '  return res', '}');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 3 })]);
  });

  it('ignores cookies with httpOnly, secure and sameSite, including options held in a variable', async () => {
    expect(await runRule(rule, { [ROUTE]: post("cookieStore.set('session', id, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 60 * 60 * 8 })") })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: post("const opts = { httpOnly: true, secure: true, sameSite: 'strict' as const }", "cookieStore.set('oauth_state', s, opts)") })).toEqual([]);
  });

  it('ignores non-sensitive cookie names', async () => {
    expect(await runRule(rule, { [ROUTE]: post("cookieStore.set('theme', 'dark')") })).toEqual([]);
  });

  it('ignores the @supabase/ssr cookie adapter', async () => {
    const adapter = code(
      'export async function createClient() {',
      '  const cookieStore = await cookies()',
      '  return createServerClient(url, key, {',
      '    cookies: {',
      '      getAll() { return cookieStore.getAll() },',
      "      setAll(list) { list.forEach(({ name, value, options }) => cookieStore.set('sb-auth-token', value, options)) },",
      '    },',
      '  })',
      '}',
    );
    expect(await runRule(rule, { 'lib/supabase/server.ts': adapter })).toEqual([]);
  });
});
