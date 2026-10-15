import { describe, expect, it } from 'vitest';
import { auth013 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-013-logout-session.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/logout/route.ts';
const post = (...body: string[]) => code('export async function POST() {', '  const cookieStore = await cookies()', ...body.map((l) => `  ${l}`), '  return NextResponse.json({ ok: true })', '}');

describe('AUTH-013 Logout leaves session valid', () => {
  it('reports a logout that only clears the cookie', async () => {
    expect(await runRule(rule, { [ROUTE]: post("cookieStore.delete('session')") })).toEqual([{ file: ROUTE, line: 3, evidence: "cookieStore.delete('session')" }]);
  });

  it('reports a server action logout that expires the cookie', async () => {
    const text = code("'use server'", 'export async function logout() {', "  (await cookies()).set('session', '', { maxAge: 0 })", '}');
    expect(await runRule(rule, { 'app/actions.ts': text })).toEqual([expect.objectContaining({ line: 3 })]);
  });

  it('ignores logouts that call signOut()', async () => {
    expect(await runRule(rule, { [ROUTE]: post('await supabase.auth.signOut()', "cookieStore.delete('session')") })).toEqual([]);
  });

  it('ignores logouts that delete the server-side session', async () => {
    expect(await runRule(rule, { [ROUTE]: post("await pool.query('delete from sessions where id = $1', [id])", "cookieStore.delete('session')") })).toEqual([]);
  });

  it('ignores handlers that are not logouts', async () => {
    expect(await runRule(rule, { 'app/api/preferences/route.ts': post("cookieStore.delete('theme')") })).toEqual([]);
  });
});
