import { describe, expect, it } from 'vitest';
import { http004 as rule } from '../../../src/packs/nextjs-supabase/rules/http-004-csrf.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/profile/route.ts';
const post = (...body: string[]) =>
  code("import { createClient } from '@/lib/supabase/server'", 'export async function POST(request: Request) {', '  const supabase = await createClient()', '  const { data: { user } } = await supabase.auth.getUser()', ...body.map((l) => `  ${l}`), '}');

describe('HTTP-004 CSRF on a cookie-authenticated handler', () => {
  it('reports a form-handling mutation with cookie auth and no origin check', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const form = await request.formData()', "await supabase.from('profiles').update({ name: String(form.get('name')) }).eq('id', user.id)") })).toEqual([
      { file: ROUTE, line: 2, evidence: 'export async function POST(request: Request) {' },
    ]);
  });

  it('reports mutations without a body', async () => {
    expect(await runRule(rule, { 'app/api/account/route.ts': post("await supabase.from('profiles').delete().eq('id', user.id)").replace('POST', 'DELETE') })).toHaveLength(1);
  });

  it('accepts an Origin or Referer check, including in a same-file helper', async () => {
    expect(await runRule(rule, { [ROUTE]: post("if (request.headers.get('origin') !== new URL(request.url).origin) return new Response(null, { status: 403 })", 'const form = await request.formData()') })).toEqual([]);
    const helper = code("function sameOrigin(r: Request) { return r.headers.get('referer')?.startsWith(process.env.APP_URL!) }", post('if (!sameOrigin(request)) return new Response(null, { status: 403 })', 'await request.formData()'));
    expect(await runRule(rule, { [ROUTE]: helper })).toEqual([]);
  });

  it('ignores JSON-only handlers and unauthenticated handlers', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const body = await request.json()') })).toEqual([]);
    expect(await runRule(rule, { 'app/api/contact/route.ts': code('export async function POST(request: Request) {', '  await request.formData()', '}') })).toEqual([]);
  });
});
