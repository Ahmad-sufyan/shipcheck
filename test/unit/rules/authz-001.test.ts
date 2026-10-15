import { describe, expect, it } from 'vitest';
import { authz001 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-001-handler-without-auth.js';
import { code, locations, runRule } from '../../helpers/memory-context.js';

const createUser = code(
  "import { createClient } from '@/lib/supabase/server'",
  'export async function POST(request: Request) {',
  '  const supabase = await createClient()',
  "  const { data } = await supabase.from('notes').insert({ text: 'x' })",
  '  return Response.json(data)',
  '}',
);

describe('AUTHZ-001 Handler without auth check', () => {
  it('reports a mutating handler that writes to the database as critical', async () => {
    const findings = await runRule(rule, { 'app/api/notes/route.ts': createUser });
    expect(findings).toEqual([expect.objectContaining({ file: 'app/api/notes/route.ts', line: 2, severity: 'critical' })]);
  });

  it('reports a mutating handler without database access as high', async () => {
    const text = code('export async function PUT(request: Request) {', "  revalidatePath('/')", '  return Response.json({ ok: true })', '}');
    const findings = await runRule(rule, { 'app/api/cache/route.ts': text });
    expect(findings).toEqual([expect.objectContaining({ line: 1 })]);
    expect(findings[0]?.severity).toBeUndefined();
  });

  it('reports a GET on a private-looking path that reads data, with medium confidence', async () => {
    const text = code('export async function GET() {', "  const { data } = await supabase.from('profiles').select('*')", '  return Response.json(data)', '}');
    expect(await runRule(rule, { 'app/api/admin/profiles/route.ts': text })).toEqual([expect.objectContaining({ line: 1, confidence: 'medium' })]);
  });

  it('reports server actions that touch data without auth', async () => {
    const text = code("'use server'", 'export async function deleteNote(id: string) {', "  await supabase.from('notes').delete().eq('id', id)", '}');
    expect(await runRule(rule, { 'app/actions.ts': text })).toEqual([expect.objectContaining({ file: 'app/actions.ts', line: 2, severity: 'critical' })]);
  });

  it('ignores handlers that check auth', async () => {
    const text = createUser.replace('const supabase = await createClient()', 'const supabase = await createClient()\n  const { data: { user } } = await supabase.auth.getUser()\n  if (!user) return new Response(null, { status: 401 })');
    expect(await runRule(rule, { 'app/api/notes/route.ts': text })).toEqual([]);
  });

  it('ignores sign-in flows, webhooks, configured public paths and public GET reads', async () => {
    expect(await runRule(rule, { 'app/api/login/route.ts': createUser, 'app/api/webhooks/stripe/route.ts': createUser })).toEqual([]);
    expect(await runRule(rule, { 'app/api/public/notes/route.ts': createUser }, { publicPaths: ['/api/public/**'] })).toEqual([]);
    const search = code('export async function GET(request: Request) {', "  const { rows } = await pool.query('select * from posts')", '  return Response.json(rows)', '}');
    expect(await runRule(rule, { 'app/api/search/route.ts': search })).toEqual([]);
  });

  it('ignores routes covered by an auth-checking proxy', async () => {
    const proxy = code(
      'export async function proxy(request: NextRequest) {',
      '  const { data: { user } } = await supabase.auth.getUser()',
      "  if (!user) return NextResponse.redirect(new URL('/login', request.url))",
      '}',
      "export const config = { matcher: ['/api/:path*'] }",
    );
    expect(await runRule(rule, { 'app/api/notes/route.ts': createUser, 'proxy.ts': proxy })).toEqual([]);
  });

  it('explains when the handler only calls getSession()', async () => {
    const text = createUser.replace('const supabase = await createClient()', 'const supabase = await createClient()\n  const { data } = await supabase.auth.getSession()');
    const [finding] = await runRule(rule, { 'app/api/notes/route.ts': text });
    expect(finding?.explanation).toMatch(/getSession\(\)/);
    expect(locations(await runRule(rule, { 'app/api/notes/route.ts': text }))).toEqual(['app/api/notes/route.ts:2']);
  });
});
