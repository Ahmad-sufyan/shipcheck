import { describe, expect, it } from 'vitest';
import { authz002 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-002-matcher-gap.js';
import { code, runRule } from '../../helpers/memory-context.js';

const proxy = (matchers: string) =>
  code(
    "import { NextResponse, type NextRequest } from 'next/server'",
    'export async function proxy(request: NextRequest) {',
    '  const { data: { user } } = await supabase.auth.getUser()',
    "  if (!user) return NextResponse.redirect(new URL('/login', request.url))",
    '}',
    'export const config = {',
    `  matcher: ${matchers},`,
    '}',
  );

const unprotected = code('export async function POST(request: Request) {', "  await supabase.from('users').insert(await request.json())", '}');
const protectedRoute = code('export async function POST() {', '  const { data } = await supabase.auth.getUser()', '}');

describe('AUTHZ-002 Middleware matcher gap', () => {
  it('reports unmatched sensitive routes at the matcher line', async () => {
    const findings = await runRule(rule, { 'proxy.ts': proxy("['/dashboard/:path*']"), 'app/api/admin/users/route.ts': unprotected, 'app/dashboard/page.tsx': 'export default function P() {}' });
    expect(findings).toEqual([expect.objectContaining({ file: 'proxy.ts', line: 7, evidence: "matcher: ['/dashboard/:path*'],", explanation: expect.stringContaining('/api/admin/users') })]);
  });

  it('ignores routes that check auth themselves', async () => {
    expect(await runRule(rule, { 'proxy.ts': proxy("['/dashboard/:path*']"), 'app/api/admin/users/route.ts': protectedRoute })).toEqual([]);
  });

  it('ignores routes the matcher covers and public auth routes', async () => {
    expect(await runRule(rule, { 'proxy.ts': proxy("['/dashboard/:path*', '/api/:path*']"), 'app/api/admin/users/route.ts': unprotected })).toEqual([]);
    expect(await runRule(rule, { 'proxy.ts': proxy("['/dashboard/:path*']"), 'app/api/login/route.ts': unprotected })).toEqual([]);
  });

  it('does nothing when the proxy has no matcher or never checks auth', async () => {
    const noMatcher = proxy("['/dashboard/:path*']").replace("  matcher: ['/dashboard/:path*'],\n", '');
    expect(await runRule(rule, { 'proxy.ts': noMatcher, 'app/api/admin/users/route.ts': unprotected })).toEqual([]);
    const noAuth = code('export function proxy() { return NextResponse.next() }', "export const config = { matcher: ['/dashboard/:path*'] }");
    expect(await runRule(rule, { 'proxy.ts': noAuth, 'app/api/admin/users/route.ts': unprotected })).toEqual([]);
  });
});
