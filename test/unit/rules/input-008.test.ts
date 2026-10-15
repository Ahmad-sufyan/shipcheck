import { describe, expect, it } from 'vitest';
import { input008 as rule } from '../../../src/packs/nextjs-supabase/rules/input-008-open-redirect.js';
import { code, runRule } from '../../helpers/memory-context.js';

const get = (...body: string[]) =>
  code("import { redirect } from 'next/navigation'", 'export async function GET(request: NextRequest) {', '  const { searchParams } = request.nextUrl', ...body.map((l) => `  ${l}`), '}');

describe('INPUT-008 Open redirect', () => {
  it('reports redirect() to a request-controlled location', async () => {
    expect(await runRule(rule, { 'app/go/route.ts': get("redirect(searchParams.get('next') ?? '/')") })).toEqual([
      { file: 'app/go/route.ts', line: 4, evidence: "redirect(searchParams.get('next') ?? '/')" },
    ]);
  });

  it('reports NextResponse.redirect, Response.redirect and permanentRedirect', async () => {
    const text = get("const next = searchParams.get('next')!", 'if (next.length > 100) return Response.redirect(next)', 'permanentRedirect(next)', 'return NextResponse.redirect(new URL(next, request.url))');
    expect((await runRule(rule, { 'app/go/route.ts': text })).map((f) => f.line)).toEqual([5, 6, 7]);
  });

  it('ignores allowlist lookups and same-origin checks', async () => {
    const lookup = get("const MAP: Record<string, string> = { home: '/' }", "redirect(MAP[searchParams.get('to') ?? 'home'] ?? '/')");
    expect(await runRule(rule, { 'app/go/route.ts': lookup })).toEqual([]);
    const origin = get("const target = new URL(searchParams.get('next') ?? '/', request.url)", 'if (target.origin !== request.nextUrl.origin) redirect(\'/\')', 'redirect(target.toString())');
    expect(await runRule(rule, { 'app/go/route.ts': origin })).toEqual([]);
  });

  it('leaves auth callback routes to AUTH-009', async () => {
    expect(await runRule(rule, { 'app/auth/callback/route.ts': get("redirect(searchParams.get('next') ?? '/')") })).toEqual([]);
  });
});
