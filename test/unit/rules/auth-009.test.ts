import { describe, expect, it } from 'vitest';
import { auth009 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-009-oauth-redirect.js';
import { code, runRule } from '../../helpers/memory-context.js';

const CALLBACK = 'app/auth/callback/route.ts';
const callback = (...body: string[]) =>
  code(
    'export async function GET(request: Request) {',
    '  const { searchParams, origin } = new URL(request.url)',
    "  await supabase.auth.exchangeCodeForSession(searchParams.get('code')!)",
    ...body.map((l) => `  ${l}`),
    '}',
  );

describe('AUTH-009 OAuth redirect from user input', () => {
  it('reports an auth callback that redirects to a request-controlled target', async () => {
    const text = callback("const redirectTo = searchParams.get('redirectTo') ?? '/dashboard'", 'return NextResponse.redirect(redirectTo)');
    expect(await runRule(rule, { [CALLBACK]: text })).toEqual([{ file: CALLBACK, line: 5, evidence: 'return NextResponse.redirect(redirectTo)' }]);
  });

  it('reports signInWithOAuth with a request-controlled redirectTo', async () => {
    const text = code("'use server'", 'export async function signIn(formData: FormData) {', "  await supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: String(formData.get('next')) } })", '}');
    expect(await runRule(rule, { 'app/login/actions.ts': text })).toEqual([expect.objectContaining({ line: 3 })]);
  });

  it('ignores callbacks that verify the target stays on the same origin', async () => {
    const text = callback("const target = new URL(searchParams.get('next') ?? '/', origin)", 'if (target.origin !== origin) return NextResponse.redirect(origin)', 'return NextResponse.redirect(target)');
    expect(await runRule(rule, { [CALLBACK]: text })).toEqual([]);
  });

  it('ignores constant redirect targets', async () => {
    expect(await runRule(rule, { [CALLBACK]: callback('return NextResponse.redirect(`${origin}/dashboard`)') })).toEqual([]);
    const oauth = code('export async function signIn() {', "  await supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: `${process.env.NEXT_PUBLIC_SITE_URL}/auth/callback` } })", '}');
    expect(await runRule(rule, { 'app/login/actions.ts': oauth })).toEqual([]);
  });
});
