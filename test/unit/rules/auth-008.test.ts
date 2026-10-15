import { describe, expect, it } from 'vitest';
import { auth008 as rule } from '../../../src/packs/nextjs-supabase/rules/auth-008-oauth-without-state.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/oauth/start/route.ts';

describe('AUTH-008 Custom OAuth without state/PKCE', () => {
  it('reports a hand-built authorize URL with client_id and redirect_uri only', async () => {
    const text = code('export async function GET() {', '  const url = `https://github.com/login/oauth/authorize?client_id=${id}&redirect_uri=${uri}`', '  return NextResponse.redirect(url)', '}');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([{ file: ROUTE, line: 2, evidence: 'const url = `https://github.com/login/oauth/authorize?client_id=${id}&redirect_uri=${uri}`' }]);
  });

  it('reports URLSearchParams with response_type=code and no state', async () => {
    const text = code('export function authorizeUrl() {', "  const params = new URLSearchParams({ response_type: 'code', client_id: ID, redirect_uri: URI })", '  return `https://idp.example.com/authorize?${params}`', '}');
    expect(await runRule(rule, { 'lib/oauth.ts': text })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('ignores flows that send state and a PKCE challenge', async () => {
    const text = code(
      'export async function GET() {',
      "  const url = new URL('https://github.com/login/oauth/authorize')",
      "  url.searchParams.set('client_id', id)",
      "  url.searchParams.set('redirect_uri', uri)",
      "  url.searchParams.set('state', state)",
      "  url.searchParams.set('code_challenge', challenge)",
      '  return NextResponse.redirect(url)',
      '}',
    );
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores Supabase signInWithOAuth', async () => {
    const text = code('export async function signIn() {', "  return supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: `${origin}/auth/callback?client_id=x&redirect_uri=y` } })", '}');
    expect(await runRule(rule, { 'app/login/actions.ts': text })).toEqual([]);
  });
});
