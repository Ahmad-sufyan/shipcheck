import { describe, expect, it } from 'vitest';
import { hasAuthCheck, isIntentionallyPublic, middlewareAuthCovers } from '../../../src/packs/nextjs-supabase/analysis/auth-check.js';
import type { ShipcheckConfig } from '../../../src/types.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/things/route.ts';

function handlerHasAuth(text: string, config: Partial<ShipcheckConfig> = {}): boolean {
  const ctx = memoryContext({ [ROUTE]: text }, config);
  const [handler] = ctx.next.routeHandlers();
  if (!handler) throw new Error('no handler');
  return hasAuthCheck(handler.node, ctx);
}

describe('hasAuthCheck', () => {
  it.each([
    ['supabase.auth.getUser()', 'const { data: { user } } = await supabase.auth.getUser()'],
    ['supabase.auth.getClaims()', 'const { data } = await supabase.auth.getClaims()'],
    ['Auth.js auth()', 'const session = await auth()'],
    ['getServerSession()', 'const session = await getServerSession(authOptions)'],
    ['Clerk currentUser()', 'const user = await currentUser()'],
    ['Clerk auth().protect()', 'await auth.protect()'],
  ])('recognises %s', (_name, line) => {
    expect(handlerHasAuth(code('export async function POST() {', `  ${line}`, '}'))).toBe(true);
  });

  it('does not count supabase.auth.getSession(), which Supabase says must not be trusted on the server', () => {
    expect(handlerHasAuth(code('export async function POST() {', '  const { data } = await supabase.auth.getSession()', '}'))).toBe(false);
  });

  it('recognises configured authHelpers', () => {
    const text = code("import { requireAdmin } from '@/lib/auth'", 'export async function POST() {', '  await requireAdmin()', '}');
    expect(handlerHasAuth(text)).toBe(false);
    expect(handlerHasAuth(text, { authHelpers: ['requireAdmin'] })).toBe(true);
  });

  it('follows calls to same-file helpers', () => {
    const text = code(
      'async function requireUser() {',
      '  const { data } = await createClient().auth.getUser()',
      '  if (!data.user) throw new Error("401")',
      '  return data.user',
      '}',
      'export async function POST() {',
      '  const user = await requireUser()',
      '}',
    );
    expect(handlerHasAuth(text)).toBe(true);
  });

  it('recognises auth wrappers around the exported handler', () => {
    expect(handlerHasAuth(code("import { withAuth } from '@/lib/auth'", 'export const POST = withAuth(async (req: Request) => Response.json({}))'))).toBe(true);
  });

  it('is false without any auth call', () => {
    expect(handlerHasAuth(code('export async function POST(request: Request) {', '  const body = await request.json()', '  return Response.json(body)', '}'))).toBe(false);
  });

  it('is false for unrelated same-file helpers and unknown imports', () => {
    const text = code("import { getThing } from '@/lib/things'", 'function format(x: unknown) { return String(x) }', 'export async function POST() {', '  return Response.json(format(await getThing()))', '}');
    expect(handlerHasAuth(text)).toBe(false);
  });
});

const proxy = (matcher: string, body = 'const { data: { user } } = await supabase.auth.getUser()\n  if (!user) return NextResponse.redirect(new URL("/login", request.url))') =>
  code('export async function proxy(request: NextRequest) {', `  ${body}`, '}', matcher ? `export const config = { matcher: ${matcher} }` : '');

describe('middlewareAuthCovers', () => {
  it('covers routes matched by an auth-checking proxy', () => {
    const ctx = memoryContext({ 'proxy.ts': proxy("['/dashboard/:path*']") });
    expect(middlewareAuthCovers('/dashboard', ctx)).toBe(true);
    expect(middlewareAuthCovers('/dashboard/invoices/[id]', ctx)).toBe(true);
    expect(middlewareAuthCovers('/api/admin/users', ctx)).toBe(false);
  });

  it('covers every route when there is no matcher', () => {
    expect(middlewareAuthCovers('/api/x', memoryContext({ 'middleware.ts': proxy('') }))).toBe(true);
  });

  it('handles negative-lookahead matchers', () => {
    const ctx = memoryContext({ 'proxy.ts': proxy("['/((?!_next/static|_next/image|favicon.ico).*)']") });
    expect(middlewareAuthCovers('/api/search', ctx)).toBe(true);
  });

  it('does not count a proxy that never checks auth or never blocks', () => {
    expect(middlewareAuthCovers('/api/x', memoryContext({ 'proxy.ts': proxy('', 'return NextResponse.next()') }))).toBe(false);
    expect(middlewareAuthCovers('/api/x', memoryContext({ 'proxy.ts': proxy('', 'await supabase.auth.getUser()\n  return NextResponse.next()') }))).toBe(false);
  });

  it('is false without a proxy or middleware file', () => {
    expect(middlewareAuthCovers('/api/x', memoryContext({ 'app/page.tsx': '' }))).toBe(false);
  });
});

describe('isIntentionallyPublic', () => {
  const ctx = memoryContext({}, { publicPaths: ['/api/public/**', '/api/status'] });

  it.each(['/api/login', '/api/auth/callback', '/auth/callback', '/api/password-reset', '/api/oauth/start', '/api/logout', '/api/webhooks/stripe', '/api/cron/daily', '/api/health', '/api/public/feed/latest', '/api/status'])(
    '%s is public',
    (path) => {
      expect(isIntentionallyPublic(path, ctx)).toBe(true);
    },
  );

  it.each(['/api/admin/users', '/api/invoices/[id]', '/api/settings', '/api/statuses'])('%s is not public', (path) => {
    expect(isIntentionallyPublic(path, ctx)).toBe(false);
  });
});
