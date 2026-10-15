import { describe, expect, it } from 'vitest';
import { hasRateLimit } from '../../../src/packs/nextjs-supabase/analysis/rate-limit.js';
import type { ShipcheckConfig } from '../../../src/types.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/login/route.ts';

function limited(text: string, extra: Record<string, string> = {}, config: Partial<ShipcheckConfig> = {}): boolean {
  const ctx = memoryContext({ [ROUTE]: text, ...extra }, config);
  const [handler] = ctx.next.routeHandlers();
  if (!handler) throw new Error('no handler');
  return hasRateLimit(handler.node, ctx, handler.routePath);
}

const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('hasRateLimit', () => {
  it('recognises an @upstash/ratelimit instance', () => {
    const text = code(
      "import { Ratelimit } from '@upstash/ratelimit'",
      "import { Redis } from '@upstash/redis'",
      "const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, '1 m') })",
      post("const { success } = await ratelimit.limit(request.headers.get('x-forwarded-for') ?? 'anon')"),
    );
    expect(limited(text)).toBe(true);
  });

  it.each(['if (!rateLimit(`login:${ip}`)) return new Response(null, { status: 429 })', 'await checkRateLimit(request)', 'await limiter.consume(ip)'])('recognises %s', (line) => {
    expect(limited(post(line))).toBe(true);
  });

  it('recognises configured rateLimitHelpers', () => {
    expect(limited(post('await guardLogin(request)'))).toBe(false);
    expect(limited(post('await guardLogin(request)'), {}, { rateLimitHelpers: ['guardLogin'] })).toBe(true);
  });

  it('recognises a covering proxy that rate limits', () => {
    const proxy = code('export async function proxy(request: NextRequest) {', '  const { success } = await ratelimit.limit(request.ip ?? "anon")', '}', "export const config = { matcher: ['/api/:path*'] }");
    expect(limited(post('return Response.json({})'), { 'proxy.ts': proxy })).toBe(true);
    const narrow = proxy.replace("'/api/:path*'", "'/dashboard/:path*'");
    expect(limited(post('return Response.json({})'), { 'proxy.ts': narrow })).toBe(false);
  });

  it('ignores .limit() on query builders', () => {
    expect(limited(post("const { data } = await supabase.from('posts').select('*').limit(10)"))).toBe(false);
  });

  it('is false without any limiter', () => {
    expect(limited(post('const body = await request.json()', 'return Response.json(body)'))).toBe(false);
  });
});
