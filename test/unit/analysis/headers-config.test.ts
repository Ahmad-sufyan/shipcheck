import { describe, expect, it } from 'vitest';
import { collectHeaders, headerValues } from '../../../src/packs/nextjs-supabase/analysis/headers-config.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

describe('collectHeaders', () => {
  it('reads next.config headers() including constants and spreads', () => {
    const ctx = memoryContext({
      'next.config.mjs': code(
        "const base = [{ key: 'X-Content-Type-Options', value: 'nosniff' }]",
        'const securityHeaders = [',
        '  ...base,',
        "  { key: 'Content-Security-Policy', value: \"default-src 'self'\" },",
        ']',
        'export default {',
        '  async headers() {',
        "    return [{ source: '/:path*', headers: securityHeaders }]",
        '  },',
        '}',
      ),
    });
    expect(collectHeaders(ctx).map((h) => [h.key, h.value, h.source, h.line])).toEqual([
      ['x-content-type-options', 'nosniff', 'next.config', 1],
      ['content-security-policy', "default-src 'self'", 'next.config', 4],
    ]);
  });

  it('reads headers set in proxy/middleware, including dynamic values', () => {
    const ctx = memoryContext({
      'middleware.ts': code(
        'export function middleware(request: NextRequest) {',
        '  const response = NextResponse.next()',
        "  response.headers.set('Strict-Transport-Security', 'max-age=63072000')",
        "  response.headers.set('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}'`)",
        '  return response',
        '}',
      ),
    });
    expect(collectHeaders(ctx).map((h) => [h.key, h.value, h.line])).toEqual([
      ['strict-transport-security', 'max-age=63072000', 3],
      ['content-security-policy', "script-src 'self' 'nonce-${}'", 4],
    ]);
  });

  it('reads vercel.json and public/_headers', () => {
    const ctx = memoryContext({
      'vercel.json': JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: 'Referrer-Policy', value: 'no-referrer' }] }] }, null, 2),
      'public/_headers': '/*\n  X-Frame-Options: DENY\n  Permissions-Policy: camera=()\n',
    });
    expect(collectHeaders(ctx).map((h) => [h.key, h.value, h.source, h.file, h.line])).toEqual([
      ['referrer-policy', 'no-referrer', 'vercel.json', 'vercel.json', 7],
      ['x-frame-options', 'DENY', '_headers', 'public/_headers', 2],
      ['permissions-policy', 'camera=()', '_headers', 'public/_headers', 3],
    ]);
  });

  it('returns nothing when no headers are configured', () => {
    expect(collectHeaders(memoryContext({ 'next.config.mjs': 'export default { poweredByHeader: false }' }))).toEqual([]);
  });

  it('groups values by header name', () => {
    const ctx = memoryContext({ 'public/_headers': '/*\n  X-Frame-Options: DENY\n/admin/*\n  X-Frame-Options: SAMEORIGIN\n' });
    expect(headerValues(ctx, 'x-frame-options')).toEqual(['DENY', 'SAMEORIGIN']);
  });
});
