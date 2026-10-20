import { describe, expect, it } from 'vitest';
import { http001 as rule } from '../../../src/packs/nextjs-supabase/rules/http-001-csp.js';
import { code, runRule } from '../../helpers/memory-context.js';

const config = (headers: string) =>
  code('const nextConfig = {', '  poweredByHeader: false,', '  async headers() {', `    return [{ source: '/:path*', headers: [${headers}] }]`, '  },', '}', 'export default nextConfig');

describe('HTTP-001 Content-Security-Policy missing or unsafe', () => {
  it('reports a missing CSP at the next.config object', async () => {
    expect(await runRule(rule, { 'next.config.mjs': 'const nextConfig = {\n  poweredByHeader: false,\n}\nexport default nextConfig' })).toEqual([
      { file: 'next.config.mjs', line: 1, evidence: 'const nextConfig = {' },
    ]);
  });

  it("reports 'unsafe-eval' and script 'unsafe-inline' without a nonce as low", async () => {
    const evalCsp = await runRule(rule, { 'next.config.mjs': config(`{ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-eval'" }`) });
    expect(evalCsp).toEqual([expect.objectContaining({ line: 4, severity: 'low' })]);
    const inline = await runRule(rule, { 'next.config.mjs': config(`{ key: 'Content-Security-Policy', value: "default-src 'self' 'unsafe-inline'" }`) });
    expect(inline).toHaveLength(1);
  });

  it('accepts a strict CSP from next.config or a nonce-based CSP from middleware', async () => {
    expect(await runRule(rule, { 'next.config.mjs': config(`{ key: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'none'" }`) })).toEqual([]);
    const middleware = code(
      'export function middleware() {',
      '  const response = NextResponse.next()',
      "  response.headers.set('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-inline'`)",
      '  return response',
      '}',
    );
    expect(await runRule(rule, { 'next.config.mjs': 'export default {}', 'middleware.ts': middleware })).toEqual([]);
  });

  it('accepts a CSP set in vercel.json', async () => {
    const vercel = JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }] });
    expect(await runRule(rule, { 'next.config.mjs': 'export default {}', 'vercel.json': vercel })).toEqual([]);
  });
});
