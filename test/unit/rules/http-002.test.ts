import { describe, expect, it } from 'vitest';
import { http002 as rule } from '../../../src/packs/nextjs-supabase/rules/http-002-security-headers.js';
import { code, runRule } from '../../helpers/memory-context.js';

const withHeaders = (...headers: string[]) =>
  code('export default {', '  async headers() {', `    return [{ source: '/:path*', headers: [${headers.join(', ')}] }]`, '  },', '}');
const all = [
  "{ key: 'Strict-Transport-Security', value: 'max-age=63072000' }",
  "{ key: 'X-Content-Type-Options', value: 'nosniff' }",
  "{ key: 'X-Frame-Options', value: 'DENY' }",
  "{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }",
  "{ key: 'Permissions-Policy', value: 'camera=()' }",
];

describe('HTTP-002 Missing security headers', () => {
  it('reports one finding listing every missing header', async () => {
    const findings = await runRule(rule, { 'next.config.mjs': 'const nextConfig = {}\nexport default nextConfig' });
    expect(findings).toEqual([expect.objectContaining({ file: 'next.config.mjs', line: 1 })]);
    expect(findings[0]?.explanation).toMatch(/Strict-Transport-Security.*X-Content-Type-Options.*X-Frame-Options.*Referrer-Policy.*Permissions-Policy/);
  });

  it('accepts frame-ancestors in the CSP instead of X-Frame-Options', async () => {
    const headers = [...all.filter((h) => !h.includes('X-Frame-Options')), `{ key: 'Content-Security-Policy', value: "frame-ancestors 'none'" }`];
    expect(await runRule(rule, { 'next.config.mjs': withHeaders(...headers) })).toEqual([]);
  });

  it('reports only HSTS with low confidence on Vercel, which sends it by default', async () => {
    const findings = await runRule(rule, { 'next.config.mjs': withHeaders(...all.slice(1)), 'vercel.json': '{}' });
    expect(findings).toEqual([expect.objectContaining({ confidence: 'low' })]);
  });

  it('accepts a complete set of headers', async () => {
    expect(await runRule(rule, { 'next.config.mjs': withHeaders(...all) })).toEqual([]);
  });
});
