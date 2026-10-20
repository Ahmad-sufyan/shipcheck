import { describe, expect, it } from 'vitest';
import { infra004 as rule } from '../../../src/packs/nextjs-supabase/rules/infra-004-next-config-options.js';
import { code, lineOf, runRule } from '../../helpers/memory-context.js';

const config = (...body: string[]) => code('const nextConfig = {', ...body.map((l) => `  ${l}`), '}', 'export default nextConfig');

describe('INFRA-004 Risky next.config options', () => {
  it('reports a remote pattern that matches any host', async () => {
    const text = config('images: {', "  remotePatterns: [{ protocol: 'https', hostname: '**' }],", '},');
    expect(await runRule(rule, { 'next.config.mjs': text })).toEqual([
      { file: 'next.config.mjs', line: 3, evidence: "remotePatterns: [{ protocol: 'https', hostname: '**' }],", explanation: expect.stringContaining('matches any host') },
    ]);
  });

  it('reports wildcard subdomains with low confidence, including the URL form', async () => {
    const text = config('images: {', '  remotePatterns: [', "    { hostname: '*.supabase.co' },", "    new URL('https://**.cdn.example.com/**'),", "    { hostname: 'abcdefgh.supabase.co' },", '  ],', '},');
    const findings = await runRule(rule, { 'next.config.mjs': text });
    expect(findings.map((f) => `${f.line} ${f.confidence}`)).toEqual([`${lineOf(text, "'*.supabase.co'")} low`, `${lineOf(text, 'new URL')} low`]);
  });

  it('reports dangerouslyAllowSVG without a content security policy', async () => {
    const unsafe = config('images: {', '  dangerouslyAllowSVG: true,', '},');
    expect(await runRule(rule, { 'next.config.ts': unsafe })).toEqual([expect.objectContaining({ line: 3, evidence: 'dangerouslyAllowSVG: true,' })]);
    const safe = config('images: {', '  dangerouslyAllowSVG: true,', "  contentDispositionType: 'attachment',", '  contentSecurityPolicy: "default-src \'self\'; script-src \'none\'; sandbox;",', '},');
    expect(await runRule(rule, { 'next.config.ts': safe })).toEqual([]);
  });

  it('reports serverActions.allowedOrigins that accept any origin', async () => {
    const text = config('experimental: {', "  serverActions: { allowedOrigins: ['my-proxy.com', '*.my-proxy.com', '*'] },", '},');
    expect(await runRule(rule, { 'next.config.js': text })).toEqual([expect.objectContaining({ line: 3, explanation: expect.stringContaining('"*" accepts Server Action requests from any origin') })]);
  });

  it('accepts specific hosts and ignores projects without next.config', async () => {
    expect(await runRule(rule, { 'next.config.mjs': config('images: {', "  remotePatterns: [{ protocol: 'https', hostname: 'abcdefgh.supabase.co' }],", '},') })).toEqual([]);
    expect(await runRule(rule, { 'app/page.tsx': 'export default function Page() { return null }' })).toEqual([]);
  });
});
