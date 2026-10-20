import { describe, expect, it } from 'vitest';
import { rate004 as rule } from '../../../src/packs/nextjs-supabase/rules/rate-004-spoofable-key.js';
import { code, runRule } from '../../helpers/memory-context.js';

describe('RATE-004 Limiter keyed on a spoofable header', () => {
  it('reports x-forwarded-for read inside a limiter', async () => {
    const text = code('export function checkRateLimit(request: Request) {', "  const ip = request.headers.get('x-forwarded-for') ?? 'anon'", '  return hits(ip)', '}');
    expect(await runRule(rule, { 'lib/rate-limit.ts': text })).toEqual([{ file: 'lib/rate-limit.ts', line: 2, evidence: "const ip = request.headers.get('x-forwarded-for') ?? 'anon'" }]);
  });

  it('reports x-real-ip used to key a limiter call in a handler', async () => {
    const text = code('export async function POST(request: Request) {', "  const ip = (await headers()).get('X-Real-IP')", '  if (!(await rateLimit(`reset:${ip}`))) return new Response(null, { status: 429 })', '}');
    expect(await runRule(rule, { 'app/api/reset/route.ts': text })).toEqual([expect.objectContaining({ line: 2 })]);
  });

  it('lowers confidence on Vercel, which overwrites forwarded headers', async () => {
    const text = code('export function checkRateLimit(request: Request) {', "  return hits(request.headers.get('x-forwarded-for'))", '}');
    expect(await runRule(rule, { 'lib/rate-limit.ts': text, 'vercel.json': '{}' })).toEqual([expect.objectContaining({ confidence: 'low' })]);
  });

  it('ignores the platform IP helper', async () => {
    const text = code("import { ipAddress } from '@vercel/functions'", 'export async function POST(request: Request) {', '  if (!(await rateLimit(ipAddress(request) ?? "anon"))) return new Response(null, { status: 429 })', '}');
    expect(await runRule(rule, { 'app/api/reset/route.ts': text })).toEqual([]);
  });

  it('ignores forwarded headers used for things other than rate limiting', async () => {
    const text = code('export async function GET(request: Request) {', "  console.info('request from', request.headers.get('x-forwarded-for'))", '}');
    expect(await runRule(rule, { 'app/api/ping/route.ts': text })).toEqual([]);
  });
});
