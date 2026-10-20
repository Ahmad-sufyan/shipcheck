import { describe, expect, it } from 'vitest';
import { http003 as rule } from '../../../src/packs/nextjs-supabase/rules/http-003-unsafe-cors.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/data/route.ts';
const get = (...body: string[]) => code('export async function GET(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('HTTP-003 Unsafe CORS', () => {
  it('reports an origin reflected from the request with credentials', async () => {
    const text = get("const origin = request.headers.get('origin') ?? '*'", "return Response.json({}, { headers: { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' } })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ file: ROUTE, line: 3 })]);
  });

  it('reports a wildcard origin with credentials, in code and in config files', async () => {
    const text = get('const res = NextResponse.json({})', "res.headers.set('Access-Control-Allow-Origin', '*')", "res.headers.set('Access-Control-Allow-Credentials', 'true')", 'return res');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 3 })]);
    const vercel = JSON.stringify({ headers: [{ source: '/api/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }, { key: 'Access-Control-Allow-Credentials', value: 'true' }] }] }, null, 2);
    expect(await runRule(rule, { 'vercel.json': vercel })).toEqual([expect.objectContaining({ file: 'vercel.json', line: 7 })]);
  });

  it('accepts reflected origins checked against an allowlist', async () => {
    const text = get(
      "const origin = request.headers.get('origin')",
      'const headers: Record<string, string> = {}',
      "if (origin && ALLOWED.has(origin)) headers['Access-Control-Allow-Origin'] = origin",
      "headers['Access-Control-Allow-Credentials'] = 'true'",
      'return Response.json({}, { headers })',
    );
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('accepts a public wildcard without credentials', async () => {
    expect(await runRule(rule, { [ROUTE]: get("return Response.json({}, { headers: { 'Access-Control-Allow-Origin': '*' } })") })).toEqual([]);
  });
});
