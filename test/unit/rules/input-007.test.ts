import { describe, expect, it } from 'vitest';
import { input007 as rule } from '../../../src/packs/nextjs-supabase/rules/input-007-ssrf.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/preview/route.ts';
const get = (...body: string[]) => code('export async function GET(request: NextRequest) {', '  const { searchParams } = request.nextUrl', ...body.map((l) => `  ${l}`), '}');

describe('INPUT-007 SSRF', () => {
  it('reports fetch of a request-controlled URL', async () => {
    expect(await runRule(rule, { [ROUTE]: get("const res = await fetch(searchParams.get('url')!)") })).toEqual([
      { file: ROUTE, line: 3, evidence: "const res = await fetch(searchParams.get('url')!)" },
    ]);
  });

  it('reports axios and got with a request-controlled host', async () => {
    expect(await runRule(rule, { [ROUTE]: get("const host = searchParams.get('host')", 'await axios.get(`https://${host}/status`)') })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: get("const target = new URL(searchParams.get('u') ?? '')", 'await got(target)') })).toHaveLength(1);
  });

  it('ignores URLs checked against a hostname allowlist', async () => {
    const guarded = get(
      "const target = new URL(searchParams.get('url') ?? '')",
      "if (!['example.com'].includes(target.hostname)) return new Response(null, { status: 400 })",
      'await fetch(target)',
    );
    expect(await runRule(rule, { [ROUTE]: guarded })).toEqual([]);
  });

  it('ignores constant URLs and tainted request bodies', async () => {
    expect(await runRule(rule, { [ROUTE]: get("await fetch('https://api.example.com/v1', { method: 'POST', body: searchParams.get('q') })") })).toEqual([]);
  });
});
