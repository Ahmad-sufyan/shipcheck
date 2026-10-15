import { describe, expect, it } from 'vitest';
import { http005 as rule } from '../../../src/packs/nextjs-supabase/rules/http-005-error-leak.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/orders/route.ts';
const get = (...catchBody: string[]) => code('export async function GET() {', '  try {', '    return Response.json(await load())', '  } catch (error) {', ...catchBody.map((l) => `    ${l}`), '  }', '}');

describe('HTTP-005 Error details leaked', () => {
  it('reports error.message returned to the client', async () => {
    expect(await runRule(rule, { [ROUTE]: get('return NextResponse.json({ error: (error as Error).message }, { status: 500 })') })).toEqual([
      { file: ROUTE, line: 5, evidence: 'return NextResponse.json({ error: (error as Error).message }, { status: 500 })' },
    ]);
  });

  it.each([
    ['the stack', 'return Response.json({ stack: (error as Error).stack }, { status: 500 })'],
    ['String(err)', 'return new Response(String(error), { status: 500 })'],
    ['JSON.stringify(err)', 'return new Response(JSON.stringify(error), { status: 500 })'],
    ['a template', 'return new Response(`Failed: ${error}`, { status: 500 })'],
  ])('reports %s', async (_name, line) => {
    expect(await runRule(rule, { [ROUTE]: get(line) })).toHaveLength(1);
  });

  it('accepts generic messages and logging', async () => {
    expect(await runRule(rule, { [ROUTE]: get("console.error('load failed', error)", "return NextResponse.json({ error: 'Something went wrong' }, { status: 500 })") })).toEqual([]);
  });

  it('accepts validation error branches', async () => {
    const text = get('if (error instanceof ZodError) return NextResponse.json({ error: error.message }, { status: 400 })', "return NextResponse.json({ error: 'Internal error' }, { status: 500 })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });
});
