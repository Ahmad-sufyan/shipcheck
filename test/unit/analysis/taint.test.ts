import { Node, SyntaxKind, type CallExpression } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { entryFunctionOf, isUserInput } from '../../../src/packs/nextjs-supabase/analysis/taint.js';
import { code, memoryContext } from '../../helpers/memory-context.js';

/** Is the first argument of the n-th `sink(...)` call user input? */
function sinkTainted(file: string, text: string, nth = 0): boolean {
  const ctx = memoryContext({ [file]: text });
  const sinks = ctx
    .getSourceFile(file)
    .getDescendantsOfKind(SyntaxKind.CallExpression)
    .filter((c: CallExpression) => c.getExpression().getText() === 'sink');
  const call = sinks[nth];
  if (!call) throw new Error('no sink call');
  const arg = call.getArguments()[0]!;
  return isUserInput(arg, entryFunctionOf(call));
}

const ROUTE = 'app/api/x/route.ts';
const handler = (...body: string[]) => code('export async function POST(request: Request, ctx: { params: Promise<{ id: string }> }) {', ...body, '}');

describe('isUserInput: sources', () => {
  it.each([
    ['request.json()', handler('const body = await request.json()', 'sink(body)')],
    ['request.formData().get()', handler("sink((await request.formData()).get('f'))")],
    ['request.text() through a string method', handler('const t = await request.text()', 'sink(t.trim())')],
    ['nextUrl.searchParams.get() with ??', handler("const q = request.nextUrl.searchParams.get('q') ?? ''", 'sink(`select ${q}`)')],
    ['destructured searchParams', handler('const { searchParams } = new URL(request.url)', "sink(searchParams.get('u'))")],
    ['awaited route params', handler('const { id } = await ctx.params', 'sink(id)')],
    ['route params property', handler('sink((await ctx.params).id)')],
    ['headers().get()', handler("const h = await headers()", "sink(h.get('x-forwarded-host'))")],
    ['cookies().get()?.value', handler("sink((await cookies()).get('a')?.value)")],
    ['destructured body field', handler('const { email, role } = await request.json()', 'sink(role)')],
    ['element access', handler('const body = await request.json()', "sink(body['k'])")],
    ['nested property and index', handler('const body = await request.json()', 'sink(body.items[0])')],
    ['concatenation', handler("const q = request.nextUrl.searchParams.get('q')", "sink('a' + q)")],
    ['new URL()', handler("const u = new URL(request.nextUrl.searchParams.get('u')!)", 'sink(u)')],
    ['spread into an object literal', handler('const body = await request.json()', 'sink({ ...body, id: 1 })')],
    ['let reassignment', handler("let next = '/'", "next = request.nextUrl.searchParams.get('next') ?? '/'", 'sink(next)')],
  ])('%s', (_name, text) => {
    expect(sinkTainted(ROUTE, text)).toBe(true);
  });

  it('treats destructured route params as user input', () => {
    const text = code('export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {', '  const { id } = await params', '  sink(id)', '}');
    expect(sinkTainted(ROUTE, text)).toBe(true);
  });

  it('treats server action parameters as user input', () => {
    expect(sinkTainted('app/actions.ts', code("'use server'", 'export async function save(formData: FormData) {', "  sink(formData.get('x'))", '}'))).toBe(true);
    expect(sinkTainted('app/page.tsx', code('export default function P() {', '  async function act(id: string) {', "    'use server'", '    sink(id)', '  }', '}'))).toBe(true);
  });

  it('follows nested callbacks back to the handler', () => {
    const text = handler("const image = request.nextUrl.searchParams.get('image')", 'await new Promise((resolve) => {', '  sink(`convert ${image}`)', '})');
    expect(sinkTainted(ROUTE, text)).toBe(true);
  });

  it('follows at most 3 hops', () => {
    const text = handler('const a = await request.json()', 'const b = a', 'const c = b', 'const d = c', 'sink(c)', 'sink(d)');
    expect(sinkTainted(ROUTE, text, 0)).toBe(true);
    expect(sinkTainted(ROUTE, text, 1)).toBe(false);
  });
});

describe('isUserInput: trustSchemas option', () => {
  it('keeps schema-validated values tainted when schemas are not trusted', () => {
    const ctx = memoryContext({ [ROUTE]: handler('const { persona } = Schema.parse(await request.json())', 'sink(persona)') });
    const call = ctx.getSourceFile(ROUTE).getDescendantsOfKind(SyntaxKind.CallExpression).find((c) => c.getExpression().getText() === 'sink')!;
    const fn = entryFunctionOf(call);
    expect(isUserInput(call.getArguments()[0]!, fn)).toBe(false);
    expect(isUserInput(call.getArguments()[0]!, fn, { trustSchemas: false })).toBe(true);
  });
});

describe('isUserInput: not user input', () => {
  it.each([
    ['zod parse output', handler('const parsed = Schema.parse(await request.json())', 'sink(parsed)')],
    ['zod safeParse().data', handler('const body = await request.json()', 'const r = Schema.safeParse(body)', 'sink(r.data)')],
    ['valibot parse output', handler('const body = await request.json()', 'const v = parse(Schema, body)', 'sink(v)')],
    ['yup validate output', handler('const body = await request.json()', 'const v = await schema.validate(body)', 'sink(v)')],
    ['a string literal', handler("sink('literal')")],
    ['an env var', handler('sink(process.env.DATABASE_URL)')],
    ['a fetch response body', handler("const res = await fetch('https://api.example.com')", 'const data = await res.json()', 'sink(data)')],
    ['request.url', handler('sink(request.url)')],
    ['a regex-validated value', handler("const name = request.nextUrl.searchParams.get('n') ?? ''", 'if (!/^[a-z]+$/.test(name)) return', 'sink(name)')],
    ['an allowlist lookup by tainted key', handler("const key = request.nextUrl.searchParams.get('to') ?? 'a'", "const MAP: Record<string, string> = { a: '/a' }", 'sink(MAP[key])')],
    ['the result of an unknown helper', handler('const body = await request.json()', 'sink(sanitize(body))')],
    ['a comparison', handler("const role = request.nextUrl.searchParams.get('r')", "sink(role === 'admin')")],
  ])('%s', (_name, text) => {
    expect(sinkTainted(ROUTE, text)).toBe(false);
  });

  it('does not treat parameters of ordinary library functions as user input', () => {
    expect(sinkTainted('lib/util.ts', code('export function run(cmd: string) {', '  sink(cmd)', '}'))).toBe(false);
  });

  it('does not treat a non-request first parameter of a library function as a request', () => {
    expect(sinkTainted('lib/util.ts', code('export async function load(res: Response) {', '  sink(await res.json())', '}'))).toBe(false);
  });

  it('returns false for nodes outside any function', () => {
    const ctx = memoryContext({ 'lib/a.ts': "const x = 'a'\nsink(x)" });
    const call = ctx.getSourceFile('lib/a.ts').getDescendantsOfKind(SyntaxKind.CallExpression)[0]!;
    expect(Node.isCallExpression(call) && isUserInput(call.getArguments()[0]!, undefined)).toBe(false);
  });
});
