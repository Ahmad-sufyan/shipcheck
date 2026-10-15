import { describe, expect, it } from 'vitest';
import { input006 as rule } from '../../../src/packs/nextjs-supabase/rules/input-006-path-traversal.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/files/route.ts';
const get = (...body: string[]) =>
  code(
    "import { readFile, createReadStream } from 'node:fs'",
    "import path from 'node:path'",
    "const base = path.join(process.cwd(), 'storage')",
    'export async function GET(request: NextRequest) {',
    "  const name = request.nextUrl.searchParams.get('name') ?? ''",
    ...body.map((l) => `  ${l}`),
    '}',
  );

describe('INPUT-006 Path traversal', () => {
  it('reports a request-controlled segment joined into a path that is read', async () => {
    expect(await runRule(rule, { [ROUTE]: get('const file = await readFile(path.join(base, name))') })).toEqual([
      { file: ROUTE, line: 6, evidence: 'const file = await readFile(path.join(base, name))' },
    ]);
  });

  it('reports a tainted path passed straight to fs', async () => {
    expect(await runRule(rule, { [ROUTE]: get('const stream = createReadStream(`./uploads/${name}`)') })).toHaveLength(1);
  });

  it('ignores paths verified with normalize/resolve and startsWith', async () => {
    const guarded = get('const target = path.resolve(base, name)', 'if (!target.startsWith(base + path.sep)) return new Response(null, { status: 400 })', 'return new Response(await readFile(target))');
    expect(await runRule(rule, { [ROUTE]: guarded })).toEqual([]);
  });

  it('ignores basename() and constant paths', async () => {
    expect(await runRule(rule, { [ROUTE]: get('const file = await readFile(path.join(base, path.basename(name)))') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: get("const file = await readFile(path.join(base, 'index.html'))") })).toEqual([]);
  });
});
