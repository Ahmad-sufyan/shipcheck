import { describe, expect, it } from 'vitest';
import { input009 as rule } from '../../../src/packs/nextjs-supabase/rules/input-009-unvalidated-upload.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/upload/route.ts';
const post = (...body: string[]) =>
  code('export async function POST(request: Request) {', '  const form = await request.formData()', "  const file = form.get('file') as File", ...body.map((l) => `  ${l}`), '}');

describe('INPUT-009 Unvalidated upload', () => {
  it('reports an upload written under public/ without checks', async () => {
    const text = post('const bytes = Buffer.from(await file.arrayBuffer())', "await writeFile(path.join(process.cwd(), 'public', 'uploads', name), bytes)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([{ file: ROUTE, line: 5, evidence: "await writeFile(path.join(process.cwd(), 'public', 'uploads', name), bytes)" }]);
  });

  it('reports a storage upload without size and type checks', async () => {
    expect(await runRule(rule, { [ROUTE]: post("await supabase.storage.from('uploads').upload(`${id}.bin`, file)") })).toHaveLength(1);
  });

  it('reports a checked upload that is still written under public/', async () => {
    const text = post("if (file.size > 1e6 || !['image/png'].includes(file.type)) return new Response(null, { status: 400 })", "await writeFile(`public/uploads/${id}.png`, Buffer.from(await file.arrayBuffer()))");
    expect(await runRule(rule, { [ROUTE]: text })).toHaveLength(1);
  });

  it('ignores uploads checked for size and type and stored privately', async () => {
    const text = post("if (file.size > 1e6 || !['image/png'].includes(file.type)) return new Response(null, { status: 400 })", "await supabase.storage.from('uploads').upload(`${id}.png`, file)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores form handlers that never store a file', async () => {
    expect(await runRule(rule, { [ROUTE]: post('return Response.json({ name: file.name })') })).toEqual([]);
  });
});
