import { describe, expect, it } from 'vitest';
import { input010 as rule } from '../../../src/packs/nextjs-supabase/rules/input-010-no-schema-validation.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/things/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('INPUT-010 No schema validation', () => {
  it('reports a JSON body read without a schema', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const body = await request.json()', 'return Response.json(body)') })).toEqual([
      { file: ROUTE, line: 2, evidence: 'const body = await request.json()' },
    ]);
  });

  it('reports form fields read without a schema', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const form = await request.formData()', "const name = form.get('name') as string", 'return Response.json({ name })') })).toHaveLength(1);
  });

  it('reports server action arguments that are never validated', async () => {
    const text = code("'use server'", 'export async function rename(id: string, name: string) {', "  await db.from('things').update({ name }).eq('id', id)", '}');
    expect(await runRule(rule, { 'app/actions.ts': text })).toEqual([expect.objectContaining({ file: 'app/actions.ts', line: 2 })]);
  });

  it('ignores bodies parsed with zod, valibot or yup', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const body = Schema.parse(await request.json())') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: post('const result = Schema.safeParse(await request.json())') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: post('const body = v.parse(Schema, await request.json())') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: post('const body = await schema.validate(await request.json())') })).toEqual([]);
  });

  it('does not count JSON.parse as validation', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const body = JSON.parse(await request.text())') })).toHaveLength(1);
  });

  it('leaves webhook routes to INTEG-001, which checks their signature', async () => {
    expect(await runRule(rule, { 'app/api/webhooks/stripe/route.ts': post('const event = await request.json()') })).toEqual([]);
  });

  it('ignores file-only form reads and handlers without a body', async () => {
    expect(await runRule(rule, { [ROUTE]: post('const form = await request.formData()', "const file = form.get('file')", 'if (!(file instanceof File)) return new Response(null, { status: 400 })') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: post('return Response.json({ ok: true })') })).toEqual([]);
    const noArgs = code("'use server'", 'export async function refresh() {', "  revalidatePath('/')", '}');
    expect(await runRule(rule, { 'app/actions.ts': noArgs })).toEqual([]);
  });
});
