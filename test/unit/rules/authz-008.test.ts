import { describe, expect, it } from 'vitest';
import { authz008 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-008-mass-assignment.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/things/route.ts';
const post = (...body: string[]) => code('export async function POST(request: Request) {', ...body.map((l) => `  ${l}`), '}');

describe('AUTHZ-008 Mass assignment', () => {
  it('reports the raw body inserted into a users table as critical', async () => {
    const text = post('const body = await request.json()', "await supabase.from('users').insert(body)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ line: 3, severity: 'critical' })]);
  });

  it('reports a spread body in an update as high', async () => {
    const text = post('const body = await request.json()', "await supabase.from('posts').update({ ...body, updated_at: new Date() }).eq('id', 1)");
    const findings = await runRule(rule, { [ROUTE]: text });
    expect(findings).toEqual([expect.objectContaining({ line: 3 })]);
    expect(findings[0]).not.toHaveProperty('severity');
  });

  it('reports prisma data from the request body', async () => {
    const text = post('const data = await request.json()', 'await prisma.user.create({ data })');
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([expect.objectContaining({ severity: 'critical' })]);
  });

  it('reports server action form data written whole', async () => {
    const text = code("'use server'", 'export async function save(input: Record<string, unknown>) {', "  await supabase.from('profiles').upsert(input)", '}');
    expect(await runRule(rule, { 'app/actions.ts': text })).toHaveLength(1);
  });

  it('ignores named fields picked from the body', async () => {
    const text = post('const body = await request.json()', "await supabase.from('users').insert({ email: body.email, name: body.name })");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });

  it('ignores schema-validated input', async () => {
    const text = post('const input = UserSchema.parse(await request.json())', "await supabase.from('users').insert(input)");
    expect(await runRule(rule, { [ROUTE]: text })).toEqual([]);
  });
});
