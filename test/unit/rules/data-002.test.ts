import { describe, expect, it } from 'vitest';
import { data002 as rule } from '../../../src/packs/nextjs-supabase/rules/data-002-over-exposed-response.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/profile/route.ts';
const get = (...body: string[]) => code('export async function GET() {', '  const { data: { user } } = await supabase.auth.getUser()', ...body.map((l) => `  ${l}`), '}');

describe('DATA-002 Over-exposed response', () => {
  it("returns a select('*') result", async () => {
    expect(await runRule(rule, { [ROUTE]: get("const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single()", 'return NextResponse.json(profile)') })).toEqual([
      expect.objectContaining({ file: ROUTE, line: 4, evidence: 'return NextResponse.json(profile)', explanation: expect.stringContaining("select('*')") }),
    ]);
  });

  it('reports the auth user object and objects with secret-looking keys', async () => {
    expect(await runRule(rule, { [ROUTE]: get('return NextResponse.json(user)') })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: get('return Response.json({ id: user.id, password_hash: row.password_hash })') })).toHaveLength(1);
  });

  it('accepts explicit column lists and picked fields', async () => {
    expect(await runRule(rule, { [ROUTE]: get("const { data } = await supabase.from('profiles').select('id, display_name').eq('id', user.id).single()", 'return NextResponse.json(data)') })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: get('return NextResponse.json({ id: user.id, email: user.email })') })).toEqual([]);
  });

  it('ignores head-only count queries', async () => {
    expect(await runRule(rule, { [ROUTE]: get("const { count } = await supabase.from('profiles').select('*', { count: 'exact', head: true })", 'return NextResponse.json({ count })') })).toEqual([]);
  });
});
