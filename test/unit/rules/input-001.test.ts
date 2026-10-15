import { describe, expect, it } from 'vitest';
import { input001 as rule } from '../../../src/packs/nextjs-supabase/rules/input-001-sql-injection.js';
import { code, locations, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/search/route.ts';
const get = (...body: string[]) => code('export async function GET(request: NextRequest) {', "  const q = request.nextUrl.searchParams.get('q') ?? ''", ...body.map((l) => `  ${l}`), '}');

describe('INPUT-001 SQL injection', () => {
  it.each([
    ['a template literal in pool.query', 'await pool.query(`select * from posts where title ilike \'%${q}%\'`)'],
    ['string concatenation in client.query', "await client.query('select * from posts where id = ' + q)"],
    ['a Supabase .or() filter string', "await supabase.from('posts').select().or(`title.ilike.%${q}%,body.ilike.%${q}%`)"],
    ['prisma.$queryRawUnsafe', 'await prisma.$queryRawUnsafe(`select * from "Post" where id = ${q}`)'],
    ['knex.raw', 'await knex.raw(`select * from posts where id = ${q}`)'],
  ])('reports %s', async (_name, line) => {
    expect(locations(await runRule(rule, { [ROUTE]: get(line) }))).toEqual([`${ROUTE}:3`]);
  });

  it('follows a query string built in a variable', async () => {
    expect(await runRule(rule, { [ROUTE]: get('const sql = `delete from posts where id = ${q}`', 'await pool.query(sql)') })).toEqual([expect.objectContaining({ line: 4 })]);
  });

  it('ignores parameterised queries and tagged sql templates', async () => {
    expect(await runRule(rule, { [ROUTE]: get("await pool.query('select * from posts where title ilike $1', [`%${q}%`])") })).toEqual([]);
    expect(await runRule(rule, { [ROUTE]: get('await sql`select * from posts where id = ${q}`') })).toEqual([]);
  });

  it('ignores queries built only from constants', async () => {
    expect(await runRule(rule, { [ROUTE]: get("const table = 'posts'", 'await pool.query(`select * from ${table}`)') })).toEqual([]);
  });

  it('ignores non-database query() calls', async () => {
    expect(await runRule(rule, { [ROUTE]: get('await graphql.query({ query: `{ post(id: ${q}) { id } }` })') })).toEqual([]);
  });
});
