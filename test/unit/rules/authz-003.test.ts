import { describe, expect, it } from 'vitest';
import { authz003 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-003-idor.js';
import { code, runRule } from '../../helpers/memory-context.js';

const ROUTE = 'app/api/invoices/[id]/route.ts';
const handler = (query: string, client = 'await createClient()') =>
  code(
    'export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {',
    '  const { id } = await params',
    `  const supabase = ${client}`,
    '  const { data: { user } } = await supabase.auth.getUser()',
    "  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 })",
    `  const { data } = ${query}`,
    '  return Response.json(data)',
    '}',
  );

const noRls = 'create table public.invoices (id uuid primary key, user_id uuid);';
const ownerRls = code(
  noRls,
  'alter table public.invoices enable row level security;',
  'create policy "own invoices" on public.invoices for select using ((select auth.uid()) = user_id);',
);

describe('AUTHZ-003 IDOR', () => {
  it('reports a lookup by a request-controlled id without an owner filter or owner policy', async () => {
    const findings = await runRule(rule, { [ROUTE]: handler("await supabase.from('invoices').select('*').eq('id', id).single()"), 'supabase/migrations/0001.sql': noRls });
    expect(findings).toEqual([{ file: ROUTE, line: 6, evidence: "const { data } = await supabase.from('invoices').select('*').eq('id', id).single()" }]);
  });

  it('reports even with an owner policy when the client uses the service role', async () => {
    const findings = await runRule(rule, {
      [ROUTE]: handler("await supabase.from('invoices').select('*').eq('id', id).single()", 'createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)'),
      'supabase/migrations/0001.sql': ownerRls,
    });
    expect(findings).toHaveLength(1);
  });

  it('reports prisma lookups by a tainted id without an owner condition', async () => {
    expect(await runRule(rule, { [ROUTE]: handler('await prisma.invoice.findUnique({ where: { id } })') })).toHaveLength(1);
    expect(await runRule(rule, { [ROUTE]: handler('await prisma.invoice.findFirst({ where: { id, userId: user.id } })') })).toEqual([]);
  });

  it('ignores queries with an owner filter', async () => {
    const query = "await supabase.from('invoices').select('*').eq('id', id).eq('user_id', user.id).single()";
    expect(await runRule(rule, { [ROUTE]: handler(query), 'supabase/migrations/0001.sql': noRls })).toEqual([]);
  });

  it('ignores tables protected by an owner RLS policy', async () => {
    expect(await runRule(rule, { [ROUTE]: handler("await supabase.from('invoices').select('*').eq('id', id).single()"), 'supabase/migrations/0001.sql': ownerRls })).toEqual([]);
  });

  it('ignores ids that do not come from the request', async () => {
    expect(await runRule(rule, { [ROUTE]: handler("await supabase.from('profiles').select('*').eq('id', user.id).single()") })).toEqual([]);
  });
});
