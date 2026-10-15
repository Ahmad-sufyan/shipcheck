import { describe, expect, it } from 'vitest';
import { authz006 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-006-permissive-policy.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'supabase/migrations/0001_init.sql';
const table = code('create table public.profiles (id uuid primary key);', 'alter table public.profiles enable row level security;');

describe('AUTHZ-006 Permissive RLS policy', () => {
  it('reports using (true) on a write policy as high', async () => {
    const sql = code(table, 'create policy "Anyone can update"', '  on public.profiles for update', '  using (true);');
    expect(await runRule(rule, { [FILE]: sql })).toEqual([{ file: FILE, line: 3, evidence: 'create policy "Anyone can update"' }]);
  });

  it('reports with check (true) on insert', async () => {
    const sql = code(table, 'create policy ins on profiles for insert to authenticated with check (true);');
    expect(await runRule(rule, { [FILE]: sql })).toHaveLength(1);
  });

  it('reports select using (true) as medium with low confidence, unless it is granted to anon', async () => {
    const authenticated = code(table, 'create policy read on profiles for select to authenticated using (true);');
    expect(await runRule(rule, { [FILE]: authenticated })).toEqual([expect.objectContaining({ severity: 'medium', confidence: 'low' })]);
    const anon = code(table, 'create policy read on profiles for select to anon using ( TRUE );');
    const findings = await runRule(rule, { [FILE]: anon });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBeUndefined();
  });

  it('ignores policies scoped to the user', async () => {
    const sql = code(table, 'create policy own on profiles for update using ((select auth.uid()) = id) with check ((select auth.uid()) = id);');
    expect(await runRule(rule, { [FILE]: sql })).toEqual([]);
  });

  it('ignores expressions that merely contain true', async () => {
    const sql = code(table, "create policy pub on profiles for select using (is_public = true and (select auth.uid()) is not null);");
    expect(await runRule(rule, { [FILE]: sql })).toEqual([]);
  });
});
