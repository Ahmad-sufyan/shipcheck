import { describe, expect, it } from 'vitest';
import { authz005 as rule } from '../../../src/packs/nextjs-supabase/rules/authz-005-rls-disabled.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'supabase/migrations/0001_init.sql';

describe('AUTHZ-005 RLS disabled', () => {
  it('reports a public table created without row level security', async () => {
    const sql = code('-- invoices', 'create table public.invoices (', '  id uuid primary key', ');');
    expect(await runRule(rule, { [FILE]: sql })).toEqual([{ file: FILE, line: 2, evidence: 'create table public.invoices (' }]);
  });

  it('reports a table whose RLS is disabled later, at the disable statement', async () => {
    const sql = code('create table notes (id int);', 'alter table notes enable row level security;', 'alter table notes disable row level security;');
    expect(await runRule(rule, { [FILE]: sql })).toEqual([{ file: FILE, line: 3, evidence: 'alter table notes disable row level security;' }]);
  });

  it('ignores tables with RLS enabled, even in a later migration', async () => {
    expect(await runRule(rule, { [FILE]: code('create table notes (id int);', 'alter table public.notes enable row level security;') })).toEqual([]);
    expect(await runRule(rule, { [FILE]: 'create table notes (id int);', 'supabase/migrations/0002.sql': 'alter table notes enable row level security;' })).toEqual([]);
  });

  it('ignores tables revoked from the API roles and tables outside the public schema', async () => {
    expect(await runRule(rule, { [FILE]: code('create table secrets (id int);', 'revoke all on table secrets from anon, authenticated;') })).toEqual([]);
    expect(await runRule(rule, { [FILE]: 'create table private.audit (id int);' })).toEqual([]);
  });
});
