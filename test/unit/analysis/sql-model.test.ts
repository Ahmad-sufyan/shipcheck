import { describe, expect, it } from 'vitest';
import { buildSqlModel } from '../../../src/packs/nextjs-supabase/analysis/sql-model.js';
import { code } from '../../helpers/memory-context.js';

const migration = code(
  '-- create table fake_in_comment (id int);',
  'create table public.invoices (',
  '  id uuid primary key,',
  "  note text default 'create table nope ()'",
  ');',
  'CREATE TABLE IF NOT EXISTS "Profiles" (id uuid);',
  'create table notes (id int);',
  'create table private.audit (id int);',
  '/* create table hidden (id int); */',
  'alter table public.invoices enable row level security;',
  'ALTER TABLE ONLY "Profiles" ENABLE ROW LEVEL SECURITY;',
  'alter table notes enable row level security;',
  'alter table if exists notes disable row level security;',
  'revoke all on table public.secrets from anon, authenticated;',
  'create table secrets (id int);',
  'create policy "Owners update" on public.invoices',
  '  as permissive for update to authenticated',
  '  using ((select auth.uid()) = user_id)',
  '  with check (true);',
  'create policy everyone on "Profiles" using (true);',
  'create function public.touch() returns trigger language plpgsql as $$',
  'begin',
  '  create table inside_function (id int);',
  '  return new;',
  'end;',
  '$$;',
);

describe('buildSqlModel', () => {
  const model = buildSqlModel([{ file: 'supabase/migrations/0001.sql', text: migration }]);

  it('collects created tables with schema, quoting and line numbers', () => {
    expect(model.tables.map((t) => `${t.schema}.${t.name}:${t.line}`)).toEqual([
      'public.invoices:2',
      'public.Profiles:6',
      'public.notes:7',
      'private.audit:8',
      'public.secrets:15',
    ]);
  });

  it('tracks the final RLS state per table', () => {
    expect([...model.rlsEnabled].sort()).toEqual(['Profiles', 'invoices']);
    expect(model.rlsDisabled).toEqual([{ table: 'notes', file: 'supabase/migrations/0001.sql', line: 13 }]);
  });

  it('records tables revoked from both API roles', () => {
    expect([...model.revokedFromApi]).toEqual(['secrets']);
  });

  it('parses policies with defaults for command and roles', () => {
    expect(model.policies).toEqual([
      {
        table: 'invoices',
        name: 'Owners update',
        command: 'update',
        roles: ['authenticated'],
        using: '(select auth.uid()) = user_id',
        withCheck: 'true',
        permissive: true,
        file: 'supabase/migrations/0001.sql',
        line: 16,
      },
      { table: 'Profiles', name: 'everyone', command: 'all', roles: ['public'], using: 'true', withCheck: null, permissive: true, file: 'supabase/migrations/0001.sql', line: 20 },
    ]);
  });

  it('applies later migrations on top of earlier ones', () => {
    const later = buildSqlModel([
      { file: 'supabase/migrations/0001.sql', text: 'create table t (id int);' },
      { file: 'supabase/migrations/0002.sql', text: '\nalter table public.t enable row level security;' },
    ]);
    expect([...later.rlsEnabled]).toEqual(['t']);
  });
});
