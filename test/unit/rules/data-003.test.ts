import { describe, expect, it } from 'vitest';
import { data003 as rule } from '../../../src/packs/nextjs-supabase/rules/data-003-public-bucket.js';
import { code, runRule } from '../../helpers/memory-context.js';

const FILE = 'supabase/migrations/0002_storage.sql';

describe('DATA-003 Public storage bucket', () => {
  it('reports a bucket inserted with public = true', async () => {
    const sql = code('-- avatars', 'insert into storage.buckets (id, name, public)', "values ('avatars', 'avatars', true);");
    expect(await runRule(rule, { [FILE]: sql })).toEqual([{ file: FILE, line: 2, evidence: 'insert into storage.buckets (id, name, public)' }]);
  });

  it('reports buckets made public with update or createBucket, and open storage.objects reads', async () => {
    expect(await runRule(rule, { [FILE]: "update storage.buckets set public = true where id = 'docs';" })).toHaveLength(1);
    expect(await runRule(rule, { 'scripts/setup.ts': "await supabase.storage.createBucket('docs', { public: true })" })).toEqual([expect.objectContaining({ file: 'scripts/setup.ts', line: 1 })]);
    expect(await runRule(rule, { [FILE]: 'create policy "read" on storage.objects for select using (true);' })).toHaveLength(1);
  });

  it('ignores private buckets and owner-scoped object policies', async () => {
    const sql = code(
      "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);",
      'create policy "own" on storage.objects for select to authenticated using (bucket_id = \'avatars\' and (select auth.uid())::text = (storage.foldername(name))[1]);',
    );
    expect(await runRule(rule, { [FILE]: sql })).toEqual([]);
  });

  it('ignores createBucket without public', async () => {
    expect(await runRule(rule, { 'scripts/setup.ts': "await supabase.storage.createBucket('docs', { public: false, fileSizeLimit: '5MB' })" })).toEqual([]);
  });
});
