-- Avatars uploaded by users.
-- shipcheck-expect: DATA-003
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true);

create policy "Users upload their own avatars"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (select auth.uid())::text = (storage.foldername(name))[1]);
