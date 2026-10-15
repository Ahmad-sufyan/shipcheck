-- Avatars are private: users reach their own files through signed URLs.
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', false);

create policy "Users read their own avatars"
  on storage.objects for select to authenticated
  using (bucket_id = 'avatars' and (select auth.uid())::text = (storage.foldername(name))[1]);

create policy "Users upload their own avatars"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (select auth.uid())::text = (storage.foldername(name))[1]);
