-- Profiles: one row per auth user.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text,
  role text not null default 'member',
  settings jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Users can read their own profile"
  on public.profiles for select
  using ((select auth.uid()) = id);

-- shipcheck-expect: AUTHZ-006
create policy "Users can update profiles"
  on public.profiles for update
  using (true);

-- Invoices belong to a user.
-- shipcheck-expect: AUTHZ-005
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  amount_cents integer not null check (amount_cents >= 0),
  status text not null default 'draft',
  created_at timestamptz not null default now()
);

create index invoices_user_id_idx on public.invoices (user_id);
