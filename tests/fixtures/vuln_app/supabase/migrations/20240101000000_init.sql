-- Intentionally vulnerable schema used by the test suite. Do not copy.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique,
  phone text
);
alter table public.profiles enable row level security;
create policy "Profiles are public" on public.profiles for select using (true);
create policy "Users update own profile" on public.profiles for update using (auth.uid() = id);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric not null,
  address text
);

create table public.messages (id bigint generated always as identity primary key, body text);
alter table public.messages enable row level security;
create policy "Anyone can send" on public.messages for insert to anon with check (true);

create table public.documents (id uuid primary key, owner uuid, content text);
alter table public.documents enable row level security;
create policy "Signed in users manage documents" on public.documents
  for all to authenticated using (auth.role() = 'authenticated');

create table public.notes (id uuid primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "Read notes" on public.notes for select to authenticated using (true);

create table public.admin_logs (id bigint primary key, event text);
alter table public.admin_logs enable row level security;

create table public.projects (id uuid primary key, name text);
alter table public.projects enable row level security;
create policy "Admins read projects" on public.projects for select
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create table public.invoices (id uuid primary key, user_id uuid, amount numeric);
alter table public.invoices enable row level security;
create policy "Own invoices" on public.invoices for select using ((select auth.uid()) = user_id);

create view public.order_summary as
  select user_id, count(*) as orders, sum(total) as spent from public.orders group by user_id;

create materialized view public.daily_stats as
  select date_trunc('day', now()) as day, count(*) from public.orders;

create function public.get_all_emails()
returns setof text
language sql
security definer
as $$
  select email from auth.users; -- semicolons inside bodies must not split statements
$$;

insert into storage.buckets (id, name, public) values ('receipts', 'receipts', true);

create policy "Upload receipts" on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts');
