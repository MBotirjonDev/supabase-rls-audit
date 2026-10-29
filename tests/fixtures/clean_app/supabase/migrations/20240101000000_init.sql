-- Reference schema: RLS everywhere, ownership checks, invoker views, safe definer functions.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique,
  phone text
);
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles for select to authenticated
  using ((select auth.uid()) = id);
create policy "Users update own profile" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users default auth.uid(),
  total numeric not null
);
alter table public.orders enable row level security;
create policy "Read own orders" on public.orders for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "Create own orders" on public.orders for insert to authenticated
  with check ((select auth.uid()) = user_id);

create table public.projects (id uuid primary key, name text, org_id uuid not null);
alter table public.projects enable row level security;
create policy "Members read projects" on public.projects for select to authenticated
  using (exists (
    select 1 from public.memberships m
    where m.org_id = projects.org_id and m.user_id = (select auth.uid())
  ));
create policy "Admins manage projects" on public.projects for all to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
  with check (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

create table public.memberships (org_id uuid, user_id uuid, primary key (org_id, user_id));
alter table public.memberships enable row level security;
create policy "Read own memberships" on public.memberships for select to authenticated
  using (user_id = (select auth.uid()));

create view public.my_orders with (security_invoker = true) as
  select id, total from public.orders;

create view public.legacy_summary as select user_id, count(*) from public.orders group by user_id;
alter view public.legacy_summary set (security_invoker = true);

create function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from auth.users where id = (select auth.uid());
end;
$$;

create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

create schema if not exists private;
create table private.audit_log (id bigint primary key, event text);

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
create policy "Users upload own avatar" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
