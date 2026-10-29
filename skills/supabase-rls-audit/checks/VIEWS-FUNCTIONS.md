# Views and functions

Views and `SECURITY DEFINER` functions run with their **owner's** privileges (usually
`postgres`, which bypasses RLS). In an exposed schema they are reachable through the API,
so they are the classic way to undo every policy you wrote.

## Checklist

- [ ] Every view in an exposed schema is `security_invoker = true`, or lives in a private schema
- [ ] No materialized views in exposed schemas
- [ ] Every `security definer` function has `set search_path = ''` and schema-qualified names
- [ ] Every `security definer` function in an exposed schema checks the caller, or has execute revoked from `anon` (and `authenticated` if not needed)
- [ ] Trigger functions are not callable as RPC (they are not, but helpers they call might be)

## Views bypass RLS

```sql
create view public.order_summary as
  select user_id, sum(total) from public.orders group by user_id;
-- GET /rest/v1/order_summary → every user's spend, RLS on orders ignored
```

Postgres 15+ (all current Supabase projects):

```sql
create view public.order_summary with (security_invoker = true) as ...;
-- or, for an existing view
alter view public.order_summary set (security_invoker = true);
```

**Validate:** if the view only selects from tables without RLS-worthy data, or filters by
`auth.uid()` itself, explain why it is acceptable instead of reporting it. Supabase's
Security Advisor calls this *Security definer view*.

## Materialized views

Materialized views cannot have RLS. In `public` they are readable by `anon` and
`authenticated` through the API. Move them to a private schema, revoke select from `anon`,
`authenticated`, and serve the data through a function that checks the caller.

## Security definer functions

Every function in an exposed schema is callable at `/rest/v1/rpc/<name>`, and Supabase
grants `execute` to `anon` and `authenticated` by default. A `security definer` function
runs as its owner, so RLS does not apply inside it.

```sql
-- ❌ anyone can call this and get every user's email
create function public.get_all_emails() returns setof text
language sql security definer as $$ select email from auth.users $$;
```

Safe pattern:

```sql
create function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''                      -- no schema lookups the caller can influence
as $$
begin
  delete from auth.users where id = (select auth.uid());   -- acts only on the caller
end;
$$;

revoke execute on function public.delete_my_account() from anon;
```

`set search_path = ''` matters because the function owner is powerful: without it,
unqualified names (`profiles`, `now()`) are resolved through a search path that a caller may
be able to influence. Supabase's advisor calls this *Function search path mutable*.

**Validate:** read the function body. It is a finding only if a caller can make it return
or change data they should not reach. Functions that are only used by triggers
(`returns trigger`) are not callable as RPC.
