# Tables and Row Level Security

Supabase serves every table in an **exposed schema** (by default `public`) through the Data
API at `/rest/v1/<table>`. The `anon` key that authorizes those calls ships inside every web
and mobile app, so it is public. Row Level Security is the only thing between that key and
your data.

## Checklist

- [ ] Every table in an exposed schema has `enable row level security`
- [ ] No later migration (or dashboard edit) disabled it again
- [ ] Tables the app never reads directly live in a non-exposed schema (`private`), not `public` with "no policies"
- [ ] The live database matches the migrations (see the queries below)
- [ ] New tables get RLS in the **same** migration that creates them

## Tables without RLS

With RLS off, `anon` and `authenticated` have full table privileges by default (Supabase
grants them on `public`). Anyone can run, from any browser console:

```js
const supabase = createClient(SUPABASE_URL, ANON_KEY_FROM_YOUR_APP);
await supabase.from('orders').select('*');           // every order
await supabase.from('orders').delete().neq('id', 0);   // or delete them
```

Fix in a new migration:

```sql
alter table public.orders enable row level security;

create policy "Read own orders" on public.orders
  for select to authenticated using ((select auth.uid()) = user_id);
```

**Validate:** confirm the table really exists in the live database with RLS off (query
below). Tables created only for local tests, or dropped later, are not findings. Supabase's
Security Advisor reports the same thing as *RLS disabled in public*.

Disabling RLS "temporarily" to debug a failing policy is the most common way this ships.
If a migration contains `disable row level security`, find out why, fix the policy, and
re-enable it.

## RLS without policies

RLS on with no policies means deny-all for `anon` and `authenticated`. That is safe, but:

- if the app reads the table, the app is broken in production (and someone will "fix" it by
  disabling RLS);
- if only the backend uses it (with the service role), a non-exposed schema says that more
  clearly and removes it from the API entirely.

## Check the live database

Migrations are not the whole truth: tables and policies edited in the dashboard never reach
the repo. Ask the developer to run these in the SQL Editor (read-only) and paste the result:

```sql
-- tables in exposed schemas and whether RLS is on
select n.nspname as schema, c.relname as table, c.relrowsecurity as rls_enabled
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and n.nspname in ('public')
order by rls_enabled, schema, "table";

-- every policy, with its expressions
select schemaname, tablename, policyname, permissive, roles, cmd, qual as using, with_check
from pg_policies
where schemaname in ('public', 'storage')
order by schemaname, tablename, policyname;
```

Add any extra schemas listed under *Exposed schemas* in the project's API settings, and pass
them to the analyzer with `--schemas public,api`.
