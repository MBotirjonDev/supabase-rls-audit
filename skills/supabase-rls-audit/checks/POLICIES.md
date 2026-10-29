# Policies

A policy is a boolean SQL expression evaluated per row. `USING` filters which existing rows a
command can see or touch; `WITH CHECK` validates rows being written (insert, and the new
version of an updated row). For UPDATE, if `WITH CHECK` is omitted, Postgres reuses `USING`.

Permissive policies for the same command are **OR-ed**: one loose policy opens the table
even if the others are strict. Restrictive policies (`as restrictive`) are AND-ed on top.

## Checklist

- [ ] Every policy names its role (`to authenticated` / `to anon`); no accidental `public`
- [ ] Read policies on user data compare against `(select auth.uid())`
- [ ] Write policies check ownership in `USING` **and** `WITH CHECK`
- [ ] Nothing reads `user_metadata` / `raw_user_meta_data`
- [ ] Membership checks (orgs, teams, chats) go through a table the user cannot write
- [ ] No two permissive policies where one undoes the other
- [ ] UPDATE also has a matching SELECT policy (otherwise updates silently affect 0 rows)
- [ ] Columns used in policies are indexed (`user_id`, `org_id`)

## using true

```sql
create policy "Profiles are public" on public.profiles for select using (true);
```

With no `to`, the policy applies to `public`, which includes `anon`. Every row is readable
with the anon key. Decide per table:

- **Genuinely public** (product catalogue, published posts): fine. Make sure the table has
  no private columns (phone, email, address, internal notes). If it does, split them into a
  separate table, or expose a view with only the public columns.
- **User data**: replace with an ownership check.

`true` on a write policy (`for insert ... with check (true)`, `for update using (true)`,
`for all using (true)`) is almost never right: any caller can create rows for other users,
change any row, or delete everything.

**Validate:** read the table's columns. A `using (true)` select on a table with `phone`,
`email` or `address` is high. On `products` it is a hardening note at most.

## Signed in is not authorization

```sql
using (auth.role() = 'authenticated')       -- any logged-in user
using (auth.uid() is not null)              -- same
to authenticated using (true)               -- same
```

Sign-up is open in most apps, so "authenticated" is a few seconds away for an attacker. These
policies are only correct when every authenticated user is meant to see every row (a shared
team space with closed sign-up, for example). Otherwise add the real condition:

```sql
using ((select auth.uid()) = user_id)
using (exists (select 1 from public.memberships m
               where m.org_id = projects.org_id and m.user_id = (select auth.uid())))
```

## user_metadata is user-controlled

`auth.users.raw_user_meta_data` (exposed as `auth.jwt() -> 'user_metadata'`) is written by
the client at sign-up and can be changed later by the signed-in user:

```js
await supabase.auth.updateUser({ data: { role: 'admin' } });   // anyone can do this
```

A policy like `(auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'` is therefore bypassable.
Use `app_metadata` (only the service role can set it), a custom access-token hook, or a
`user_roles` table the user cannot write. Supabase's Security Advisor flags this as
*RLS references user metadata*.

## Anonymous writes

Policies `to anon` (or with no `to`) for insert/update/delete let anyone write without an
account. Legitimate cases exist (contact form, waitlist), but they need protection the
database cannot give alone: rate limiting, CAPTCHA, size limits. Prefer an Edge Function
that validates input and inserts with the service role, and keep the table closed to `anon`.

**Validate:** if the expression calls a helper (`is_member(org_id)`) or a subquery, read the
helper: it may well reject anonymous callers (where `auth.uid()` is null), in which case the
policy is fine.

## Performance

`auth.uid()` in a policy is a function call per row. Wrapping it lets Postgres evaluate it
once per statement (an *initPlan*):

```sql
using ((select auth.uid()) = user_id)      -- evaluated once
using (auth.uid() = user_id)               -- evaluated for every row
```

On large tables the difference is orders of magnitude. Also index the compared column:
`create index on public.orders (user_id);`. Supabase's Performance Advisor reports this as
*Auth RLS initialization plan*.

## Test a policy as a real user

The only proof is a request with the anon key and a real user session (not the service role,
which bypasses RLS):

```js
const a = createClient(URL, ANON_KEY);
await a.auth.signInWithPassword({ email: 'alice@test.local', password: '…' });
const { data } = await a.from('orders').select('id, user_id');
// every row must belong to alice; repeat with bob and with no session
```

Do this only against the developer's own project, ideally a local (`supabase start`) or
staging instance, never against someone else's.
