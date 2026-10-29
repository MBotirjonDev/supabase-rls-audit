---
name: supabase-rls-audit
description: Security audit of Supabase Row Level Security and database exposure for any app on Supabase (Flutter, Next.js, React, Expo, SvelteKit). Use when asked to check or review RLS policies, Supabase security, "can users see each other's data", migrations in supabase/migrations, storage bucket policies, security definer views or functions, service_role key handling, or to fix Supabase Security Advisor warnings.
---

# Supabase RLS Audit

You are auditing a Supabase project the way an attacker would: someone who copied the
`anon` key out of the app, can sign up for an account in seconds, and can call
`/rest/v1/<table>`, `/rest/v1/rpc/<function>` and Storage directly with any filter they like.
Your job is to find **reachable** data exposure and write the exact SQL that fixes it.

## Principles

1. **The anon key is public; RLS is the boundary.** Anything the policies allow `anon` or
   `authenticated` to do, assume an attacker does.
2. **Migrations are not the database.** Dashboard edits never reach the repo. Confirm leads
   against the live schema (queries in `checks/TABLES.md`) when the developer can run them.
3. **Leads are not findings.** A `using (true)` on a product catalogue is a design choice;
   on `profiles` with phone numbers it is a leak. Confirm with the table's columns and the
   app's intent.
4. **The finder never confirms its own finding.** Re-read the final state of the table
   (all migrations, later `drop policy` / `alter policy`) in a fresh pass before confirming.
5. **Never use the service role to "prove" anything**, never test against a project that is
   not the developer's own, and never print keys you find (first characters only).

## Modes

- **Full audit**: "audit my Supabase security / RLS" → all phases, artifacts.
- **Guidance**: "is this policy safe?" → answer from `checks/*.md` and the SQL they show.
- **Fix**: "fix it" → write a **new** migration (never edit applied ones) in the project's
  style, one concern per statement, and re-run the analyzer.

## Phase 1: Map

- Find every Supabase project in the repo (each folder with `supabase/`), the migrations
  (`supabase/migrations/*.sql`), schema dumps, seed files, and `supabase/config.toml`
  (exposed schemas under `[api] schemas`).
- Find the clients: Flutter `lib/`, web `src/`/`app/`, Edge Functions `supabase/functions/`,
  server routes. Note which use the anon key and which the service role.
- List the **assets** per table: personal data, money, messages, files, admin actions.

## Phase 2: Analyze

```bash
node <skill-dir>/scripts/audit.cjs <project-root> --out <output-dir>/leads.json
```

It replays every migration in order and reports the **final** state: tables without RLS,
policies that are open or only check sign-in, `user_metadata` in policies, views without
`security_invoker`, materialized views, `security definer` functions without `search_path`
or caller checks, public buckets, storage writes without owner checks, and service role keys
in code. Use `--schemas public,api` if more schemas are exposed, `--sarif` for GitHub code
scanning.

Its summary line shows tables, RLS coverage and policy counts. If it found 0 tables, the
schema is not in the repo: ask for a schema dump (`supabase db dump --schema public`) or the
live-database query results.

## Phase 3: Hunt what the analyzer cannot see

Read `checks/*.md` for each area and walk its checklist against the real SQL:

| Area | Guide |
|---|---|
| RLS coverage, live-database queries | `checks/TABLES.md` |
| Policy logic: ownership, memberships, OR-ed policies, user_metadata, performance | `checks/POLICIES.md` |
| Views and security definer functions | `checks/VIEWS-FUNCTIONS.md` |
| Storage buckets and object policies | `checks/STORAGE.md` |
| anon / service_role / secret keys | `checks/KEYS.md` |

Logic bugs the analyzer misses and you must look for:

- ownership on the **wrong column** (`auth.uid() = id` on a table where `id` is the row id)
- UPDATE policies that let users change `user_id`, `role`, `org_id`, `price`, `status`
  (no `with check`, or columns not restricted by a trigger/column grant)
- membership tables users can insert into themselves (join any org)
- helper functions used in policies that are `security definer` and leak
- permissive policies OR-ed together where one is much wider than intended
- the app trusting client-side checks while the table allows more

## Phase 4: Validate

A fresh pass tries to disprove each candidate: later migrations, restrictive policies, column
grants, the table really being public data, a helper function that does reject `anon`.
Outcomes: `confirmed`, `needs_validation` (name the missing fact, usually "live DB state"),
`rejected` (say why).

## Phase 5: Record and report

`findings.json` in the shape of `templates/findings.example.json`, then:

```bash
node <skill-dir>/scripts/validate-findings.cjs <output-dir>/findings.json
```

`REPORT.md` from `templates/REPORT.md`: summary table, confirmed findings with the attacker's
request and the **fix migration**, needs-validation items with the query to run, and an RLS
coverage table (table → RLS → policies → verdict).

Default output folder: `~/supabase-rls-audit/<project>/run-<N>/`. Do not write into the repo
unless asked; fix migrations go into `supabase/migrations/` only in Fix mode.

## What this skill runs

`scripts/audit.cjs`, `scripts/sql.cjs` and `scripts/validate-findings.cjs` are plain Node.js
with no dependencies. They only read files in the project folder and write JSON where you
point them. They make no network calls and run no shell commands. SQL in `checks/*.md` is for
the developer to run in their own SQL Editor.

## Severity guide

| Severity | Examples |
|---|---|
| Critical | table with user data and RLS off; write policy `true` for anon; service role key in the repo or client |
| High | open select on personal data; write policies with only a sign-in check; `user_metadata` roles; view leaking an RLS-protected table; definer function returning other users' data |
| Medium | every signed-in user reads all rows; storage writes without owner checks; definer function without `search_path` |
| Low | inefficient or redundant policies with no exposure |
| Info | public buckets for public assets; RLS on with no policies for backend-only tables; `(select auth.uid())` performance |
