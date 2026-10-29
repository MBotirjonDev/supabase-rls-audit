<div align="center">

# Supabase RLS Audit

<h3>Find the table your anon key can read before someone else does.</h3>

<p>An agent skill that audits Supabase Row Level Security the way an attacker with your anon key sees it,<br>
plus a zero-dependency analyzer that replays your migrations, for your laptop and your CI.</p>

[![tests](https://github.com/MBotirjonDev/supabase-rls-audit/actions/workflows/test.yml/badge.svg)](https://github.com/MBotirjonDev/supabase-rls-audit/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rules](https://img.shields.io/badge/rules-18-58a6ff)](#rules)
[![SARIF](https://img.shields.io/badge/output-JSON%20%7C%20SARIF-6f42c1)](#3-in-github-actions)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[**Quick start**](#quick-start) · [**Rules**](#rules) · [**How it works**](#how-it-works) · [**Contribute**](#roadmap--help-wanted) · [🇺🇿 O'zbekcha](README.uz.md)

</div>

---

> ```
> audit the RLS policies in this supabase project
> ```

## Why this exists

Every Supabase app ships its `anon` key inside the client. That key can call
`/rest/v1/<any table>` directly. Row Level Security is the only thing standing between it and
your data, and it fails in the same few ways:

- a table created in a migration **without `enable row level security`**, or disabled "temporarily"
- `using (true)` on a table with **phone numbers and emails**
- write policies that only check **"is signed in"**, when sign-up is open to everyone
- an admin check that reads **`user_metadata`**, which the user can edit with `auth.updateUser()`
- a **view** or **security definer function** in `public` that silently bypasses every policy
- the **service_role key** in a Flutter app or a `NEXT_PUBLIC_` variable

## Quick start

### 1. As an agent skill (recommended)

```bash
npx skills add https://github.com/MBotirjonDev/supabase-rls-audit --skill supabase-rls-audit --global
```

Or copy `skills/supabase-rls-audit/` into `~/.claude/skills/` (Claude Code) or your agent's
skills folder. Then ask:

```
audit the RLS policies in this supabase project
```
```
can users see each other's orders?
```
```
fix the Supabase Security Advisor warnings with a new migration
```

The agent maps your tables to the data they hold, confirms each lead (and asks you to run
read-only queries against the live database, because dashboard edits never reach the repo),
and writes `REPORT.md` with the attacker's request and a **fix migration** for every finding.

### 2. As a standalone analyzer

Node 18+ only. No `npm install`, no database connection.

```bash
git clone https://github.com/MBotirjonDev/supabase-rls-audit
node supabase-rls-audit/skills/supabase-rls-audit/scripts/audit.cjs path/to/your_project
```

```
supabase-rls-audit · vuln_app · 2 SQL files · 8 tables (6 with RLS) · 7 policies · 2 views · 1 security definer functions

CRITICAL RLS-KEY-002  service role referenced in Flutter app code
         lib/supabase.dart:5
CRITICAL RLS-TBL-001  public.orders never gets "enable row level security" in any migration
         supabase/migrations/20240101000000_init.sql:12
CRITICAL RLS-POL-006  "Anyone can send" on public.messages (for insert to anon) lets anonymous callers write
         supabase/migrations/20240101000000_init.sql:21
CRITICAL RLS-TBL-002  RLS on public.invoices is turned off
         supabase/migrations/20240201000000_debug.sql:2
HIGH     RLS-POL-001  "Profiles are public" on public.profiles (for select to public) is readable by anyone with the anon key (columns include phone)
         supabase/migrations/20240101000000_init.sql:9
HIGH     RLS-POL-004  "Admins read projects" on public.projects (for select to public) reads user_metadata
         supabase/migrations/20240101000000_init.sql:37
HIGH     RLS-VIEW-001 public.order_summary has no security_invoker = true
         supabase/migrations/20240101000000_init.sql:44
...
```

It **replays every migration in order** and reports the final state: a table that gets RLS in
a later migration is fine; a policy that was dropped is gone; a view fixed with
`alter view … set (security_invoker = true)` is fixed. It understands `pg_dump` style quoted
SQL, dollar-quoted function bodies, and monorepos with several Supabase projects.

Options: `--schemas public,api`, `--out leads.json`, `--sarif leads.sarif`,
`--min-severity medium`, `--fail-on high`, `--include-tests`, `--quiet`.

### 3. In GitHub Actions

```yaml
# .github/workflows/rls.yml
name: rls
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MBotirjonDev/supabase-rls-audit@v0
        with:
          fail-on: high        # info | low | medium | high | critical | none
          sarif: rls.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: rls.sarif
```

A pull request that adds a table without RLS now fails before it reaches production.

## How it works

| Phase | What happens | Output |
|---|---|---|
| 1. Map | every Supabase project, migrations, exposed schemas, clients, what each table holds | — |
| 2. Analyze | replay migrations, build the final RLS state, run the rules | `leads.json` |
| 3. Hunt | logic the analyzer cannot see: wrong ownership column, users editing `user_id` or `role`, self-join membership tables, OR-ed permissive policies | candidates |
| 4. Validate | a fresh pass tries to disprove each candidate, with live-database queries when possible | confirmed / needs_validation / rejected |
| 5. Report | attacker request + fix migration per finding, RLS coverage table | `findings.json`, `REPORT.md` |

## Rules

| Rule | What it looks for | Severity hint |
|---|---|---|
| `RLS-TBL-001` | Table in an exposed schema without Row Level Security | critical |
| `RLS-TBL-002` | RLS disabled by a later migration | critical |
| `RLS-TBL-003` | RLS enabled but no policies | info |
| `RLS-POL-001` | Policy lets anyone read every row (`using true`); high when the table has personal columns | high / medium |
| `RLS-POL-002` | Policy lets any caller write any row | critical / high |
| `RLS-POL-003` | Policy only checks that the user is signed in | medium |
| `RLS-POL-004` | Policy trusts user-editable `user_metadata` | high |
| `RLS-POL-005` | `auth.uid()` evaluated per row (wrap it in `select`) | info |
| `RLS-POL-006` | Write policy for anonymous users | high / critical |
| `RLS-VIEW-001` | View bypasses RLS (no `security_invoker`) | high |
| `RLS-VIEW-002` | Materialized view in an exposed schema | medium |
| `RLS-FN-001` | `SECURITY DEFINER` function without a fixed `search_path` | medium |
| `RLS-FN-002` | `SECURITY DEFINER` function callable through `/rpc` with no caller check | medium |
| `RLS-STO-001` | Public storage bucket | info |
| `RLS-STO-002` | Storage write policy without an owner check | medium / high |
| `RLS-KEY-001` | `service_role` JWT or `sb_secret_` key in the repository | critical |
| `RLS-KEY-002` | `service_role` key exposed to the client (public env prefix, Flutter `lib/`) | critical |
| `RLS-KEY-003` | Local development service key (`supabase-demo`) | info |

Guides with the reasoning and fixes: [`TABLES.md`](skills/supabase-rls-audit/checks/TABLES.md) ·
[`POLICIES.md`](skills/supabase-rls-audit/checks/POLICIES.md) ·
[`VIEWS-FUNCTIONS.md`](skills/supabase-rls-audit/checks/VIEWS-FUNCTIONS.md) ·
[`STORAGE.md`](skills/supabase-rls-audit/checks/STORAGE.md) ·
[`KEYS.md`](skills/supabase-rls-audit/checks/KEYS.md)

Suppress a reviewed statement with a comment **inside** it:

```sql
create policy "Catalogue is public" on public.products for select -- rls-ignore: RLS-POL-001 public catalogue
  using (true);
```

Tested on 72 SQL files from five open-source codebases (27 Supabase projects, including the
official `supabase/supabase` examples, `vercel/nextjs-subscription-payments` and Basejump).
The critical leads it reported there were real: example projects that never enable RLS.

## How this compares to Supabase's Security Advisor

The dashboard advisor checks the **live** database and is the source of truth; use it.
This tool checks the **repository**, so it runs in CI before anything is deployed, sees
service role keys in client code, explains every lead with a fix migration, and gives your
AI agent the context to review policy *logic* that no linter can judge.

## Roadmap — help wanted

- [ ] Column-level checks: UPDATE policies that let users change `user_id`, `role` or `price`
- [ ] Membership tables users can insert themselves into
- [ ] Policies referencing helper functions that are themselves leaky security definer functions
- [ ] Read `supabase/config.toml` `[api] schemas` automatically
- [ ] `pg_policies` JSON import, so the live database can be analyzed too
- [ ] Realtime: publications on tables with weak SELECT policies

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © Botirjon ([@MBotirjonDev](https://github.com/MBotirjonDev)). Not affiliated with Supabase.
