# Supabase security audit: {{project}}

| | |
|---|---|
| Commit | `{{commit}}` |
| Date | {{date}} |
| Exposed schemas | {{public, …}} |
| Sources | {{migrations / schema dump / live-database query results}} |
| Method | supabase-rls-audit skill: map → analyze → hunt → adversarial validation |

## Summary

| Critical | High | Medium | Low | Needs validation |
|---:|---:|---:|---:|---:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

{{3–5 sentences: what the app stores, the most serious exposure in plain words, what to fix first.}}

## RLS coverage

| Table | RLS | Policies | Verdict |
|---|:---:|---|---|
| `public.{{table}}` | ✅ / ❌ | {{select own, insert own}} | {{ok / F-n}} |

## Confirmed findings

### F-1 · {{title}} (**{{Severity}}**)

**Where:** `{{file}}:{{line}}`

**Attacker:** {{who, and what they hold: anon key / any account}}

**The request they make**
```js
// supabase-js with the app's anon key
await supabase.from('{{table}}').select('*');
```

**Impact:** {{what leaks or changes, in business terms}}

**Fix migration** (`supabase/migrations/<timestamp>_{{name}}.sql`)
```sql
{{alter table … enable row level security; create policy …}}
```

---

## Needs validation

| ID | Title | Run this in the SQL Editor |
|---|---|---|
| F-n | {{title}} | `{{query}}` |

## Hardening notes

- {{e.g. wrap auth.uid() in (select …), index user_id}}

_Generated with [Supabase RLS Audit](https://github.com/MBotirjonDev/supabase-rls-audit). Automated audits miss things; a review with real user sessions increases coverage._
