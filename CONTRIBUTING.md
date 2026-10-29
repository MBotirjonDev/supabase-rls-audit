# Contributing

Every RLS mistake you have seen in the wild is a rule someone else needs.

## Add a rule (≈20 minutes)

1. **Open an issue** with the *New rule* template: vulnerable SQL, safe SQL, what an attacker gains.
2. Add the rule's metadata to `skills/supabase-rls-audit/scripts/rules.cjs`
   (`RLS-<AREA>-<NNN>`, areas `TBL POL VIEW FN STO KEY`).
3. Add the detection to `analyze()` (or `buildModel()` if it needs new state) in
   `scripts/audit.cjs`. Work on the **final state** after replaying all migrations, never on a
   single statement in isolation.
4. Add a positive case to `tests/fixtures/vuln_app/` and keep `tests/fixtures/clean_app/` clean;
   add a focused test in `tests/audit.test.cjs` for the tricky negative cases.
5. Add or extend the section in `checks/*.md` (the `guide` anchor must exist; tests check it).
6. Update the rules table in `README.md`.
7. `npm test`: all green, no new dependencies.

Please run your rule on a few open-source Supabase projects and report the false-positive count
in the PR. Key-shaped test values (JWTs, `sb_secret_`) must be generated in the test, never
committed.

## SQL parsing

`scripts/sql.cjs` is a deliberately small statement splitter, not a Postgres parser. If you hit
SQL it misreads, add the smallest failing snippet to the splitter test first.

## Ground rules

- Zero runtime dependencies. Node ≥ 18 standard library only.
- The analyzer never connects to a database or the network.
- Rules produce **leads**; wording says "review"/"may".
- Found a vulnerability *in this project*? See [SECURITY.md](SECURITY.md).
- Be kind in reviews. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
