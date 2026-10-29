# API keys

| Key | Where it may live | What it can do |
|---|---|---|
| `anon` JWT / `sb_publishable_…` | apps, browsers, public repos | whatever your RLS policies allow `anon`/`authenticated` |
| `service_role` JWT / `sb_secret_…` | server secrets only | **everything**, RLS is bypassed |

## Checklist

- [ ] No `service_role` JWT or `sb_secret_` key in git (including history and `.env` files)
- [ ] No service role key in Flutter `lib/`, mobile apps, browser code, or public env vars
- [ ] Server code that uses the service role cannot be reached without its own auth check
- [ ] Keys that ever leaked were rotated

## Service role key

The service role key is a JWT with `"role": "service_role"`. The analyzer decodes JWT-shaped
strings and reports the ones with that role. New-style secret keys start with `sb_secret_`.

Client-exposed variable prefixes inline values into the bundle every user downloads:
`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`, `GATSBY_`.
A service role key under any of them is published. In Flutter, anything in `lib/` (including
`--dart-define` and `envied` values) is in the app binary.

If it leaked: rotate it in **Project Settings → API Keys** (with new-style keys you can
create a new secret key and delete the old one), update server secrets, and purge history.

**Validate:** `supabase/functions/**` (Edge Functions) and server-only files (Next.js route
handlers, `server-only` modules) may read the service role key from the environment; that is
correct. A key **literal** in any file is still a finding.

## Local demo keys

`supabase start` uses fixed, publicly documented JWTs signed for the issuer `supabase-demo`.
They only work against the local stack. The analyzer reports them as info; they are fine in
`.env.example` and local config, but production must never use them.
