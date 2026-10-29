'use strict';
/**
 * Rule catalogue for supabase-rls-audit. Detection logic lives in audit.cjs;
 * this file holds what each rule means, how bad it usually is, and how to fix it.
 *
 *   id        RLS-<AREA>-<NNN>   AREA: TBL POL VIEW FN STO KEY
 *   severity  critical | high | medium | low | info   (triage guess; the skill confirms it)
 *   guide     checks/<FILE>.md#anchor
 */
module.exports = {
  'RLS-TBL-001': {
    title: 'Table in an exposed schema without Row Level Security',
    severity: 'critical',
    guide: 'TABLES.md#tables-without-rls',
    message: 'The Data API serves every table in the public schema. Without RLS, anyone holding the anon key (it ships in every app) can read, insert, update and delete every row.',
    fix: 'alter table <name> enable row level security; then add policies for exactly the access each role needs.',
  },
  'RLS-TBL-002': {
    title: 'RLS disabled by a later migration',
    severity: 'critical',
    guide: 'TABLES.md#tables-without-rls',
    message: 'A migration turned Row Level Security off again. Often done "temporarily" while debugging a policy, then shipped.',
    fix: 'Re-enable RLS in a new migration and fix the policy that was failing instead.',
  },
  'RLS-TBL-003': {
    title: 'RLS enabled but no policies',
    severity: 'info',
    guide: 'TABLES.md#rls-without-policies',
    message: 'Nobody except service_role and the table owner can access this table through the API. Correct for backend-only tables; a bug if the app reads it.',
    fix: 'If the app should read or write it, add explicit policies. If it is backend-only, consider moving it to a non-exposed schema.',
  },
  'RLS-POL-001': {
    title: 'Policy lets anyone read every row (using true)',
    severity: 'high',
    guide: 'POLICIES.md#using-true',
    message: 'USING (true) for anon/public means every row is readable with the public anon key. Fine for genuinely public data (product catalogue); a data leak for anything user-owned.',
    fix: 'Restrict rows: using ((select auth.uid()) = user_id), or limit to authenticated, or expose a view with only public columns.',
  },
  'RLS-POL-002': {
    title: 'Policy lets any caller write any row',
    severity: 'critical',
    guide: 'POLICIES.md#using-true',
    message: 'An INSERT/UPDATE/DELETE/ALL policy with true (or no ownership check) lets callers create, modify or delete rows that are not theirs.',
    fix: 'Check ownership in both clauses: using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id).',
  },
  'RLS-POL-003': {
    title: 'Policy only checks that the user is signed in',
    severity: 'medium',
    guide: 'POLICIES.md#signed-in-is-not-authorization',
    message: 'auth.role() = \'authenticated\' / auth.uid() is not null / TO authenticated with true lets every signed-up user act on every row. Sign-up is usually open, so this is almost public.',
    fix: 'Add the ownership or membership condition: (select auth.uid()) = user_id, or an exists(...) against a membership table.',
  },
  'RLS-POL-004': {
    title: 'Policy trusts user-editable user_metadata',
    severity: 'high',
    guide: 'POLICIES.md#user_metadata-is-user-controlled',
    message: 'raw_user_meta_data / user_metadata can be changed by the signed-in user with supabase.auth.updateUser(). A policy that reads a role or tenant from it can be bypassed by the user.',
    fix: 'Keep roles in app_metadata (only the server can write it), or in a table the user cannot write, and read that in the policy.',
  },
  'RLS-POL-005': {
    title: 'auth function evaluated per row',
    severity: 'info',
    guide: 'POLICIES.md#performance',
    message: 'auth.uid() / auth.jwt() called directly in a policy is re-evaluated for every row. Wrapping it in (select …) lets Postgres evaluate it once per query.',
    fix: 'Write (select auth.uid()) instead of auth.uid(), and index the column it is compared with.',
  },
  'RLS-POL-006': {
    title: 'Write policy for anonymous users',
    severity: 'high',
    guide: 'POLICIES.md#anonymous-writes',
    message: 'A policy grants INSERT/UPDATE/DELETE to anon (or public). Anyone with the anon key can write without signing in: spam, data tampering, storage abuse.',
    fix: 'Grant writes to authenticated with an ownership check, or route anonymous writes (contact forms) through an Edge Function with rate limits and validation.',
  },
  'RLS-VIEW-001': {
    title: 'View bypasses RLS (security definer view)',
    severity: 'high',
    guide: 'VIEWS-FUNCTIONS.md#views-bypass-rls',
    message: 'Postgres views run with the privileges of their owner (postgres), so RLS on the underlying tables does not apply. A view in an exposed schema can leak every row.',
    fix: 'create view ... with (security_invoker = true) as ... (Postgres 15+), or alter view <name> set (security_invoker = true); or move the view to a non-exposed schema.',
  },
  'RLS-VIEW-002': {
    title: 'Materialized view in an exposed schema',
    severity: 'medium',
    guide: 'VIEWS-FUNCTIONS.md#materialized-views',
    message: 'Materialized views cannot have RLS and are served by the Data API if they are in an exposed schema.',
    fix: 'Move it to a private schema and expose the data through a security_invoker view or an RPC that checks the caller.',
  },
  'RLS-FN-001': {
    title: 'SECURITY DEFINER function without a fixed search_path',
    severity: 'medium',
    guide: 'VIEWS-FUNCTIONS.md#security-definer-functions',
    message: 'A SECURITY DEFINER function runs as its owner. Without SET search_path, objects it references can be resolved through a schema the caller controls.',
    fix: 'Add set search_path = \'\' and schema-qualify every object inside the function (public.profiles, auth.uid()).',
  },
  'RLS-FN-002': {
    title: 'SECURITY DEFINER function callable through the API',
    severity: 'medium',
    guide: 'VIEWS-FUNCTIONS.md#security-definer-functions',
    message: 'Functions in an exposed schema are callable via /rest/v1/rpc by anon and authenticated by default. A SECURITY DEFINER function bypasses RLS, so it must check the caller itself.',
    fix: 'Check (select auth.uid()) inside the function, or revoke execute on function <name> from anon, authenticated, public; or move it to a private schema.',
  },
  'RLS-STO-001': {
    title: 'Public storage bucket',
    severity: 'info',
    guide: 'STORAGE.md#public-buckets',
    message: 'Files in a public bucket are readable by anyone who has (or guesses) the URL, regardless of storage policies.',
    fix: 'Keep public only for assets meant to be public (avatars, product images). Use a private bucket with signed URLs for documents, receipts, IDs.',
  },
  'RLS-STO-002': {
    title: 'Storage write policy without an owner check',
    severity: 'medium',
    guide: 'STORAGE.md#owner-checks',
    message: 'The policy only checks bucket_id, so any allowed user can upload, overwrite or delete any file in the bucket, including other users\' files.',
    fix: 'Tie objects to the user: (storage.foldername(name))[1] = (select auth.uid())::text, or owner_id = (select auth.uid())::text.',
  },
  'RLS-KEY-001': {
    title: 'service_role / secret key in the repository',
    severity: 'critical',
    guide: 'KEYS.md#service-role-key',
    message: 'The service_role JWT or sb_secret_ key bypasses every RLS policy. Anyone who reads this file has full read/write access to the database and storage.',
    fix: 'Rotate it now (Project Settings → API Keys), keep it only in server-side secrets, and purge it from git history.',
  },
  'RLS-KEY-002': {
    title: 'service_role key exposed to the client bundle',
    severity: 'critical',
    guide: 'KEYS.md#service-role-key',
    message: 'This variable name is inlined into client code (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, PUBLIC_, REACT_APP_) or used in Flutter app code, so the service role key ships to every user.',
    fix: 'Use the anon / publishable key in clients. Move privileged work to an Edge Function or server route that holds the secret.',
  },
  'RLS-KEY-003': {
    title: 'Local development service key (supabase-demo)',
    severity: 'info',
    guide: 'KEYS.md#local-demo-keys',
    message: 'This is the well-known service key of the local Supabase CLI stack (issuer supabase-demo). Harmless for local dev; make sure production never uses it.',
    fix: 'Keep it in .env.example / local config only.',
  },
};
