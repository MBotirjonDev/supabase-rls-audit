#!/usr/bin/env node
'use strict';
/**
 * supabase-rls-audit analyzer (zero dependencies).
 *
 *   node audit.cjs <project-dir> [--out leads.json] [--sarif leads.sarif] [--schemas public,api]
 *                  [--min-severity low] [--fail-on high] [--quiet]
 *
 * Replays every SQL migration in filename order to build the final state of each
 * table (RLS on/off, policies), view and function, then reports leads. It also
 * scans app code for service_role / secret keys. Leads are triage hints; the
 * skill workflow confirms each one.
 *
 * Suppress a reviewed statement with a comment inside it:  -- rls-ignore: RLS-POL-001 public catalogue
 */
const fs = require('fs');
const path = require('path');
const RULES = require('./rules.cjs');
const { splitStatements, stripBodies, normName, clause, normExpr, QNAME } = require('./sql.cjs');

const VERSION = '0.1.0';
const TOOL = 'supabase-rls-audit';
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', '.nuxt', '.svelte-kit', '.output', '.turbo',
  '.vercel', 'coverage', '.venv', 'venv', '__pycache__', 'vendor', '.dart_tool', 'Pods', '.temp', '.branches']);
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|fixtures?|e2e)\/|[._-](test|spec)\.(m?[jt]sx?|sql)$|_test\.(sql|dart)$/;
const WRITE_CMDS = new Set(['insert', 'update', 'delete', 'all']);
const RX = (s, f = 'i') => new RegExp(s, f);

function parseArgs(argv) {
  const args = { dir: null, out: null, sarif: null, schemas: ['public'], minSeverity: 'info', failOn: null, quiet: false, includeTests: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--sarif') args.sarif = argv[++i];
    else if (a === '--schemas') args.schemas = argv[++i].split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--min-severity') args.minSeverity = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--include-tests') args.includeTests = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else if (a === '-v' || a === '--version') args.version = true;
    else if (!args.dir) args.dir = a;
    else throw new Error(`Unexpected argument: ${a}`);
  }
  for (const [k, flag] of [['minSeverity', '--min-severity'], ['failOn', '--fail-on']]) {
    if (args[k] && !SEVERITIES.includes(args[k])) throw new Error(`${flag} must be one of ${SEVERITIES.join(', ')}`);
  }
  return args;
}

function* walk(dir, root) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(full, root); } else if (e.isFile()) yield path.relative(root, full).split(path.sep).join('/');
  }
}

function read(root, rel) {
  try {
    const full = path.join(root, rel);
    if (fs.statSync(full).size > MAX_FILE_BYTES) return '';
    const t = fs.readFileSync(full, 'utf8');
    return t.includes('\u0000') ? '' : t;
  } catch { return ''; }
}

// The Supabase project a SQL file belongs to: the folder holding supabase/, else the file's folder.
function projectOf(rel) {
  const m = /^(.*?)(?:^|\/)supabase\//.exec(rel);
  if (m) return m[1];
  const dir = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
  return dir.replace(/\/(migrations|schemas?|sql|db)$/, '');
}

// Migrations replay in timestamp order; other SQL (schema dumps, seed) after them.
function sqlOrder(a, b) {
  const rank = (p) => (/(^|\/)migrations\//.test(p) ? 0 : /seed/i.test(p) ? 2 : 1);
  return rank(a) - rank(b) || path.basename(a).localeCompare(path.basename(b)) || a.localeCompare(b);
}

const ignored = (sql, id) => {
  const m = sql.match(/rls-ignore(?::\s*([A-Z0-9,\- ]+))?/);
  return Boolean(m && (!m[1] || m[1].includes(id)));
};

// ------------------------------------------------------------------ model
function buildModel(files) {
  const tables = new Map();
  const views = new Map();
  const functions = [];
  const revoked = new Set();
  const buckets = [];
  const loc = (file, st) => ({ file, line: st.line, sql: st.sql });

  for (const { file, text } of files) {
    for (const st of splitStatements(text)) {
      const s = st.clean;
      const head = stripBodies(s);
      let m;

      if ((m = RX(String.raw`^create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QNAME}`).exec(head))) {
        if (/^create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary))\s/i.test(head)) continue;
        const name = normName(m[1]);
        if (/\bpartition\s+of\b/i.test(head)) continue; // partitions inherit RLS from the parent
        const prev = tables.get(name);
        const body = clause(s, String.raw`${m[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+')}\s*`) || clause(s, String.raw`table[^(]*`);
        const columns = body ? body.text.split(/,(?![^(]*\))/).map((c) => c.trim().split(/\s+/)[0].replace(/"/g, '').toLowerCase()) : [];
        if (!prev || prev.dropped) tables.set(name, { name, ...loc(file, st), columns, rls: false, rlsEver: false, disabledAt: null, policies: [], dropped: false });
        continue;
      }
      if ((m = RX(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+(enable|disable|force|no\s+force)\s+row\s+level\s+security`).exec(head))) {
        const t = tables.get(normName(m[1]));
        if (!t) continue;
        const action = m[2].toLowerCase();
        if (action === 'enable') { t.rls = true; t.rlsEver = true; t.disabledAt = null; }
        if (action === 'disable') { t.rls = false; t.disabledAt = loc(file, st); }
        continue;
      }
      if ((m = RX(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+rename\s+to\s+(\S+)`).exec(head))) {
        const from = normName(m[1]);
        const t = tables.get(from);
        if (!t) continue;
        const to = `${from.split('.')[0]}.${normName(m[2]).split('.')[1]}`;
        tables.delete(from); t.name = to; tables.set(to, t);
        continue;
      }
      if ((m = RX(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?${QNAME}\s+set\s+schema\s+(\S+)`).exec(head))) {
        const from = normName(m[1]);
        const t = tables.get(from);
        if (!t) continue;
        const to = `${normName(m[2], m[2]).split('.').pop()}.${from.split('.')[1]}`;
        tables.delete(from); t.name = to; tables.set(to, t);
        continue;
      }
      if ((m = /^drop\s+table\s+(?:if\s+exists\s+)?([\s\S]+?)(\s+cascade|\s+restrict)?$/i.exec(head))) {
        for (const n of m[1].split(',')) { const t = tables.get(normName(n.trim())); if (t) t.dropped = true; }
        continue;
      }
      if ((m = RX(String.raw`^create\s+policy\s+(?:"(?:[^"]|"")+"|[\w$]+)\s+on\s+${QNAME}`).exec(s))) {
        const name = policyName(s);
        const table = normName(m[1]);
        const p = parsePolicy(s, name, table, loc(file, st));
        const t = tables.get(table);
        if (t) { t.policies = t.policies.filter((x) => x.name !== name); t.policies.push(p); }
        if (table.startsWith('storage.')) storagePolicies.push(p);
        continue;
      }
      if ((m = RX(String.raw`^alter\s+policy\s+(?:"(?:[^"]|"")+"|[\w$]+)\s+on\s+${QNAME}`).exec(s))) {
        const name = policyName(s);
        const t = tables.get(normName(m[1]));
        const p = t && t.policies.find((x) => x.name === name);
        if (!p) continue;
        const using = clause(s, 'using');
        const check = clause(s, String.raw`with\s+check`);
        if (using) p.using = unquote(using.text);
        if (check) p.check = unquote(check.text);
        const to = /\bto\s+([\w\s,"]+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(s.replace(/\s+rename\s+to\s+.*/i, ''));
        if (to) p.roles = to[1].split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase());
        Object.assign(p, loc(file, st));
        continue;
      }
      if ((m = RX(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?("(?:[^"]|"")+"|[\w$]+)\s+on\s+${QNAME}`).exec(s))) {
        const name = m[1].replace(/^"|"$/g, '');
        const t = tables.get(normName(m[2]));
        if (t) t.policies = t.policies.filter((x) => x.name !== name);
        const i = storagePolicies.findIndex((x) => x.name === name && x.table === normName(m[2]));
        if (i !== -1) storagePolicies.splice(i, 1);
        continue;
      }
      if ((m = RX(String.raw`^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:recursive\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?${QNAME}`).exec(head))) {
        const name = normName(m[2]);
        const opts = /^[^]*?\bwith\s*\(([^)]*)\)\s*as\b/i.exec(head.replace(/\bview\s+\S+/i, 'view x'));
        const invoker = Boolean(opts && /security_invoker\s*=\s*(true|on|'?1'?|yes)/i.test(opts[1]));
        views.set(name, { name, materialized: Boolean(m[1]), invoker, ...loc(file, st) });
        continue;
      }
      if ((m = RX(String.raw`^alter\s+(materialized\s+)?view\s+(?:if\s+exists\s+)?${QNAME}\s+set\s*\(([^)]*)\)`).exec(head))) {
        const v = views.get(normName(m[2]));
        if (v && /security_invoker\s*=\s*(true|on|'?1'?|yes)/i.test(m[3])) v.invoker = true;
        if (v && /security_invoker\s*=\s*(false|off|'?0'?|no)/i.test(m[3])) v.invoker = false;
        continue;
      }
      if ((m = RX(String.raw`^drop\s+(materialized\s+)?view\s+(?:if\s+exists\s+)?${QNAME}`).exec(head))) {
        views.delete(normName(m[2]));
        continue;
      }
      if ((m = RX(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${QNAME}\s*\(`).exec(head))) {
        const name = normName(m[1]);
        const returnsTrigger = /\breturns\s+(event_)?trigger\b/i.test(head);
        const secDef = /\bsecurity\s+definer\b/i.test(head);
        const searchPath = /\bset\s+search_path\b/i.test(head);
        const checksCaller = /auth\.(uid|jwt|role)\s*\(|current_setting\s*\(\s*'request\.jwt|current_user|session_user|raise\s+exception/i.test(unquote(s));
        const idx = functions.findIndex((f) => f.name === name);
        const fn = { name, secDef, searchPath, returnsTrigger, checksCaller, ...loc(file, st) };
        if (idx === -1) functions.push(fn); else functions[idx] = fn;
        continue;
      }
      if ((m = RX(String.raw`^alter\s+function\s+${QNAME}(?:\s*\([^)]*\))?\s+([\s\S]*)$`).exec(head))) {
        const fn = functions.find((f) => f.name === normName(m[1]));
        if (fn && /\bset\s+search_path\b/i.test(m[2])) fn.searchPath = true;
        if (fn && /\bsecurity\s+invoker\b/i.test(m[2])) fn.secDef = false;
        continue;
      }
      if ((m = RX(String.raw`^revoke\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:function|routine)\s+([\s\S]+?)\s+from\s+([\s\S]+)$`).exec(head))) {
        const roles = m[2].toLowerCase();
        if (/\banon\b/.test(roles)) {
          for (const f of m[1].split(/,(?![^(]*\))/)) revoked.add(normName(f.replace(/\([^)]*\)/, '').trim()));
        }
        continue;
      }
      if ((m = /^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*([\s\S]+?)(\s+on\s+conflict[\s\S]*)?$/i.exec(s))) {
        const cols = m[1].split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase());
        const pi = cols.indexOf('public');
        const ii = cols.indexOf('id');
        for (const tuple of m[2].match(/\((?:[^()']|'(?:[^']|'')*')*\)/g) || []) {
          const vals = splitTop(tuple.slice(1, -1));
          if (pi !== -1 && /^true$/i.test((vals[pi] || '').trim())) {
            buckets.push({ id: (vals[ii] || vals[0] || '').trim().replace(/^'|'$/g, ''), ...loc(file, st) });
          }
        }
      }
    }
  }
  return { tables, views, functions, revoked, buckets, storagePolicies: storagePolicies.splice(0) };
}
const storagePolicies = [];

// "auth"."uid"() → auth.uid() (pg_dump quotes every identifier); quoted names with spaces stay quoted.
const unquote = (sql) => sql.replace(/"([A-Za-z_][A-Za-z0-9_$]*)"/g, (m, id) => (id === id.toLowerCase() ? id : m));

function policyName(s) {
  const m = /^(?:create|alter)\s+policy\s+("(?:[^"]|"")+"|[\w$]+)/i.exec(s);
  return m[1].startsWith('"') ? m[1].slice(1, -1).replace(/""/g, '"') : m[1];
}

function parsePolicy(s, name, table, where) {
  const checkC = clause(s, String.raw`with\s+check`);
  const usingC = clause(s.slice(0, checkC ? checkC.start : s.length), 'using');
  const header = s.slice(0, usingC ? usingC.start : checkC ? checkC.start : s.length);
  const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(header) || [, 'all'])[1].toLowerCase();
  const to = /\bto\s+([\w\s,"]+?)\s*$/i.exec(header);
  const roles = to ? to[1].split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase()) : ['public'];
  const restrictive = /\bas\s+restrictive\b/i.test(header);
  return { name, table, cmd, roles, restrictive, using: usingC ? unquote(usingC.text) : null, check: checkC ? unquote(checkC.text) : null, ...where };
}

function splitTop(s) {
  const out = [];
  let depth = 0; let cur = ''; let q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") { q = !q; cur += c; continue; }
    if (!q && c === '(') depth++;
    if (!q && c === ')') depth--;
    if (!q && depth === 0 && c === ',') { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

// ------------------------------------------------------------------ expression helpers
const isTrue = (e) => e !== null && /^(true|1\s*=\s*1|'t')$/.test(normExpr(e));
const AUTH_REF = /auth\.(uid|jwt)\s*\(|current_setting\s*\(\s*'request\.jwt/i;
// A policy that calls a helper function or runs a subquery may check the caller indirectly
// (is_member(org_id), authorize('x')), so it is not reported as anonymous/unchecked.
const INDIRECT = /\bexists\s*\(|\bselect\b|\b(?!(?:coalesce|lower|upper|now|length|char_length|nullif|greatest|least|array_length|cardinality|date_trunc|to_char|any|all|in)\b)[a-z_][\w$]*(?:\.[a-z_][\w$]*)?\s*\(/i;
const SIGNED_IN_ONLY = [
  /^auth\.role\s*\(\s*\)\s*=\s*'authenticated'$/,
  /^\(?\s*(\(\s*select\s+)?auth\.uid\s*\(\s*\)\s*\)?\s*is\s+not\s+null$/,
  /^\(?\s*(\(\s*select\s+)?auth\.role\s*\(\s*\)\s*\)?\s*=\s*'authenticated'$/,
  /^\(?\s*(\(\s*select\s+)?auth\.jwt\s*\(\s*\)\s*\)?\s*is\s+not\s+null$/,
];
const signedInOnly = (e) => e !== null && SIGNED_IN_ONLY.some((re) => re.test(normExpr(e)));
const PERSONAL = /^(user_?id|owner(_id)?|email|phone|phone_number|address|full_name|first_name|last_name|birth|dob|passport|ssn|ip|ip_address|location|lat|lng|latitude|longitude|stripe_customer_id|customer_id|token|password|secret)$/;
const USER_META = /user_metadata|raw_user_meta_data|raw_user_metadata/i;
const ANON_ROLES = (roles) => roles.some((r) => r === 'anon' || r === 'public');
const ONLY_AUTHENTICATED = (roles) => roles.every((r) => r === 'authenticated');
const BARE_AUTH_CALL = /(?<!select\s{1,10})(?<!\(\s{0,5}select\s{1,10})\bauth\.(uid|jwt|role)\s*\(\s*\)/i;

// ------------------------------------------------------------------ analysis
function analyze(model, opts) {
  const leads = [];
  const exposed = (name) => opts.schemas.includes(name.split('.')[0]);
  const add = (id, at, detail, extra = {}) => {
    if (ignored(at.sql || '', id)) return;
    const r = RULES[id];
    leads.push({ rule: id, title: r.title, severity_hint: extra.severity || r.severity, file: at.file, line: at.line,
      object: extra.object, snippet: snippet(at.sql), detail, guide: r.guide, message: r.message, fix: r.fix });
  };

  for (const t of model.tables.values()) {
    if (t.dropped || !exposed(t.name)) continue;
    if (!t.rls) {
      if (t.disabledAt) add('RLS-TBL-002', t.disabledAt, `RLS on ${t.name} is turned off`, { object: t.name });
      else add('RLS-TBL-001', t, `${t.name} never gets "enable row level security" in any migration`, { object: t.name });
      continue;
    }
    if (!t.policies.length) add('RLS-TBL-003', t, `${t.name} has RLS but no policies`, { object: t.name });
  }

  const policies = [...[...model.tables.values()].filter((t) => !t.dropped && exposed(t.name)).flatMap((t) => t.policies)];
  for (const p of policies) {
    if (p.restrictive) continue;
    const exprs = [p.using, p.check].filter((e) => e !== null);
    const write = WRITE_CMDS.has(p.cmd);
    const anon = ANON_ROLES(p.roles);
    const authOnlyRole = ONLY_AUTHENTICATED(p.roles);
    const open = exprs.length > 0 && exprs.every((e) => isTrue(e));
    const signedIn = exprs.length > 0 && exprs.every((e) => isTrue(e) || signedInOnly(e)) && exprs.some((e) => signedInOnly(e));
    const label = `"${p.name}" on ${p.table} (for ${p.cmd} to ${p.roles.join(', ')})`;

    const indirect = exprs.some((e) => INDIRECT.test(e.replace(/\bstorage\.foldername\s*\(/g, '')));
    if (write && anon && !exprs.some((e) => AUTH_REF.test(e)) && (open || !indirect)) {
      add('RLS-POL-006', p, `${label} lets anonymous callers write`, { object: p.table, severity: open ? 'critical' : 'high' });
    } else if (write && (open || signedIn)) {
      add('RLS-POL-002', p, `${label}: ${open ? 'true' : 'signed-in only'} on a write policy`, { object: p.table, severity: anon ? 'critical' : 'high' });
    } else if (!write && open && anon) {
      const t = model.tables.get(p.table);
      const personal = t && t.columns.some((c) => PERSONAL.test(c));
      add('RLS-POL-001', p, `${label} is readable by anyone with the anon key${personal ? ` (columns include ${t.columns.filter((c) => PERSONAL.test(c)).join(', ')})` : ''}`,
        { object: p.table, severity: personal ? 'high' : 'medium' });
    } else if (!write && (signedIn || (open && authOnlyRole))) {
      add('RLS-POL-003', p, `${label} lets every signed-in user read every row`, { object: p.table });
    }
    if (exprs.some((e) => USER_META.test(e))) add('RLS-POL-004', p, `${label} reads user_metadata`, { object: p.table });
    if (exprs.some((e) => BARE_AUTH_CALL.test(e))) add('RLS-POL-005', p, `${label} calls auth.*() without (select …)`, { object: p.table });
  }

  for (const v of model.views.values()) {
    if (!exposed(v.name)) continue;
    if (v.materialized) add('RLS-VIEW-002', v, `${v.name} is a materialized view in an exposed schema`, { object: v.name });
    else if (!v.invoker) add('RLS-VIEW-001', v, `${v.name} has no security_invoker = true`, { object: v.name });
  }

  for (const f of model.functions) {
    if (!f.secDef) continue;
    if (!f.searchPath) add('RLS-FN-001', f, `${f.name} is security definer without set search_path`, { object: f.name });
    if (exposed(f.name) && !f.returnsTrigger && !model.revoked.has(f.name) && !f.checksCaller) {
      add('RLS-FN-002', f, `${f.name} is security definer, callable via /rpc, and never checks auth.uid()`, { object: f.name });
    }
  }

  for (const b of model.buckets) add('RLS-STO-001', b, `bucket "${b.id}" is public`, { object: `storage:${b.id}` });
  for (const p of model.storagePolicies) {
    if (p.table !== 'storage.objects' || !WRITE_CMDS.has(p.cmd) || p.restrictive) continue;
    const exprs = [p.using, p.check].filter((e) => e !== null);
    const owner = exprs.some((e) => /auth\.uid\s*\(|owner(_id)?\b|foldername/i.test(e));
    if (!owner) add('RLS-STO-002', p, `"${p.name}" (for ${p.cmd} to ${p.roles.join(', ')}) has no owner check`, { object: 'storage.objects', severity: ANON_ROLES(p.roles) ? 'high' : 'medium' });
  }
  return leads;
}

// ------------------------------------------------------------------ keys in code
const CODE_FILE = /\.(m?[jt]sx?|cjs|vue|svelte|astro|dart|py|go|rb|php|kt|swift|json|ya?ml|toml|env|txt|md)$|(^|\/)\.env(\.[\w-]+)*$/;
const JWT = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const SB_SECRET = /\bsb_secret_[A-Za-z0-9_-]{20,}/g;
const PUBLIC_SR = /\b(NEXT_PUBLIC|VITE|EXPO_PUBLIC|PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY)_\w*SERVICE_?ROLE\w*/g;
const DART_SR = /service_?role|serviceRole|SERVICE_ROLE/g;

function jwtPayload(tok) {
  try { return JSON.parse(Buffer.from(tok.split('.')[1], 'base64url').toString('utf8')); } catch { return null; }
}

function scanKeys(root, rel, text, push) {
  const lineOf = (i) => text.slice(0, i).split('\n').length;
  const lineText = (i) => text.split('\n')[lineOf(i) - 1] || '';
  let m;
  JWT.lastIndex = 0;
  while ((m = JWT.exec(text)) !== null) {
    const p = jwtPayload(m[0]);
    if (!p || p.role !== 'service_role') continue;
    const id = p.iss === 'supabase-demo' ? 'RLS-KEY-003' : 'RLS-KEY-001';
    push(id, rel, lineOf(m.index), lineText(m.index), 'service_role JWT literal');
  }
  SB_SECRET.lastIndex = 0;
  while ((m = SB_SECRET.exec(text)) !== null) push('RLS-KEY-001', rel, lineOf(m.index), lineText(m.index), 'sb_secret_ key literal');
  PUBLIC_SR.lastIndex = 0;
  while ((m = PUBLIC_SR.exec(text)) !== null) push('RLS-KEY-002', rel, lineOf(m.index), lineText(m.index), `${m[0]} is a client-exposed variable`);
  if (/(^|\/)lib\/.+\.dart$/.test(rel)) {
    DART_SR.lastIndex = 0;
    if ((m = DART_SR.exec(text)) !== null) push('RLS-KEY-002', rel, lineOf(m.index), lineText(m.index), 'service role referenced in Flutter app code');
  }
}

const snippet = (sql) => (sql || '')
  .replace(/eyJ[A-Za-z0-9_-]{6}[A-Za-z0-9_.-]+/g, (t) => `${t.slice(0, 9)}…`)
  .replace(/(sb_secret_)[A-Za-z0-9_-]+/g, '$1…')
  .replace(/\s+/g, ' ').trim().slice(0, 220);

// ------------------------------------------------------------------ entry
function audit(rootDir, opts = {}) {
  const o = { schemas: ['public'], minSeverity: 'info', ...opts };
  const root = path.resolve(rootDir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`Not a directory: ${rootDir}`);
  const all = [];
  for (const rel of walk(root, root)) if (o.includeTests || !TEST_PATH.test(rel)) all.push(rel);

  const sqlFiles = all.filter((f) => /\.sql$/i.test(f)).sort(sqlOrder);
  // Monorepos hold several Supabase projects; each is replayed on its own.
  const groups = new Map();
  for (const f of sqlFiles) {
    const key = projectOf(f);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const leads = [];
  const models = [];
  for (const files of groups.values()) {
    const model = buildModel(files.map((file) => ({ file, text: read(root, file) })));
    models.push(model);
    leads.push(...analyze(model, o));
  }

  let codeFiles = 0;
  for (const rel of all) {
    if (!CODE_FILE.test(rel) || /\.sql$/i.test(rel) || /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(rel)) continue;
    const text = read(root, rel);
    if (!text) continue;
    codeFiles++;
    scanKeys(root, rel, text, (id, file, line, lineText, detail) => {
      if (/rls-ignore/.test(lineText) && ignored(lineText, id)) return;
      const r = RULES[id];
      leads.push({ rule: id, title: r.title, severity_hint: r.severity, file, line, object: null, snippet: snippet(lineText), detail, guide: r.guide, message: r.message, fix: r.fix });
    });
  }

  const minIdx = SEVERITIES.indexOf(o.minSeverity);
  const kept = leads.filter((l) => SEVERITIES.indexOf(l.severity_hint) >= minIdx);
  kept.sort((a, b) => SEVERITIES.indexOf(b.severity_hint) - SEVERITIES.indexOf(a.severity_hint) || a.file.localeCompare(b.file) || a.line - b.line);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const l of kept) counts[l.severity_hint]++;
  const live = models.flatMap((m) => [...m.tables.values()]).filter((t) => !t.dropped && o.schemas.includes(t.name.split('.')[0]));
  return {
    tool: `${TOOL}/audit`, version: VERSION, target: path.basename(root), generated_at: new Date().toISOString(),
    exposed_schemas: o.schemas, sql_files: sqlFiles.length, code_files_scanned: codeFiles,
    model: {
      tables: live.length, tables_with_rls: live.filter((t) => t.rls).length,
      projects: models.length, policies: live.reduce((n, t) => n + t.policies.length, 0),
      views: models.reduce((n, m) => n + m.views.size, 0),
      security_definer_functions: models.reduce((n, m) => n + m.functions.filter((f) => f.secDef).length, 0),
    },
    counts,
    note: 'Leads are triage hints from replaying the migrations in this repo. The live database may differ (dashboard edits); confirm before reporting.',
    leads: kept,
  };
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SARIF_SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
function toSarif(result) {
  const used = [...new Set(result.leads.map((l) => l.rule))];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: TOOL, version: VERSION, informationUri: 'https://github.com/MBotirjonDev/supabase-rls-audit',
        rules: used.map((id) => ({ id, shortDescription: { text: RULES[id].title }, fullDescription: { text: RULES[id].message },
          help: { text: `${RULES[id].fix}\n\nGuide: skills/${TOOL}/checks/${RULES[id].guide}` },
          properties: { tags: ['security', 'supabase', 'rls'], 'security-severity': SARIF_SCORE[RULES[id].severity] } })) } },
      results: result.leads.map((l) => ({ ruleId: l.rule, level: SARIF_LEVEL[l.severity_hint], message: { text: `${l.detail}. ${l.message}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: l.file }, region: { startLine: l.line } } }] })),
    }],
  };
}

function printHuman(r) {
  const colors = { critical: 35, high: 31, medium: 33, low: 36, info: 90 };
  const tty = process.stdout.isTTY;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  const m = r.model;
  console.log(`\n${TOOL} · ${r.target} · ${r.sql_files} SQL files · ${m.tables} tables (${m.tables_with_rls} with RLS) · ${m.policies} policies · ${m.views} views · ${m.security_definer_functions} security definer functions\n`);
  if (!r.leads.length) { console.log('No leads. Run the full skill workflow to review policy logic and the live database.\n'); return; }
  for (const l of r.leads) {
    console.log(`${c(colors[l.severity_hint], l.severity_hint.toUpperCase().padEnd(8))} ${l.rule.padEnd(12)} ${l.detail}`);
    console.log(`         ${l.file}:${l.line}`);
  }
  console.log(`\n${r.leads.length} leads  (${SEVERITIES.slice().reverse().map((s) => `${s}: ${r.counts[s]}`).join('  ')})`);
  console.log('Leads are hints. Confirm each one against the live database (see SKILL.md).\n');
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.version) { console.log(VERSION); return; }
  if (args.help || !args.dir) {
    console.log('Usage: node audit.cjs <project-dir> [--out leads.json] [--sarif leads.sarif] [--schemas public,api] [--min-severity info|low|medium|high|critical] [--fail-on <severity>] [--include-tests] [--quiet]');
    process.exit(args.help ? 0 : 2);
  }
  let result;
  try { result = audit(args.dir, args); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.out) writeJson(args.out, result);
  if (args.sarif) writeJson(args.sarif, toSarif(result));
  if (!args.quiet) printHuman(result);
  if (args.failOn && result.leads.some((l) => SEVERITIES.indexOf(l.severity_hint) >= SEVERITIES.indexOf(args.failOn))) process.exit(1);
}

if (require.main === module) main();
module.exports = { audit, buildModel, analyze, toSarif, SEVERITIES, VERSION };
