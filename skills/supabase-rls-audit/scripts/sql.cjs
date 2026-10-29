'use strict';
/**
 * Minimal PostgreSQL statement splitter and helpers (zero dependencies).
 *
 * Not a full parser. It understands exactly what is needed to read Supabase
 * migrations reliably: -- and nested block comments, 'strings' (with ''), E'strings',
 * "identifiers", and $tag$ dollar-quoted bodies, so semicolons inside function
 * bodies and strings never split a statement.
 */

/** Split SQL text into statements. Returns [{ sql, clean, start, line }]. */
function splitStatements(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  let start = -1;       // index of first significant char of the current statement
  let clean = '';       // statement text with comments replaced by spaces
  let raw = '';

  const begin = (idx) => { if (start === -1) start = idx; };
  const flush = () => {
    if (start !== -1 && clean.trim()) out.push({ sql: raw.trim(), clean: clean.trim(), start });
    start = -1; clean = ''; raw = '';
  };

  while (i < n) {
    const c = text[i];
    const d = text[i + 1];
    // line comment
    if (c === '-' && d === '-') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      if (start !== -1) { clean += ' '; raw += text.slice(i, stop); }
      i = stop;
      continue;
    }
    // block comment (Postgres allows nesting)
    if (c === '/' && d === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (text[j] === '/' && text[j + 1] === '*') { depth++; j += 2; } else if (text[j] === '*' && text[j + 1] === '/') { depth--; j += 2; } else j++;
      }
      if (start !== -1) { clean += ' '; raw += text.slice(i, j); }
      i = j;
      continue;
    }
    // single-quoted string (also E'..' with backslash escapes)
    if (c === "'") {
      begin(i);
      const escape = i > 0 && /[eE]/.test(text[i - 1]) && !/\w/.test(text[i - 2] || ' ');
      let j = i + 1;
      while (j < n) {
        if (escape && text[j] === '\\') { j += 2; continue; }
        if (text[j] === "'") { if (text[j + 1] === "'") { j += 2; continue; } j++; break; }
        j++;
      }
      clean += text.slice(i, j); raw += text.slice(i, j);
      i = j;
      continue;
    }
    // quoted identifier
    if (c === '"') {
      begin(i);
      let j = i + 1;
      while (j < n) { if (text[j] === '"') { if (text[j + 1] === '"') { j += 2; continue; } j++; break; } j++; }
      clean += text.slice(i, j); raw += text.slice(i, j);
      i = j;
      continue;
    }
    // dollar-quoted body: $$...$$ or $tag$...$tag$
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i, i + 64));
      if (m && !(i > 0 && /[\w$]/.test(text[i - 1]))) {
        begin(i);
        const tag = m[0];
        const end = text.indexOf(tag, i + tag.length);
        const stop = end === -1 ? n : end + tag.length;
        clean += text.slice(i, stop); raw += text.slice(i, stop);
        i = stop;
        continue;
      }
    }
    if (c === ';') { flush(); i++; continue; }
    if (!/\s/.test(c)) begin(i);
    if (start !== -1) { clean += c; raw += c; }
    i++;
  }
  flush();

  // line numbers
  let line = 1;
  let pos = 0;
  for (const s of out) {
    for (; pos < s.start; pos++) if (text.charCodeAt(pos) === 10) line++;
    s.line = line;
  }
  return out;
}

/** Remove dollar-quoted bodies and string literals, for analysing a statement's header. */
function stripBodies(sql) {
  return sql
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)?\$[\s\S]*?\$\1\$/g, ' $body$ ')
    .replace(/'(?:[^']|'')*'/g, "''");
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;

/** Normalise a possibly schema-qualified, possibly quoted name to schema.name (lowercase unquoted parts). */
function normName(name, defaultSchema = 'public') {
  const parts = [];
  const re = new RegExp(IDENT, 'g');
  let m;
  while ((m = re.exec(name)) !== null) {
    const p = m[0];
    parts.push(p.startsWith('"') ? p.slice(1, -1).replace(/""/g, '"') : p.toLowerCase());
  }
  if (parts.length === 1) parts.unshift(defaultSchema);
  return parts.slice(-2).join('.');
}

/**
 * Find `keyword (` (keyword is a regex source) at paren depth 0 and return the balanced
 * contents of the parentheses, or null. Strings and quoted identifiers are respected.
 */
function clause(sql, keyword, from = 0) {
  const re = new RegExp(String.raw`\b${keyword}\s*\(`, 'gi');
  re.lastIndex = from;
  let m;
  while ((m = re.exec(sql)) !== null) {
    if (depthAt(sql, m.index) !== 0) continue;
    const open = m.index + m[0].length - 1;
    const close = matchParen(sql, open);
    if (close === -1) return null;
    return { text: sql.slice(open + 1, close), start: m.index, end: close + 1 };
  }
  return null;
}

function matchParen(sql, open) {
  let depth = 0;
  for (let i = open; i < sql.length; i++) {
    const c = sql[i];
    if (c === "'") { i = skipQuoted(sql, i, "'"); continue; }
    if (c === '"') { i = skipQuoted(sql, i, '"'); continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function skipQuoted(sql, i, q) {
  let j = i + 1;
  while (j < sql.length) { if (sql[j] === q) { if (sql[j + 1] === q) { j += 2; continue; } return j; } j++; }
  return j;
}

function depthAt(sql, idx) {
  let depth = 0;
  for (let i = 0; i < idx; i++) {
    const c = sql[i];
    if (c === "'") { i = skipQuoted(sql, i, "'"); continue; }
    if (c === '"') { i = skipQuoted(sql, i, '"'); continue; }
    if (c === '(') depth++; else if (c === ')') depth--;
  }
  return depth;
}

/** Collapse whitespace and redundant outer parentheses: '( (true) )' → 'true'. */
function normExpr(expr) {
  let e = (expr || '').replace(/\s+/g, ' ').trim().toLowerCase();
  for (;;) {
    if (e.startsWith('(') && matchParen(e, 0) === e.length - 1) e = e.slice(1, -1).trim();
    else return e;
  }
}

module.exports = { splitStatements, stripBodies, normName, clause, normExpr, IDENT, QNAME };
