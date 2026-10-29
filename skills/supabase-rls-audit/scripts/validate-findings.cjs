#!/usr/bin/env node
'use strict';
/**
 * Validates findings.json produced by the audit workflow (zero dependencies).
 *
 *   node validate-findings.cjs <findings.json>
 *
 * Exit code 0 = valid, 1 = invalid (errors printed), 2 = usage / IO error.
 */
const fs = require('fs');

const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const AREAS = ['tables', 'policies', 'views', 'functions', 'storage', 'keys'];

function validate(doc) {
  const errors = [];
  const err = (where, msg) => errors.push(`${where}: ${msg}`);
  const str = (v) => typeof v === 'string' && v.trim().length > 0;

  if (!doc || typeof doc !== 'object') return ['root: must be an object'];
  if (!str(doc.target)) err('root', '"target" (project name) is required');
  if (!Array.isArray(doc.findings)) return [...errors, 'root: "findings" must be an array'];

  const ids = new Set();
  doc.findings.forEach((f, i) => {
    const at = `findings[${i}]${f && f.id ? ` (${f.id})` : ''}`;
    if (!f || typeof f !== 'object') return err(at, 'must be an object');
    if (!/^F-\d{1,4}$/.test(f.id || '')) err(at, 'id must look like F-1, F-12');
    else if (ids.has(f.id)) err(at, 'duplicate id'); else ids.add(f.id);
    if (!VERDICTS.includes(f.verdict)) err(at, `verdict must be one of ${VERDICTS.join(', ')}`);
    if (!str(f.title)) err(at, 'title is required');
    if (f.area !== undefined && !AREAS.includes(f.area)) err(at, `area must be one of ${AREAS.join(', ')}`);
    if (!f.location || !str(f.location.file)) err(at, 'location.file is required');
    else if (f.location.line !== undefined && !(Number.isInteger(f.location.line) && f.location.line > 0)) {
      err(at, 'location.line must be a positive integer');
    }
    if (f.cwe !== undefined && !/^CWE-\d{1,4}$/.test(f.cwe)) err(at, 'cwe must look like CWE-639');
    if (f.leads !== undefined && !(Array.isArray(f.leads) && f.leads.every((l) => /^RLS-[A-Z]{2,4}-\d{3}$/.test(l)))) {
      err(at, 'leads must be an array of scanner rule ids (RLS-XXX-000)');
    }

    if (f.verdict === 'confirmed') {
      if (!SEVERITIES.includes(f.severity)) err(at, `confirmed findings need severity (${SEVERITIES.join('|')})`);
      if (!Array.isArray(f.trace) || f.trace.length < 2 || !f.trace.every(str)) {
        err(at, 'confirmed findings need a trace: at least 2 steps from attacker-controlled source to impact');
      }
      if (!str(f.attacker)) err(at, 'confirmed findings must say who the attacker is and what they control');
      if (!str(f.impact)) err(at, 'confirmed findings need impact');
      if (!str(f.fix)) err(at, 'confirmed findings need a fix');
      if (!str(f.verified_by)) err(at, 'confirmed findings need verified_by (the independent verifier)');
    }
    if (f.verdict === 'needs_validation') {
      if (f.severity !== undefined) err(at, 'needs_validation must NOT have a severity');
      if (!str(f.unresolved)) err(at, 'needs_validation must name the exact unresolved fact');
    }
    if (f.verdict === 'rejected') {
      if (f.severity !== undefined) err(at, 'rejected must NOT have a severity');
      if (!str(f.rejection_reason)) err(at, 'rejected findings need rejection_reason');
    }
  });
  return errors;
}

function main() {
  const file = process.argv[2];
  if (!file) { console.error('Usage: node validate-findings.cjs <findings.json>'); process.exit(2); }
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { console.error(`Cannot read ${file}: ${e.message}`); process.exit(2); }
  const errors = validate(doc);
  if (errors.length) {
    console.error(`${file}: ${errors.length} error(s)`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  const by = (v) => doc.findings.filter((f) => f.verdict === v).length;
  console.log(`${file}: valid · ${by('confirmed')} confirmed · ${by('needs_validation')} needs_validation · ${by('rejected')} rejected`);
}

if (require.main === module) main();
module.exports = { validate };
