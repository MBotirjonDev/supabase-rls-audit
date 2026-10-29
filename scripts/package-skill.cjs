#!/usr/bin/env node
'use strict';
/**
 * Builds dist/<skill>-<version>.zip for marketplaces that take a SKILL.md zip
 * (Agensi, manual installs). Uses the system `zip` command; no npm dependencies.
 *
 *   npm run package:skill
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const { version } = require(path.join(ROOT, 'package.json'));
const SKILL = 'supabase-rls-audit';
const src = path.join(ROOT, 'skills', SKILL);
const dist = path.join(ROOT, 'dist');
const stage = path.join(dist, 'stage');
const out = path.join(dist, `${SKILL}-${version}.zip`);

fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });
fs.cpSync(src, path.join(stage, SKILL), { recursive: true });
fs.copyFileSync(path.join(ROOT, 'LICENSE'), path.join(stage, SKILL, 'LICENSE'));
fs.writeFileSync(path.join(stage, SKILL, 'VERSION'), `${version}\n`);
fs.rmSync(out, { force: true });
execFileSync('zip', ['-qr', out, SKILL], { cwd: stage });
fs.rmSync(stage, { recursive: true, force: true });
console.log(`built ${path.relative(ROOT, out)}`);
