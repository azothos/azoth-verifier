#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Build the offline web verifier: ONE self-contained HTML file — the verifier's own modules, with
 * crypto-web.mjs as their cryptography, bundled into a single inline script; no dependency, no
 * network, nothing to install. It opens from a file (file://) as well as from a web server, under
 * a policy that allows its own script and style by hash and no connection at all
 * (connect-src 'none').
 *
 *   node scripts/build-web.mjs          writes web/azoth-verify.html
 *   node scripts/build-web.mjs --check  fails if web/azoth-verify.html is not what the sources build
 *
 * `buildPage()` also returns the policy a server should send with the page (the header form adds
 * frame-ancestors, which a <meta> policy cannot carry). The bundler is deliberately small: each
 * module becomes a function scope, its `import { … } from` lines read the modules before it, its
 * `export` names are returned. The modules form a graph without cycles, listed here in order.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** The modules, dependencies first: [name, path inside the package]. */
const MODULES = [
  ['bytes', 'src/bytes.mjs'], ['der', 'src/der.mjs'], ['keys', 'src/keys.mjs'], ['crypto', 'src/crypto-web.mjs'], ['x509', 'src/x509.mjs'], ['zip', 'src/zip.mjs'],
  ['chain', 'src/chain.mjs'], ['timestamp', 'src/timestamp.mjs'], ['incident', 'src/incident.mjs'],
  ['platform', 'src/platform.mjs'], ['jurisdiction', 'src/jurisdiction.mjs'], ['litigation', 'src/litigation.mjs'], ['signature', 'src/signature.mjs'], ['pricing', 'src/pricing.mjs'], ['footprint', 'src/footprint.mjs'], ['retention', 'src/retention.mjs'], ['headroot', 'src/headroot.mjs'], ['compliance', 'src/compliance.mjs'], ['verify', 'src/verify.mjs'], ['receipt', 'src/receipt.mjs'], ['export', 'src/export.mjs'], ['app', 'web/app.mjs'],
];
/** An import specifier → the module it names (crypto.mjs is the web one here). */
const nameOf = spec => {
  const base = spec.replace(/^.*\//, '').replace(/\.mjs$/, '');
  return base === 'crypto-web' ? 'crypto' : base;
};
const known = new Set(MODULES.map(m => m[0]));
const bindings = list => list.split(',').map(s => s.trim()).filter(Boolean).map(s => s.replace(/\s+as\s+/, ': ')).join(', ');

function moduleScope(name, source, done) {
  const exported = [];
  const need = spec => {
    const dep = nameOf(spec);
    if (!known.has(dep) || !done.has(dep)) throw new Error(`${name}: imports ${spec} before it is built`);
    return dep;
  };
  let body = source
    .replace(/^import \{([^}]+)\} from '([^']+)';$/gm, (_, list, spec) => `const { ${bindings(list)} } = M.${need(spec)};`)
    .replace(/^export \{([^}]+)\} from '([^']+)';$/gm, (_, list, spec) => { exported.push(...list.split(',').map(s => s.trim())); return `const { ${bindings(list)} } = M.${need(spec)};`; })
    .replace(/^export \{([^}]+)\};$/gm, (_, list) => { exported.push(...list.split(',').map(s => s.trim())); return ''; })
    .replace(/^export (async function|function|const|let) (\w+)/gm, (_, kind, id) => { exported.push(id); return `${kind} ${id}`; });
  if (/^\s*(import|export)\b/m.test(body)) throw new Error(`${name}: an import or export form the bundler does not read`);
  body = body.replace(/^#!.*\n/, '');
  return `M.${name} = (() => {\n${body}\nreturn { ${[...new Set(exported)].join(', ')} };\n})();\n`;
}

const hash = text => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

/** The page and its policy, as built from the sources now. */
export function buildPage() {
  const done = new Set();
  let script = '"use strict";\nconst M = Object.create(null);\n';
  for (const [name, path] of MODULES) {
    script += moduleScope(name, readFileSync(join(PKG, path), 'utf8'), done);
    done.add(name);
  }
  const style = readFileSync(join(PKG, 'web/style.css'), 'utf8');
  const policy = `default-src 'none'; script-src ${hash(script)}; style-src ${hash(style)}; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'`;
  const html = readFileSync(join(PKG, 'web/template.html'), 'utf8')
    .replace('%CSP%', policy).replace('%STYLE%', () => style).replace('%SCRIPT%', () => script);
  // The header adds what a <meta> policy cannot carry: nobody may frame the page.
  return { html, csp: `${policy}; frame-ancestors 'none'` };
}

/** Where the page is kept in this package. */
export const PAGE_PATH = join(PKG, 'web/azoth-verify.html');

/**
 * Write (or, with `check`, compare) each [path, text] output; returns the paths that were out of
 * date. The page is one output; a server that also serves the page can pass its own copy and its
 * policy file.
 */
export function syncOutputs(outputs, { check = false } = {}) {
  const stale = [];
  for (const [path, text] of outputs) {
    let current = null;
    try { current = readFileSync(path, 'utf8'); } catch { current = null; }
    if (current === text) continue;
    stale.push(path);
    if (!check) writeFileSync(path, text);
  }
  return stale;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes('--check');
  const stale = syncOutputs([[PAGE_PATH, buildPage().html]], { check });
  if (check && stale.length) {
    for (const path of stale) process.stderr.write(`out of date: ${path}\n`);
    process.stderr.write('run: node scripts/build-web.mjs\n');
    process.exit(1);
  }
  if (!check) process.stdout.write('azoth-verify.html built\n');
}
