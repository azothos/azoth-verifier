// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * What the package promises about itself: no dependency, no network, the cryptography in one
 * module per runtime, a license header on every file, and a web page that is exactly what these
 * sources build.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPage, PAGE_PATH } from '../scripts/build-web.mjs';

const PKG = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = rel => readFileSync(join(PKG, rel), 'utf8');
const list = dir => readdirSync(join(PKG, dir)).filter(f => f.endsWith('.mjs')).map(f => `${dir}/${f}`);
const specifiers = src => [...src.matchAll(/^\s*(?:import|export)\s[^'"]*?from\s+'([^']+)'/gm)].map(m => m[1]);

test('package.json declares no dependency of any kind', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies']) assert.equal(pkg[k], undefined, k);
  assert.equal(pkg.license, 'Apache-2.0');
});

test('the checks import only each other; only crypto.mjs reaches a Node API', () => {
  for (const file of list('src')) {
    for (const spec of specifiers(read(file))) {
      if (file === 'src/crypto.mjs' && spec === 'node:crypto') continue;
      assert.match(spec, /^\.\/[\w-]+\.mjs$/, `${file} imports ${spec}`);
    }
  }
  for (const file of [...list('bin'), ...list('scripts'), ...list('test'), 'web/app.mjs']) {
    for (const spec of specifiers(read(file))) assert.match(spec, /^(\.{1,2}\/|node:)/, `${file} imports ${spec}`);
  }
});

test('nothing in the verifier can reach a network', () => {
  for (const file of [...list('src'), ...list('bin'), 'web/app.mjs']) {
    assert.doesNotMatch(read(file), /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|\bimport\s*\(|node:(http|https|net|dgram|dns|tls)\b/, file);
  }
  assert.match(buildPage().csp, /connect-src 'none'/);
});

test('every source file carries its license header', () => {
  const files = [...list('src'), ...list('bin'), ...list('scripts'), ...list('test'), 'web/app.mjs', 'web/style.css', 'web/template.html'];
  for (const file of files) assert.match(read(file), /SPDX-License-Identifier: Apache-2\.0/, file);
});

test('web/azoth-verify.html is exactly what these sources build', () => {
  assert.equal(readFileSync(PAGE_PATH, 'utf8'), buildPage().html, 'run: node scripts/build-web.mjs');
});
