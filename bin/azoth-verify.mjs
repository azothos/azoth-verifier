#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * azoth-verify — verify an Azoth audit dossier independently.
 *
 * Usage:
 *   azoth-verify <dossier.zip | dossier-dir> --keys <jwks.json>   human-readable PASS/FAIL per check
 *   azoth-verify <dossier> --keys <jwks.json> --json              machine-readable, for CI
 *   azoth-verify <dossier> --tsa-root root.pem                    pin the time-stamping authority's root
 *   azoth-verify <dossier> --published-roots roots.json           compare its hourly roots with the published ones
 *   azoth-verify receipt <token|file> --dossier <dossier> | --keys <jwks.json>   a call's receipt (Check 10)
 *   azoth-verify export <body.json> --signature <token|file> --keys <jwks.json>  a signed JSON evidence pack (Check 17)
 *
 * Exit code 0 = every check PASS, 1 = any FAIL (or a usage error). Zero runtime
 * dependencies, zero network. Reimplements the manifest + chain algorithms
 * (see SPEC.md); it does not import Azoth application code, by design.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { readZip } from '../src/zip.mjs';
import { verifyDossier } from '../src/verify.mjs';
import { verifyReceipt } from '../src/receipt.mjs';
import { verifyExport } from '../src/export.mjs';
import { readPublishedRoots } from '../src/headroot.mjs';

const HELP = `azoth-verify — verify an Azoth audit dossier independently

Usage:
  azoth-verify <dossier.zip | dossier-dir> --keys <jwks.json> [--json] [--tsa-root <root.pem>] [--vault-content <file|dir>]
               [--published-roots <roots.json>]
  azoth-verify receipt <token | file> [--dossier <dossier>] [--keys <jwks.json>] [--json]
  azoth-verify export <body.json> --signature <token | file> --keys <jwks.json> [--workspace <id>] [--json]

Checks:
  - every file's sha256 matches manifest.json
  - manifest.root_hash matches the file hashes
  - the sealed decision chain in evidence.json verifies (hash + linkage)
  - for a decision dossier: each call recomputes and sits in a verified chain
    segment, segments end on timestamped journal heads (RFC 3161), and the
    rule sets / use cases in force hash to their archived files
  - with --vault-content <file|dir>: each file (content you decrypted from your
    vault, or the stored envelope) hashes to a sealed vault receipt
  - when the dossier carries anchor.tsr: the RFC 3161 timestamp covers
    root_hash under a valid TSA signature; with --tsa-root, its chain ends
    on that root (without it: WARN, the chain ends on a root the dossier ships)
  - when the dossier carries head-roots.json: each head it names is one of the
    dossier's sealed links and a leaf of an hourly platform root (Merkle
    inclusion proof), and that root's RFC 3161 token is valid — trusted with
    --tsa-root, as above — and dated neither before its hour nor before the
    entries it covers nor after the dossier was signed (WARN when dated more
    than 2 h late); WARN when head-roots.json is missing although the signature
    says the export shipped one, or that the producer dated heads by then
  - with --published-roots <roots.json> (repeatable): each of those roots is the
    one the producer published for its hour — a file you saved from its
    /api/proof/head-roots?from=<hour>&to=<hour> (read from disk: the verifier
    fetches nothing); another root, tree size or token FAILS (the chain was
    rooted again after the publication); an hour the files do not cover is
    said (WARN: not compared)
  - signature.jws (required): the workspace's Ed25519 key — Azoth's platform key,
    for a platform package — signed root_hash, and the key is one of those given
    with --keys (the keys Azoth publishes). Without --keys, or without
    signature.jws, the dossier does NOT verify: a key the dossier ships vouches
    only for itself, and an unsigned dossier binds its content to no key
  - what the signature commits: the dossier's kind, the chain's head at export,
    the count and seq range of the entries listed — evidence.json must match it,
    and the verifier says what the dossier covers and what it leaves out
  - for a litigation dossier: the hold designated exactly the decisions listed
  - receipt: a call's receipt (the x-azoth-receipt header) is signed by one of the
    workspace's keys (--keys, or the dossier's keys.jwks.json); with --dossier, the
    dossier verifies and the decision the receipt certifies is sealed in its chain
  - export: a JSON evidence pack (GET /api/v1/journal/export, saved exactly as
    received) and its X-Azoth-Export-Signature header (the token, or a file
    holding it or the header line): the body's sha256 is the one signed, by one of
    the workspace's keys given with --keys, at an instant that key may sign; the
    pack is the workspace's (and, with --workspace or a JWKS that names it, the
    keys'); it lists what the signature commits; its chain verifies

Exit code: 0 = all PASS (warnings allowed), 1 = any FAIL. No network, no dependencies.`;

function die(msg) { process.stderr.write(msg + '\n'); process.exit(1); }

/** Load a dossier (zip file or directory) into { path: Uint8Array }. */
function loadDossier(target) {
  const st = statSync(target);
  if (st.isDirectory()) {
    const files = {};
    for (const name of readdirSync(target)) {
      const full = join(target, name);
      if (statSync(full).isFile()) files[name] = new Uint8Array(readFileSync(full));
    }
    return files;
  }
  return readZip(new Uint8Array(readFileSync(target)));
}

function print(result, json, what) {
  if (json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    for (const c of result.checks) {
      process.stdout.write(`${!c.ok ? 'FAIL' : c.level === 'warn' ? 'WARN' : 'PASS'}  ${c.id.padEnd(28)} ${c.detail}\n`);
    }
    process.stdout.write(`\n${result.ok ? `VERIFIED — ${what} is intact.` : `FAILED — ${what} did not verify.`}\n`);
  }
  process.exit(result.ok ? 0 : 1);
}

/** Check 10: `azoth-verify receipt <token|file> [--dossier <dossier>] [--keys <jwks.json>] [--json]`. */
function runReceipt(argv) {
  const json = argv.includes('--json');
  const opt = (name) => {
    const at = argv.indexOf(name);
    if (at < 0) return undefined;
    const v = argv[at + 1];
    if (!v || v.startsWith('-')) die(`error: ${name} needs a path. Try --help.`);
    return v;
  };
  const keysPath = opt('--keys');
  const dossierPath = opt('--dossier');
  const optionValues = new Set(argv.flatMap((a, i) => (a === '--keys' || a === '--dossier' ? [i + 1] : [])));
  const target = argv.find((a, i) => !a.startsWith('-') && !optionValues.has(i));
  if (!target) die('error: no receipt given (the token, or a file holding it). Try --help.');
  const token = existsSync(target) && statSync(target).isFile() ? readFileSync(target, 'utf8').trim() : target;

  let files = null;
  if (dossierPath) {
    try { files = loadDossier(dossierPath); } catch (err) { die(`error: could not read dossier: ${err.message}`); }
  }
  const dec = new TextDecoder();
  let jwks;
  try {
    if (keysPath) jwks = JSON.parse(readFileSync(keysPath, 'utf8'));
    else if (files?.['keys.jwks.json']) jwks = JSON.parse(dec.decode(files['keys.jwks.json']));
  } catch (err) { die(`error: the keys are not valid JSON: ${err.message}`); }
  if (!jwks) die('error: no keys — give --keys <jwks.json>, or a --dossier that holds keys.jwks.json.');
  let pack = null;
  try { pack = files?.['evidence.json'] ? JSON.parse(dec.decode(files['evidence.json'])) : null; } catch { pack = null; }

  // Keys given with --keys are the ones pinned: the dossier's signature is checked against them too.
  const checks = [...(files ? verifyDossier(files, { keys: keysPath ? jwks : null }).checks : []), ...verifyReceipt(token, jwks, { pack })];
  print({ ok: checks.every(c => c.ok), checks }, json, 'receipt');
}

/** Check 17: `azoth-verify export <body.json> --signature <token|file> --keys <jwks.json> [--workspace <id>] [--json]`. */
function runExport(argv) {
  const json = argv.includes('--json');
  const opt = (name, what) => {
    const at = argv.indexOf(name);
    if (at < 0) return undefined;
    const v = argv[at + 1];
    if (!v || v.startsWith('-')) die(`error: ${name} needs ${what}. Try --help.`);
    return v;
  };
  const signatureArg = opt('--signature', 'the X-Azoth-Export-Signature value, or a file holding it');
  const keysPath = opt('--keys', 'a JWKS file');
  const workspace = opt('--workspace', 'a workspace id');
  const optionValues = new Set(argv.flatMap((a, i) => (['--signature', '--keys', '--workspace'].includes(a) ? [i + 1] : [])));
  const target = argv.find((a, i) => !a.startsWith('-') && !optionValues.has(i));
  if (!target) die('error: no evidence pack given (the body GET /api/v1/journal/export answered, saved as received). Try --help.');
  if (!signatureArg) die('error: no signature — give --signature with the X-Azoth-Export-Signature header (the token, or a file holding it).');
  if (!keysPath) die('error: no keys — give --keys with the workspace\'s published keys (/api/proof/keys/<workspace>): a pack ships none of its own.');
  let body;
  try { body = new Uint8Array(readFileSync(target)); } catch (err) { die(`error: could not read the evidence pack: ${err.message}`); }
  const signature = existsSync(signatureArg) && statSync(signatureArg).isFile() ? readFileSync(signatureArg, 'utf8') : signatureArg;
  let keys;
  try { keys = JSON.parse(readFileSync(keysPath, 'utf8')); } catch (err) { die(`error: could not read --keys: ${err.message}`); }
  print(verifyExport(body, signature, { keys, workspace }), json, 'evidence pack');
}

export function run(argv) {
  if (argv[0] === 'receipt') return runReceipt(argv.slice(1));
  if (argv[0] === 'export') return runExport(argv.slice(1));
  if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
    process.stdout.write(HELP + '\n');
    process.exit(argv.length === 0 ? 1 : 0);
  }
  const json = argv.includes('--json');
  const rootAt = argv.indexOf('--tsa-root');
  const rootPath = rootAt >= 0 ? argv[rootAt + 1] : undefined;
  if (rootAt >= 0 && (!rootPath || rootPath.startsWith('-'))) die('error: --tsa-root needs a PEM file. Try --help.');
  // --vault-content <file|dir>, repeatable: content the client decrypted (or the stored envelopes).
  const vaultPaths = argv.flatMap((a, i) => (a === '--vault-content' ? [argv[i + 1]] : []));
  if (vaultPaths.some(p => !p || p.startsWith('-'))) die('error: --vault-content needs a file or a directory. Try --help.');
  const keysAt = argv.indexOf('--keys');
  const keysPath = keysAt >= 0 ? argv[keysAt + 1] : undefined;
  if (keysAt >= 0 && (!keysPath || keysPath.startsWith('-'))) die('error: --keys needs a JWKS file. Try --help.');
  // --published-roots <file>, repeatable: the roots the producer published (its /api/proof/head-roots answers, saved).
  const publishedPaths = argv.flatMap((a, i) => (a === '--published-roots' ? [argv[i + 1]] : []));
  if (publishedPaths.some(p => !p || p.startsWith('-'))) die('error: --published-roots needs a JSON file. Try --help.');
  const optionValues = new Set(argv.flatMap((a, i) => (['--tsa-root', '--vault-content', '--keys', '--published-roots'].includes(a) ? [i + 1] : [])));
  const target = argv.find((a, i) => !a.startsWith('-') && !optionValues.has(i));
  if (!target) die('error: no dossier path given. Try --help.');

  let files;
  try { files = loadDossier(target); }
  catch (err) { die(`error: could not read dossier: ${err.message}`); }
  let tsaRootPem;
  if (rootPath) {
    try { tsaRootPem = readFileSync(rootPath, 'utf8'); }
    catch (err) { die(`error: could not read --tsa-root: ${err.message}`); }
  }

  let keys = null;
  if (keysPath) {
    try { keys = JSON.parse(readFileSync(keysPath, 'utf8')); }
    catch (err) { die(`error: could not read --keys: ${err.message}`); }
  }

  const vaultContents = [];
  for (const p of vaultPaths) {
    try {
      const st = statSync(p);
      const list = st.isDirectory() ? readdirSync(p).map(n => join(p, n)).filter(f => statSync(f).isFile()) : [p];
      for (const f of list) vaultContents.push({ name: basename(f), bytes: new Uint8Array(readFileSync(f)) });
    } catch (err) { die(`error: could not read --vault-content ${p}: ${err.message}`); }
  }

  let publishedRoots = null;
  for (const p of publishedPaths) {
    let read;
    try { read = readPublishedRoots(new Uint8Array(readFileSync(p))); }
    catch (err) { die(`error: could not read --published-roots ${p}: ${err.message}`); }
    if (read.error) die(`error: --published-roots ${p}: ${read.error}`);
    publishedRoots = [...(publishedRoots ?? []), ...read.roots];
  }

  print(verifyDossier(files, { tsaRootPem, vaultContents, keys, publishedRoots }), json, 'dossier');
}

run(process.argv.slice(2));
