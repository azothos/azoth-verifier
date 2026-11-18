// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The examples, as a reader runs them: the demo dossier and the receipt pass with the demo keys
 * pinned — through the command line and through the library — and one byte changed, another
 * key or another dossier makes them fail. `node --test test/`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalCore, computeEntryHash, verifyDossier } from '../src/verify.mjs';
import { verifyReceipt } from '../src/receipt.mjs';
import { readZip } from '../src/zip.mjs';

const PKG = join(dirname(fileURLToPath(import.meta.url)), '..');
const EXAMPLES = join(PKG, 'examples');
const BIN = join(PKG, 'bin', 'azoth-verify.mjs');
const zip = new Uint8Array(readFileSync(join(EXAMPLES, 'demo-dossier.zip')));
const keys = JSON.parse(readFileSync(join(EXAMPLES, 'demo-keys.jwks.json'), 'utf8'));
const receipt = readFileSync(join(EXAMPLES, 'receipt.txt'), 'utf8').trim();
const packOf = files => JSON.parse(new TextDecoder().decode(files['evidence.json']));

const cli = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
const tmp = mkdtempSync(join(tmpdir(), 'azoth-verify-test-'));
const write = (name, data) => { const p = join(tmp, name); writeFileSync(p, data); return p; };

/** Another Ed25519 key, published under its own kid, as a workspace would. */
function otherKeys() {
  const { x } = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
  return { keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig', status: 'active', created_at: '2026-01-01T00:00:00Z', retired_at: null }] };
}

test('the demo dossier verifies with its keys pinned, every check passing', () => {
  const r = verifyDossier(readZip(zip), { keys });
  assert.equal(r.ok, true);
  assert.deepEqual(r.checks.filter(c => !c.ok || c.level === 'warn'), []);
  const ids = r.checks.map(c => c.id);
  for (const id of ['manifest.root_hash', 'chain', 'signature', 'pricing']) assert.ok(ids.includes(id), id);
});

test('the command line says VERIFIED and exits 0 — the README commands', () => {
  const dossier = cli(join(EXAMPLES, 'demo-dossier.zip'), '--keys', join(EXAMPLES, 'demo-keys.jwks.json'));
  assert.equal(dossier.status, 0, dossier.stdout + dossier.stderr);
  assert.match(dossier.stdout, /VERIFIED — dossier is intact\./);
  const r = cli('receipt', join(EXAMPLES, 'receipt.txt'), '--dossier', join(EXAMPLES, 'demo-dossier.zip'), '--keys', join(EXAMPLES, 'demo-keys.jwks.json'));
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /PASS {2}receipt\.decision/);
  assert.doesNotMatch(r.stdout, /^(WARN|FAIL)/m);
});

test('without the keys pinned, the dossier does not verify: a key it ships vouches only for itself', () => {
  const r = verifyDossier(readZip(zip));
  assert.equal(r.ok, false);
  assert.match(r.checks.find(c => c.id === 'signature')?.detail ?? '', /only the dossier itself vouches for/);
  const out = cli(join(EXAMPLES, 'demo-dossier.zip'));
  assert.equal(out.status, 1);
  assert.match(out.stdout, /FAILED — dossier did not verify\./);
});

test('the signature commits what the dossier covers, and the verifier says it', () => {
  const r = verifyDossier(readZip(zip), { keys });
  const coverage = r.checks.find(c => c.id === 'coverage');
  assert.equal(coverage?.ok, true);
  assert.match(coverage.detail, /lists 5 sealed entries, seq 1–5; the head of the workspace’s journal was seq 5 /);
});

// ── Tampering (gate G3): every way to cut or rewrite a dossier fails, whoever re-signs it ────────────

const sha = data => createHash('sha256').update(data).digest('hex');
const b64u = v => Buffer.from(v).toString('base64url');

/** The pristine files, with evidence.json changed by `edit` and the manifest recomputed to match. */
function tampered(edit) {
  const files = { ...readZip(zip) };
  const pack = edit(packOf(files));
  pack.count = pack.entries.length;
  pack.seqRange = { first: pack.entries[0]?.seq ?? null, last: pack.entries.at(-1)?.seq ?? null };
  files['evidence.json'] = new TextEncoder().encode(JSON.stringify(pack));
  return rehashManifest(files);
}
function rehashManifest(files) {
  const m = JSON.parse(new TextDecoder().decode(files['manifest.json']));
  for (const f of m.files) f.sha256 = sha(files[f.path]);
  m.root_hash = sha(m.files.map(f => f.sha256).sort().join(''));
  files['manifest.json'] = new TextEncoder().encode(JSON.stringify(m, null, 2));
  return files;
}
const rootOf = files => JSON.parse(new TextDecoder().decode(files['manifest.json'])).root_hash;
const rehashChain = pack => {
  let prev = '';
  for (const e of pack.entries.sort((x, y) => x.seq - y.seq)) { e.prevHash = prev; e.entryHash = computeEntryHash(prev, canonicalCore(e.core)); prev = e.entryHash; }
  return pack;
};
const CASES = {
  truncate_tail: pack => ({ ...pack, entries: pack.entries.filter(e => e.seq <= 3) }),
  truncate_head: pack => ({ ...pack, entries: pack.entries.filter(e => e.seq !== 1) }),
  rehash_chain: pack => { pack.entries.find(e => e.seq === 3).core.decision = 'served'; return rehashChain(pack); },
  rehash_receipted: pack => { pack.entries.find(e => e.seq === 2).core.decision = 'served'; return rehashChain(pack); },
};

/** A key of the attacker's own, its public half put in the dossier's keys.jwks.json, signing what `claims` says. */
function resign(files, claims) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
  files['keys.jwks.json'] = new TextEncoder().encode(JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig', status: 'active', created_at: '2026-11-06T10:00:00Z', retired_at: null }] }));
  rehashManifest(files);
  const input = `${b64u(JSON.stringify({ alg: 'EdDSA', typ: 'azoth-dossier+jws', kid }))}.${b64u(JSON.stringify({ ...claims(files), root: rootOf(files) }))}`;
  files['signature.jws'] = new TextEncoder().encode(`${input}.${b64u(sign(null, Buffer.from(input), privateKey))}`);
  return { files, jwks: JSON.parse(new TextDecoder().decode(files['keys.jwks.json'])) };
}
const v2Claims = files => {
  const pack = packOf(files);
  const seqs = pack.entries.map(e => e.seq);
  const last = pack.entries.find(e => e.seq === Math.max(...seqs));
  return { v: 2, ws: 'demo-workspace', iat: 1793959200, kind: 'audit', head: { seq: last.seq, hash: last.entryHash }, entries: { count: seqs.length, first: Math.min(...seqs), last: Math.max(...seqs) }, filters: {} };
};

for (const [name, edit] of Object.entries(CASES)) {
  test(`${name}: the original signature kept — FAIL`, () => {
    const r = verifyDossier(tampered(edit), { keys });
    assert.equal(r.ok, false);
    assert.match(r.checks.find(c => c.id === 'signature')?.detail ?? '', /another root_hash/);
  });
  test(`${name}: the signature removed — FAIL, unsigned, with and without the keys`, () => {
    const files = tampered(edit);
    delete files['signature.jws'];
    for (const opts of [{ keys }, {}]) {
      const r = verifyDossier(files, opts);
      assert.equal(r.ok, false);
      assert.match(r.checks.find(c => c.id === 'signature')?.detail ?? '', /the dossier is unsigned/);
    }
  });
  test(`${name}: re-signed by an attacker's key (format 1 and 2) — FAIL, with and without the keys`, () => {
    for (const claims of [() => ({ v: 1, ws: 'demo-workspace', iat: 1793959200 }), v2Claims]) {
      const { files } = resign(tampered(edit), claims);
      const pinned = verifyDossier(files, { keys });
      assert.equal(pinned.ok, false);
      assert.match(pinned.checks.find(c => c.id === 'signature')?.detail ?? '', /among the keys given/);
      const unpinned = verifyDossier(files);
      assert.equal(unpinned.ok, false);
      assert.match(unpinned.checks.find(c => c.id === 'signature')?.detail ?? '', /only the dossier itself vouches for/);
    }
  });
}

test('the command line: the cut dossier, signature removed, exits 1 and says it is unsigned', () => {
  const files = tampered(CASES.truncate_tail);
  delete files['signature.jws'];
  const dir = mkdtempSync(join(tmp, 'cut-'));
  for (const [n, d] of Object.entries(files)) writeFileSync(join(dir, n), d);
  const r = cli(dir, '--keys', join(EXAMPLES, 'demo-keys.jwks.json'));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL {2}signature {20}the dossier is unsigned/);
});

test('coverage: evidence.json that does not hold what the key signed fails, even under the right key', () => {
  // A key that signed claims evidence.json does not match — the entries cut after signing, or the head
  // overtaken: the signature's own key is pinned, so only the coverage can tell.
  const cut = tampered(CASES.truncate_tail);
  const { files, jwks } = resign(cut, f => ({ ...v2Claims(f), entries: { count: 5, first: 1, last: 5 } }));
  const r = verifyDossier(files, { keys: jwks });
  assert.equal(r.checks.find(c => c.id === 'signature')?.ok, true);
  assert.match(r.checks.find(c => c.id === 'coverage')?.detail ?? '', /evidence\.json lists 3 entries \(seq 1–3\); the signature committed 5 entries \(seq 1–5\)/);
  assert.equal(r.ok, false);
  const early = resign(tampered(p => p), f => ({ ...v2Claims(f), head: { seq: 3, hash: packOf(f).entries.find(e => e.seq === 3).entryHash } }));
  const r2 = verifyDossier(early.files, { keys: early.jwks });
  assert.match(r2.checks.find(c => c.id === 'coverage')?.detail ?? '', /carries seq 4, after the chain's head the signature committed \(seq 3\)/);
  const wrongKind = resign(tampered(p => p), f => ({ ...v2Claims(f), kind: 'decision' }));
  assert.match(verifyDossier(wrongKind.files, { keys: wrongKind.jwks }).checks.find(c => c.id === 'coverage')?.detail ?? '', /signature is for a decision dossier/);
  const honest = resign(tampered(CASES.truncate_tail), f => ({ ...v2Claims(f), head: { seq: 5, hash: 'a'.repeat(64) }, filters: { to: '2026-11-06T09:12:00.000Z' } }));
  const ok = verifyDossier(honest.files, { keys: honest.jwks });
  assert.equal(ok.ok, true, JSON.stringify(ok.checks.filter(c => !c.ok)));
  assert.match(ok.checks.find(c => c.id === 'coverage')?.detail ?? '', /seq 1–3; the head of the workspace’s journal was seq 5 .* nothing sealed after seq 3 is in it \(2 later entries\); filters: to=2026-11-06T09:12:00\.000Z/);
});

test('one byte changed in the dossier: FAILED, exit 1', () => {
  const altered = Uint8Array.from(zip);
  const at = Buffer.from(altered).indexOf('blocked_by_policy');
  assert.ok(at > 0);
  altered[at] = 'c'.charCodeAt(0);
  assert.equal(verifyDossier(readZip(altered), { keys }).ok, false);
  const r = cli(write('altered.zip', altered), '--keys', join(EXAMPLES, 'demo-keys.jwks.json'));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAILED — dossier did not verify\./);
});

test('another key pinned: the signature fails', () => {
  const r = verifyDossier(readZip(zip), { keys: otherKeys() });
  assert.equal(r.ok, false);
  assert.equal(r.checks.find(c => c.id === 'signature')?.ok, false);
});

test('the receipt: signed by the demo key, certifying a decision sealed in the dossier', () => {
  const files = readZip(zip);
  const checks = verifyReceipt(receipt, keys, { pack: packOf(files) });
  assert.deepEqual(checks.map(c => `${c.id}:${c.ok}`), ['receipt.format:true', 'receipt.key:true', 'receipt.signature:true', 'receipt.decision:true']);
});

test('the receipt altered, or under another key, fails', () => {
  const [h, c, s] = receipt.split('.');
  const claims = JSON.parse(Buffer.from(c, 'base64url').toString('utf8'));
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...claims, out: 'allowed' })).toString('base64url')}.${s}`;
  assert.equal(verifyReceipt(forged, keys).find(x => x.id === 'receipt.signature')?.ok, false);
  assert.equal(verifyReceipt(receipt, otherKeys()).find(x => x.id === 'receipt.key')?.ok, false);
  const r = cli('receipt', write('forged.txt', forged), '--keys', join(EXAMPLES, 'demo-keys.jwks.json'));
  assert.equal(r.status, 1);
});
