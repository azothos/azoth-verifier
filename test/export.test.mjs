// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 17 — a signed JSON evidence pack, built here from SPEC.md's rules: a pack, its exact bytes, a
 * compact JWS over their sha256 and the coverage, by an Ed25519 key made in memory (never written).
 * What passes, and every way to alter it fails, with the reason. The hashes and the signature are made
 * with node:crypto, never with the module under test. `node --test test/`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { verifyExport, exportSignatureOf, signedFilters } from '../src/export.mjs';
import { canonicalCore, verifyChain } from '../src/verify.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const byId = (checks, id) => checks.find(c => c.id === id);
const failing = (checks) => checks.filter(c => !c.ok).map(c => c.id);

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
  return { kid, privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig', status: 'active', created_at: '2026-11-01T00:00:00.000Z', retired_at: null } };
}

/** Three sealed decisions, each core binding its time, actor type and trace (Check 16). */
function packOf(ws = 'ws_demo', filters = { from: '2026-11-01T00:00:00.000Z' }) {
  let prev = '';
  const entries = ['served', 'blocked_by_policy', 'served'].map((decision, i) => {
    const occurredAt = `2026-11-0${i + 2}T10:00:00.000Z`;
    const core = { surface: 'inference', decision, tools: [], dataSources: [], occurredAt, actorType: 'api_key', traceId: `t${i}` };
    const entryHash = sha(prev + canonicalCore(core));
    const e = { seq: i + 1, occurredAt, surface: 'inference', actorType: 'api_key', actorId: null, actorRole: null, sessionId: null, traceId: `t${i}`, agentId: null, model: null, hasTools: false, costEur: null, core, piiErased: false, prevHash: prev, entryHash };
    prev = entryHash;
    return e;
  });
  return { workspaceId: ws, filters, seqRange: { first: 1, last: 3 }, count: 3, truncated: false, integrity: { ok: true }, footprint: { count: 3, costEur: 0, energyWh: 0, carbonG: 0 }, entries };
}

/** The producer's signature over `body`: claims v1 with the coverage SPEC.md Check 17 states. */
function signExport(key, ws, body, pack, { iat = 1763550000, head, entries, kind = 'audit', filters } = {}) {
  const seqs = pack.entries.map(e => e.seq);
  const last = pack.entries[pack.entries.length - 1];
  const claims = {
    v: 1, ws, body: sha(body), iat, kind,
    head: head === undefined ? (last ? { seq: last.seq, hash: last.entryHash } : null) : head,
    entries: entries ?? { count: seqs.length, first: seqs.length ? Math.min(...seqs) : null, last: seqs.length ? Math.max(...seqs) : null },
    filters: filters ?? signedFilters(pack.filters),
  };
  const input = `${b64({ alg: 'EdDSA', typ: 'azoth-journal-export+jws', kid: key.kid })}.${b64(claims)}`;
  return `${input}.${sign(null, Buffer.from(input, 'ascii'), key.privateKey).toString('base64url')}`;
}

const key = keyPair();
const keys = { keys: [key.jwk] };
const pack = packOf();
const body = JSON.stringify(pack);
const signature = signExport(key, 'ws_demo', body, pack);

test('a signed pack verifies: its body, its key, its workspace, its coverage, its chain and sealed fields', () => {
  const r = verifyExport(new TextEncoder().encode(body), signature, { keys, workspace: 'ws_demo' });
  assert.deepEqual(failing(r.checks), []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.checks.map(c => c.id), ['export.format', 'export.body', 'export.signature', 'export.workspace', 'export.coverage', 'chain', 'sealed.fields']);
  assert.match(byId(r.checks, 'export.coverage').detail, /lists 3 sealed entries, seq 1–3; the head of the workspace’s journal was seq 3/);
  assert.match(byId(r.checks, 'chain').detail, /chain intact \(3 sealed decisions\)/);
  assert.equal(byId(r.checks, 'export.workspace').level, undefined);
});

test('the workspace is said, and a warning given when nothing pins whose keys they are', () => {
  const r = verifyExport(body, signature, { keys });
  assert.equal(r.ok, true);
  assert.equal(byId(r.checks, 'export.workspace').level, 'warn');
  assert.equal(verifyExport(body, signature, { keys: { ...keys, workspaceId: 'ws_demo' } }).checks.find(c => c.id === 'export.workspace').level, undefined);
  assert.match(byId(verifyExport(body, signature, { keys: { ...keys, workspaceId: 'ws_other' } }).checks, 'export.workspace').detail, /keys given are workspace ws_other’s/);
  assert.match(byId(verifyExport(body, signature, { keys, workspace: 'ws_other' }).checks, 'export.workspace').detail, /the workspace you named is ws_other/);
  assert.match(byId(verifyExport(body, signature, { keys: { ...keys, workspaceId: 'ws_demo' }, workspace: 'ws_other' }).checks, 'export.workspace').detail, /the workspace you named is ws_other/);
  const foreign = packOf('ws_other');
  const foreignBody = JSON.stringify(foreign);
  assert.match(byId(verifyExport(foreignBody, signExport(key, 'ws_demo', foreignBody, foreign), { keys }).checks, 'export.workspace').detail, /the pack is workspace ws_other’s/);
});

test('one byte of the body changed, or the body re-indented: it is not the body signed', () => {
  const altered = body.replace('blocked_by_policy', 'clocked_by_policy');
  const r = verifyExport(altered, signature, { keys });
  assert.equal(r.ok, false);
  assert.match(byId(r.checks, 'export.body').detail, /not the one signed/);
  assert.match(byId(r.checks, 'chain').detail, /entry_hash mismatch/);
  const pretty = verifyExport(JSON.stringify(pack, null, 2), signature, { keys });
  assert.deepEqual(failing(pretty.checks), ['export.body']);
});

test('another key, a key that does not hash to its id, a signature altered: refused', () => {
  const other = keyPair();
  assert.match(byId(verifyExport(body, signature, { keys: { keys: [other.jwk] } }).checks, 'export.signature').detail, /no Ed25519 key/);
  assert.match(byId(verifyExport(body, signature, { keys: { keys: [{ ...key.jwk, x: other.jwk.x }] } }).checks, 'export.signature').detail, /does not hash to its id/);
  const [h, c, s] = signature.split('.');
  const flipped = `${h}.${c}.${s.slice(0, -2)}${s.at(-2) === 'A' ? 'B' : 'A'}${s.at(-1)}`;
  assert.match(byId(verifyExport(body, flipped, { keys }).checks, 'export.signature').detail, /does not verify/);
  assert.match(byId(verifyExport(body, signature, { keys: null }).checks, 'export.signature').detail, /no keys given/);
});

test('a key declared compromised: refused at or after its instant, a warning before it (keys.mjs keyTrustAt)', () => {
  const compromised = at => ({ keys: [{ ...key.jwk, status: 'compromised', compromised_at: at, compromise_declared_at: at }] });
  const refused = verifyExport(body, signature, { keys: compromised('2000-01-01T00:00:00.000Z') });
  assert.equal(refused.ok, false);
  assert.match(byId(refused.checks, 'export.signature').detail, /is refused: it signed on .* from when its producer declared it compromised/);
  const warned = verifyExport(body, signature, { keys: compromised('2999-01-01T00:00:00.000Z') });
  assert.equal(warned.ok, true);
  assert.equal(byId(warned.checks, 'export.signature.key').level, 'warn');
});

test('the coverage it commits: entries renumbered, a head behind the pack, another kind, other filters — refused', () => {
  const removed = verifyExport(body, signExport(key, 'ws_demo', body, pack, { entries: { count: 4, first: 1, last: 4 } }), { keys });
  assert.match(byId(removed.checks, 'export.coverage').detail, /the pack lists 3 entries \(seq 1–3\); the signature committed 4 entries/);
  const behind = verifyExport(body, signExport(key, 'ws_demo', body, pack, { head: { seq: 2, hash: pack.entries[1].entryHash } }), { keys });
  assert.match(byId(behind.checks, 'export.coverage').detail, /the pack carries seq 3, after the chain's head/);
  const kind = verifyExport(body, signExport(key, 'ws_demo', body, pack, { kind: 'decision' }), { keys });
  assert.match(byId(kind.checks, 'export.coverage').detail, /signature is for a decision dossier; the pack is a audit dossier/);
  const filters = verifyExport(body, signExport(key, 'ws_demo', body, pack, { filters: { from: '2026-10-01T00:00:00.000Z' } }), { keys });
  assert.match(byId(filters.checks, 'export.coverage').detail, /filters are not the ones its signature committed/);
});

test('a filtered pack: its chain segment carried, the listed entries in it', () => {
  const full = packOf('ws_demo', { surface: 'inference', refusalsOnly: true });
  const filtered = { ...full, entries: [full.entries[1]], count: 1, chain: full.entries.map(e => ({ seq: e.seq, prevHash: e.prevHash, entryHash: e.entryHash, coreCanonical: canonicalCore(e.core) })) };
  const filteredBody = JSON.stringify(filtered);
  const r = verifyExport(filteredBody, signExport(key, 'ws_demo', filteredBody, filtered, { head: { seq: 3, hash: full.entries[2].entryHash } }), { keys });
  assert.deepEqual(failing(r.checks), []);
  assert.match(byId(r.checks, 'export.coverage').detail, /lists 1 sealed entry, seq 2; .* \(1 later entry\); filters: refusalsOnly=true, surface=inference/);
  assert.match(byId(r.checks, 'chain').detail, /the 1 listed decisions are in it/);
});

test('the signature as given: the token, or the header line curl -D writes; anything else is not a JWS', () => {
  assert.equal(exportSignatureOf(`HTTP/2 200\r\ncontent-type: application/json\r\nx-azoth-export-signature: ${signature}\r\n\r\n`), signature);
  assert.equal(exportSignatureOf(`  ${signature}\n`), signature);
  assert.equal(verifyExport(body, `X-Azoth-Export-Signature: ${signature}`, { keys }).ok, true);
  assert.match(byId(verifyExport(body, 'not a token', { keys }).checks, 'export.format').detail, /not a compact JWS/);
  const [, c, s] = signature.split('.');
  assert.match(byId(verifyExport(body, `${b64({ alg: 'EdDSA', typ: 'azoth-dossier+jws', kid: key.kid })}.${c}.${s}`, { keys }).checks, 'export.format').detail, /typ: "azoth-journal-export\+jws"/);
});

test('an entry that carries its coreCanonical beside its core must state the core sealed (Check 3)', () => {
  const p = packOf();
  const ok = { ...p, entries: p.entries.map(e => ({ ...e, coreCanonical: canonicalCore(e.core) })) };
  assert.equal(verifyChain(ok).ok, true);
  const shown = { ...p, entries: p.entries.map((e, i) => (i === 1 ? { ...e, core: { ...e.core, decision: 'served' }, coreCanonical: canonicalCore(e.core) } : e)) };
  const r = verifyChain(shown);
  assert.equal(r.ok, false);
  assert.match(r.reason, /its core is not the one its coreCanonical seals/);
});
