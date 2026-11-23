// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 4's certification path (x509.mjs, certificationPath), on certificates made here with
 * node:crypto. A time-stamping authority may ship, in its token, a copy of its root cross-signed by
 * another root — the root's subject and key under another issuer:
 *
 *   TSA ← CA1 ← « Root G4 » cross-signed by « Other Root »   (in the token)
 *               « Root G4 » self-signed                      (what the reader pins)
 *
 * The path ends on the pinned root whatever order the certificates come in, the cross-signed copy
 * counts as the root, a dead end is backtracked from, and a certificate with the root's name but
 * another key is never the root. `node --test`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { parseCertificate, certificationPath, sameAuthority } from '../src/x509.mjs';

// ── A minimal DER writer, for the certificates only ───────────────────────────
const len = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const der = (tag, bytes) => Uint8Array.from([tag, ...len(bytes.length), ...bytes]);
const cat = (...parts) => parts.flatMap(p => [...p]);
const seq = (...parts) => der(0x30, cat(...parts));
const set = (...parts) => der(0x31, cat(...parts));
const oid = (dotted) => {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [a * 40 + b];
  for (let v of rest) {
    const chunk = [v & 0x7f];
    while ((v = Math.floor(v / 128)) > 0) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return der(0x06, out);
};
const utf8 = (s) => der(0x0c, [...new TextEncoder().encode(s)]);
const utc = (d) => der(0x17, [...new TextEncoder().encode(`${d.toISOString().slice(2, 19).replace(/[-:T]/g, '')}Z`)]);
const SHA256_WITH_RSA = seq(oid('1.2.840.113549.1.1.11'), [0x05, 0x00]);
const name = (cn) => seq(set(seq(oid('2.5.4.10'), utf8('Example PKI'))), set(seq(oid('2.5.4.3'), utf8(cn))));

let serial = 1;
/** An RSA SHA-256 certificate of `subject`'s `key`, signed by `issuerKey` in `issuer`'s name. */
function certificate(subject, issuer, key, issuerKey) {
  const tbs = seq(
    der(0xa0, der(0x02, [2])), der(0x02, [serial++]), SHA256_WITH_RSA, name(issuer),
    seq(utc(new Date(Date.now() - 86_400_000)), utc(new Date(Date.now() + 86_400_000))), name(subject),
    key.export({ type: 'spki', format: 'der' }),
  );
  const signature = sign('sha256', Uint8Array.from(tbs), issuerKey);
  return parseCertificate(seq(tbs, SHA256_WITH_RSA, der(0x03, [0, ...signature])));
}

const rsa = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const [g4, other, ca1Key, tsaKey, lookalikeKey] = [rsa(), rsa(), rsa(), rsa(), rsa()];
const ROOT = 'Root G4';
const root = certificate(ROOT, ROOT, g4.publicKey, g4.privateKey);
const cross = certificate(ROOT, 'Other Root', g4.publicKey, other.privateKey);
const otherRoot = certificate('Other Root', 'Other Root', other.publicKey, other.privateKey);
const ca1 = certificate('CA1', ROOT, ca1Key.publicKey, g4.privateKey);
const tsa = certificate('TSA', 'CA1', tsaKey.publicKey, ca1Key.privateKey);
const lookalike = certificate(ROOT, ROOT, lookalikeKey.publicKey, lookalikeKey.privateKey);
const forgedCa1 = certificate('CA1', ROOT, ca1Key.publicKey, lookalikeKey.privateKey);
// Two CAs that certify each other, and a leaf under one of them: a loop, never a path by itself.
const [aKey, bKey] = [rsa(), rsa()];
const caA = certificate('CA A', 'CA B', aKey.publicKey, bKey.privateKey);
const caB = certificate('CA B', 'CA A', bKey.publicKey, aKey.privateKey);
const leaf = certificate('Leaf', 'CA A', tsaKey.publicKey, aKey.privateKey);

const LABELS = new Map([[root, 'root'], [cross, 'cross-signed root'], [otherRoot, 'other root'], [lookalike, 'look-alike'], [caB, 'CA B']].map(([c, l]) => [c.fingerprint256, l]));
/** The path as `trusted:<end>`, `untrusted:<end>` or `none`. */
const ends = (path) => (path ? `${path.trusted ? 'trusted' : 'untrusted'}:${LABELS.get(path.end.fingerprint256)}` : 'none');

test('the cross-signed copy is the same authority as the root; a look-alike is not', () => {
  assert.notEqual(cross.fingerprint256, root.fingerprint256);
  assert.equal(sameAuthority(cross, root), true);
  assert.equal(sameAuthority(lookalike, root), false);
});

test('the pinned root ends the path, whatever order the certificates come in', () => {
  for (const pool of [[ca1, cross], [cross, ca1], [cross, ca1, root], [root, cross, ca1]]) {
    assert.equal(ends(certificationPath(tsa, pool, [root])), 'trusted:root', pool.map(c => c.subject).join(' | '));
  }
});

test('the cross-signed copy pinned is the root too; the root that cross-signed it is an anchor of its own', () => {
  assert.equal(ends(certificationPath(tsa, [ca1, root], [cross])), 'trusted:cross-signed root');
  assert.equal(ends(certificationPath(tsa, [ca1, cross], [otherRoot])), 'trusted:other root');
});

test('without an anchor, the path backtracks from a dead end to a self-signed root: untrusted', () => {
  assert.equal(ends(certificationPath(tsa, [ca1, cross, root], [])), 'untrusted:root');
  assert.equal(ends(certificationPath(tsa, [cross, ca1, otherRoot], [])), 'untrusted:other root');
  assert.equal(ends(certificationPath(tsa, [ca1, cross], [])), 'none');   // the cross-signer is nowhere
  assert.equal(ends(certificationPath(tsa, [cross], [root])), 'none');    // CA1 is nowhere
});

test('a look-alike of the root, or a CA1 forged under its key, never reaches the root', () => {
  assert.equal(ends(certificationPath(tsa, [ca1, cross], [lookalike])), 'none');
  assert.equal(ends(certificationPath(tsa, [ca1, cross, root], [lookalike])), 'untrusted:root');
  assert.equal(ends(certificationPath(tsa, [forgedCa1, lookalike], [root])), 'untrusted:look-alike');
  assert.equal(ends(certificationPath(tsa, [forgedCa1, lookalike, ca1], [root])), 'trusted:root');
});

test('a loop of certificates is no path; an anchor inside it ends one', () => {
  assert.equal(ends(certificationPath(leaf, [caA, caB], [])), 'none');
  assert.equal(ends(certificationPath(leaf, [caA, caB], [caB])), 'trusted:CA B');
});
