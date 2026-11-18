// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The two cryptographic modules, held to node:crypto: crypto.mjs (the command line's, over
 * node:crypto) and crypto-web.mjs (the web page's, plain JavaScript). The same digests, and every
 * signature a dossier or a timestamp token can carry — RSA PKCS #1 v1.5 and PSS, ECDSA on P-256,
 * P-384 and P-521, Ed25519 — accepted when node:crypto made it, refused once a byte changes, and
 * refused under a scheme that does not fit the key. Then the rules both read through keys.mjs: one
 * verdict on the same bytes in both, and `false` — never an exception — for whatever does not
 * verify. `node --test`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, constants } from 'node:crypto';
import * as node from '../src/crypto.mjs';
import * as web from '../src/crypto-web.mjs';

const IMPLEMENTATIONS = [['crypto.mjs', node], ['crypto-web.mjs', web]];
const spki = (k) => Uint8Array.from(k.export({ type: 'spki', format: 'der' }));
const flip = (b) => { const c = Uint8Array.from(b); c[c.length >> 1] ^= 0x01; return c; };
const hex = (b) => Buffer.from(b).toString('hex');
const data = Uint8Array.from(randomBytes(200));

test('digests equal node:crypto for every length, sha1 to sha512', () => {
  for (const [name, impl] of IMPLEMENTATIONS) {
    for (const alg of ['sha1', 'sha256', 'sha384', 'sha512']) {
      // The block edges (55/56, 63/64, 111/112, 127/128) are where a padding bug shows.
      for (const n of [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 300, 4097]) {
        const input = Uint8Array.from(randomBytes(n));
        assert.equal(hex(impl.digest(alg, input)), createHash(alg).update(input).digest('hex'), `${name} ${alg} over ${n} bytes`);
      }
    }
  }
  const big = Uint8Array.from(randomBytes(2 * 1024 * 1024));   // an evidence.json can be megabytes
  assert.equal(hex(web.digest('sha256', big)), createHash('sha256').update(big).digest('hex'));
});

test('RSA PKCS #1 v1.5, every hash: accepted as signed, refused once altered', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const hash of ['sha1', 'sha256', 'sha384', 'sha512']) {
    const signature = Uint8Array.from(sign(hash, data, privateKey));
    for (const [name, impl] of IMPLEMENTATIONS) {
      const key = { scheme: 'rsa-pkcs1', hash, spki: spki(publicKey) };
      assert.equal(impl.verifySignature({ ...key, data, signature }), true, `${name} ${hash}`);
      assert.equal(impl.verifySignature({ ...key, data: flip(data), signature }), false, `${name} ${hash}, data altered`);
      assert.equal(impl.verifySignature({ ...key, data, signature: flip(signature) }), false, `${name} ${hash}, signature altered`);
    }
  }
});

test('RSA PSS, whatever the salt length', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  for (const [hash, saltLength] of [['sha256', 32], ['sha256', 0], ['sha384', 48], ['sha512', constants.RSA_PSS_SALTLEN_MAX_SIGN]]) {
    const signature = Uint8Array.from(sign(hash, data, { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength }));
    for (const [name, impl] of IMPLEMENTATIONS) {
      const key = { scheme: 'rsa-pss', hash, spki: spki(publicKey) };
      assert.equal(impl.verifySignature({ ...key, data, signature }), true, `${name} ${hash} salt ${saltLength}`);
      assert.equal(impl.verifySignature({ ...key, data: flip(data), signature }), false, `${name} ${hash} salt ${saltLength}, data altered`);
    }
  }
});

test('ECDSA on P-256, P-384 and P-521, DER signatures', () => {
  for (const [namedCurve, hash] of [['P-256', 'sha256'], ['P-384', 'sha384'], ['P-521', 'sha512'], ['P-256', 'sha512']]) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve });
    const signature = Uint8Array.from(sign(hash, data, { key: privateKey, dsaEncoding: 'der' }));
    for (const [name, impl] of IMPLEMENTATIONS) {
      const key = { scheme: 'ecdsa', hash, spki: spki(publicKey) };
      assert.equal(impl.verifySignature({ ...key, data, signature }), true, `${name} ${namedCurve} ${hash}`);
      assert.equal(impl.verifySignature({ ...key, data: flip(data), signature }), false, `${name} ${namedCurve}, data altered`);
      assert.equal(impl.verifySignature({ ...key, data, signature: flip(signature) }), false, `${name} ${namedCurve}, signature altered`);
    }
  }
});

test("Ed25519, by its key info and by a JWK's x", () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const signature = Uint8Array.from(sign(null, data, privateKey));
  const { x } = publicKey.export({ format: 'jwk' });
  for (const [name, impl] of IMPLEMENTATIONS) {
    assert.equal(impl.verifySignature({ scheme: 'ed25519', hash: null, spki: spki(publicKey), data, signature }), true, name);
    assert.equal(impl.verifyEd25519(x, data, signature), true, `${name}, by x`);
    assert.equal(impl.verifyEd25519(x, flip(data), signature), false, `${name}, data altered`);
    assert.equal(impl.verifyEd25519(x, data, flip(signature)), false, `${name}, signature altered`);
  }
  // Another key's x never verifies this signature.
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;
  for (const [name, impl] of IMPLEMENTATIONS) assert.equal(impl.verifyEd25519(other, data, signature), false, `${name}, another key`);
});

// ── The same verdict in both, never an exception (keys.mjs; SPEC.md « Keys and signatures ») ──

/** Both cryptographies on one input: each answers a boolean — no exception — and the same one. */
function verdict(call, label) {
  const out = IMPLEMENTATIONS.map(([name, impl]) => {
    let v;
    try { v = call(impl); } catch (err) { assert.fail(`${label}: ${name} threw ${err?.message ?? err}`); }
    assert.equal(typeof v, 'boolean', `${label}: ${name} answered ${v}`);
    return v;
  });
  assert.equal(out[0], out[1], `${label}: crypto.mjs ${out[0]}, crypto-web.mjs ${out[1]}`);
  return out[0];
}
/** [label, input, expected] → each input's verdict, the same in both, is `expected`. */
const expectAll = (cases) => {
  for (const [label, input, expected] of cases) assert.equal(verdict(impl => impl.verifySignature({ data, ...input }), label), expected, label);
};

// A little DER, for the keys and signatures node:crypto would not make.
const len = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const der = (tag, body) => Uint8Array.from([tag, ...len(body.length), ...body]);
const seq = (...parts) => der(0x30, parts.flatMap(p => [...p]));
const int = (bytes) => der(0x02, [...bytes]);
const bitString = (bytes, unused = 0) => der(0x03, [unused, ...bytes]);
const minimal = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; const t = [...b.subarray(i)]; return t[0] & 0x80 ? [0, ...t] : t; };
const OID_EC = der(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
const OID_P256 = der(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
const OID_RSA = der(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const OID_ED25519 = der(0x06, [0x2b, 0x65, 0x70]);
const NULL = Uint8Array.of(0x05, 0x00);
const le32 = (v) => { const b = new Uint8Array(32); for (let i = 0; i < 32; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const leBig = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
const P25519 = 2n ** 255n - 19n;
const L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;
const N_P256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const bytesOf = (v, size) => Uint8Array.from(Buffer.from(v.toString(16).padStart(size * 2, '0'), 'hex'));

const ed = generateKeyPairSync('ed25519');
const edSig = Uint8Array.from(sign(null, data, ed.privateKey));
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ecSig = Uint8Array.from(sign('sha256', data, { key: ec.privateKey, dsaEncoding: 'der' }));
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaSig = Uint8Array.from(sign('sha256', data, rsa.privateKey));
const pssSig = Uint8Array.from(sign('sha256', data, { key: rsa.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }));

test("a signature checked under a scheme that is not its key's fails in both", () => {
  const ed448 = generateKeyPairSync('ed448');
  const pssKey = generateKeyPairSync('rsa-pss', { modulusLength: 2048, hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 });
  const pssKeySig = Uint8Array.from(sign('sha256', data, pssKey.privateKey));
  // Every signature here is valid for its key: only the scheme it is checked under is not the key's.
  // node:crypto picks the algorithm from the key, so the command line used to accept most of them.
  expectAll([
    ['an ECDSA-SHA256 signature by a P-256 key, labelled Ed25519', { scheme: 'ed25519', hash: null, spki: spki(ec.publicKey), signature: ecSig }, false],
    ['an RSA PKCS #1 v1.5 signature, labelled Ed25519', { scheme: 'ed25519', hash: null, spki: spki(rsa.publicKey), signature: rsaSig }, false],
    ['an Ed448 signature, labelled Ed25519', { scheme: 'ed25519', hash: null, spki: spki(ed448.publicKey), signature: Uint8Array.from(sign(null, data, ed448.privateKey)) }, false],
    ['an RSA PKCS #1 v1.5 signature, labelled ECDSA', { scheme: 'ecdsa', hash: 'sha256', spki: spki(rsa.publicKey), signature: rsaSig }, false],
    ['an Ed25519 signature, labelled ECDSA', { scheme: 'ecdsa', hash: 'sha256', spki: spki(ed.publicKey), signature: edSig }, false],
    ['an ECDSA signature, labelled RSA PKCS #1 v1.5', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(ec.publicKey), signature: ecSig }, false],
    ['an ECDSA signature, labelled RSA PSS', { scheme: 'rsa-pss', hash: 'sha256', spki: spki(ec.publicKey), signature: ecSig }, false],
    ['an Ed25519 signature, labelled RSA PKCS #1 v1.5', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(ed.publicKey), signature: edSig }, false],
    ['a PSS signature by an id-RSASSA-PSS key, labelled PKCS #1 v1.5', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(pssKey.publicKey), signature: pssKeySig }, false],
    ['an id-RSASSA-PSS key bound to SHA-256, asked for SHA-384', { scheme: 'rsa-pss', hash: 'sha384', spki: spki(pssKey.publicKey), signature: pssKeySig }, false],
    ['an unknown scheme', { scheme: 'dsa', hash: 'sha256', spki: spki(ec.publicKey), signature: ecSig }, false],
    ['no scheme', { hash: 'sha256', spki: spki(ec.publicKey), signature: ecSig }, false],
    // The same signatures under their own scheme.
    ['ECDSA as ECDSA', { scheme: 'ecdsa', hash: 'sha256', spki: spki(ec.publicKey), signature: ecSig }, true],
    ['PKCS #1 v1.5 as PKCS #1 v1.5', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(rsa.publicKey), signature: rsaSig }, true],
    ['PSS under its id-RSASSA-PSS key', { scheme: 'rsa-pss', hash: 'sha256', spki: spki(pssKey.publicKey), signature: pssKeySig }, true],
    ['PSS under an rsaEncryption key', { scheme: 'rsa-pss', hash: 'sha256', spki: spki(rsa.publicKey), signature: pssSig }, true],
    ['Ed25519 as Ed25519', { scheme: 'ed25519', hash: null, spki: spki(ed.publicKey), signature: edSig }, true],
  ]);
});

test('hashes: SHA-1 to SHA-512, named, for RSA and ECDSA', () => {
  expectAll([
    ['an RSA MD5 signature', { scheme: 'rsa-pkcs1', hash: 'md5', spki: spki(rsa.publicKey), signature: Uint8Array.from(sign('md5', data, rsa.privateKey)) }, false],
    ['an ECDSA SHA3-256 signature', { scheme: 'ecdsa', hash: 'sha3-256', spki: spki(ec.publicKey), signature: Uint8Array.from(sign('sha3-256', data, { key: ec.privateKey, dsaEncoding: 'der' })) }, false],
    ['ECDSA with no hash named', { scheme: 'ecdsa', hash: undefined, spki: spki(ec.publicKey), signature: ecSig }, false],
    ['RSA with a null hash', { scheme: 'rsa-pkcs1', hash: null, spki: spki(rsa.publicKey), signature: rsaSig }, false],
    ['RSA PSS with an unknown hash', { scheme: 'rsa-pss', hash: 'unknown', spki: spki(rsa.publicKey), signature: pssSig }, false],
    // Ed25519 takes no hash: one given is ignored.
    ['Ed25519 with a hash', { scheme: 'ed25519', hash: 'sha256', spki: spki(ed.publicKey), signature: edSig }, true],
  ]);
});

test('keys: what one cryptography refuses, the other refuses', () => {
  const ecSpki = spki(ec.publicKey);
  const point = ecSpki.subarray(ecSpki.length - 65);
  const odd = point[64] & 1;
  const ecKey = (pt, unused = 0) => seq(seq(OID_EC, OID_P256), bitString(pt, unused));
  const k1 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const edKey = (bytes, params = []) => seq(seq(OID_ED25519, ...params), bitString(bytes));
  const edBytes = spki(ed.publicKey).subarray(12);
  const n = Buffer.from(rsa.publicKey.export({ format: 'jwk' }).n, 'base64url');
  const rsaKey = (e, params = [NULL]) => seq(seq(OID_RSA, ...params), bitString(seq(int([0, ...n]), int(e))));
  // Under e = 1 the encoded message itself "verifies" — RFC 8017 allows no such key.
  const t = Buffer.concat([Buffer.from('3031300d060960864801650304020105000420', 'hex'), createHash('sha256').update(data).digest()]);
  const em = Buffer.alloc(n.length, 0xff); em[0] = 0; em[1] = 1; em[n.length - t.length - 1] = 0; t.copy(em, n.length - t.length);
  // R = the identity and S = 0 "verify" any message under the identity: refused when not canonical.
  const identitySig = Uint8Array.from([...le32(1n), ...new Uint8Array(32)]);
  expectAll([
    ['the same P-256 key, rebuilt', { scheme: 'ecdsa', hash: 'sha256', spki: ecKey([...point]), signature: ecSig }, true],
    ['a compressed point', { scheme: 'ecdsa', hash: 'sha256', spki: ecKey([2 + odd, ...point.subarray(1, 33)]), signature: ecSig }, false],
    ['a hybrid point', { scheme: 'ecdsa', hash: 'sha256', spki: ecKey([6 + odd, ...point.subarray(1)]), signature: ecSig }, false],
    ['a point off the curve', { scheme: 'ecdsa', hash: 'sha256', spki: ecKey([...point.subarray(0, 64), point[64] ^ 1]), signature: ecSig }, false],
    ['a key info with a byte after it', { scheme: 'ecdsa', hash: 'sha256', spki: Uint8Array.from([...ecKey([...point]), 0]), signature: ecSig }, false],
    ['a key info with an element after the key', { scheme: 'ecdsa', hash: 'sha256', spki: seq(seq(OID_EC, OID_P256), bitString([...point]), NULL), signature: ecSig }, false],
    ['a key BIT STRING with unused bits', { scheme: 'ecdsa', hash: 'sha256', spki: ecKey([...point], 1), signature: ecSig }, false],
    ['a secp256k1 key', { scheme: 'ecdsa', hash: 'sha256', spki: spki(k1.publicKey), signature: Uint8Array.from(sign('sha256', data, { key: k1.privateKey, dsaEncoding: 'der' })) }, false],
    ['an RSA key with its parameters absent', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: rsaKey([1, 0, 1], []), signature: rsaSig }, true],
    ['an RSA key with exponent 1', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: rsaKey([1]), signature: Uint8Array.from(em) }, false],
    ['an RSA key with an even exponent', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: rsaKey([1, 0, 0]), signature: rsaSig }, false],
    ['an RSA modulus written as a negative INTEGER', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: seq(seq(OID_RSA, NULL), bitString(seq(int([...n]), int([1, 0, 1])))), signature: rsaSig }, false],
    ['an Ed25519 key with NULL parameters', { scheme: 'ed25519', hash: null, spki: edKey(edBytes, [NULL]), signature: edSig }, false],
    ['an Ed25519 key of 31 bytes', { scheme: 'ed25519', hash: null, spki: edKey(edBytes.subarray(1)), signature: edSig }, false],
    ['the identity, y written as p + 1', { scheme: 'ed25519', hash: null, spki: edKey(le32(P25519 + 1n)), signature: identitySig }, false],
    ['the identity, with a sign bit on x = 0', { scheme: 'ed25519', hash: null, spki: edKey(le32(1n | (1n << 255n))), signature: identitySig }, false],
    ['a key info that is not DER', { scheme: 'ed25519', hash: null, spki: Uint8Array.of(1, 2, 3), signature: edSig }, false],
    ['an empty key info', { scheme: 'ecdsa', hash: 'sha256', spki: new Uint8Array(0), signature: ecSig }, false],
    ['no key info', { scheme: 'ecdsa', hash: 'sha256', spki: undefined, signature: ecSig }, false],
  ]);
});

test('signatures: the same strict encodings in both', () => {
  const raw = Uint8Array.from(sign('sha256', data, { key: ec.privateKey, dsaEncoding: 'ieee-p1363' }));
  const r = minimal(raw.subarray(0, 32));
  const s = minimal(raw.subarray(32));
  const body = [...int(r), ...int(s)];
  const highS = minimal(bytesOf(N_P256 - BigInt(`0x${hex(raw.subarray(32))}`), 32));
  const k = { scheme: 'ecdsa', hash: 'sha256', spki: spki(ec.publicKey) };
  // An RSA signature whose first byte is 0: valid, then shortened by that byte.
  let shortMsg; let shortSig;
  for (let i = 0; !shortSig; i++) {
    const m = Uint8Array.from(Buffer.from(`message ${i}`));
    const sig = sign('sha256', m, { key: rsa.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
    if (sig[0] === 0) { shortMsg = m; shortSig = Uint8Array.from(sig.subarray(1)); }
  }
  const nRsa = BigInt(`0x${Buffer.from(rsa.publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex')}`);
  const sPlusL = Uint8Array.from([...edSig.subarray(0, 32), ...le32(leBig(edSig.subarray(32)) + L25519)]);
  expectAll([
    ['ECDSA in DER', { ...k, signature: seq(int(r), int(s)) }, true],
    ['ECDSA with the other s (n − s)', { ...k, signature: seq(int(r), int(highS)) }, true],
    ['ECDSA with a byte after the SEQUENCE', { ...k, signature: Uint8Array.from([...seq(int(r), int(s)), 0]) }, false],
    ['ECDSA with r padded by a 0x00', { ...k, signature: seq(int([0, ...r]), int(s)) }, false],
    ['ECDSA with r read as negative', { ...k, signature: seq(int([0xff, ...r]), int(s)) }, false],
    ['ECDSA with a third INTEGER', { ...k, signature: seq(int(r), int(s), int([1])) }, false],
    ['ECDSA with an OCTET STRING for r', { ...k, signature: seq(der(0x04, r), int(s)) }, false],
    ['ECDSA with a long-form length where the short one fits', { ...k, signature: Uint8Array.from([0x30, 0x81, body.length, ...body]) }, false],
    ['ECDSA in a SET', { ...k, signature: der(0x31, body) }, false],
    ['ECDSA in raw r ‖ s', { ...k, signature: raw }, false],
    ['ECDSA with r = 0', { ...k, signature: seq(int([0]), int(s)) }, false],
    ['ECDSA with s = n', { ...k, signature: seq(int(r), int(minimal(bytesOf(N_P256, 32)))) }, false],
    ['an empty ECDSA signature', { ...k, signature: Uint8Array.of(0x30, 0x00) }, false],
    ['an RSA PSS signature one byte short', { scheme: 'rsa-pss', hash: 'sha256', spki: spki(rsa.publicKey), data: shortMsg, signature: shortSig }, false],
    ['the same with its 0x00 back', { scheme: 'rsa-pss', hash: 'sha256', spki: spki(rsa.publicKey), data: shortMsg, signature: Uint8Array.from([0, ...shortSig]) }, true],
    ['an RSA signature one byte long', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(rsa.publicKey), signature: Uint8Array.from([0, ...rsaSig]) }, false],
    ['an RSA signature equal to the modulus', { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(rsa.publicKey), signature: bytesOf(nRsa, 256) }, false],
    ['an Ed25519 signature with S + L', { scheme: 'ed25519', hash: null, spki: spki(ed.publicKey), signature: sPlusL }, false],
    ['an Ed25519 signature of 63 bytes', { scheme: 'ed25519', hash: null, spki: spki(ed.publicKey), signature: edSig.subarray(0, 63) }, false],
    ['no signature', { scheme: 'ed25519', hash: null, spki: spki(ed.publicKey), signature: undefined }, false],
  ]);
});

test("verifyEd25519: an x that is not a canonical Ed25519 key is false, never an exception", () => {
  const { x } = ed.publicKey.export({ format: 'jwk' });
  const identitySig = Uint8Array.from([...le32(1n), ...new Uint8Array(32)]);
  const b64 = (b) => Buffer.from(b).toString('base64url');
  for (const [label, xx, signature, expected] of [
    ['the key', x, edSig, true],
    ['x of 15 bytes', x.slice(0, 20), edSig, false],
    ['x of 35 bytes', `${x}AAAA`, edSig, false],
    ['x not base64', '!!!', edSig, false],
    ['no x', undefined, edSig, false],
    ['x a number', 42, edSig, false],
    ['the identity, y written as p + 1', b64(le32(P25519 + 1n)), identitySig, false],
    ['the identity, with a sign bit on x = 0', b64(le32(1n | (1n << 255n))), identitySig, false],
    ['a signature of 65 bytes', x, Uint8Array.from([...edSig, 0]), false],
    ['no signature', x, null, false],
  ]) assert.equal(verdict(impl => impl.verifyEd25519(xx, data, signature), label), expected, label);
});

test('altered keys and signatures: a boolean from both, the same one', () => {
  const pssKey = generateKeyPairSync('rsa-pss', { modulusLength: 1024, hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 });
  const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const vectors = [
    { scheme: 'rsa-pkcs1', hash: 'sha256', spki: spki(rsa.publicKey), signature: rsaSig },
    { scheme: 'rsa-pss', hash: 'sha256', spki: spki(pssKey.publicKey), signature: Uint8Array.from(sign('sha256', data, pssKey.privateKey)) },
    { scheme: 'ecdsa', hash: 'sha384', spki: spki(p384.publicKey), signature: Uint8Array.from(sign('sha384', data, { key: p384.privateKey, dsaEncoding: 'der' })) },
    { scheme: 'ed25519', hash: null, spki: spki(ed.publicKey), signature: edSig },
  ];
  // Deterministic: the same alterations every run.
  let seed = 0x2545f491;
  const rand = (n) => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % n; };
  for (const v of vectors) {
    assert.equal(verdict(impl => impl.verifySignature({ ...v, data }), `${v.scheme} as signed`), true);
    for (let round = 0; round < 60; round++) {
      const field = round % 2 ? 'spki' : 'signature';
      const bytes = Uint8Array.from(v[field]);
      const altered = round % 3 === 0 ? bytes.subarray(0, rand(bytes.length))
        : (bytes[rand(bytes.length)] ^= 1 << rand(8), bytes);
      verdict(impl => impl.verifySignature({ ...v, [field]: altered, data }), `${v.scheme}, ${field} altered (round ${round})`);
    }
  }
});
