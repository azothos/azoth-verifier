// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The verifier's cryptography in plain JavaScript — what the offline web page runs instead of
 * crypto.mjs (node:crypto), with the same three functions. Verification only: no secret is ever
 * handled, so nothing here needs to be constant-time. Written from the standards (FIPS 180-4,
 * RFC 8017, FIPS 186-5 / SEC 1, RFC 8032); the producer's test suite holds every function to
 * node:crypto on the same inputs.
 *
 * Which key, scheme, hash and signature encoding are acceptable is NOT decided here: keys.mjs
 * reads them for both cryptographies, so this file only does the arithmetic. A signature is a
 * verdict, never an exception: anything that does not verify — a key of another type than the
 * scheme names, a malformed key or signature — is `false`, as in crypto.mjs.
 */
import { concat, equal } from './bytes.mjs';
import { signedWith, ed25519Signed, toBig, mod, bitLength } from './keys.mjs';

// ── SHA-1 / SHA-256 (32-bit words) ──────────────────────────────────────────

const rotr = (x, n) => (x >>> n) | (x << (32 - n));
const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/** Message padding for 64-byte blocks, big-endian 64-bit length. */
function pad64(msg) {
  const len = msg.length;
  const total = ((len + 9 + 63) >> 6) << 6;
  const out = new Uint8Array(total);
  out.set(msg);
  out[len] = 0x80;
  const bits = len * 8;
  const dv = new DataView(out.buffer);
  dv.setUint32(total - 8, Math.floor(bits / 2 ** 32));
  dv.setUint32(total - 4, bits >>> 0);
  return out;
}

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(msg) {
  const m = pad64(msg);
  const dv = new DataView(m.buffer);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let o = 0; o < m.length; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]);
  return out;
}

function sha1(msg) {
  const m = pad64(msg);
  const dv = new DataView(m.buffer);
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const w = new Uint32Array(80);
  for (let o = 0; o < m.length; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let [a, b, c, d, e] = h;
    for (let i = 0; i < 80; i++) {
      const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
      const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 5; i++) ov.setUint32(i * 4, h[i]);
  return out;
}

// ── SHA-384 / SHA-512 (64-bit words, BigInt — small inputs only: signed attributes, Ed25519) ──

const M64 = (1n << 64n) - 1n;
const r64 = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
const K512 = [
  '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
  'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
  'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
  '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
  '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
  'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
  '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
  '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
  'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
  '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817',
].map(h => BigInt(`0x${h}`));
const IV512 = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1', '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'];
const IV384 = ['cbbb9d5dc1059ed8', '629a292a367cd507', '9159015a3070dd17', '152fecd8f70e5939', '67332667ffc00b31', '8eb44a8768581511', 'db0c2e0d64f98fa7', '47b5481dbefa4fa4'];

function sha512Family(msg, iv, outLen) {
  const len = msg.length;
  const total = ((len + 17 + 127) >> 7) << 7;
  const m = new Uint8Array(total);
  m.set(msg); m[len] = 0x80;
  const dv = new DataView(m.buffer);
  const bits = BigInt(len) * 8n;
  dv.setBigUint64(total - 8, bits & M64);
  const h = iv.map(x => BigInt(`0x${x}`));
  const w = new Array(80);
  for (let o = 0; o < total; o += 128) {
    for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(o + i * 8);
    for (let i = 16; i < 80; i++) {
      const s0 = r64(w[i - 15], 1n) ^ r64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
      const s1 = r64(w[i - 2], 19n) ^ r64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const t1 = (hh + (r64(e, 14n) ^ r64(e, 18n) ^ r64(e, 41n)) + ((e & f) ^ (~e & M64 & g)) + K512[i] + w[i]) & M64;
      const t2 = ((r64(a, 28n) ^ r64(a, 34n) ^ r64(a, 39n)) + ((a & b) ^ (a & c) ^ (b & c))) & M64;
      hh = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
    }
    for (const [i, v] of [a, b, c, d, e, f, g, hh].entries()) h[i] = (h[i] + v) & M64;
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setBigUint64(i * 8, h[i]);
  return out.subarray(0, outLen);
}

const HASH = { sha1, sha256, sha384: m => sha512Family(m, IV384, 48), sha512: m => sha512Family(m, IV512, 64) };
const HASH_LEN = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };

export function digest(alg, data) {
  const f = HASH[alg];
  if (!f) throw new Error(`unsupported hash ${alg}`);
  return f(data);
}

// ── Big integers ─────────────────────────────────────────────────────────────

function toBytes(v, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return v === 0n ? out : null;   // did not fit
}
function modPow(b, e, m) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
function modInv(a, m) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

// ── RSA: PKCS #1 v1.5 and PSS (RFC 8017) ─────────────────────────────────────

const DIGEST_INFO = {
  sha1: '3021300906052b0e03021a05000414', sha256: '3031300d060960864801650304020105000420',
  sha384: '3041300d060960864801650304020205000430', sha512: '3051300d060960864801650304020305000440',
};
const fromHexStr = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));

function rsaOpen(key, signature) {
  const k = Math.ceil(bitLength(key.n) / 8);
  if (signature.length !== k) return null;
  const s = toBig(signature);
  if (s >= key.n) return null;
  return { em: toBytes(modPow(s, key.e, key.n), k), k };
}

function rsaPkcs1(key, hash, data, signature) {
  const open = rsaOpen(key, signature);
  if (!open || !DIGEST_INFO[hash]) return false;
  const t = concat(fromHexStr(DIGEST_INFO[hash]), digest(hash, data));
  if (open.k < t.length + 11) return false;
  const want = new Uint8Array(open.k).fill(0xff);
  want[0] = 0; want[1] = 1; want[open.k - t.length - 1] = 0;
  want.set(t, open.k - t.length);
  return equal(open.em, want);
}

function mgf1(hash, seed, len) {
  const out = new Uint8Array(len);
  for (let c = 0, o = 0; o < len; c++) {
    const block = digest(hash, concat(seed, Uint8Array.of(c >>> 24, (c >>> 16) & 255, (c >>> 8) & 255, c & 255)));
    out.set(block.subarray(0, Math.min(block.length, len - o)), o);
    o += block.length;
  }
  return out;
}

function rsaPss(key, hash, data, signature) {
  const open = rsaOpen(key, signature);
  const hLen = HASH_LEN[hash];
  if (!open || !hLen) return false;
  const emBits = bitLength(key.n) - 1;
  const emLen = Math.ceil(emBits / 8);
  const em = open.em.subarray(open.k - emLen);
  if (open.k > emLen && open.em[0] !== 0) return false;
  if (emLen < hLen + 2 || em[emLen - 1] !== 0xbc) return false;
  const masked = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);
  const zeroBits = 8 * emLen - emBits;
  if (masked[0] >> (8 - zeroBits) && zeroBits) return false;
  const db = mgf1(hash, h, masked.length).map((x, i) => x ^ masked[i]);
  db[0] &= 0xff >> zeroBits;
  let i = 0;
  while (i < db.length && db[i] === 0) i++;
  if (db[i] !== 1) return false;
  const salt = db.subarray(i + 1);   // its length recovered, as node:crypto's RSA_PSS_SALTLEN_AUTO does
  return equal(digest(hash, concat(new Uint8Array(8), digest(hash, data), salt)), h);
}

// ── ECDSA over the NIST prime curves (FIPS 186-5; the curves: keys.mjs) ─────

// Jacobian coordinates; null is the point at infinity.
function jDouble(c, P) {
  if (!P || P[1] === 0n) return null;
  const [x, y, z] = P; const p = c.p;
  const z2 = (z * z) % p;
  const m = mod(3n * (x - z2) * (x + z2), p);   // a = -3
  const y2 = (y * y) % p;
  const s = (4n * x * y2) % p;
  const x3 = mod(m * m - 2n * s, p);
  return [x3, mod(m * (s - x3) - 8n * y2 * y2, p), (2n * y * z) % p];
}
function jAdd(c, P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  const p = c.p;
  const z1z1 = (P[2] * P[2]) % p; const z2z2 = (Q[2] * Q[2]) % p;
  const u1 = (P[0] * z2z2) % p; const u2 = (Q[0] * z1z1) % p;
  const s1 = (P[1] * Q[2] * z2z2) % p; const s2 = (Q[1] * P[2] * z1z1) % p;
  if (u1 === u2) return s1 === s2 ? jDouble(c, P) : null;
  const h = mod(u2 - u1, p); const r = mod(s2 - s1, p);
  const h2 = (h * h) % p; const h3 = (h2 * h) % p;
  const x3 = mod(r * r - h3 - 2n * u1 * h2, p);
  return [x3, mod(r * (u1 * h2 - x3) - s1 * h3, p), (h * P[2] * Q[2]) % p];
}
function jMul(c, P, k) {
  let R = null;
  for (let i = bitLength(k) - 1; i >= 0; i--) {
    R = jDouble(c, R);
    if ((k >> BigInt(i)) & 1n) R = jAdd(c, R, P);
  }
  return R;
}

/** `key`: keys.mjs's — its point on its curve; r and s already in [1, n − 1]. */
function ecdsa(key, hash, data, r, s) {
  const c = key.curve;
  const hb = digest(hash, data);
  let e = toBig(hb);
  const excess = hb.length * 8 - bitLength(c.n);
  if (excess > 0) e >>= BigInt(excess);
  const w = modInv(s, c.n);
  const X = jAdd(c, jMul(c, [c.g[0], c.g[1], 1n], mod(e * w, c.n)), jMul(c, [key.x, key.y, 1n], mod(r * w, c.n)));
  if (!X) return false;
  const zi = modInv(X[2], c.p);
  return mod(X[0] * zi * zi, c.p) % c.n === r;
}

// ── Ed25519 (RFC 8032 §5.1.7) ────────────────────────────────────────────────

const P25519 = 2n ** 255n - 19n;
const L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;
const D25519 = mod(-121665n * modInv(121666n, P25519), P25519);
const SQRT_M1 = modPow(2n, (P25519 - 1n) / 4n, P25519);
const leBig = b => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };

function edDecode(bytes) {
  if (bytes.length !== 32) return null;
  const y = leBig(bytes) & ((1n << 255n) - 1n);
  const sign = bytes[31] >> 7;
  if (y >= P25519) return null;
  const y2 = (y * y) % P25519;
  const u = mod(y2 - 1n, P25519); const v = mod(D25519 * y2 + 1n, P25519);
  let x = (u * modPow(v, 3n, P25519) * modPow(u * modPow(v, 7n, P25519), (P25519 - 5n) / 8n, P25519)) % P25519;
  const vx2 = (v * x * x) % P25519;
  if (vx2 !== u) { if (vx2 === mod(-u, P25519)) x = (x * SQRT_M1) % P25519; else return null; }
  if (x === 0n && sign) return null;
  if (Number(x & 1n) !== sign) x = P25519 - x;
  return [x, y, 1n, (x * y) % P25519];   // extended coordinates
}
function edAdd(P, Q) {
  const p = P25519;
  const a = ((P[1] - P[0]) * (Q[1] - Q[0])) % p; const b = ((P[1] + P[0]) * (Q[1] + Q[0])) % p;
  const c = (2n * P[3] * Q[3] * D25519) % p; const d = (2n * P[2] * Q[2]) % p;
  const e = b - a; const f = d - c; const g = d + c; const h = b + a;
  return [mod(e * f, p), mod(g * h, p), mod(f * g, p), mod(e * h, p)];
}
function edMul(P, k) {
  let R = [0n, 1n, 1n, 0n];
  for (let i = bitLength(k) - 1; i >= 0; i--) { R = edAdd(R, R); if ((k >> BigInt(i)) & 1n) R = edAdd(R, P); }
  return R;
}
const edEqual = (P, Q) => mod(P[0] * Q[2] - Q[0] * P[2], P25519) === 0n && mod(P[1] * Q[2] - Q[1] * P[2], P25519) === 0n;
const B25519 = [15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  46316835694926478169428394003475163141307993866256225615783033603165251855960n, 1n, 0n];
B25519[3] = (B25519[0] * B25519[1]) % P25519;

function ed25519(publicKey, data, signature) {
  if (signature.length !== 64) return false;
  const A = edDecode(publicKey);
  const R = edDecode(signature.subarray(0, 32));
  const S = leBig(signature.subarray(32));
  if (!A || !R || S >= L25519) return false;
  const k = leBig(digest('sha512', concat(signature.subarray(0, 32), publicKey, data))) % L25519;
  return edEqual(edMul(B25519, S), edAdd(R, edMul(A, k)));
}

// ── The adapter ──────────────────────────────────────────────────────────────

export function verifySignature({ scheme, hash, spki, data, signature }) {
  try {
    const fit = signedWith({ scheme, hash, spki, signature });
    if (!fit) return false;
    if (scheme === 'rsa-pkcs1') return rsaPkcs1(fit.key, fit.hash, data, signature);
    if (scheme === 'rsa-pss') return rsaPss(fit.key, fit.hash, data, signature);
    if (scheme === 'ecdsa') return ecdsa(fit.key, fit.hash, data, fit.r, fit.s);
    return ed25519(fit.key.key, data, signature);
  } catch {
    return false;
  }
}

export function verifyEd25519(x, data, signature) {
  try {
    const key = ed25519Signed(x, signature);
    return key ? ed25519(key, data, signature) : false;
  } catch {
    return false;
  }
}
