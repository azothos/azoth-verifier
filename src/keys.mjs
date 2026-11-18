// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * What a public key, a signature and the scheme they are checked under must be — read ONCE, here,
 * for both cryptographies: crypto.mjs (node:crypto, the command line's) and crypto-web.mjs (plain
 * JavaScript, the web page's) ask this module before any arithmetic, so the two refuse exactly the
 * same inputs. node:crypto never reads a key from its own encoding: it is given the key rebuilt from
 * the parts read here, so a lenient reading there cannot accept what the web page refuses.
 *
 *   readPublicKey(spki)                                   SubjectPublicKeyInfo (DER) → its parts, or null
 *   signedWith({ scheme, hash, spki, signature })         → { key, hash, r?, s? } when they fit, else null
 *   ed25519Signed(x, signature)                           a JWK's `x` → the key's 32 bytes, or null
 *   keyTrustAt(jwk, signedAt)                             a producer's published key at the instant it signed:
 *                                                         refused at or after its declared compromise
 *
 * The rules (SPEC.md, « Keys and signatures »):
 *   - DER only: minimal lengths, nothing after the last element, no unused bit in a key's BIT STRING;
 *   - the scheme is the key's: rsa-pkcs1 an rsaEncryption key; rsa-pss an rsaEncryption key or an
 *     id-RSASSA-PSS key (whose parameters, when present, must name the signature's hash for both the
 *     digest and MGF1); ecdsa an id-ecPublicKey key on P-256, P-384 or P-521; ed25519 an Ed25519 key;
 *   - a hash among sha1, sha256, sha384, sha512 (Ed25519 takes none: one given is ignored);
 *   - RSA: a modulus of 512 to 16384 bits, odd; an exponent odd, at least 3, below the modulus, at
 *     most 64 bits; a signature of exactly the modulus' length, below the modulus (RFC 8017 §8.1.2, §8.2.2);
 *   - ECDSA: an uncompressed point (RFC 5480), on its curve, coordinates below the field prime; a
 *     DER `SEQUENCE { INTEGER r, INTEGER s }`, both in [1, n − 1];
 *   - Ed25519: a 32-byte key in its canonical encoding (RFC 8032 §5.1.3) with no parameters; a
 *     64-byte signature whose S is below the group order L.
 */
import { oidOf } from './der.mjs';
import { fromBase64 } from './bytes.mjs';

// ── Big integers ─────────────────────────────────────────────────────────────

export const toBig = b => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
export const mod = (a, m) => ((a % m) + m) % m;
export const bitLength = v => (v === 0n ? 0 : v.toString(2).length);
const leBig = b => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };

// ── The NIST prime curves (FIPS 186-5), a = −3 ───────────────────────────────

const curve = (name, size, p, b, gx, gy, n) => ({ name, size, p: BigInt(p), a: BigInt(p) - 3n, b: BigInt(b), g: [BigInt(gx), BigInt(gy)], n: BigInt(n) });
export const CURVES = {
  '1.2.840.10045.3.1.7': curve('P-256', 32, '0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff', '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  '1.3.132.0.34': curve('P-384', 48, '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
    '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
    '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
  '1.3.132.0.35': curve('P-521', 66, '0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    '0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
    '0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
    '0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
    '0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
};

// ── Strict DER ───────────────────────────────────────────────────────────────

/** One TLV at `at`, its length in minimal form; null when it is not DER. `end` is relative to `buf`. */
function node(buf, at = 0) {
  if (at + 2 > buf.length || (buf[at] & 0x1f) === 0x1f) return null;
  let len = buf[at + 1];
  let p = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3 || p + n > buf.length || buf[p] === 0) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    if (len < 0x80) return null;   // the short form was required
  }
  if (p + len > buf.length) return null;
  return { tag: buf[at], body: buf.subarray(p, p + len), end: p + len };
}
/** `buf` as exactly one TLV, nothing after it. */
const whole = buf => { const n = node(buf); return n && n.end === buf.length ? n : null; };
/** A constructed node's elements, or null when one is not DER. */
function elements(n) {
  const out = [];
  for (let o = 0; o < n.body.length;) { const c = node(n.body, o); if (!c) return null; out.push(c); o = c.end; }
  return out;
}
/** A non-negative INTEGER in its minimal encoding, or null. */
function uint(n) {
  if (!n || n.tag !== 0x02 || !n.body.length) return null;
  const b = n.body;
  if (b[0] & 0x80 || (b[0] === 0 && b.length > 1 && !(b[1] & 0x80))) return null;
  return toBig(b);
}
const isNull = n => n.tag === 0x05 && n.body.length === 0;
/** An AlgorithmIdentifier → { oid, params }, or null. */
function algorithm(n) {
  const a = n && n.tag === 0x30 ? elements(n) : null;
  if (!a || a.length < 1 || a.length > 2 || a[0].tag !== 0x06) return null;
  return { oid: oidOf(a[0]), params: a[1] ?? null };
}

// ── Hashes and RSASSA-PSS parameters (RFC 4055) ──────────────────────────────

export const HASHES = ['sha1', 'sha256', 'sha384', 'sha512'];
const HASH_OF = {
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512',
};
const MGF1 = '1.2.840.113549.1.1.8';
/** A hash AlgorithmIdentifier (parameters absent or NULL) → its name, or null. */
function hashOf(n) {
  const a = algorithm(n);
  return a && (!a.params || isNull(a.params)) ? HASH_OF[a.oid] ?? null : null;
}

/**
 * RSASSA-PSS-params → { hash, mgf1Hash, saltLength }, the defaults (SHA-1, MGF1 with SHA-1, 20)
 * where a field is absent; `params` null (absent) gives the defaults too. Null when the parameters
 * are not DER, name a hash or a mask function this verifier does not compute, or a trailer field
 * other than 1.
 */
export function pssParams(params) {
  const out = { hash: 'sha1', mgf1Hash: 'sha1', saltLength: 20 };
  if (!params) return out;
  const fields = params.tag === 0x30 ? elements(params) : null;
  if (!fields) return null;
  let last = -1;
  for (const f of fields) {
    const i = f.tag - 0xa0;
    if (i <= last || i > 3) return null;   // [0]..[3], in order, each once
    last = i;
    const inner = elements(f);
    if (!inner || inner.length !== 1) return null;
    if (i === 0) {
      out.hash = hashOf(inner[0]);
      if (!out.hash) return null;
    } else if (i === 1) {
      const mgf = algorithm(inner[0]);
      if (!mgf || mgf.oid !== MGF1) return null;
      out.mgf1Hash = hashOf(mgf.params);
      if (!out.mgf1Hash) return null;
    } else {
      const v = uint(inner[0]);
      if (v === null) return null;
      if (i === 2) out.saltLength = Number(v);
      else if (v !== 1n) return null;
    }
  }
  return out;
}

// ── Public keys (SubjectPublicKeyInfo, RFC 5280 §4.1) ────────────────────────

const RSA = '1.2.840.113549.1.1.1';
const RSA_PSS = '1.2.840.113549.1.1.10';
const EC = '1.2.840.10045.2.1';
const ED25519 = '1.3.101.112';

const P25519 = 2n ** 255n - 19n;
const L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;

/** An Ed25519 public key in its canonical encoding: y below p, and no sign bit on x = 0. */
function ed25519Bytes(b) {
  if (!b || b.length !== 32) return null;
  const y = leBig(b) & ((1n << 255n) - 1n);
  if (y >= P25519) return null;
  if (b[31] >> 7 && (y === 1n || y === P25519 - 1n)) return null;   // x = 0 exactly there
  return b;
}

/** Big-endian bytes of an INTEGER's value, without its sign byte. */
const magnitude = n => (n.body[0] === 0 && n.body.length > 1 ? n.body.subarray(1) : n.body);

/**
 * A SubjectPublicKeyInfo (DER) → `{ type: 'rsa' | 'rsa-pss', n, e, size, bytes: { n, e }, pss }`,
 * `{ type: 'ec', curve, x, y, point }` or `{ type: 'ed25519', key }`; null for anything else.
 */
export function readPublicKey(spki) {
  const top = spki ? whole(spki) : null;
  const parts = top && top.tag === 0x30 ? elements(top) : null;
  if (!parts || parts.length !== 2) return null;
  const alg = algorithm(parts[0]);
  const bits = parts[1];
  if (!alg || bits.tag !== 0x03 || bits.body.length < 2 || bits.body[0] !== 0) return null;
  const key = bits.body.subarray(1);
  if (alg.oid === RSA || alg.oid === RSA_PSS) {
    let pss = null;
    if (alg.oid === RSA && alg.params && !isNull(alg.params)) return null;
    if (alg.oid === RSA_PSS && alg.params) { pss = pssParams(alg.params); if (!pss) return null; }
    const k = whole(key);
    const ne = k && k.tag === 0x30 ? elements(k) : null;
    if (!ne || ne.length !== 2) return null;
    const n = uint(ne[0]);
    const e = uint(ne[1]);
    if (n === null || e === null) return null;
    const modBits = bitLength(n);
    if (modBits < 512 || modBits > 16384 || !(n & 1n) || e < 3n || !(e & 1n) || e >= n || bitLength(e) > 64) return null;
    return { type: alg.oid === RSA ? 'rsa' : 'rsa-pss', n, e, size: Math.ceil(modBits / 8), bytes: { n: magnitude(ne[0]), e: magnitude(ne[1]) }, pss };
  }
  if (alg.oid === EC) {
    const c = alg.params && alg.params.tag === 0x06 ? CURVES[oidOf(alg.params)] : null;
    if (!c || key.length !== 1 + 2 * c.size || key[0] !== 4) return null;
    const x = toBig(key.subarray(1, 1 + c.size));
    const y = toBig(key.subarray(1 + c.size));
    if (x >= c.p || y >= c.p || mod(y * y - (x * x * x + c.a * x + c.b), c.p) !== 0n) return null;
    return { type: 'ec', curve: c, x, y, point: key };
  }
  if (alg.oid === ED25519) {
    if (alg.params) return null;   // RFC 8410 §3: absent
    return ed25519Bytes(key) ? { type: 'ed25519', key } : null;
  }
  return null;
}

// ── Signatures ───────────────────────────────────────────────────────────────

const KEYS_OF = { 'rsa-pkcs1': ['rsa'], 'rsa-pss': ['rsa', 'rsa-pss'], ecdsa: ['ec'], ed25519: ['ed25519'] };

/** An ECDSA signature: DER `SEQUENCE { INTEGER r, INTEGER s }`, both in [1, n − 1] — else null. */
function ecdsaSignature(signature, n) {
  const top = whole(signature);
  const rs = top && top.tag === 0x30 ? elements(top) : null;
  if (!rs || rs.length !== 2) return null;
  const r = uint(rs[0]);
  const s = uint(rs[1]);
  if (r === null || s === null || r < 1n || s < 1n || r >= n || s >= n) return null;
  return { r, s };
}

/** A 64-byte Ed25519 signature whose S is below L (RFC 8032 §5.1.7). */
const ed25519Signature = sig => sig.length === 64 && leBig(sig.subarray(32)) < L25519;

/**
 * Do the key, the scheme, the hash and the signature's encoding fit? `{ key, hash }` (with `r` and
 * `s` for ECDSA) when they do — only the arithmetic is left — else null. Never throws.
 */
export function signedWith({ scheme, hash, spki, signature }) {
  try {
    const key = readPublicKey(spki);
    if (!key || !(Object.hasOwn(KEYS_OF, scheme) && KEYS_OF[scheme].includes(key.type)) || typeof signature?.length !== 'number') return null;
    if (scheme === 'ed25519') return ed25519Signature(signature) ? { key, hash: null } : null;
    if (!HASHES.includes(hash)) return null;
    if (key.type === 'ec') {
      const rs = ecdsaSignature(signature, key.curve.n);
      return rs ? { key, hash, ...rs } : null;
    }
    // An id-RSASSA-PSS key with parameters signs only with their hash, in the digest and in MGF1.
    if (key.pss && (key.pss.hash !== hash || key.pss.mgf1Hash !== hash)) return null;
    if (signature.length !== key.size || toBig(signature) >= key.n) return null;
    return { key, hash };
  } catch {
    return null;
  }
}

/** A JWK's `x` and a signature fit Ed25519: the key's 32 bytes, else null. Never throws. */
export function ed25519Signed(x, signature) {
  try {
    const key = ed25519Bytes(fromBase64(x));
    return key && typeof signature?.length === 'number' && ed25519Signature(signature) ? key : null;
  } catch {
    return null;
  }
}

// ── A producer's key, at the instant it signed ──────────────────────────────

const STATUSES = ['active', 'retired', 'compromised'];

/**
 * May a signature dated `signedAt` (seconds — a JWS `iat`) be trusted under this published key? The ONE
 * rule for every check that verifies under a producer's key — a dossier's or a platform package's signature
 * (Check 12), a receipt (Check 10) — on the command line and on the web page alike (SPEC.md, « Keys and
 * signatures »):
 *   - a key its producer declared compromised (`status` "compromised") refuses every signature dated at or
 *     after its `compromised_at`; one dated before it stands, with a warning: that date is the signer's own
 *     claim, and whoever holds the key can write an earlier one;
 *   - a compromised key without a readable `compromised_at`, or a status this verifier does not know, refuses
 *     every signature;
 *   - an active or retired key (or one with no status: an older producer) is trusted.
 * Never throws. `{ ok: false, detail }`, or `{ ok: true, warn? }`.
 * @param {{ status?: unknown, compromised_at?: unknown, compromise_declared_at?: unknown }} key
 * @param {number} signedAt
 */
export function keyTrustAt(key, signedAt) {
  const status = key?.status;
  if (status === undefined || status === null || status === 'active' || status === 'retired') return { ok: true };
  if (!STATUSES.includes(status)) return { ok: false, detail: `its producer publishes it with a status this verifier does not know ("${String(status)}"): no signature under it is trusted` };
  const from = typeof key.compromised_at === 'string' ? Date.parse(key.compromised_at) : NaN;
  const declared = typeof key.compromise_declared_at === 'string' ? ` (declared ${key.compromise_declared_at})` : '';
  if (!Number.isFinite(from)) return { ok: false, detail: `its producer declared it compromised${declared} without a readable instant: no signature under it is trusted` };
  const at = Number.isFinite(signedAt) ? signedAt * 1000 : NaN;
  if (!Number.isFinite(at) || at >= from) {
    return { ok: false, detail: `it signed on ${Number.isFinite(at) ? new Date(at).toISOString() : 'an unreadable date'}, at or after ${new Date(from).toISOString()}, from when its producer declared it compromised${declared}: anyone holding the key could have made this signature` };
  }
  return { ok: true, warn: `its producer declared it compromised from ${new Date(from).toISOString()}${declared}; this signature is dated ${new Date(at).toISOString()}, before — but that date is the signer's own claim: only a trusted timestamp (Check 4) shows it existed then` };
}
