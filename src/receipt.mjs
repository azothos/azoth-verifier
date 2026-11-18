// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 10 — a call's receipt (SPEC.md): the compact JWS the gateway hands back with every
 * answer. Verified with the workspace's published keys (a JWKS — `keys.jwks.json` in any
 * dossier), and, with a dossier, tied to the sealed decision it certifies.
 *
 * Zero dependencies, zero network, and no Azoth code: the rules are SPEC.md's,
 * reimplemented here; the cryptography is crypto.mjs's (node:crypto, or the web verifier's).
 */
import { canonicalCore, sha256Hex } from './chain.mjs';
import { base64url, fromBase64, fromUtf8, utf8 } from './bytes.mjs';
import { digest, verifyEd25519 } from './crypto.mjs';
import { keyTrustAt } from './keys.mjs';

const TYP = 'azoth-receipt+jws';
const OUTCOMES = new Set(['allowed', 'blocked', 'rerouted', 'held', 'failed', 'act']);
const B64URL = /^[A-Za-z0-9_-]+$/;
const json = part => JSON.parse(fromUtf8(fromBase64(part)));

/** The receipt's header, claims, signing input and signature — or an error naming what is wrong. */
export function decodeReceipt(token) {
  const parts = String(token).trim().split('.');
  if (parts.length !== 3 || !parts.every(p => B64URL.test(p))) return { error: 'not a compact JWS (three base64url parts)' };
  let header; let claims;
  try { header = json(parts[0]); claims = json(parts[1]); } catch { return { error: 'header or claims are not JSON' }; }
  if (header?.alg !== 'EdDSA' || header?.typ !== TYP || typeof header?.kid !== 'string') return { error: `header must be { alg: "EdDSA", typ: "${TYP}", kid }` };
  const c = claims ?? {};
  if (c.v !== 1 || typeof c.ws !== 'string' || typeof c.trace !== 'string' || !/^[0-9a-f]{64}$/.test(String(c.core))
      || !OUTCOMES.has(c.out) || !Number.isInteger(c.iat) || (c.ref !== undefined && !/^[0-9a-f]{64}$/.test(String(c.ref)))) {
    return { error: 'claims must be { v: 1, ws, trace, core: sha256 hex, out, ref?: sha256 hex, iat: seconds }' };
  }
  return { header, claims: c, signingInput: `${parts[0]}.${parts[1]}`, signature: fromBase64(parts[2]) };
}

/** Every sealed core the dossier holds, by its sha256: listed entries and chain links. */
function coresOf(pack) {
  const at = new Map();
  for (const e of Array.isArray(pack?.entries) ? pack.entries : []) at.set(sha256Hex(canonicalCore(e.core)), { seq: e.seq, traceId: e.traceId ?? null });
  const links = [...(Array.isArray(pack?.chain) ? pack.chain : []), ...(Array.isArray(pack?.segments) ? pack.segments.flatMap(s => s.links ?? []) : [])];
  for (const l of links) if (typeof l.coreCanonical === 'string' && !at.has(sha256Hex(l.coreCanonical))) at.set(sha256Hex(l.coreCanonical), { seq: l.seq, traceId: null });
  return at;
}

/**
 * Check 10. `jwks`: { keys: [...] } (the workspace's published keys). `pack`: a dossier's
 * evidence.json, to find the decision the receipt certifies (optional).
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyReceipt(token, jwks, { pack = null } = {}) {
  const out = [];
  const push = (id, ok, detail, level) => out.push(level ? { id, ok, detail, level } : { id, ok, detail });
  const r = decodeReceipt(token);
  if (r.error) { push('receipt.format', false, r.error); return out; }
  const { header, claims } = r;
  push('receipt.format', true, `outcome ${claims.out}, trace ${claims.trace}, signed ${new Date(claims.iat * 1000).toISOString()}`);

  const key = (Array.isArray(jwks?.keys) ? jwks.keys : []).find(k => k?.kid === header.kid);
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string') {
    push('receipt.key', false, `no Ed25519 key ${header.kid} among the keys given`);
    return out;
  }
  // The kid is the key's RFC 7638 thumbprint: a key cannot be swapped under the same id.
  const thumbprint = base64url(digest('sha256', utf8(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: key.x }))));
  if (thumbprint !== header.kid) { push('receipt.key', false, `key ${header.kid} does not hash to its id`); return out; }
  // A key its producer declared compromised signs nothing trusted from that instant on (keys.mjs, keyTrustAt).
  const trust = keyTrustAt(key, claims.iat);
  if (!trust.ok) { push('receipt.key', false, `key ${header.kid.slice(0, 12)}… is refused: ${trust.detail}`); return out; }
  const retiredLate = key.status === 'retired' && key.retired_at && claims.iat * 1000 > Date.parse(key.retired_at) + 10 * 60_000;
  push('receipt.key', true, `key ${header.kid.slice(0, 12)}…${key.status === 'retired' ? ` (retired ${key.retired_at})` : ''}`);
  if (retiredLate) push('receipt.key.retired', true, 'signed more than 10 minutes after its key was retired', 'warn');
  if (trust.warn) push('receipt.key.compromised', true, trust.warn, 'warn');

  let valid = false;
  try { valid = verifyEd25519(key.x, utf8(r.signingInput), r.signature); }
  catch { valid = false; }
  push('receipt.signature', valid, valid ? 'Ed25519 signature valid' : 'signature does not verify (receipt altered, or another key)');
  if (!valid || !pack) return out;

  const hit = coresOf(pack).get(claims.core);
  if (!hit) push('receipt.decision', false, 'the decision this receipt certifies is not in this dossier (outside its period, or missing from its chain)');
  else if (hit.traceId && hit.traceId !== claims.trace) push('receipt.decision', false, `sealed at seq ${hit.seq} under another trace (${hit.traceId})`);
  else push('receipt.decision', true, `the decision it certifies is sealed at seq ${hit.seq} of this dossier's chain (see the chain checks)`);
  return out;
}
