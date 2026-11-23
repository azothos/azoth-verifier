// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 17 — a signed JSON evidence pack (SPEC.md): the body Azoth answers to
 * `GET /api/v1/journal/export` (without `format=dossier`) and its `X-Azoth-Export-Signature` header,
 * a compact JWS (EdDSA) by the workspace's Ed25519 key over the sha256 of that exact body and the
 * coverage it commits — the dossier's (Check 12), with the body in place of the manifest's root.
 *
 * The body is read as the bytes received: re-indented, re-encoded or re-serialised, it is another body,
 * and fails. The key must be one the reader pinned (`--keys`): the pack ships no key of its own. Then
 * the pack is the audit pack a dossier's evidence.json is — its chain (Check 3), the retention
 * checkpoint it starts after (Check 15), the law and the cost decided again from the seals (Checks 11
 * and 13, without the files only a dossier ships), the time, actor type and trace each core seals
 * (Check 16).
 *
 * Zero dependencies, zero network, no Azoth code: the rules are SPEC.md's, reimplemented here; the
 * cryptography is crypto.mjs's (node:crypto, or the web verifier's), the key rules keys.mjs's.
 */
import { sha256Hex } from './chain.mjs';
import { base64url, bytesOf, fromBase64, fromUtf8, utf8 } from './bytes.mjs';
import { digest, verifyEd25519 } from './crypto.mjs';
import { keyTrustAt } from './keys.mjs';
import { kindOf, verifyCoverage, wellFormedV2 } from './signature.mjs';
import { chainCheck, verifySealedFields } from './verify.mjs';
import { verifyRetention } from './retention.mjs';
import { verifyJurisdiction } from './jurisdiction.mjs';
import { verifyPricing } from './pricing.mjs';

export const EXPORT_SIGNATURE_HEADER = 'X-Azoth-Export-Signature';
const TYP = 'azoth-journal-export+jws';
const B64URL = /^[A-Za-z0-9_-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;
const json = part => JSON.parse(fromUtf8(fromBase64(part)));
const isScalar = v => v === null || ['string', 'number', 'boolean'].includes(typeof v);

/**
 * The signature as given: the token itself, or a text that holds it — the header line as `curl -D`
 * writes it (`X-Azoth-Export-Signature: <token>`), any case.
 */
export function exportSignatureOf(text) {
  const s = String(text ?? '');
  const line = new RegExp(`^${EXPORT_SIGNATURE_HEADER}:[ \\t]*(\\S+)`, 'im').exec(s);
  return (line ? line[1] : s).trim();
}

/**
 * The export's filters as it signed them (the producer's rule): scalars kept, a list joined with ",",
 * an object or an absent value dropped.
 */
export function signedFilters(filters) {
  const out = {};
  for (const [k, v] of Object.entries(filters && typeof filters === 'object' ? filters : {})) {
    if (Array.isArray(v)) out[k] = v.map(String).join(',');
    else if (isScalar(v)) out[k] = v;
  }
  return out;
}
/** The same names with the same values, in whatever order. */
const sameFilters = (a, b) => {
  const names = Object.keys(a);
  return names.length === Object.keys(b).length && names.every(k => Object.prototype.hasOwnProperty.call(b, k) && Object.is(a[k], b[k]));
};

/**
 * Check 17. `body`: the pack's bytes as received (or its text). `signature`: the header's value.
 * `keys`: the workspace's published keys (a JWKS), pinned by the reader. `workspace`: the workspace the
 * reader fetched the keys for (`--workspace`), when the JWKS does not name it.
 * @param {Uint8Array | string} body
 * @param {string} signature
 * @param {{ keys?: { keys?: unknown[], workspaceId?: unknown } | null, workspace?: string | null }} [opts]
 * @returns {{ ok: boolean, checks: Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }> }}
 */
export function verifyExport(body, signature, { keys = null, workspace = null } = {}) {
  const checks = [];
  const push = (id, ok, detail, level) => checks.push(level ? { id, ok, detail, level } : { id, ok, detail });
  const done = () => ({ ok: checks.every(c => c.ok), checks });

  // 1. The signature's form.
  const token = exportSignatureOf(signature);
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every(p => B64URL.test(p))) { push('export.format', false, `the ${EXPORT_SIGNATURE_HEADER} value is not a compact JWS (three base64url parts)`); return done(); }
  let header; let claims;
  try { header = json(parts[0]); claims = json(parts[1]); } catch { push('export.format', false, 'the signature\'s header or claims are not JSON'); return done(); }
  if (header?.alg !== 'EdDSA' || header?.typ !== TYP || typeof header?.kid !== 'string') { push('export.format', false, `the signature's header must be { alg: "EdDSA", typ: "${TYP}", kid }`); return done(); }
  if (claims?.v !== 1 || typeof claims?.ws !== 'string' || !HEX64.test(String(claims?.body)) || !Number.isInteger(claims?.iat) || !wellFormedV2(claims)) {
    push('export.format', false, 'the claims must be { v: 1, ws, body: sha256 hex, iat: seconds, kind, head ({ seq, hash } or null), entries ({ count, first, last }), filters (scalars) }');
    return done();
  }
  const when = new Date(claims.iat * 1000).toISOString();
  push('export.format', true, `a JSON evidence pack signature for workspace ${claims.ws}, made ${when}`);

  // 2. The body is the one signed, byte for byte.
  const bytes = bytesOf(body);
  const got = sha256Hex(bytes);
  push('export.body', got === claims.body, got === claims.body
    ? `the body is the one signed (sha256 ${got.slice(0, 12)}…, ${bytes.length} bytes)`
    : `the body is not the one signed: its sha256 is ${got.slice(0, 12)}…, the signature committed ${claims.body.slice(0, 12)}… — changed, re-indented or re-encoded after it was answered (keep the body exactly as received)`);

  // 3. Signed by a key the reader pinned, which may sign at that instant (keys.mjs, keyTrustAt).
  const published = `the keys Azoth publishes for this workspace (/api/proof/keys/${claims.ws})`;
  if (!keys) { push('export.signature', false, `no keys given: the pack ships none, so its signature is checked only against keys you pin — give ${published} with --keys`); return done(); }
  const key = (Array.isArray(keys?.keys) ? keys.keys : []).find(k => k?.kid === header.kid);
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string') {
    push('export.signature', false, `no Ed25519 key ${header.kid} among the keys given (${published})`);
    return done();
  }
  // The kid is the key's RFC 7638 thumbprint: a key cannot be swapped under the same id.
  const thumbprint = base64url(digest('sha256', utf8(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: key.x }))));
  if (thumbprint !== header.kid) { push('export.signature', false, `key ${header.kid} does not hash to its id`); return done(); }
  let valid = false;
  try { valid = verifyEd25519(key.x, utf8(`${parts[0]}.${parts[1]}`), fromBase64(parts[2])); } catch { valid = false; }
  if (!valid) { push('export.signature', false, 'the signature does not verify (claims altered, or another key)'); return done(); }
  const trust = keyTrustAt(key, claims.iat);
  if (!trust.ok) { push('export.signature', false, `key ${header.kid.slice(0, 12)}… is refused: ${trust.detail}`); return done(); }
  push('export.signature', true, `signed by the workspace's key ${header.kid.slice(0, 12)}… on ${when}, among the keys given`);
  if (trust.warn) push('export.signature.key', true, `key ${header.kid.slice(0, 12)}…: ${trust.warn}`, 'warn');

  // 4. Whose: the pack's workspace, the keys', the reader's.
  let pack = null;
  try { pack = JSON.parse(fromUtf8(bytes)); } catch { pack = null; }
  if (!pack || typeof pack !== 'object' || Array.isArray(pack)) { push('export.pack', false, 'the body is not a JSON evidence pack'); return done(); }
  // The workspace the keys name (a JWKS's `workspaceId`) and the one the reader names (--workspace), each held.
  const pins = [];
  if (typeof keys?.workspaceId === 'string') pins.push([keys.workspaceId, w => `the keys given are workspace ${w}’s`]);
  if (typeof workspace === 'string' && workspace) pins.push([workspace, w => `the workspace you named is ${w}`]);
  const off = pins.find(([w]) => w !== claims.ws);
  if (pack.workspaceId !== claims.ws) push('export.workspace', false, `signed for workspace ${claims.ws}, but the pack is ${typeof pack.workspaceId === 'string' ? `workspace ${pack.workspaceId}’s` : 'no workspace’s'}`);
  else if (off) push('export.workspace', false, `signed for workspace ${claims.ws}, but ${off[1](off[0])}`);
  else if (pins.length) push('export.workspace', true, `workspace ${claims.ws}: the pack's, the signature's and the keys'`);
  else push('export.workspace', true, `workspace ${claims.ws}: the pack's and the signature's — the keys given do not say whose they are; give --workspace with the workspace you fetched them for`, 'warn');

  // 5. What the signature commits: the kind, the chain's head, the entries listed — and the filters.
  const coverage = verifyCoverage(claims, pack, { id: 'export.coverage', file: 'the pack', whole: 'the pack' });
  const filters = signedFilters(pack.filters);
  if (coverage[0]?.ok && !sameFilters(filters, claims.filters)) push('export.coverage', false, 'the pack\'s filters are not the ones its signature committed');
  else checks.push(...coverage);

  // 6. The pack itself, as a dossier's evidence.json of an audit export (Checks 3, 15, 11, 13, 16).
  if (kindOf(pack) === 'audit') {
    checks.push(chainCheck(pack));
    checks.push(...verifyRetention(pack));
    checks.push(...verifyJurisdiction(pack.entries, {}));
    checks.push(...verifyPricing(pack.entries, {}));
    checks.push(...verifySealedFields(pack));
  }
  return done();
}
