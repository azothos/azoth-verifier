// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 12 — the dossier's signature (SPEC.md): `signature.jws`, a compact JWS (EdDSA) by the
 * workspace's Ed25519 key (Azoth's platform key, for a platform package) over the manifest's
 * root_hash, outside the manifest. It is REQUIRED: without it nothing binds the content to a key,
 * and whoever handed the dossier over could have removed entries and recomputed the manifest.
 *
 * The key must be one the reader pinned (`--keys`, the keys the producer publishes): a key the
 * dossier ships vouches only for itself, so a signature under it alone fails. From format 2 the
 * signed claims also commit what the dossier covers — its kind, the chain's head at export, the
 * count and range of the entries it lists, the filters of the export — and evidence.json must
 * match them.
 *
 * Zero dependencies, zero network, no Azoth code: the rules are SPEC.md's, reimplemented here;
 * the cryptography is crypto.mjs's (node:crypto, or the web verifier's).
 */
import { base64url, fromBase64, fromUtf8, utf8 } from './bytes.mjs';
import { digest, verifyEd25519 } from './crypto.mjs';
import { keyTrustAt } from './keys.mjs';

export const SIGNATURE_FILE = 'signature.jws';
const TYP = 'azoth-dossier+jws';
const B64URL = /^[A-Za-z0-9_-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;
export const DOSSIER_KINDS = ['audit', 'decision', 'incident', 'compliance', 'litigation', 'regulator', 'risk_profile', 'exhaustion', 'ai_footprint', 'platform'];
const json = part => JSON.parse(fromUtf8(fromBase64(part)));
const isSeq = v => Number.isInteger(v) && v >= 1;
const isScalar = v => v === null || ['string', 'number', 'boolean'].includes(typeof v);

/** The kind of a pack: its `kind`, or `audit` for a journal export (it has none). */
export const kindOf = pack => (typeof pack?.kind === 'string' ? pack.kind : 'audit');

/** What a pack lists: its entries — a platform package's chain links. Count, first and last seq. */
export function coverageOf(pack) {
  const listed = kindOf(pack) === 'platform' ? pack?.chain : pack?.entries;
  const seqs = (Array.isArray(listed) ? listed : []).map(e => Number(e?.seq)).filter(Number.isFinite);
  return { count: seqs.length, first: seqs.length ? Math.min(...seqs) : null, last: seqs.length ? Math.max(...seqs) : null };
}

/** The time a link's core seals (`occurredAt`, its `core` — else its `coreCanonical` — read), or null. */
function sealedAt(link) {
  let core = link?.core && typeof link.core === 'object' ? link.core : null;
  if (!core && typeof link?.coreCanonical === 'string') {
    try { core = JSON.parse(link.coreCanonical); } catch { core = null; }
  }
  return typeof core?.occurredAt === 'string' ? core.occurredAt : null;
}

/**
 * Every sealed link a pack carries, wherever it sits: [{ seq, entryHash, sealedAt }] (also Check 18's) — `sealedAt`
 * the time its core seals, null when it seals none.
 */
export function carried(pack) {
  const out = [];
  const add = list => { for (const l of Array.isArray(list) ? list : []) out.push({ seq: Number(l?.seq), entryHash: l?.entryHash, sealedAt: sealedAt(l) }); };
  add(pack?.entries); add(pack?.chain);
  for (const s of Array.isArray(pack?.segments) ? pack.segments : []) add(s?.links);
  add(pack?.impact?.entries); add(pack?.impact?.completeness?.links);
  return out;
}

const range = c => (c.count ? (c.first === c.last ? `seq ${c.first}` : `seq ${c.first}–${c.last}`) : 'nothing');
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/** Format 2 claims' coverage is well formed — a dossier's signature, and a JSON pack's (Check 17). */
export function wellFormedV2(c) {
  const e = c?.entries;
  const head = c?.head;
  return DOSSIER_KINDS.includes(c?.kind)
    && (head === null || (head && isSeq(head.seq) && HEX64.test(String(head.hash))))
    && e && Number.isInteger(e.count) && e.count >= 0
    && (e.count === 0 ? e.first === null && e.last === null : isSeq(e.first) && isSeq(e.last) && e.first <= e.last)
    && c.filters && typeof c.filters === 'object' && !Array.isArray(c.filters) && Object.values(c.filters).every(isScalar);
}

/**
 * Format 2: what the signature committed, against evidence.json. FAILs when the pack does not hold
 * what was signed; else one PASS line saying plainly what the dossier covers. A JSON evidence pack's
 * signature (Check 17) commits the same coverage: `file` and `whole` name it there, `id` its check.
 */
export function verifyCoverage(claims, pack, { id = 'coverage', file = 'evidence.json', whole = 'the dossier' } = {}) {
  const push = (ok, detail) => [{ id, ok, detail }];
  const kind = kindOf(pack);
  if (claims.kind !== kind) return push(false, `the signature is for a ${claims.kind} dossier; ${file} is a ${kind} dossier`);
  const got = coverageOf(pack);
  const want = claims.entries;
  if (got.count !== want.count || got.first !== want.first || got.last !== want.last) {
    return push(false, `${file} lists ${plural(got.count, 'entry', 'entries')} (${range(got)}); the signature committed ${plural(want.count, 'entry', 'entries')} (${range(want)}) — entries were removed, added or renumbered after signing`);
  }
  const links = carried(pack).filter(l => Number.isFinite(l.seq));
  const head = claims.head;
  if (!head) {
    if (links.length) return push(false, `the signature says the journal was empty at export, but ${whole} carries seq ${links[0].seq}`);
  } else {
    const after = links.find(l => l.seq > head.seq);
    if (after) return push(false, `${whole} carries seq ${after.seq}, after the chain's head the signature committed (seq ${head.seq})`);
    const atHead = links.find(l => l.seq === head.seq && l.entryHash !== head.hash);
    if (atHead) return push(false, `the entry at seq ${head.seq} is not the chain's head the signature committed (${head.hash.slice(0, 12)}…)`);
  }
  const journal = kind === 'platform' ? 'Azoth’s platform journal' : 'the workspace’s journal';
  const what = got.count ? `lists ${plural(got.count, 'sealed entry', 'sealed entries')}, ${range(got)}` : 'lists no sealed entry';
  const later = head && got.count && head.seq > got.last ? ` — nothing sealed after seq ${got.last} is in it (${plural(head.seq - got.last, 'later entry', 'later entries')})` : '';
  const at = head ? `the head of ${journal} was seq ${head.seq} (${head.hash.slice(0, 12)}…) when it was exported${later}` : `${journal} was empty when it was exported`;
  // Keys in code-point order: the same line whatever order the producer wrote them in.
  const f = Object.entries(claims.filters).filter(([, v]) => v !== null && v !== '').sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return push(true, `${what}; ${at}; filters: ${f.length ? f.map(([k, v]) => `${k}=${v}`).join(', ') : 'none'}`);
}

/**
 * @param {Record<string, Uint8Array>} files the dossier's files
 * @param {string} rootHash the manifest's root_hash
 * @param {{ keys?: { keys?: unknown[] } | null, pack?: unknown }} [opts] `keys`: the keys the reader pinned;
 *   `pack`: the parsed evidence.json, for the coverage the signature commits
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyDossierSignature(files, rootHash, { keys = null, pack = null } = {}) {
  const fail = detail => [{ id: 'signature', ok: false, detail }];
  const platform = kindOf(pack) === 'platform';
  const raw = files[SIGNATURE_FILE];
  if (!raw) {
    return fail(`the dossier is unsigned (no ${SIGNATURE_FILE}): nothing binds its content to ${platform ? 'Azoth’s platform key' : 'the workspace’s key'}, so it cannot be trusted — entries removed and the manifest recomputed would go unnoticed`);
  }
  const parts = fromUtf8(raw).trim().split('.');
  if (parts.length !== 3 || !parts.every(p => B64URL.test(p))) return fail(`${SIGNATURE_FILE} is not a compact JWS`);
  let header; let claims;
  try { header = json(parts[0]); claims = json(parts[1]); } catch { return fail(`${SIGNATURE_FILE}: header or claims are not JSON`); }
  if (header?.alg !== 'EdDSA' || header?.typ !== TYP || typeof header?.kid !== 'string') return fail(`${SIGNATURE_FILE}: header must be { alg: "EdDSA", typ: "${TYP}", kid }`);
  if (![1, 2].includes(claims?.v) || typeof claims?.ws !== 'string' || !HEX64.test(String(claims?.root)) || !Number.isInteger(claims?.iat)) {
    return fail(`${SIGNATURE_FILE}: claims must be { v: 1 | 2, ws, root: sha256 hex, iat: seconds, … }`);
  }
  if (claims.v === 2 && !wellFormedV2(claims)) return fail(`${SIGNATURE_FILE}: format 2 claims must carry kind, head ({ seq, hash } or null), entries ({ count, first, last }) and filters (scalars)`);
  if (claims.root !== rootHash) return fail('the signature bears on another root_hash than this manifest’s');
  if (typeof pack?.workspaceId === 'string' && pack.workspaceId !== claims.ws) return fail(`signed for workspace ${claims.ws}, but evidence.json is workspace ${pack.workspaceId}’s`);
  if (platform && claims.ws !== 'platform') return fail('a platform package is signed by Azoth’s platform key (claims ws "platform")');

  const published = platform ? 'the platform keys Azoth publishes (/api/proof/platform-keys)' : `the keys Azoth publishes for this workspace (/api/proof/keys/${claims.ws})`;
  let jwks = keys;
  const shipped = !jwks;
  if (shipped) {
    try { jwks = files['keys.jwks.json'] ? JSON.parse(fromUtf8(files['keys.jwks.json'])) : null; } catch { jwks = null; }
  }
  const key = (Array.isArray(jwks?.keys) ? jwks.keys : []).find(k => k?.kid === header.kid);
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string') {
    return fail(`no Ed25519 key ${header.kid} among ${shipped ? `the dossier’s keys.jwks.json — and none was pinned: give ${published} with --keys` : 'the keys given'}`);
  }
  // The kid is the key's RFC 7638 thumbprint: a key cannot be swapped under the same id.
  const thumbprint = base64url(digest('sha256', utf8(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: key.x }))));
  if (thumbprint !== header.kid) return fail(`key ${header.kid} does not hash to its id`);
  let valid = false;
  try { valid = verifyEd25519(key.x, utf8(`${parts[0]}.${parts[1]}`), fromBase64(parts[2])); } catch { valid = false; }
  if (!valid) return fail('the signature does not verify (dossier altered, or another key)');
  const when = new Date(claims.iat * 1000).toISOString();
  if (shipped) {
    // A key the dossier ships vouches only for itself: anyone can rebuild a dossier and sign it with a key of their own.
    return fail(`signed on ${when} by key ${header.kid.slice(0, 12)}…, which only the dossier itself vouches for — whoever handed it over could have rebuilt and re-signed it. Give ${published} with --keys`);
  }
  // A key its producer declared compromised signs nothing trusted from that instant on (keys.mjs, keyTrustAt).
  const trust = keyTrustAt(key, claims.iat);
  if (!trust.ok) return fail(`key ${header.kid.slice(0, 12)}… is refused: ${trust.detail}`);
  const out = [{ id: 'signature', ok: true, detail: `signed by ${platform ? 'Azoth’s platform key' : 'the workspace’s key'} ${header.kid.slice(0, 12)}… on ${when}, among the keys given` }];
  if (trust.warn) out.push({ id: 'signature.key', ok: true, level: 'warn', detail: `key ${header.kid.slice(0, 12)}…: ${trust.warn}` });
  if (claims.v === 1) {
    out.push({ id: 'coverage', ok: true, level: 'warn', detail: 'signed in format 1: the signature binds every file, but does not state the chain’s head at export nor the export’s filters' });
  } else {
    out.push(...verifyCoverage(claims, pack));
  }
  return out;
}
