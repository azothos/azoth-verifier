// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 13 — each decision's cost, recomputed from its sealed price (SPEC.md).
 * An inference decision that carries tokens seals `core.pricing`: where its price came from (`src`),
 * the unit prices in USD per 1M tokens (`in`, `out`), the prompt-cache multipliers when the call
 * used the cache, and the EUR→USD rate (`eurUsd`). From the seal alone, this module recomputes the
 * cost and holds it equal to the sealed `costEur`; a model without a price is sealed at 0, never a
 * guess. When the dossier ships the catalog versions (`model-catalog.json`), each document must hash
 * to its sha256, and a price sealed from a catalog version must be that version's price — its cache
 * read multiple too, when the version gives a cached-input price (or 0.1, the multiple sealed before
 * one was read).
 *
 * Its own copy of the producer's formulas (`costEurOf`, `cacheReadMultiple`): it imports nothing
 * from Azoth. A parity test in the producer's repository keeps them identical — change both or
 * neither.
 */
import { sha256Hex } from './chain.mjs';
import { base64url, fromBase64, fromUtf8, utf8 } from './bytes.mjs';
import { digest, verifyEd25519 } from './crypto.mjs';

export const CATALOG_FILE = 'model-catalog.json';
/**
 * The public halves of the keys that sign Azoth's model catalog — the same as the producer pins,
 * copied (the verifier imports nothing from Azoth). Empty until the key is made: a version is then
 * shown as carrying no signature this verifier can check.
 */
export const CATALOG_SIGNING_KEYS = [];
const PRICED = ['catalog', 'matrix', 'declared'];
const SOURCES = [...PRICED, 'none', 'cache', 'provider', 'reported'];

const round8 = x => Math.round(x * 1e8) / 1e8;
const close = (a, b) => Math.abs(a - b) <= 1e-12 + 1e-9 * Math.max(Math.abs(a), Math.abs(b));
const n = v => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const finite = v => typeof v === 'number' && Number.isFinite(v) && v >= 0;

/** The EUR cost a sealed price makes of the sealed tokens. */
export function costEurOf(p, t) {
  let usd = round8((t.tokensIn / 1_000_000) * p.in + (t.tokensOut / 1_000_000) * p.out);
  if (t.cacheReadTokens || t.cacheWriteTokens) usd = round8(usd + (t.cacheReadTokens * (p.cacheRead ?? 0) + t.cacheWriteTokens * (p.cacheWrite ?? 0)) / 1_000_000 * p.in);
  return usd / p.eurUsd;
}

/** The cache read multiple every seal carried before the catalog's cached-input price was read. */
export const LEGACY_CACHE_READ = 0.1;

/** A catalog entry's prompt-cache read as a multiple of its input price: cached ÷ in, to 1e-12; 0.1 without a cached price. */
export function cacheReadOf(at) {
  if (typeof at.cached !== 'number' || !(at.in > 0)) return LEGACY_CACHE_READ;
  return Math.round((at.cached / at.in) * 1e12) / 1e12;
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const kidOf = x => base64url(digest('sha256', utf8(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x }))));

/** A version's signature by Azoth's catalog key: 'verified', 'unsigned', 'unpinned' (no key to check with) or 'invalid'. */
export function catalogSignatureStatus(jws, version, sha256, keys = CATALOG_SIGNING_KEYS) {
  if (typeof jws !== 'string' || !jws) return 'unsigned';
  const parts = jws.split('.');
  if (parts.length !== 3 || !parts.every(p => B64URL.test(p))) return 'invalid';
  let header; let claims;
  try { header = JSON.parse(fromUtf8(fromBase64(parts[0]))); claims = JSON.parse(fromUtf8(fromBase64(parts[1]))); } catch { return 'invalid'; }
  if (header?.alg !== 'EdDSA' || header?.typ !== 'azoth-catalog+jws' || claims?.v !== 1 || claims?.catalog !== version || claims?.sha256 !== sha256) return 'invalid';
  if (!keys.length) return 'unpinned';
  const key = keys.find(k => kidOf(k.x) === header.kid);
  if (!key) return 'invalid';
  try { return verifyEd25519(key.x, utf8(`${parts[0]}.${parts[1]}`), fromBase64(parts[2])) ? 'verified' : 'invalid'; } catch { return 'invalid'; }
}

/** The shipped catalog versions: version → (provider\0model → { in, out, cached }); or an error detail. */
function readCatalog(raw, keys) {
  let doc;
  try { doc = JSON.parse(new TextDecoder().decode(raw)); } catch { doc = null; }
  if (!doc || doc.format !== 'azoth.model.catalog.versions/1' || !Array.isArray(doc.versions)) return { error: `${CATALOG_FILE} is not a list of catalog versions` };
  const versions = new Map();
  const signatures = new Map();
  for (const v of doc.versions) {
    let parsed = null;
    try { parsed = JSON.parse(v.document); } catch { parsed = null; }
    if (!parsed || parsed.format !== 'azoth.model.catalog/1' || parsed.version !== v.version || sha256Hex(v.document) !== v.sha256) {
      return { error: `the catalog version ${v.version} does not match its sha256 or its number` };
    }
    const signature = catalogSignatureStatus(v.signature, v.version, v.sha256, keys);
    if (signature === 'invalid') return { error: `the catalog version ${v.version} carries a signature that does not verify` };
    const prices = new Map();
    for (const e of parsed.entries ?? []) prices.set(`${e.provider}\u0000${e.model}`, { in: e.inputPer1M, out: e.outputPer1M, cached: e.cachedInputPer1M ?? null });
    versions.set(v.version, prices);
    signatures.set(v.version, signature);
  }
  return { versions, signatures };
}

export function verifyPricing(entries, files, { keys = CATALOG_SIGNING_KEYS } = {}) {
  const sealed = (entries ?? []).filter(e => e?.core?.pricing);
  if (!sealed.length) return [];
  const raw = files?.[CATALOG_FILE];
  const catalog = raw ? readCatalog(raw, keys) : null;
  if (catalog?.error) return [{ id: 'pricing', ok: false, detail: catalog.error }];

  const count = Object.fromEntries(SOURCES.map(s => [s, 0]));
  let unshipped = 0;
  for (const e of sealed) {
    const p = e.core.pricing;
    const { src } = p;   // destructured: the web page's no-network test flags a property `src` followed by `=`
    const cost = n(e.core.costEur);
    if (p.v !== 1 || !SOURCES.includes(src)) return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: an unknown pricing seal (v ${p.v}, src ${src})` }];
    if ((src === 'none' || src === 'cache') && cost !== 0) {
      return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: ${src === 'none' ? 'no price' : 'a cached answer'}, yet a cost of ${cost} EUR was sealed` }];
    }
    if (PRICED.includes(src)) {
      if (![p.in, p.out, p.eurUsd].every(finite) || !(p.eurUsd > 0)) return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: a ${src} price without its unit prices or rate` }];
      const tokens = {
        tokensIn: n(e.core.tokensIn), tokensOut: n(e.core.tokensOut),
        cacheReadTokens: n(e.core.policy?.cacheReadTokens), cacheWriteTokens: n(e.core.policy?.cacheWriteTokens),
      };
      const again = costEurOf(p, tokens);
      if (!close(again, cost)) return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: its tokens at its sealed price cost ${again} EUR, not the sealed ${cost}` }];
      if (src === 'catalog') {
        const prices = catalog?.versions.get(p.catalog);
        const at = prices?.get(`${e.core.provider ?? ''}\u0000${p.key}`) ?? [...(prices?.entries() ?? [])].find(([k]) => k.endsWith(`\u0000${p.key}`))?.[1];
        if (!prices) unshipped++;
        else if (!at || at.in !== p.in || at.out !== p.out) return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: the price sealed for ${p.key} is not catalog version ${p.catalog}'s` }];
        else if (p.cacheRead !== undefined && p.cacheRead !== cacheReadOf(at) && p.cacheRead !== LEGACY_CACHE_READ) {
          return [{ id: 'pricing', ok: false, detail: `seq ${e.seq}: the cache read price sealed for ${p.key} is not catalog version ${p.catalog}'s` }];
        }
      }
    }
    count[src]++;
  }
  const said = SOURCES.filter(s => count[s]).map(s => `${count[s]} ${s}`).join(', ');
  const out = [{ id: 'pricing', ok: true, detail: `${sealed.length} sealed costs recomputed from their sealed price (${said})` }];
  if (unshipped) out.push({ id: 'pricing.catalog', ok: true, level: 'warn', detail: `${unshipped} prices name a catalog version the dossier does not ship (${CATALOG_FILE}): their arithmetic holds, the version itself is not shown` });
  if (catalog) {
    const by = s => [...catalog.signatures].filter(([, st]) => st === s).map(([v]) => v);
    const verified = by('verified'), unchecked = [...by('unsigned'), ...by('unpinned')];
    if (verified.length) out.push({ id: 'pricing.signature', ok: true, detail: `catalog versions ${verified.join(', ')} signed by Azoth's catalog key` });
    if (unchecked.length) out.push({ id: 'pricing.signature', ok: true, level: 'warn', detail: `catalog versions ${unchecked.join(', ')} carry no signature this verifier can check: their prices are Azoth's word` });
  }
  return out;
}
