// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The chain's primitives (SPEC.md, Checks 1–3): the hash, the canonical form of a sealed core,
 * an entry's hash, the manifest's root hash, a run of linked entries. Shared by every check —
 * the dossier, decision, incident, compliance and platform packs, and receipts.
 */
import { digest } from './crypto.mjs';
import { bytesOf, hex } from './bytes.mjs';

/** sha256 hex of a string (UTF-8) or of bytes. */
export function sha256Hex(data) {
  return hex(digest('sha256', bytesOf(data)));
}

/**
 * Recursively sort object keys ascending, preserve array order, drop keys whose
 * value is `undefined`. Mirrors the journal's `sortKeys`. (In JSON, undefined
 * only appears via absent keys, so this is mostly key-ordering — but we honour
 * the exact spec so the canonical string is identical.)
 */
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      const v = value[k];
      if (v !== undefined) out[k] = sortKeys(v);
    }
    return out;
  }
  return value;
}

/** core_canonical = JSON.stringify(sortKeys(core)). */
export function canonicalCore(core) {
  return JSON.stringify(sortKeys(core));
}

/** entry_hash = sha256(prev_hash || core_canonical) — plain concatenation, hex. */
export function computeEntryHash(prevHash, coreCanonical) {
  return sha256Hex(prevHash + coreCanonical);
}

/** root_hash = sha256( sorted(file sha256 hex).join('') ). */
export function computeRootHash(files) {
  return sha256Hex(files.map(f => f.sha256).sort().join(''));
}

export const bySeq = (a, b) => a.seq - b.seq;

/**
 * Verify consecutive links: each entryHash recomputes from (prevHash, canonical),
 * each prevHash is the previous entryHash, seqs follow each other. The first
 * link starts the segment: at seq 1 its prevHash must be "" (genesis); later,
 * it is where the segment attaches to the earlier chain.
 */
export function verifyLinks(links) {
  let prev = '';
  for (let i = 0; i < links.length; i++) {
    const l = links[i];
    if (computeEntryHash(l.prevHash, l.canonical) !== l.entryHash) {
      return { ok: false, brokenAt: l.seq, reason: 'entry_hash mismatch (row altered)', verified: i };
    }
    if (i === 0) {
      if (l.seq === 1 && l.prevHash !== '') return { ok: false, brokenAt: l.seq, reason: 'the genesis entry must have an empty prev_hash', verified: i };
    } else if (l.seq !== links[i - 1].seq + 1) {
      return { ok: false, brokenAt: l.seq, reason: `seq gap after ${links[i - 1].seq} (entries missing from the segment)`, verified: i };
    } else if (l.prevHash !== prev) {
      return { ok: false, brokenAt: l.seq, reason: 'prev_hash break (row inserted/removed/reordered)', verified: i };
    }
    prev = l.entryHash;
  }
  return {
    ok: true, brokenAt: null, reason: null, verified: links.length,
    first: links[0]?.seq ?? null, last: links[links.length - 1]?.seq ?? null, startPrevHash: links[0]?.prevHash ?? null,
  };
}

