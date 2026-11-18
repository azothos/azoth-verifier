// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 9 — an Azoth platform evidence package (`evidence.json` kind "platform",
 * SPEC.md): one month of Azoth's OWN journal — its deployments, restore drills,
 * staff access, break-glass, access reviews, platform admin grants — handed to
 * Azoth's auditor. The month's segment must be intact, attach where the package
 * says (the previous month's last link, or the genesis), hold no entry dated after
 * the month, and its counts per event type must recompute from it. Like the rest
 * of the verifier it shares nothing with Azoth's code.
 */
import { canonicalCore, verifyLinks } from './chain.mjs';

const bySeq = (a, b) => a.seq - b.seq;
const day = (s) => Date.parse(`${s}T00:00:00Z`);

export function verifyPlatformPack(pack) {
  const out = [];
  const push = (id, ok, detail, level) => out.push(level ? { id, ok, detail, level } : { id, ok, detail });

  const from = day(pack?.period?.from), to = day(pack?.period?.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    push('platform.period', false, 'the period is not a valid date range');
    return out;
  }
  if (!Array.isArray(pack.chain)) {
    push('platform.chain', false, 'evidence.json has no chain');
    return out;
  }
  const chain = [...pack.chain].sort(bySeq);

  // 1. Every link recomputes and follows the previous one.
  const v = verifyLinks(chain.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
  push('platform.chain', v.ok, v.ok
    ? (chain.length ? `chain intact (${chain.length} sealed entries, seq ${v.first}–${v.last})` : 'no entry sealed in the period')
    : `${v.reason} at seq ${v.brokenAt}`);
  if (!v.ok) return out;

  // 2. The seam: where this month's segment attaches.
  const prev = pack.previous ?? null;
  if (prev && (typeof prev.toSeq !== 'number' || typeof prev.entryHash !== 'string')) {
    push('platform.seam', false, '`previous` must name a seq and an entry hash');
  } else if (!chain.length) {
    push('platform.seam', true, prev ? `nothing sealed after seq ${prev.toSeq}` : 'empty, from the genesis');
  } else if (prev) {
    const ok = chain[0].seq === prev.toSeq + 1 && chain[0].prevHash === prev.entryHash;
    push('platform.seam', ok, ok
      ? `attaches to seq ${prev.toSeq} (${prev.entryHash.slice(0, 12)}…) — compare with the previous month's package`
      : 'the first entry does not follow the `previous` link the package names');
  } else {
    const ok = chain[0].seq === 1 && chain[0].prevHash === '';
    push('platform.seam', ok, ok ? 'starts at the genesis of the journal' : 'without `previous`, the segment must start at the genesis (seq 1)');
  }

  // 3. Canonical cores, none dated after the period.
  let canonBad = null, late = null;
  const counts = {};
  for (const l of chain) {
    let core;
    try { core = JSON.parse(l.coreCanonical); } catch { canonBad = l.seq; break; }
    if (canonicalCore(core) !== l.coreCanonical) { canonBad = l.seq; break; }
    const at = Date.parse(core.occurredAt);
    if (late === null && !(Number.isFinite(at) && at < to)) late = l.seq;
    counts[core.act] = (counts[core.act] ?? 0) + 1;
  }
  push('platform.canonical', canonBad === null, canonBad === null ? 'every core is in canonical form' : `the core at seq ${canonBad} is not in canonical form`);
  if (canonBad !== null) return out;
  push('platform.dates', late === null, late === null ? `no entry dated after ${pack.period.to}` : `the entry at seq ${late} is dated at or after the end of the period`);

  // 4. The counts the package states.
  const stated = pack.counts && typeof pack.counts === 'object' ? pack.counts : {};
  const keys = new Set([...Object.keys(counts), ...Object.keys(stated)]);
  const same = [...keys].every(k => counts[k] === stated[k]);
  push('platform.counts', same, same ? `the counts per event type recompute (${keys.size} types)` : 'the counts per event type do not recompute from the chain');

  // 5. What the verifier cannot check.
  if (pack.snapshot) push('platform.snapshot', true, 'the snapshot (platform admins, serving commit…) is stated by Azoth when it generated the package, not sealed — not verified', 'warn');
  return out;
}
