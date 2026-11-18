// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 15 — the journal retention checkpoint (SPEC.md).
 *
 * A workspace's plan keeps its sealed journal for a limited time: the producer removes only the
 * OLDEST contiguous prefix of the chain, and records where the kept chain starts — the last removed
 * entry's seq and entry hash (a checkpoint), declared by a sealed act (`journal_retention_applied`)
 * appended before the removal. The first kept entry's prevHash is that hash: a chain that starts
 * there is the continuation of what was removed, not a cut.
 *
 * Reimplemented from SPEC.md; this module shares no code with the producer.
 */
import { bySeq } from './chain.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const ACT = 'journal_retention_applied';
const isSeq = v => Number.isInteger(v) && v >= 1;

function parse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

/** Every link the pack carries — listed entries (their `core`), the `chain` of a filtered pack, the segments' links. */
function linksOf(pack) {
  const at = new Map();
  const add = (seq, prevHash, entryHash, core) => { if (!at.has(seq)) at.set(seq, { seq, prevHash, entryHash, core }); };
  for (const e of Array.isArray(pack?.entries) ? pack.entries : []) add(Number(e.seq), e.prevHash, e.entryHash, e.core ?? null);
  for (const l of Array.isArray(pack?.chain) ? pack.chain : []) add(Number(l.seq), l.prevHash, l.entryHash, parse(l.coreCanonical));
  for (const s of Array.isArray(pack?.segments) ? pack.segments : []) {
    for (const l of Array.isArray(s?.links) ? s.links : []) add(Number(l.seq), l.prevHash, l.entryHash, parse(l.coreCanonical));
  }
  return [...at.values()].sort(bySeq);
}

const wellFormed = c => isSeq(c?.throughSeq) && HEX64.test(String(c?.throughHash ?? '')) && isSeq(c?.fromSeq) && c.fromSeq <= c.throughSeq
  && c.removed === c.throughSeq - c.fromSeq + 1 && isSeq(c?.actSeq) && c.actSeq > c.throughSeq && HEX64.test(String(c?.actHash ?? ''));

/**
 * The retention checkpoint of a pack (`retention.checkpoints`), against the links it ships. Nothing is
 * reported for a pack that ships no checkpoint and seals no retention act. Check 3 (or 5, 7, 8) has
 * already verified each link's hash and the linkage; this check says where the kept chain starts.
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyRetention(pack) {
  const out = [];
  const push = (id, ok, detail, level) => out.push(level ? { id, ok, detail, level } : { id, ok, detail });
  const links = linksOf(pack);
  const acts = links.filter(l => l.core?.decision === ACT);
  const shipped = pack?.retention?.checkpoints;

  if (!Array.isArray(shipped)) {
    if (acts.length) push('retention', true, `${acts.length} journal retention act(s) sealed in the chain; no checkpoint shipped with this dossier`, 'warn');
    return out;
  }
  if (!shipped.length || !shipped.every(wellFormed)) {
    push('retention.checkpoint', false, 'a journal retention checkpoint is malformed (seqs, hashes or count)');
    return out;
  }
  const latest = [...shipped].sort((a, b) => b.throughSeq - a.throughSeq)[0];
  const first = links[0];

  if (!first) {
    push('retention.checkpoint', true, `entries 1–${latest.throughSeq} were removed under the journal retention; this dossier lists no entry`);
  } else if (first.seq <= latest.throughSeq) {
    push('retention.checkpoint', false, `the dossier holds entry ${first.seq}, in the prefix the checkpoint says was removed (through ${latest.throughSeq})`);
  } else if (first.seq === latest.throughSeq + 1) {
    const ok = first.prevHash === latest.throughHash;
    push('retention.checkpoint', ok, ok
      ? `the kept chain starts at seq ${first.seq}: entries 1–${latest.throughSeq} were removed under the journal retention, and the first kept entry links to the last removed one (${latest.throughHash.slice(0, 12)}…)`
      : `entry ${first.seq} does not link to the retention checkpoint (prevHash ≠ the last removed entry's hash)`);
  } else {
    push('retention.checkpoint', true, `the segment starts at seq ${first.seq}, after the retention checkpoint (entries 1–${latest.throughSeq} removed): it attaches to the kept chain`);
  }

  // Each sealed act declares exactly the checkpoint shipped for it.
  const byAct = new Map(shipped.map(c => [c.actSeq, c]));
  for (const a of acts) {
    const c = byAct.get(a.seq);
    const p = a.core?.policy ?? {};
    if (!c) { push(`retention.act.${a.seq}`, true, `the journal retention act at seq ${a.seq}: its checkpoint is not shipped with this dossier`, 'warn'); continue; }
    const same = p.fromSeq === c.fromSeq && p.throughSeq === c.throughSeq && p.throughHash === c.throughHash && p.removed === c.removed && a.entryHash === c.actHash;
    push(`retention.act.${a.seq}`, same, same
      ? `the act at seq ${a.seq} sealed this removal before it took place (seqs ${c.fromSeq}–${c.throughSeq}, ${c.removed} entries)`
      : `the act at seq ${a.seq} does not declare the checkpoint shipped for it`);
  }
  if (!links.some(l => l.seq === latest.actSeq)) {
    push('retention.act', true, `the act that sealed the checkpoint (seq ${latest.actSeq}) is outside this dossier's entries: the checkpoint is shipped, its seal is not`, 'warn');
  }
  return out;
}
