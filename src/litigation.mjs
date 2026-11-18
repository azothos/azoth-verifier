// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 12, a litigation dossier (`evidence.json` kind "litigation", SPEC.md): beyond the chain
 * checks a decision dossier gets (verify.mjs verifyDecisionPack), the hold's designation —
 * `hold.entriesHash` is the sha256 of `hold.seqs` (ascending, comma-joined), every designated
 * decision is listed, and the `legal_hold_placed` entry sealed that same hash when the hold was
 * placed: the hold designated exactly these decisions then.
 *
 * Zero dependencies, no Azoth code: the rules are SPEC.md's, reimplemented here.
 */
import { sha256Hex } from './chain.mjs';

/** @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>} */
export function verifyHoldDesignation(pack) {
  const hold = pack?.hold ?? {};
  const seqs = Array.isArray(hold.seqs) ? hold.seqs.map(Number) : [];
  const out = [];
  const hash = sha256Hex([...seqs].sort((a, b) => a - b).join(','));
  if (hash !== hold.entriesHash) out.push({ id: 'litigation.designation', ok: false, detail: 'hold.entriesHash is not the sha256 of hold.seqs' });
  const listed = new Set((Array.isArray(pack?.entries) ? pack.entries : []).map(e => Number(e.seq)));
  const missing = seqs.filter(s => !listed.has(s));
  if (missing.length) out.push({ id: 'litigation.complete', ok: false, detail: `designated decisions not in the dossier: ${missing.slice(0, 10).join(', ')}${missing.length > 10 ? '…' : ''}` });
  else out.push({ id: 'litigation.complete', ok: true, detail: `the ${seqs.length} designated decisions are all in the dossier` });
  if (hash !== hold.entriesHash) return out;
  const placed = (Array.isArray(pack?.entries) ? pack.entries : []).find(e => e?.core?.decision === 'legal_hold_placed' && e?.core?.policy?.holdId === hold.id);
  if (!placed) out.push({ id: 'litigation.designation', ok: true, level: 'warn', detail: 'the act that placed the hold is not in the dossier: the designation is not tied to a sealed entry' });
  else if (placed.core.policy.entriesHash !== hold.entriesHash) out.push({ id: 'litigation.designation', ok: false, detail: `the hold sealed at seq ${placed.seq} designated other decisions` });
  else out.push({ id: 'litigation.designation', ok: true, detail: `the hold sealed at seq ${placed.seq} designated exactly these ${seqs.length} decisions` });
  return out;
}
