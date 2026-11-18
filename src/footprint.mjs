// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 14 — an AI footprint statement (SPEC.md): a repository's findings as
 * they were attested, frozen in the dossier. From them alone, this module recomputes their sha256 —
 * the `sha:ruleId` lines sorted (ASCII) and joined with a newline — and the counts (findings, distinct
 * commits declared, distinct commits with a marker, files), and holds both to `attestation` and to the
 * sealed act `ai_footprint_attested` (its `core.policy`). A finding names a commit and a rule, never an
 * author; a marker is never a proof.
 *
 * Its own copy of the producer's rule (`findingsHash`, `totalsOf`): it imports nothing from Azoth.
 * A parity test in the producer's repository keeps the two identical — change both or neither.
 */
import { sha256Hex } from './chain.mjs';

const STRENGTHS = ['declared', 'marker', 'config'];

export const footprintHash = findings => sha256Hex(findings.map(f => `${f.sha}:${f.ruleId}`).sort().join('\n'));

export function footprintCounts(findings) {
  const distinct = s => new Set(findings.filter(f => f.strength === s).map(f => f.sha)).size;
  return { findings: findings.length, declared: distinct('declared'), markers: distinct('marker') };
}

export function verifyFootprintPack(pack) {
  const a = pack?.attestation;
  if (!a || !Array.isArray(a.findings)) return [{ id: 'ai_footprint', ok: false, detail: 'evidence.json carries no attestation and its findings' }];
  const bad = a.findings.find(f => !/^[0-9a-f]{40}$/.test(String(f?.sha)) || typeof f?.ruleId !== 'string' || !STRENGTHS.includes(f?.strength) || 'author' in f || 'authorHmac' in f);
  if (bad) return [{ id: 'ai_footprint', ok: false, detail: `a finding is not a commit and a rule (${String(bad?.sha).slice(0, 12)}…), or names an author` }];
  const hash = footprintHash(a.findings);
  if (hash !== a.findingsHash) return [{ id: 'ai_footprint', ok: false, detail: 'the findings do not hash to the attestation’s findingsHash' }];
  const counts = footprintCounts(a.findings);
  const t = a.totals ?? {};
  for (const k of ['findings', 'declared', 'markers']) {
    if (t[k] !== counts[k]) return [{ id: 'ai_footprint', ok: false, detail: `the attestation counts ${t[k]} ${k}, its findings ${counts[k]}` }];
  }
  if (t.config !== (a.config ?? []).length) return [{ id: 'ai_footprint', ok: false, detail: 'the attestation’s file count is not its files' }];
  const act = (pack.entries ?? []).find(e => e?.core?.decision === 'ai_footprint_attested' && e.core?.policy?.attestationId === a.id);
  if (!act) return [{ id: 'ai_footprint', ok: false, detail: 'the dossier carries no sealed ai_footprint_attested act for this statement' }];
  const p = act.core.policy;
  if (p.findingsHash !== hash || p.findings !== counts.findings || p.declared !== counts.declared || p.markers !== counts.markers || p.config !== t.config) {
    return [{ id: 'ai_footprint', ok: false, detail: `the sealed act (seq ${act.seq}) does not seal these findings and counts` }];
  }
  return [{ id: 'ai_footprint', ok: true, detail: `${counts.findings} findings over ${t.commitsScanned ?? '?'} commits read: ${counts.declared} commits declared, ${counts.markers} with a marker (never a proof), ${t.config} files — their fingerprint is the one sealed at seq ${act.seq}; no author named` }];
}
