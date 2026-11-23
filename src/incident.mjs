// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 7 — an incident dossier (`evidence.json` kind "incident", SPEC.md).
 *
 * Like the rest of the verifier, this shares nothing with Azoth's code: the
 * scope predicate below is reimplemented from SPEC.md, not imported.
 */
import { sha256Hex, canonicalCore, entryCanonical, computeEntryHash, verifyLinks } from './chain.mjs';
import { checkTimestamp } from './timestamp.mjs';

const bySeq = (a, b) => a.seq - b.seq;
const policyOf = e => (e?.core?.policy && typeof e.core.policy === 'object' ? e.core.policy : {});

/**
 * Does a sealed entry fall in the scope? Over the sealed core only, plus the
 * capture time for a window (the `occurredAt` column, which the hash does not
 * cover). Every criterion present must hold.
 */
export function matchesScope(core, occurredAt, scope) {
  const c = core ?? {};
  if (c.surface === 'governance' && !(scope.refusalDecisions ?? []).includes(String(c.decision ?? ''))) return false;
  for (const k of ['model', 'modelVersion', 'policyVersion', 'agentId', 'mandateVersion', 'usecaseId']) {
    if (scope[k] !== undefined && c[k] !== scope[k]) return false;
  }
  if (scope.tool !== undefined && !(Array.isArray(c.tools) && c.tools.some(t => t?.name === scope.tool))) return false;
  if (scope.dataSource !== undefined) {
    const ds = scope.dataSource;
    if (!(Array.isArray(c.dataSources) && c.dataSources.some(d => d?.type === ds.type && (ds.id === undefined || d?.id === ds.id)))) return false;
  }
  const t = Date.parse(occurredAt);
  if (scope.from !== undefined && !(t >= Date.parse(scope.from))) return false;
  if (scope.to !== undefined && !(t < Date.parse(scope.to))) return false;
  return true;
}

/** @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>} */
export function verifyIncidentPack(pack, files, { shipped = [], pinned = null } = {}) {
  const out = [];
  const push = (id, ok, detail, level) => out.push(level ? { id, ok, detail, level } : { id, ok, detail });
  const segments = Array.isArray(pack.segments) ? pack.segments : [];
  const entries = Array.isArray(pack.entries) ? [...pack.entries].sort(bySeq) : [];

  // 1. The incident's actions: recomputed, naming the incident, inside a verified segment.
  const at = new Map();
  let broken = null;
  for (const seg of segments) {
    const links = [...(seg.links ?? [])].sort(bySeq);
    const v = verifyLinks(links.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
    if (!v.ok) { broken ??= `${v.reason} at seq ${v.brokenAt}`; continue; }
    if (links[0]?.seq !== seg.fromSeq || links[links.length - 1]?.seq !== seg.toSeq) broken ??= `segment ${seg.fromSeq}–${seg.toSeq} does not hold its declared range`;
    for (const l of links) at.set(l.seq, l);
  }
  for (const e of entries) {
    if (broken) break;
    const p = policyOf(e);
    if (entryCanonical(e) === null) broken = `entry ${e.seq}: its core is not the one its coreCanonical seals`;
    else if (computeEntryHash(e.prevHash, canonicalCore(e.core)) !== e.entryHash) broken = `entry_hash mismatch (action altered) at seq ${e.seq}`;
    else if (e.core?.surface !== 'governance' || !String(e.core?.decision ?? '').startsWith('incident_')) broken = `entry ${e.seq} is not an incident action`;
    else if (p.incidentId !== pack.incidentId || p.scopeHash !== pack.scopeHash) broken = `entry ${e.seq} does not name this incident and its scope`;
    else {
      const l = at.get(e.seq);
      if (!l || l.entryHash !== e.entryHash || l.prevHash !== e.prevHash) broken = `entry ${e.seq} is not in a verified chain segment`;
    }
  }
  push('incident.actions', !broken && entries.length > 0, broken ?? (entries.length ? `${entries.length} sealed actions, in ${segments.length} verified chain segment(s)` : 'no sealed action'));

  for (const seg of segments) {
    if (!seg.anchor) continue;
    const last = at.get(seg.toSeq);
    const tsr = files[seg.anchor.file];
    if (!tsr || !last) { push(`incident.anchor.${seg.toSeq}`, false, `${seg.anchor.file} missing`); continue; }
    const t = checkTimestamp(tsr, last.entryHash, { shipped, pinned });
    if (!t.ok) push(`incident.anchor.${seg.toSeq}`, false, `journal head ${seg.toSeq}: ${t.detail}`);
    else if (pinned) push(`incident.anchor.${seg.toSeq}`, t.trusted, t.trusted ? `actions up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} (${t.tsa})` : 'the TSA chain does not end on the root given with --tsa-root');
    else push(`incident.anchor.${seg.toSeq}`, true, `actions up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} — pin the TSA's root with --tsa-root to trust it`, 'warn');
  }
  if (!segments.some(s => s.anchor)) push('incident.anchor', true, 'no segment ends on a timestamped journal head: the actions are linked, not dated by a third party', 'warn');

  // 2. Order: steps 1…n, once each, in the journal's order.
  const steps = entries.map(e => policyOf(e).incidentStep);
  const sorted = [...steps].sort((a, b) => a - b);
  const contiguous = sorted.every((s, i) => s === i + 1);
  push('incident.order', contiguous, contiguous ? `steps 1–${steps.length}, each once` : `steps are not 1…${steps.length} (${sorted.join(', ')}): an action is missing or duplicated`);
  if (contiguous && steps.some((s, i) => s !== i + 1)) push('incident.order.journal', true, 'some actions were sealed after later ones (through the outbox): their step says where they belong', 'warn');

  // 3. Scope: sealed by the declaration.
  const declaration = entries.find(e => policyOf(e).incidentStep === 1);
  const sealedScope = policyOf(declaration).scope;
  const scopeOk = declaration?.core?.decision === 'incident_declared' && typeof sealedScope === 'string'
    && sealedScope === canonicalCore(pack.scope) && sha256Hex(sealedScope) === pack.scopeHash;
  push('incident.scope', scopeOk, scopeOk ? `the scope is the one declared at step 1 (sha256 ${pack.scopeHash.slice(0, 12)}…)` : 'the scope does not match the one sealed by the declaration');

  // 4. Impact: the matched set hashes to the last sealed one.
  const impacts = entries.filter(e => e.core?.decision === 'incident_scoped').sort((a, b) => policyOf(a).incidentStep - policyOf(b).incidentStep);
  const sealed = policyOf(impacts[impacts.length - 1]);
  const impact = pack.impact ?? {};
  const listed = Array.isArray(impact.decisions) ? impact.decisions : null;
  let inList = null;
  if (!impacts.length) {
    push('incident.impact', true, 'the impact has not been sealed yet', 'warn');
  } else if (!listed) {
    push('incident.impact', true, `${sealed.matched} matched decisions sealed (hash ${String(sealed.setHash).slice(0, 12)}…); their list is not in this dossier`, 'warn');
  } else {
    const ordered = listed.every((d, i) => i === 0 || d.seq > listed[i - 1].seq) && listed.every(d => d.seq <= sealed.throughSeq);
    const ok = ordered && listed.length === sealed.matched && sha256Hex(listed.map(d => d.entryHash).join('\n')) === sealed.setHash;
    push('incident.impact', ok, ok ? `${listed.length} matched decisions up to seq ${sealed.throughSeq}: the set sealed at step ${sealed.incidentStep}` : 'the matched decisions do not hash to the sealed set');
    inList = new Map(listed.map(d => [d.seq, d.entryHash]));
  }

  // 5. The matched entries shipped in full: recomputed, in the set, in the scope.
  const shown = Array.isArray(impact.entries) ? impact.entries : [];
  let bad = null;
  for (const e of shown) {
    if (entryCanonical(e) === null || computeEntryHash(e.prevHash, canonicalCore(e.core)) !== e.entryHash) bad = `matched entry ${e.seq} altered`;
    else if (inList && inList.get(e.seq) !== e.entryHash) bad = `entry ${e.seq} is not in the sealed matched set`;
    else if (!matchesScope(e.core, e.occurredAt, pack.scope)) bad = `entry ${e.seq} does not match the scope`;
    if (bad) break;
  }
  if (shown.length) push('incident.matched', !bad, bad ?? `${shown.length} matched entries recomputed, each in the set and in the scope${impact.entriesTruncated ? ' (the first ones only)' : ''}`);

  // 6. Completeness: over the whole journal up to the impact's last seq, the scope matches exactly the set.
  const links = Array.isArray(impact.completeness?.links) ? [...impact.completeness.links].sort(bySeq) : null;
  if (links && impacts.length && inList) {
    const v = verifyLinks(links.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
    let why = !v.ok ? `${v.reason} at seq ${v.brokenAt}` : links[0]?.seq !== 1 || links[links.length - 1]?.seq !== sealed.throughSeq ? `the journal shipped is not seq 1–${sealed.throughSeq}` : null;
    if (!why) {
      const found = links.filter(l => matchesScope(JSON.parse(l.coreCanonical), l.occurredAt, pack.scope)).map(l => [l.seq, l.entryHash]);
      const same = found.length === inList.size && found.every(([s, h]) => inList.get(s) === h);
      if (!same) why = `the scope matches ${found.length} entries of the journal, the sealed set holds ${inList.size}`;
    }
    push('incident.completeness', !why, why ?? `the whole journal up to seq ${sealed.throughSeq} read again: no other sealed decision matches the scope`);
  } else if (impacts.length) {
    push('incident.completeness', true, 'the journal is not shipped (too long): completeness rests on the producer; the set is committed by its sealed hash', 'warn');
  }

  // 7. Report drafts: each file is the one sealed.
  for (const e of entries.filter(x => x.core?.decision === 'incident_report_drafted')) {
    const p = policyOf(e);
    const file = pack.reports?.[p.draftId]?.file;
    if (!file || !files[file]) { push(`incident.report.${String(p.draftId).slice(0, 8)}`, true, `report draft ${String(p.draftId).slice(0, 8)} sealed, not in this dossier`, 'warn'); continue; }
    const ok = sha256Hex(files[file]) === p.sha256;
    push(`incident.report.${String(p.draftId).slice(0, 8)}`, ok, ok ? `${file} is the draft sealed at step ${p.incidentStep}` : `${file} does not hash to the sealed draft`);
  }
  return out;
}
