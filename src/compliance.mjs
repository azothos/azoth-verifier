// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 8 — a compliance bundle (`evidence.json` kind "compliance", SPEC.md).
 *
 * The bundle says which requirements of a framework are covered by sealed
 * evidence. This check makes that claim verifiable: the framework file (its
 * requirements and the predicates of its evidence kinds) hashes to what the
 * bundle names, every cited entry recomputes and matches the predicate of the
 * kind it is cited for, and no requirement is marked covered unless each of its
 * required groups has such an entry. Like the rest of the verifier it shares
 * nothing with Azoth's code: the predicate rule is reimplemented from SPEC.md.
 */
import { sha256Hex, canonicalCore, computeEntryHash, verifyLinks } from './chain.mjs';
import { checkTimestamp } from './timestamp.mjs';

const bySeq = (a, b) => a.seq - b.seq;

/** Does a sealed core count as evidence of this kind? (SPEC.md, Check 8, "Predicates".) */
export function matchesKind(kind, core) {
  if (!kind || kind.source !== 'journal' || !core || typeof core !== 'object') return false;
  const m = kind.match ?? {};
  if (core.surface !== m.surface) return false;
  const decision = typeof core.decision === 'string' ? core.decision : '';
  const decisions = Array.isArray(m.decisions) ? m.decisions : [];
  const prefixes = Array.isArray(m.decisionPrefixes) ? m.decisionPrefixes : [];
  if ((decisions.length || prefixes.length) && !(decisions.includes(decision) || prefixes.some(p => decision.startsWith(p)))) return false;
  const policy = core.policy && typeof core.policy === 'object' ? core.policy : {};
  for (const [key, rule] of Object.entries(m.policy ?? {})) {
    const v = policy[key];
    if (rule && 'present' in rule ? v === undefined || v === null : v !== rule?.eq) return false;
  }
  for (const f of m.corePresent ?? []) if (core[f] === undefined || core[f] === null) return false;
  return true;
}

export function verifyCompliancePack(pack, files, { shipped = [], pinned = null } = {}) {
  const out = [];
  const push = (id, ok, detail, level) => out.push(level ? { id, ok, detail, level } : { id, ok, detail });
  const dec = new TextDecoder();

  // 1. The framework document the statuses were computed against.
  let doc = null;
  const fwBytes = files[pack.framework?.file];
  if (!fwBytes) push('compliance.framework', false, `${pack.framework?.file ?? 'framework file'} missing`);
  else if (sha256Hex(fwBytes) !== pack.framework.sha256) push('compliance.framework', false, `${pack.framework.file} does not hash to the framework hash the bundle names`);
  else {
    try { doc = JSON.parse(dec.decode(fwBytes)); } catch { doc = null; }
    if (!doc?.framework || doc.framework.id !== pack.framework.id) { push('compliance.framework', false, 'the framework file is not the framework the bundle names'); doc = null; }
    else push('compliance.framework', true, `${doc.framework.id} ${doc.framework.version}: ${doc.framework.requirements.length} requirements, the evidence kinds and every text, hashed`);
  }
  if (doc?.framework.mappingStatus !== 'validated') push('compliance.mapping', true, 'the mapping to the framework is marked as still to be validated by an expert', 'warn');
  const disclaimed = typeof pack.disclaimer?.en === 'string' && pack.disclaimer.en.length > 0 && typeof pack.disclaimer?.fr === 'string' && pack.disclaimer.fr.length > 0;
  push('compliance.disclaimer', disclaimed, disclaimed ? 'the bundle states it is a tool to prepare an audit, not a certification or legal advice' : 'the bundle carries no disclaimer');

  // 2. The cited entries: recomputed, inside verified chain segments.
  const segments = Array.isArray(pack.segments) ? pack.segments : [];
  const entries = Array.isArray(pack.entries) ? [...pack.entries].sort(bySeq) : [];
  const individual = pack.integrity?.inclusion === 'individual';
  const at = new Map();
  let broken = null;
  for (const seg of segments) {
    const links = [...(seg.links ?? [])].sort(bySeq);
    const v = verifyLinks(links.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
    if (!v.ok) { broken ??= `${v.reason} at seq ${v.brokenAt}`; continue; }
    if (links[0]?.seq !== seg.fromSeq || links[links.length - 1]?.seq !== seg.toSeq) broken ??= `segment ${seg.fromSeq}–${seg.toSeq} does not hold its declared range`;
    for (const l of links) at.set(l.seq, l);
  }
  const verified = new Map();
  for (const e of entries) {
    if (computeEntryHash(e.prevHash, canonicalCore(e.core)) !== e.entryHash) { broken ??= `entry_hash mismatch (cited entry altered) at seq ${e.seq}`; continue; }
    const l = at.get(e.seq);
    if (!individual && (!l || l.entryHash !== e.entryHash || l.prevHash !== e.prevHash)) { broken ??= `entry ${e.seq} is not in a verified chain segment`; continue; }
    verified.set(e.seq, e);
  }
  push('compliance.chain', !broken, broken ?? `${verified.size} cited sealed entries${individual ? ', each verified on its own' : `, in ${segments.length} verified chain segment(s)`}`);

  for (const seg of segments) {
    if (!seg.anchor) continue;
    const last = at.get(seg.toSeq);
    const tsr = files[seg.anchor.file];
    if (!tsr || !last) { push(`compliance.anchor.${seg.toSeq}`, false, `${seg.anchor.file} missing`); continue; }
    const t = checkTimestamp(tsr, last.entryHash, { shipped, pinned });
    if (!t.ok) push(`compliance.anchor.${seg.toSeq}`, false, `journal head ${seg.toSeq}: ${t.detail}`);
    else if (pinned) push(`compliance.anchor.${seg.toSeq}`, t.trusted, t.trusted ? `entries up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} (${t.tsa})` : 'the TSA chain does not end on the root given with --tsa-root');
    else push(`compliance.anchor.${seg.toSeq}`, true, `entries up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} — pin the TSA's root with --tsa-root to trust it`, 'warn');
  }

  // 3. Timestamped journal heads cited as evidence.
  const heads = new Set();
  for (const h of Array.isArray(pack.heads) ? pack.heads : []) {
    const link = at.get(h.journalSeq);
    const tsr = files[h.file];
    if (!link || !tsr) { push(`compliance.head.${h.journalSeq}`, false, `head ${h.journalSeq}: ${tsr ? 'its link is not in the bundle' : `${h.file} missing`}`); continue; }
    const t = checkTimestamp(tsr, link.entryHash, { shipped, pinned });
    if (!t.ok) { push(`compliance.head.${h.journalSeq}`, false, `head ${h.journalSeq}: ${t.detail}`); continue; }
    heads.add(h.journalSeq);
  }

  if (!doc) return out;
  const kinds = new Map((doc.kinds ?? []).map(k => [k.id, k]));
  const reqs = new Map(doc.framework.requirements.map(r => [r.id, r]));
  const listed = Array.isArray(pack.requirements) ? pack.requirements : [];

  // 4. Every citation is evidence of the kind it is cited for.
  const valid = new Map();   // kind id → number of valid citations, per requirement key
  let bad = null;
  for (const r of listed) {
    for (const [kindId, ev] of Object.entries(r.evidence ?? {})) {
      const k = kinds.get(kindId);
      const cited = Array.isArray(ev?.cited) ? ev.cited : [];
      if (!k) { bad ??= `${r.id}: kind ${kindId} is not in the framework file`; continue; }
      if (k.source === 'external' && (cited.length || ev.sealed)) { bad ??= `${r.id}: ${kindId} is what only the organisation provides — it cannot be counted as sealed`; continue; }
      if (cited.length > (ev.sealed ?? 0)) { bad ??= `${r.id}: more ${kindId} entries cited than counted`; continue; }
      let n = 0;
      for (const seq of cited) {
        if (k.source === 'anchor') { if (heads.has(seq)) n++; else bad ??= `${r.id}: head ${seq} cited as ${kindId} is not a verified timestamped head`; continue; }
        const e = verified.get(seq);
        if (!e) bad ??= `${r.id}: entry ${seq} cited as ${kindId} is not a verified entry of the bundle`;
        else if (!matchesKind(k, e.core)) bad ??= `${r.id}: entry ${seq} is not evidence of ${kindId}`;
        else n++;
      }
      valid.set(`${r.id}\u0000${kindId}`, n);
    }
  }
  push('compliance.citations', !bad, bad ?? 'every cited entry is evidence of the kind it is cited for');

  // 5. No requirement is covered without evidence for each required group.
  let inflated = null;
  const missingReq = [...reqs.keys()].filter(id => !listed.some(r => r.id === id));
  if (missingReq.length) inflated = `requirements left out of the bundle: ${missingReq.join(', ')}`;
  const counts = { covered: 0, partial: 0, not_covered: 0, out_of_scope: 0 };
  for (const r of listed) {
    const req = reqs.get(r.id);
    if (!req) { inflated ??= `${r.id} is not a requirement of the framework`; continue; }
    counts[r.status] = (counts[r.status] ?? 0) + 1;
    const groupHas = g => g.some(kindId => (valid.get(`${r.id}\u0000${kindId}`) ?? 0) > 0);
    if (r.status === 'covered' && !req.required.every(groupHas)) inflated ??= `${r.id} is marked covered without verified evidence for each required group`;
    if (r.status === 'out_of_scope' && r.reason === 'declared_out_of_scope') {
      const s = (pack.scope ?? []).find(x => x.requirementId === r.id);
      const e = s?.seq != null ? verified.get(s.seq) : null;
      const p = e?.core?.policy ?? {};
      const ok = e && e.core.surface === 'governance' && e.core.decision === 'compliance_scope_declared'
        && p.requirementId === r.id && p.frameworkId === pack.framework.id && p.justificationHash === s.justificationHash;
      if (!ok) inflated ??= `${r.id} is declared out of scope without its sealed declaration`;
    }
    if (r.status === 'out_of_scope' && r.reason === 'not_applicable' && !(req.applicability === 'high_risk' && pack.context?.highRiskUseCases === 0)) {
      inflated ??= `${r.id} is marked not applicable, which its framework does not allow here`;
    }
  }
  push('compliance.coverage', !inflated, inflated ?? `${counts.covered} requirement(s) covered, each on cited sealed evidence for every required group`);
  if (listed.some(r => r.reason === 'not_applicable')) push('compliance.applicability', true, 'requirements marked not applicable rest on the registry count the producer states (no high-risk use case declared)', 'warn');

  // 6. The summary recomputes from the statuses.
  const applicable = listed.length - counts.out_of_scope;
  const s = pack.summary ?? {};
  const rate = applicable ? counts.covered / applicable : 0;
  const summaryOk = s.total === listed.length && s.covered === counts.covered && s.partial === counts.partial && s.notCovered === counts.not_covered
    && s.outOfScope === counts.out_of_scope && s.applicable === applicable && Math.abs((s.rate ?? -1) - rate) < 1e-9;
  push('compliance.summary', summaryOk, summaryOk ? `${counts.covered} covered / ${applicable} applicable (${Math.round(rate * 100)} %)` : 'the summary does not recompute from the requirements');
  return out;
}
