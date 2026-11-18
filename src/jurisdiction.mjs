// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 11 — each decision's applicable law, decided again (SPEC.md). A decision
 * seals the facts its law was decided from (where the people are, the operator, where the model
 * ran, the data, the mandate's evidence and zones, the day), the packs that covered it and the
 * sha256 of their documents, and the deciding rule. The dossier ships those documents
 * (`jurisdiction-packs.json`). From the seal and the documents alone, this module selects the packs
 * again, keeps the rules in force on the day, and applies the strictest unmet requirement — so a
 * third party sees, without trusting Azoth, that the rule sealed is the one the packs call for.
 *
 * Its own copy of the producer's engine: it imports nothing from Azoth. A parity test in the
 * producer's repository keeps the two identical — change both or neither.
 */
import { sha256Hex } from './chain.mjs';

export const PACKS_FILE = 'jurisdiction-packs.json';
const EFFECTS = ['allow', 'reroute', 'approval', 'block'];

// The same geography as the producer's zones.
const EU = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'];
const GROUPS = { EU, EEA: [...EU, 'IS', 'LI', 'NO', 'EU'] };

function within(zone, ref) {
  if (zone === ref || zone.startsWith(`${ref}-`)) return true;
  const members = GROUPS[ref];
  if (!members) return false;
  return members.includes(zone.split('-')[0]) || members.includes(zone);
}
const withinAny = (zone, refs) => refs.some(r => within(zone, r));
const someWithin = (zones, refs) => zones.some(z => withinAny(z, refs));
function intersect(a, b) {
  const out = new Set();
  for (const x of a) for (const y of b) { if (within(x, y)) out.add(x); else if (within(y, x)) out.add(y); }
  return [...out];
}

function expand(zones, lists) {
  if (!zones) return undefined;
  return zones.flatMap(z => (z.startsWith('@') ? lists[z.slice(1)] ?? [] : [z]));
}

function compileCondition(c, lists) {
  return {
    subjectIn: expand(c.subjectIn, lists), operatorIn: expand(c.operatorIn, lists), nexusIn: expand(c.nexusIn, lists),
    sectorAny: c.sectorAny, dataAny: c.dataAny, aiActClass: c.aiActClass, automatedDecision: c.automatedDecision, populationAny: c.populationAny,
  };
}

/** A pack document's pack, readied: zone lists expanded, provisions indexed. */
export function compilePack(pack) {
  const lists = pack.zoneLists ?? {};
  return {
    pack, ref: `${pack.id}@${pack.version}`,
    provisions: new Map((pack.provisions ?? []).map(p => [p.id, p])),
    scope: compileCondition(pack.scope ?? {}, lists),
    rules: (pack.rules ?? []).map(rule => ({
      rule, ref: `${pack.id}/${rule.id}`, when: compileCondition(rule.when ?? {}, lists),
      hostingIn: rule.require.kind === 'hosting' ? expand(rule.require.hostingIn, lists) ?? [] : null,
      mechanisms: rule.require.kind === 'hosting' ? (rule.require.mechanisms ?? []).map(m => ({ id: m.id, hostingIn: expand(m.hostingIn, lists) ?? null })) : [],
    })),
  };
}

function holds(c, f) {
  if (c.subjectIn && (!f.subjectZones.length || !someWithin(f.subjectZones, c.subjectIn))) return false;
  if (c.operatorIn && (!f.operatorZones.length || !someWithin(f.operatorZones, c.operatorIn))) return false;
  if (c.nexusIn && !someWithin(f.operatorZones, c.nexusIn) && !someWithin(f.subjectZones, c.nexusIn)) return false;
  if (c.sectorAny && !f.sectors.some(s => c.sectorAny.includes(s))) return false;
  if (c.dataAny && !f.dataCategories.some(d => c.dataAny.includes(d))) return false;
  if (c.aiActClass && (!f.aiActClass || !c.aiActClass.includes(f.aiActClass))) return false;
  if (c.automatedDecision !== undefined && f.automatedDecision !== c.automatedDecision) return false;
  if (c.populationAny && (!f.population || !c.populationAny.includes(f.population))) return false;
  return true;
}

function inForce(p, id, date) {
  const prov = p.provisions.get(id);
  return !!prov && prov.status === 'adopted' && prov.effectiveFrom <= date && (!prov.effectiveUntil || date < prov.effectiveUntil);
}

function hostingMet(zone, hostingIn, mechanisms, declared) {
  for (const m of mechanisms) {
    if (!declared.includes(m.id)) continue;
    if (!m.hostingIn || (zone && withinAny(zone, m.hostingIn))) return true;
  }
  return !!zone && withinAny(zone, hostingIn);
}

function evidenceMet(f, id, maxAgeDays) {
  const done = f.evidence[id];
  if (!done || done > f.date) return false;
  if (maxAgeDays === undefined) return true;
  const oldest = new Date(Date.parse(`${f.date}T00:00:00Z`) - maxAgeDays * 86_400_000).toISOString().slice(0, 10);
  return done >= oldest;
}

const rank = e => EFFECTS.indexOf(e);

/**
 * Decide again: the packs covering the facts, and the strictest unmet requirement the law calls for.
 * `adopted`: the standards the decision named; `allowed`: the mandate's zones; `conflictRules`: those it applied.
 */
export function decideAgain(packs, f, { adopted = new Set(), allowed = [], conflictRules = [] } = {}) {
  const candidates = [];
  const unmet = [];
  const strict = [];
  for (const p of packs) {
    if (p.pack.kind === 'standard' && !adopted.has(p.ref)) continue;
    if (!holds(p.scope, f)) continue;
    candidates.push(p.ref);
    for (const r of p.rules) {
      if (!inForce(p, r.rule.provision, f.date) || !holds(r.when, f)) continue;
      const req = r.rule.require;
      let met;
      if (req.kind === 'hosting') {
        if (!r.mechanisms.length) strict.push({ ref: r.ref, zones: r.hostingIn, zone: p.pack.zone });
        met = hostingMet(f.hostingZone, r.hostingIn, r.mechanisms, f.mechanisms);
      } else if (req.kind === 'provider_registered') met = f.providerRegistered;
      else if (req.kind === 'evidence') met = evidenceMet(f, req.evidence, req.maxAgeDays);
      else met = false;
      if (!met) unmet.push({ rule: r.ref, effect: r.rule.effect, reason: r.rule.reason });
    }
  }
  if (allowed.length) {
    strict.push({ ref: 'mandate/allowed_zones', zones: allowed, zone: null });
    if (!hostingMet(f.hostingZone, allowed, [], [])) unmet.push({ rule: 'mandate/allowed_zones', effect: 'reroute', reason: 'outside_mandate_zones' });
  }
  const meet = list => list.slice(1).reduce((acc, s) => intersect(acc, s.zones), list[0]?.zones ?? []);
  let conflict = null;
  if (strict.length > 1 && !meet(strict).length) {
    let kept = strict;
    for (const c of conflictRules) {
      const loser = c.zones[0] === c.prevails ? c.zones[1] : c.zones[0];
      if (!kept.some(s => s.zone === c.prevails) || !kept.some(s => s.zone === loser)) continue;
      kept = kept.filter(s => s.zone !== loser);
    }
    if (!(kept.length < strict.length && (kept.length < 2 || meet(kept).length))) {
      conflict = strict.map(s => s.ref);
      unmet.unshift({ rule: conflict[0], effect: 'block', reason: 'incompatible_requirements' });
    }
  }
  const verdict = unmet.reduce((best, u) => (rank(u.effect) > rank(best.effect) ? u : best), { rule: null, effect: 'allow', reason: null });
  return { packs: candidates, verdict, conflict };
}

/** A seal's factors as the engine reads them. */
function factorsOf(s, day) {
  const f = s.factors ?? {};
  return {
    subjectZones: f.subject ?? [], operatorZones: f.operator ?? [], hostingZone: f.hosting ?? null, provider: f.provider ?? '',
    sectors: f.sector ?? [], dataCategories: f.data ?? [], aiActClass: f.aiAct ?? null, automatedDecision: f.automated === true,
    population: f.population ?? null, mechanisms: f.mechanisms ?? [], providerRegistered: f.registered === true,
    evidence: f.evidence ?? {}, date: f.date ?? day,
  };
}

const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/**
 * Check 11 over the dossier's listed entries. Entries without a sealed law are not concerned; a v1
 * seal (the seal's first version, without the day) is checked by its packs' hash only; a v2 seal
 * is decided again.
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyJurisdiction(entries, files) {
  const sealed = (entries ?? []).filter(e => e?.core?.jurisdiction && !e.core.jurisdiction.unavailable);
  if (!sealed.length) return [];
  const raw = files[PACKS_FILE];
  if (!raw) return [{ id: 'jurisdiction', ok: true, level: 'warn', detail: `${sealed.length} decisions carry their applicable law, but the dossier ships no ${PACKS_FILE}: it cannot be decided again` }];
  let doc;
  try { doc = JSON.parse(new TextDecoder().decode(raw)); } catch { doc = null; }
  if (!doc || doc.format !== 'azoth.jurisdiction.packs/1' || !Array.isArray(doc.packs)) return [{ id: 'jurisdiction', ok: false, detail: `${PACKS_FILE} is not a pack document list` }];

  const hashes = new Map();
  const compiled = [];
  for (const p of doc.packs) {
    let parsed = null;
    try { parsed = JSON.parse(p.document); } catch { parsed = null; }
    const pack = parsed?.format === 'azoth.jurisdiction.pack/1' ? parsed.pack : null;
    if (!pack || sha256Hex(p.document) !== p.sha256 || `${pack.id}@${pack.version}` !== p.ref) {
      return [{ id: 'jurisdiction', ok: false, detail: `the pack document ${p.ref} does not match its sha256 or its ref` }];
    }
    hashes.set(p.ref, p.sha256);
    compiled.push(compilePack(pack));
  }

  let decided = 0, hashedOnly = 0, unshipped = 0;
  for (const e of sealed) {
    const s = e.core.jurisdiction;
    const refs = s.packs ?? [];
    if (refs.some(r => !hashes.has(r))) { unshipped++; continue; }
    const set = sha256Hex([...refs].sort().map(r => `${r}:${hashes.get(r)}`).join('\n'));
    if (set !== s.packSet) return [{ id: 'jurisdiction', ok: false, detail: `seq ${e.seq}: the packs it names do not hash to its sealed packSet` }];
    if (s.v !== 2) { hashedOnly++; continue; }
    const day = typeof e.occurredAt === 'string' ? e.occurredAt.slice(0, 10) : '';
    const adopted = new Set(refs.filter(r => compiled.find(c => c.ref === r)?.pack.kind === 'standard'));
    const conflictRules = (s.conflictRules ?? []).map(x => { const [a, b] = String(x).split('>'); return { zones: [a, b], prevails: a }; });
    const again = decideAgain(compiled, factorsOf(s, day), { adopted, allowed: s.factors?.allowed ?? [], conflictRules });
    const sealedVerdict = { rule: s.rule ?? null, effect: s.effect ?? 'allow', reason: s.reason ?? null };
    if (!same(again.packs, refs)) return [{ id: 'jurisdiction', ok: false, detail: `seq ${e.seq}: its facts select ${again.packs.join(', ') || 'no pack'}, not the packs it sealed` }];
    if (!same(again.verdict, sealedVerdict)) {
      return [{ id: 'jurisdiction', ok: false, detail: `seq ${e.seq}: decided again, the strictest rule is ${again.verdict.rule ?? 'none'} (${again.verdict.effect}), not the sealed ${sealedVerdict.rule ?? 'none'} (${sealedVerdict.effect})` }];
    }
    if (!same(again.conflict, s.conflict)) return [{ id: 'jurisdiction', ok: false, detail: `seq ${e.seq}: the conflict decided again differs from the sealed one` }];
    decided++;
  }
  const out = [{ id: 'jurisdiction', ok: true, detail: `${decided} decisions decided again from their sealed facts and the shipped packs: the same laws and the same strictest rule${hashedOnly ? `; ${hashedOnly} older seals checked by their packs' hash only` : ''}` }];
  if (unshipped) out.push({ id: 'jurisdiction.packs', ok: true, level: 'warn', detail: `${unshipped} decisions name a pack version the dossier does not ship: not decided again` });
  return out;
}
