// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * azoth-verify — independent verification core.
 *
 * Zero runtime dependencies, zero network. This file DELIBERATELY imports no
 * Azoth application code: the value of an independent verifier is that it
 * shares nothing with the producer. Its algorithms (here and in chain.mjs) are
 * reimplemented from SPEC.md (which documents, but does not import, the
 * producer's decision journal). A cross-import would annul the evidentiary value.
 */
import { sha256Hex, canonicalCore, entryCanonical, computeEntryHash, computeRootHash, verifyLinks, bySeq } from './chain.mjs';
import { checkTimestamp, readPem } from './timestamp.mjs';
import { verifyIncidentPack } from './incident.mjs';
import { verifyCompliancePack } from './compliance.mjs';
import { verifyPlatformPack } from './platform.mjs';
import { verifyJurisdiction } from './jurisdiction.mjs';
import { verifyPricing } from './pricing.mjs';
import { verifyFootprintPack } from './footprint.mjs';
import { verifyHoldDesignation } from './litigation.mjs';
import { verifyDossierSignature } from './signature.mjs';
import { verifyRetention } from './retention.mjs';
import { verifyHeadRoots, signedAt, span, LATE_ROOT_MS } from './headroot.mjs';

// The chain primitives, for callers of the verifier's main module (chain.mjs holds them).
export { sha256Hex, canonicalCore, computeEntryHash, computeRootHash, verifyLinks };

/**
 * Verify the sealed decision chain in an evidence pack (SPEC.md, Check 3).
 * With `pack.chain` (the listed entries were filtered), the whole segment is
 * verified and every listed entry must be one of its links, unchanged.
 * @returns {{ ok: boolean, brokenAt: number|null, reason: string|null, verified: number, first?: number|null, last?: number|null, startPrevHash?: string|null, listed?: number }}
 */
export function verifyChain(pack) {
  const listed = Array.isArray(pack?.entries) ? [...pack.entries].sort(bySeq) : [];
  // An entry that carries its coreCanonical beside its core must state the core sealed (entryCanonical).
  const restated = listed.find(e => entryCanonical(e) === null);
  if (restated) return { ok: false, brokenAt: restated.seq, reason: 'its core is not the one its coreCanonical seals (listed entry altered)', verified: 0 };
  if (!Array.isArray(pack?.chain)) {
    return verifyLinks(listed.map(e => ({ seq: e.seq, prevHash: e.prevHash, entryHash: e.entryHash, canonical: canonicalCore(e.core) })));
  }
  const links = [...pack.chain].sort(bySeq);
  const seg = verifyLinks(links.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
  if (!seg.ok) return seg;
  const at = new Map(links.map(l => [l.seq, l]));
  for (const e of listed) {
    const l = at.get(e.seq);
    if (computeEntryHash(e.prevHash, canonicalCore(e.core)) !== e.entryHash) {
      return { ok: false, brokenAt: e.seq, reason: 'entry_hash mismatch (listed entry altered)', verified: seg.verified };
    }
    if (!l || l.entryHash !== e.entryHash || l.prevHash !== e.prevHash) {
      return { ok: false, brokenAt: e.seq, reason: 'listed entry is not in the verified chain segment', verified: seg.verified };
    }
  }
  return { ...seg, listed: listed.length };
}

/**
 * Check 3's line: the chain of an audit pack (a journal export, as a dossier's evidence.json or as the
 * signed JSON pack of Check 17), with the segment it holds and the listed decisions in it.
 * @returns {{ id: 'chain', ok: boolean, detail: string }}
 */
export function chainCheck(pack) {
  const v = verifyChain(pack);
  const segment = v.ok && v.first > 1 ? `, seq ${v.first}–${v.last}, attached to prev_hash ${String(v.startPrevHash).slice(0, 12)}…` : '';
  const listed = v.ok && v.listed !== undefined ? `; the ${v.listed} listed decisions are in it` : '';
  return { id: 'chain', ok: v.ok, detail: v.ok ? `chain intact (${v.verified} sealed decisions${segment})${listed}` : `${v.reason} at seq ${v.brokenAt}` };
}

/**
 * Check 5 — a decision dossier (`evidence.json` kind "decision", SPEC.md): every
 * listed entry recomputes, carries the dossier's decision-reference hash, and is
 * a link of one of the chain segments; each segment verifies on its own; a
 * segment that ends on a timestamped journal head is closed by its RFC 3161
 * token; the rule sets and use-case snapshots named by the entries hash to their
 * archived files.
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyDecisionPack(pack, files, { shipped = [], pinned = null } = {}) {
  const out = [];
  // A litigation dossier (Check 12) is checked the same way; its entries are the hold's
  // designated decisions and the hold's own acts, instead of one decision reference's calls.
  // An exhaustion incident dossier (Check 12) too: its entries are the incident's own acts.
  const litigation = pack.kind === 'litigation';
  const exhaustion = pack.kind === 'exhaustion';
  // An AI footprint statement (Check 14): its entry is the statement's own sealed act.
  const footprint = pack.kind === 'ai_footprint';
  const kind = litigation ? 'litigation' : exhaustion ? 'exhaustion' : footprint ? 'ai_footprint' : 'decision';
  const held = new Set((litigation && Array.isArray(pack.hold?.seqs) ? pack.hold.seqs : []).map(Number));
  const belongs = e => (litigation
    ? held.has(Number(e.seq)) || (String(e.core?.decision ?? '').startsWith('legal_hold_') && e.core?.policy?.holdId === pack.hold?.id)
    : exhaustion
      ? String(e.core?.decision ?? '').startsWith('exhaustion_') && e.core?.policy?.incidentId === pack.incident?.id
      : footprint
        ? e.core?.decision === 'ai_footprint_attested' && e.core?.policy?.attestationId === pack.attestation?.id
        : e.core?.decisionRefHash === pack.decisionRefHash);
  const push = (id, ok, detail, level) => out.push(level ? { id: id.replace(/^decision\./, `${kind}.`), ok, detail, level } : { id: id.replace(/^decision\./, `${kind}.`), ok, detail });
  const segments = Array.isArray(pack.segments) ? pack.segments : [];
  const entries = Array.isArray(pack.entries) ? [...pack.entries].sort(bySeq) : [];

  // Segments, then the entries in them.
  let linkCount = 0;
  const at = new Map();
  let broken = null;
  for (const seg of segments) {
    const links = [...(seg.links ?? [])].sort(bySeq);
    linkCount += links.length;
    const v = verifyLinks(links.map(l => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, canonical: l.coreCanonical })));
    if (!v.ok) { broken ??= `${v.reason} at seq ${v.brokenAt}`; continue; }
    if (links[0]?.seq !== seg.fromSeq || links[links.length - 1]?.seq !== seg.toSeq) broken ??= `segment ${seg.fromSeq}–${seg.toSeq} does not hold its declared range`;
    for (const l of links) at.set(l.seq, l);
  }
  for (const e of entries) {
    if (broken) break;
    if (entryCanonical(e) === null) broken = `entry ${e.seq}: its core is not the one its coreCanonical seals`;
    else if (computeEntryHash(e.prevHash, canonicalCore(e.core)) !== e.entryHash) broken = `entry_hash mismatch (listed entry altered) at seq ${e.seq}`;
    else if (!belongs(e)) broken = litigation ? `entry ${e.seq} is neither designated by this hold nor one of its acts`
      : exhaustion ? `entry ${e.seq} is not an act of this exhaustion incident`
        : footprint ? `entry ${e.seq} is not this AI footprint statement's act` : `entry ${e.seq} does not carry this dossier's decision reference`;
    else {
      const l = at.get(e.seq);
      if (!l || l.entryHash !== e.entryHash || l.prevHash !== e.prevHash) broken = `entry ${e.seq} is not in a verified chain segment`;
    }
  }
  const what = litigation ? 'entries (decisions under hold, and the hold’s acts)' : exhaustion ? 'acts of this exhaustion incident' : footprint ? 'the act of this AI footprint statement' : 'calls of this decision';
  push('decision.chain', !broken, broken ?? `${entries.length} ${what}, in ${segments.length} verified chain segment(s) (${linkCount} links)`);

  // Segments closed by a timestamped journal head.
  for (const seg of segments) {
    if (!seg.anchor) continue;
    const last = at.get(seg.toSeq);
    const tsr = files[seg.anchor.file];
    if (!tsr || !last) { push(`decision.anchor.${seg.toSeq}`, false, `${seg.anchor.file} missing`); continue; }
    const t = checkTimestamp(tsr, last.entryHash, { shipped, pinned });
    if (!t.ok) push(`decision.anchor.${seg.toSeq}`, false, `journal head ${seg.toSeq}: ${t.detail}`);
    else if (pinned) push(`decision.anchor.${seg.toSeq}`, t.trusted, t.trusted ? `entries up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} (${t.tsa})` : 'the TSA chain does not end on the root given with --tsa-root');
    else push(`decision.anchor.${seg.toSeq}`, true, `entries up to seq ${seg.toSeq} existed at ${t.genTime.toISOString()} — pin the TSA's root with --tsa-root to trust it`, 'warn');
  }
  if (!segments.some(s => s.anchor)) {
    push('decision.anchor', true, 'no segment ends on a timestamped journal head: the calls are linked, not dated by a third party', 'warn');
  }

  // The policy and the use case in force.
  const named = (key, registry, label) => {
    const hashes = [...new Set(entries.map(e => e.core?.[key]).filter(h => typeof h === 'string'))];
    for (const h of hashes) {
      const file = registry?.[h]?.file;
      if (!file || !files[file]) { push(`decision.${label}.${h.slice(0, 12)}`, true, `${label} ${h.slice(0, 12)}… sealed, its text not archived in this dossier`, 'warn'); continue; }
      const ok = sha256Hex(files[file]) === h;
      push(`decision.${label}.${h.slice(0, 12)}`, ok, ok ? `${file} is the ${label} sealed by the calls` : `${file} does not hash to the sealed ${label}`);
    }
  };
  named('policyVersion', pack.policies, 'policy');
  named('usecaseSnapshotHash', pack.usecases, 'usecase');
  if (litigation) out.push(...verifyHoldDesignation(pack));
  return out;
}

/**
 * Check 6 — client-vault content (SPEC.md). Each file the client supplies (a
 * decrypted plaintext document, or the stored envelope) must hash to the
 * plaintext or ciphertext hash of a sealed `vault_receipt` entry of the dossier.
 * @param {Array<{ name: string, bytes: Uint8Array }>} contents
 */
export function verifyVaultContents(pack, contents) {
  const out = [];
  const receipts = (Array.isArray(pack?.entries) ? pack.entries : []).filter(e => e?.core?.decision === 'vault_receipt');
  for (const c of contents) {
    const h = sha256Hex(c.bytes);
    const asPlain = receipts.find(e => e.core?.policy?.vaultPlaintextHash === h);
    const asCipher = asPlain ? null : receipts.find(e => e.core?.policy?.vaultCiphertextHash === h);
    const hit = asPlain ?? asCipher;
    out.push(hit
      ? { id: `vault.${c.name}`, ok: true, detail: `${asPlain ? 'the plaintext' : 'the stored envelope'} sealed by the receipt at seq ${hit.seq} (trace ${hit.traceId ?? '?'})` }
      : { id: `vault.${c.name}`, ok: false, detail: `no sealed receipt carries sha256 ${h.slice(0, 12)}… — altered, or not of this dossier` });
  }
  if (contents.length && !receipts.length) out.push({ id: 'vault', ok: false, detail: 'the dossier holds no vault receipt' });
  return out;
}

/**
 * An ISO 8601 instant (`2026-11-14T10:00:00.123Z`, `…123+00:00` as a database writes it) in
 * microseconds since the epoch, or null when it is not one. Exact to the microsecond: the fraction is
 * read as written, never through a float.
 */
function instantMicros(s) {
  const m = typeof s === 'string' ? /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/.exec(s) : null;
  if (!m) return null;
  const [, y, mo, d, h, mi, se, frac = '', zone] = m;
  const off = zone === 'Z' ? 0 : (zone[0] === '-' ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.replace(':', '').slice(3, 5) || 0));
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(se)) - off * 60_000;
  return Number.isFinite(ms) ? ms * 1000 + Number(frac.padEnd(6, '0')) : null;
}

/** The readable fields an entry shows beside its core, and the core keys that seal them. */
const SEALED_FIELDS = ['occurredAt', 'actorType', 'traceId'];

/**
 * Check 16 — when, by which kind of actor and under which trace (SPEC.md). An entry whose sealed core
 * carries `occurredAt`, `actorType` or `traceId` must show the same in its readable fields — the time
 * as the same instant, the others as the same string — since the hash covers the core and not them.
 * An entry sealed before these keys existed shows the producer's columns, outside the hash: counted,
 * and said. Over the listed entries and, in an incident dossier, its matched entries and the journal
 * read for completeness (their `occurredAt` beside their `coreCanonical`).
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifySealedFields(pack) {
  const listed = [...(Array.isArray(pack?.entries) ? pack.entries : []), ...(Array.isArray(pack?.impact?.entries) ? pack.impact.entries : [])];
  const links = Array.isArray(pack?.impact?.completeness?.links) ? pack.impact.completeness.links : [];
  const core = l => { try { return JSON.parse(l.coreCanonical); } catch { return null; } };
  const rows = [...listed.map(e => ({ e, core: e?.core })), ...links.map(l => ({ e: l, core: core(l), link: true }))];
  if (!listed.length) return [];
  const bad = [];
  let sealed = 0;
  for (const { e, core: c, link } of rows) {
    if (!c || typeof c !== 'object') continue;
    if (!link && typeof c.occurredAt === 'string') sealed++;
    for (const k of link ? ['occurredAt'] : SEALED_FIELDS) {
      if (c[k] === undefined) continue;
      const same = k === 'occurredAt'
        ? instantMicros(c[k]) !== null && instantMicros(c[k]) === instantMicros(e[k])
        : c[k] === e[k];
      if (!same) bad.push(`entry ${e.seq}: its ${k} is not the one sealed in its core`);
    }
  }
  if (bad.length) {
    return [{ id: 'sealed.fields', ok: false, detail: `${bad.slice(0, 3).join('; ')}${bad.length > 3 ? ` (and ${bad.length - 3} more)` : ''}` }];
  }
  const legacy = listed.length - sealed;
  if (!legacy) return [{ id: 'sealed.fields', ok: true, detail: `${sealed} ${sealed === 1 ? 'entry' : 'entries'}: the time, actor type and trace sealed in each core match its readable fields` }];
  const what = 'their occurredAt, actorType and traceId are the producer’s columns, outside the hash';
  return [{
    id: 'sealed.fields', ok: true, level: 'warn',
    detail: sealed
      ? `${sealed} of ${listed.length} entries carry a sealed time, actor type and trace, matched; the other ${legacy} were sealed before: ${what}`
      : `none of the ${listed.length} entries carries a sealed time (sealed before the time, actor and trace were bound to the chain): ${what}`,
  }];
}

/**
 * Run all checks over an in-memory dossier (a Map/record of path → Uint8Array).
 * `tsaRootPem`: the TSA root(s) the auditor trusts (--tsa-root). Without it, a
 * timestamp whose signature holds is reported with a warning: its chain can
 * only end on certificates the dossier itself ships.
 * @param {Record<string, Uint8Array>} files
 * `publishedRoots`: the roots the producer published (readPublishedRoots over the files given with
 * --published-roots), each proof of head-roots.json compared with the one of its hour (Check 18, step 6).
 * @param {{ tsaRootPem?: string, vaultContents?: Array<{ name: string, bytes: Uint8Array }>, keys?: { keys?: unknown[] } | null, publishedRoots?: Array<{ hour: number, root: string, treeSize: number, token: Uint8Array | null }> | null }} [opts]
 * @returns {{ ok: boolean, checks: Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }> }}
 */
export function verifyDossier(files, opts = {}) {
  const checks = [];
  const push = (id, ok, detail, level) => checks.push(level ? { id, ok, detail, level } : { id, ok, detail });

  const dec = new TextDecoder();
  const manifestRaw = files['manifest.json'];
  if (!manifestRaw) {
    push('manifest.present', false, 'manifest.json missing');
    return { ok: false, checks };
  }
  let manifest;
  try { manifest = JSON.parse(dec.decode(manifestRaw)); }
  catch { push('manifest.parse', false, 'manifest.json is not valid JSON'); return { ok: false, checks }; }
  push('manifest.present', true, `format_version ${manifest.format_version}`);

  // 1. Per-file hashes.
  let allFilesOk = true;
  for (const f of manifest.files ?? []) {
    const bytes = files[f.path];
    if (!bytes) { push(`file.${f.path}`, false, 'listed in manifest but absent'); allFilesOk = false; continue; }
    const got = sha256Hex(bytes);
    const ok = got === f.sha256;
    if (!ok) allFilesOk = false;
    push(`file.${f.path}`, ok, ok ? 'sha256 matches' : `sha256 mismatch (expected ${f.sha256.slice(0, 12)}…, got ${got.slice(0, 12)}…)`);
  }

  // 2. root_hash.
  const rootOk = computeRootHash(manifest.files ?? []) === manifest.root_hash;
  push('manifest.root_hash', rootOk, rootOk ? 'root_hash matches' : 'root_hash does not match the file hashes');

  // The TSA certificates: shipped by the dossier (help build a chain), pinned by the auditor (trust).
  const shipped = files['tsa-chain.pem'] ? readPem(dec.decode(files['tsa-chain.pem'])) : [];
  let pinned = null;
  try { pinned = opts.tsaRootPem ? readPem(opts.tsaRootPem) : null; }
  catch (err) { push('timestamp.root', false, `--tsa-root unreadable: ${err.message}`); }
  if (pinned && pinned.length === 0) push('timestamp.root', false, '--tsa-root holds no certificate');
  if (pinned && pinned.length === 0) pinned = null;

  // 3. Sealed chain in evidence.json (5. decision dossier, 7. incident dossier, 8. compliance bundle,
  //    9. platform evidence package).
  let headTokens = 0;   // timestamped journal heads checked against the pinned root (Check 5)
  let pack = null;      // the parsed evidence.json — Check 12 compares it with what the signature committed
  const evidenceRaw = files['evidence.json'];
  if (!evidenceRaw) {
    push('chain', false, 'evidence.json missing');
  } else {
    try { pack = JSON.parse(dec.decode(evidenceRaw)); } catch { pack = null; }
    if (!pack) push('chain', false, 'evidence.json is not valid JSON');
    else {
      if (pack.kind === 'platform') {
        for (const c of verifyPlatformPack(pack)) checks.push(c);
      } else if (pack.kind === 'risk_profile' || pack.kind === 'regulator') {
        // Aggregate dossiers (Check 12): figures restated from the workspace's records, no sealed entry listed.
        push('aggregate', true, `${pack.kind === 'risk_profile' ? 'risk profile' : 'regulator dossier'}: aggregate figures, no sealed decision listed — its files hash to the manifest, its signature and timestamp bear on it`);
      } else if (['decision', 'litigation', 'exhaustion', 'ai_footprint', 'incident', 'compliance'].includes(pack.kind)) {
        const verify = ['decision', 'litigation', 'exhaustion', 'ai_footprint'].includes(pack.kind) ? verifyDecisionPack : pack.kind === 'incident' ? verifyIncidentPack : verifyCompliancePack;
        for (const c of verify(pack, files, { shipped, pinned })) checks.push(c);
        // 14. An AI footprint statement: its findings hash and count to what the act sealed.
        if (pack.kind === 'ai_footprint') for (const c of verifyFootprintPack(pack)) checks.push(c);
        headTokens = (pack.segments ?? []).filter(seg => seg.anchor).length + (pack.heads ?? []).length;
      } else {
        checks.push(chainCheck(pack));
      }
      // 15. Where the kept chain starts once the journal retention removed its oldest prefix.
      if (pack.kind !== 'platform' && pack.kind !== 'risk_profile' && pack.kind !== 'regulator') for (const c of verifyRetention(pack)) checks.push(c);
      // 6. Client-vault content supplied by the client (--vault-content).
      if (opts.vaultContents?.length) for (const c of verifyVaultContents(pack, opts.vaultContents)) checks.push(c);
      // 11. Each decision's applicable law, decided again from its seal and the shipped packs.
      if (pack.kind !== 'platform') for (const c of verifyJurisdiction(pack.entries, files)) checks.push(c);
      // 13. Each decision's cost, recomputed from its sealed price (and the shipped catalog versions).
      if (pack.kind !== 'platform') for (const c of verifyPricing(pack.entries, files)) checks.push(c);
      // 16. Each entry's time, actor type and trace, as its core seals them.
      if (pack.kind !== 'platform') for (const c of verifySealedFields(pack)) checks.push(c);
    }
  }

  // 4. Trusted timestamp (anchor.tsr, RFC 3161) over the manifest root_hash — read first: Check 18 dates the export by it.
  const tsr = files['anchor.tsr'];
  const anchor = tsr ? checkTimestamp(tsr, String(manifest.root_hash ?? ''), { shipped, pinned }) : null;

  // 18. The hourly platform root a head of the dossier is a leaf of (head-roots.json, outside the manifest), and what
  //     the signature had to state of the roots.
  const citedRoots = checks.filter(c => c.ok && /^compliance\.root\./.test(c.id)).length;
  const rooted = verifyHeadRoots(files, pack, {
    shipped, pinned, published: opts.publishedRoots ?? null,
    anchorAt: anchor?.ok ? anchor.genTime.getTime() : null, dated: headTokens > 0 || citedRoots > 0,
  });
  for (const c of rooted.checks) checks.push(c);

  if (!anchor) {
    if (opts.tsaRootPem && !headTokens && !rooted.proofs) push('timestamp', false, '--tsa-root given, but the dossier carries no RFC 3161 token');
  } else {
    push('timestamp', anchor.ok, anchor.detail);
    if (anchor.ok && pinned) {
      push('timestamp.root', anchor.trusted, anchor.trusted ? `chain ends on the pinned root (${anchor.root})` : 'the TSA chain does not end on the root given with --tsa-root');
    } else if (anchor.ok) {
      push('timestamp.root', true, `chain ends on ${anchor.root}, shipped in the dossier — pin the TSA's own root with --tsa-root <pem>`, 'warn');
    }
    // The export asks for anchor.tsr the moment it signs: a token dated long after the signature was added later.
    const signed = signedAt(files);
    if (anchor.ok && signed !== null && anchor.genTime.getTime() > signed + LATE_ROOT_MS) {
      push('timestamp.dates', true, `anchor.tsr is dated ${anchor.genTime.toISOString()}, ${span(anchor.genTime.getTime() - signed)} after the dossier was signed (${new Date(signed).toISOString()}): the export timestamps the manifest the moment it signs it, so this token was added later — it proves the dossier existed at ${anchor.genTime.toISOString()}, not when it was signed`, 'warn');
    }
  }

  // 12. The dossier's signature (signature.jws, over root_hash) — required, by a pinned key — and,
  //     from format 2, the coverage it commits: the kind, the chain's head at export, the entries listed.
  for (const c of verifyDossierSignature(files, String(manifest.root_hash ?? ''), { keys: opts.keys ?? null, pack })) checks.push(c);

  return { ok: allFilesOk && rootOk && checks.every(c => c.ok), checks };
}
