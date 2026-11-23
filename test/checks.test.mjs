// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Each check of SPEC.md on packs built here from its own rules — an AI footprint statement, a
 * litigation hold, a retention checkpoint, a platform package, a compliance bundle, a decision
 * dossier, an incident dossier, the sealed fields, client-vault content and the dossier's manifest: what passes, and
 * every way to alter it fails, with the reason. The hashes are recomputed with node:crypto, never
 * with the module under test. `node --test test/`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { canonicalCore, computeEntryHash, computeRootHash, verifyChain, verifyDecisionPack, verifyDossier, verifySealedFields, verifyVaultContents } from '../src/verify.mjs';
import { verifyFootprintPack } from '../src/footprint.mjs';
import { verifyHoldDesignation } from '../src/litigation.mjs';
import { verifyRetention } from '../src/retention.mjs';
import { verifyPlatformPack } from '../src/platform.mjs';
import { matchesKind, verifyCompliancePack } from '../src/compliance.mjs';
import { matchesScope, verifyIncidentPack } from '../src/incident.mjs';
import { keyTrustAt } from '../src/keys.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const enc = (s) => new TextEncoder().encode(s);

/** Links seq from…, each over its core, chained from `prev` (the genesis: ''). */
function chainOf(cores, { from = 1, prev = '' } = {}) {
  let p = prev;
  return cores.map((core, i) => {
    const coreCanonical = canonicalCore(core);
    const entryHash = sha(p + coreCanonical);
    const l = { seq: from + i, prevHash: p, entryHash, core, coreCanonical };
    p = entryHash;
    return l;
  });
}
const entry = (l) => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, core: l.core });
const link = (l) => ({ seq: l.seq, prevHash: l.prevHash, entryHash: l.entryHash, coreCanonical: l.coreCanonical });
const byId = (checks, id) => checks.find(c => c.id === id);
const failing = (checks) => checks.filter(c => !c.ok).map(c => c.id);

test('the chain primitives: canonical form, entry hash, root hash', () => {
  assert.equal(canonicalCore({ b: 1, a: { d: [3, { f: 1, e: 2 }], c: undefined } }), '{"a":{"d":[3,{"e":2,"f":1}]},"b":1}');
  assert.equal(computeEntryHash('ab', '{"x":1}'), sha('ab{"x":1}'));
  assert.equal(computeRootHash([{ sha256: 'bb' }, { sha256: 'aa' }]), sha('aabb'));
});

test('a filtered pack verifies through its chain segment; an altered or foreign entry fails', () => {
  const links = chainOf([{ d: 1 }, { d: 2 }, { d: 3 }]);
  const pack = { entries: [entry(links[1])], chain: links.map(link) };
  assert.equal(verifyChain(pack).ok, true);
  assert.equal(verifyChain(pack).listed, 1);
  const altered = { ...pack, entries: [{ ...entry(links[1]), core: { d: 9 } }] };
  assert.match(verifyChain(altered).reason, /listed entry altered/);
  const foreign = chainOf([{ d: 'x' }], { from: 2, prev: links[0].entryHash });
  assert.match(verifyChain({ ...pack, entries: [entry(foreign[0])] }).reason, /not in the verified chain segment/);
  assert.match(verifyChain({ entries: [], chain: [link(links[0]), link(links[2])] }).reason, /seq gap/);
  assert.match(verifyChain({ entries: [{ ...entry(links[0]), prevHash: 'x' }] }).reason, /entry_hash mismatch|genesis/);
});

// ── An AI footprint statement ───────────────────────────────────────────────────────────────────

const FINDINGS = [
  { sha: 'a'.repeat(40), ruleId: 'trailer.co-authored-by', strength: 'declared' },
  { sha: 'b'.repeat(40), ruleId: 'comment.generated', strength: 'marker' },
  { sha: 'b'.repeat(40), ruleId: 'config.assistant-rules', strength: 'config' },
];
const findingsHash = (fs) => sha(fs.map(f => `${f.sha}:${f.ruleId}`).sort().join('\n'));

function footprintPack({ findings = FINDINGS, totals = {}, policy = {}, act = true } = {}) {
  const h = findingsHash(findings);
  const attestation = { id: 'statement-1', findings, findingsHash: h, totals: { findings: 3, declared: 1, markers: 1, config: 1, commitsScanned: 12, ...totals }, config: ['.assistant-rules'] };
  const core = { surface: 'governance', decision: 'ai_footprint_attested', policy: { attestationId: 'statement-1', findingsHash: h, findings: 3, declared: 1, markers: 1, config: 1, ...policy } };
  return { kind: 'ai_footprint', attestation, entries: act ? [entry(chainOf([core])[0])] : [] };
}

test('an AI footprint statement: its findings hash and count to what the sealed act holds', () => {
  const [ok] = verifyFootprintPack(footprintPack());
  assert.equal(ok.ok, true, ok.detail);
  assert.match(ok.detail, /3 findings over 12 commits read: 1 commits declared, 1 with a marker/);
  const fail = (pack, re) => { const [c] = verifyFootprintPack(pack); assert.equal(c.ok, false); assert.match(c.detail, re); };
  fail({}, /no attestation/);
  fail(footprintPack({ findings: [{ ...FINDINGS[0], author: 'someone' }] }), /names an author/);
  fail(footprintPack({ findings: [{ ...FINDINGS[0], sha: 'not-a-commit' }] }), /not a commit and a rule/);
  const p = footprintPack(); p.attestation.findingsHash = 'f'.repeat(64);
  fail(p, /do not hash/);
  fail(footprintPack({ totals: { declared: 2 } }), /counts 2 declared, its findings 1/);
  fail(footprintPack({ totals: { config: 2 } }), /file count is not its files/);
  fail(footprintPack({ act: false }), /no sealed ai_footprint_attested act/);
  fail(footprintPack({ policy: { markers: 0 } }), /does not seal these findings/);
});

// ── A litigation hold ───────────────────────────────────────────────────────────────────────────

function holdPack({ seqs = [10, 9], placedHash, list = [9, 10], placed = true } = {}) {
  const entriesHash = sha([...seqs].sort((a, b) => a - b).join(','));
  const entries = list.map(seq => ({ seq, core: { decision: 'allowed' } }));
  if (placed) entries.push({ seq: 11, core: { decision: 'legal_hold_placed', policy: { holdId: 'hold-1', entriesHash: placedHash ?? entriesHash } } });
  return { kind: 'litigation', hold: { id: 'hold-1', seqs, entriesHash }, entries };
}

test('a litigation hold: the designation is the sha256 of its seqs in numeric order, all listed, sealed when placed', () => {
  const ok = verifyHoldDesignation(holdPack());
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'litigation.designation').detail, /seq 11 designated exactly these 2 decisions/);
  // 9 before 10: a string sort would hash "10,9".
  const lexical = holdPack(); lexical.hold.entriesHash = sha('10,9');
  assert.deepEqual(failing(verifyHoldDesignation(lexical)), ['litigation.designation']);
  assert.match(byId(verifyHoldDesignation(holdPack({ list: [9] })), 'litigation.complete').detail, /not in the dossier: 10/);
  assert.equal(byId(verifyHoldDesignation(holdPack({ placed: false })), 'litigation.designation').level, 'warn');
  assert.match(byId(verifyHoldDesignation(holdPack({ placedHash: 'e'.repeat(64) })), 'litigation.designation').detail, /designated other decisions/);
});

// ── A retention checkpoint ──────────────────────────────────────────────────────────────────────

function retained() {
  const all = chainOf([{ decision: 'allowed' }, { decision: 'allowed' }, { decision: 'allowed' }]);
  const checkpoint = { fromSeq: 1, throughSeq: 3, throughHash: all[2].entryHash, removed: 3 };
  const kept = chainOf([
    { decision: 'journal_retention_applied', policy: { fromSeq: 1, throughSeq: 3, throughHash: all[2].entryHash, removed: 3 } },
    { decision: 'allowed' }, { decision: 'blocked_by_policy' },
  ], { from: 4, prev: all[2].entryHash });
  return { all, kept, checkpoint: { ...checkpoint, actSeq: 4, actHash: kept[0].entryHash } };
}

test('a retention checkpoint: the kept chain starts where the removed prefix ended, declared by its sealed act', () => {
  const { all, kept, checkpoint } = retained();
  const pack = (entries, checkpoints = [checkpoint]) => ({ entries: entries.map(entry), retention: { checkpoints } });
  const ok = verifyRetention(pack(kept));
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'retention.checkpoint').detail, /starts at seq 4: entries 1–3 were removed/);
  assert.match(byId(ok, 'retention.act.4').detail, /sealed this removal before it took place/);
  // An entry of the removed prefix, a first kept entry linked elsewhere, an act declaring another removal.
  assert.match(byId(verifyRetention(pack([all[2], ...kept])), 'retention.checkpoint').detail, /in the prefix the checkpoint says was removed/);
  const elsewhere = chainOf([{ decision: 'allowed' }], { from: 4, prev: 'd'.repeat(64) });
  assert.match(byId(verifyRetention(pack(elsewhere)), 'retention.checkpoint').detail, /does not link to the retention checkpoint/);
  assert.equal(byId(verifyRetention(pack(kept, [{ ...checkpoint, actHash: 'c'.repeat(64) }])), 'retention.act.4').ok, false);
  // Later segments attach; an act outside the dossier, or not shipped with its checkpoint, is said.
  const later = verifyRetention(pack(kept.slice(1)));
  assert.match(byId(later, 'retention.checkpoint').detail, /after the retention checkpoint/);
  assert.equal(byId(later, 'retention.act').level, 'warn');
  assert.match(byId(verifyRetention(pack([])), 'retention.checkpoint').detail, /lists no entry/);
  assert.equal(byId(verifyRetention({ entries: kept.map(entry) }), 'retention').level, 'warn');
  assert.deepEqual(verifyRetention({ entries: kept.slice(1).map(entry) }), []);
  assert.equal(byId(verifyRetention(pack(kept, [{ ...checkpoint, removed: 2 }])), 'retention.checkpoint').ok, false);
  assert.equal(byId(verifyRetention(pack(kept, [])), 'retention.checkpoint').ok, false);
  assert.equal(byId(verifyRetention(pack(kept, [{ ...checkpoint, actSeq: 9 }])), 'retention.act.4').level, 'warn');
});

// ── A platform package ──────────────────────────────────────────────────────────────────────────

const PLATFORM_CORES = [
  { act: 'deployment_recorded', occurredAt: '2026-10-03T09:00:00.000Z', facts: { commit: '1'.repeat(40) } },
  { act: 'restore_drill_recorded', occurredAt: '2026-10-10T09:00:00.000Z', facts: { reportSha256: '2'.repeat(64) } },
  { act: 'deployment_recorded', occurredAt: '2026-10-30T23:59:00.000Z', facts: { commit: '3'.repeat(40) } },
];
const platformPack = (over = {}) => ({
  kind: 'platform', period: { from: '2026-10-01', to: '2026-11-01' }, chain: chainOf(PLATFORM_CORES).map(link),
  counts: { deployment_recorded: 2, restore_drill_recorded: 1 }, snapshot: { platformAdmins: 2 }, ...over,
});

test('a platform package: its month intact from the genesis or its previous link, dated within it, its counts recomputed', () => {
  const ok = verifyPlatformPack(platformPack());
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'platform.seam').detail, /genesis/);
  assert.equal(byId(ok, 'platform.snapshot').level, 'warn');
  assert.equal(byId(verifyPlatformPack(platformPack({ period: { from: '2026-11-01', to: '2026-10-01' } })), 'platform.period').ok, false);
  assert.equal(byId(verifyPlatformPack(platformPack({ chain: undefined })), 'platform.chain').ok, false);
  const broken = platformPack(); broken.chain[1] = { ...broken.chain[1], entryHash: '0'.repeat(64) };
  assert.match(byId(verifyPlatformPack(broken), 'platform.chain').detail, /entry_hash mismatch/);
  assert.match(byId(verifyPlatformPack(platformPack({ counts: { deployment_recorded: 3, restore_drill_recorded: 1 } })), 'platform.counts').detail, /do not recompute/);
  // The next month attaches to this one's last link.
  const prev = chainOf(PLATFORM_CORES);
  const next = chainOf([{ act: 'deployment_recorded', occurredAt: '2026-11-02T09:00:00.000Z' }], { from: 4, prev: prev[2].entryHash });
  const november = (previous) => platformPack({ period: { from: '2026-11-01', to: '2026-12-01' }, chain: next.map(link), counts: { deployment_recorded: 1 }, previous, snapshot: undefined });
  assert.deepEqual(failing(verifyPlatformPack(november({ toSeq: 3, entryHash: prev[2].entryHash }))), []);
  assert.equal(byId(verifyPlatformPack(november({ toSeq: 2, entryHash: prev[1].entryHash })), 'platform.seam').ok, false);
  assert.equal(byId(verifyPlatformPack(november({ toSeq: '3' })), 'platform.seam').ok, false);
  assert.match(byId(verifyPlatformPack(november(undefined)), 'platform.seam').detail, /must start at the genesis/);
  assert.match(byId(verifyPlatformPack(platformPack({ chain: [], counts: {}, previous: { toSeq: 3, entryHash: 'a'.repeat(64) } })), 'platform.seam').detail, /nothing sealed after seq 3/);
  // Dated after the month; a core not in canonical form (hashed as written, so the link holds).
  assert.match(byId(verifyPlatformPack(platformPack({ period: { from: '2026-10-01', to: '2026-10-30' } })), 'platform.dates').detail, /seq 3 is dated at or after/);
  const raw = '{"occurredAt":"2026-10-03T09:00:00.000Z","act":"deployment_recorded"}';
  const loose = platformPack({ chain: [{ seq: 1, prevHash: '', entryHash: sha(raw), coreCanonical: raw }], counts: { deployment_recorded: 1 } });
  assert.match(byId(verifyPlatformPack(loose), 'platform.canonical').detail, /seq 1 is not in canonical form/);
});

// ── A compliance bundle ─────────────────────────────────────────────────────────────────────────

const FRAMEWORK = {
  framework: {
    id: 'demo-framework', version: '1', mappingStatus: 'to_validate',
    requirements: [
      { id: 'REQ-1', required: [['blocks']], applicability: 'all' },
      { id: 'REQ-2', required: [['acts'], ['blocks']], applicability: 'all' },
      { id: 'REQ-3', required: [['org-policy']], applicability: 'high_risk' },
      { id: 'REQ-4', required: [['acts']], applicability: 'all' },
    ],
  },
  kinds: [
    { id: 'blocks', source: 'journal', match: { surface: 'inference', decisionPrefixes: ['blocked_'], policy: { ruleId: { present: true } } } },
    { id: 'acts', source: 'journal', match: { surface: 'governance', decisions: ['policy_rule_published'], corePresent: ['policyVersion'] } },
    { id: 'org-policy', source: 'external' },
    { id: 'heads', source: 'anchor' },
  ],
};

function bundle(edit = () => {}) {
  const links = chainOf([
    { surface: 'inference', decision: 'allowed' },
    { surface: 'inference', decision: 'blocked_by_policy', policy: { ruleId: 'rule-1' } },
    { surface: 'governance', decision: 'policy_rule_published', policyVersion: 'v'.repeat(64) },
    { surface: 'governance', decision: 'compliance_scope_declared', policy: { requirementId: 'REQ-4', frameworkId: 'demo-framework', justificationHash: 'j'.repeat(64) } },
  ]);
  const doc = structuredClone(FRAMEWORK);
  const pack = {
    kind: 'compliance',
    framework: { id: 'demo-framework', file: 'framework.json', sha256: '' },
    disclaimer: { en: 'A tool to prepare an audit.', fr: 'Un outil pour préparer un audit.' },
    segments: [{ fromSeq: 1, toSeq: 4, links: links.map(link) }],
    entries: [entry(links[1]), entry(links[2]), entry(links[3])],
    requirements: [
      { id: 'REQ-1', status: 'covered', evidence: { blocks: { cited: [2], sealed: 1 } } },
      { id: 'REQ-2', status: 'covered', evidence: { acts: { cited: [3], sealed: 1 }, blocks: { cited: [2], sealed: 1 } } },
      { id: 'REQ-3', status: 'out_of_scope', reason: 'not_applicable', evidence: {} },
      { id: 'REQ-4', status: 'out_of_scope', reason: 'declared_out_of_scope', evidence: {} },
    ],
    scope: [{ requirementId: 'REQ-4', seq: 4, justificationHash: 'j'.repeat(64) }],
    context: { highRiskUseCases: 0 },
    summary: { total: 4, covered: 2, partial: 0, notCovered: 0, outOfScope: 2, applicable: 2, rate: 1 },
  };
  edit(pack, doc, links);
  const bytes = enc(JSON.stringify(doc));
  if (!pack.framework.sha256) pack.framework.sha256 = sha(bytes);
  return { pack, files: { 'framework.json': bytes } };
}
const comply = (edit) => { const { pack, files } = bundle(edit); return verifyCompliancePack(pack, files); };

test('a compliance bundle: every covered requirement rests on cited sealed evidence of each required group', () => {
  const ok = comply();
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'compliance.coverage').detail, /2 requirement\(s\) covered/);
  assert.match(byId(ok, 'compliance.summary').detail, /2 covered \/ 2 applicable \(100 %\)/);
  assert.equal(byId(ok, 'compliance.mapping').level, 'warn');
  assert.equal(byId(ok, 'compliance.applicability').level, 'warn');
});

test('a compliance bundle never inflates: each altered claim fails with its reason', () => {
  const reason = (edit, id) => byId(comply(edit), id).detail;
  const fails = (edit, id) => assert.equal(byId(comply(edit), id).ok, false, id);
  fails((p) => { p.framework.file = 'other.json'; }, 'compliance.framework');
  fails((p) => { p.framework.sha256 = 'f'.repeat(64); }, 'compliance.framework');
  fails((p, d) => { d.framework.id = 'another-framework'; }, 'compliance.framework');
  fails((p) => { p.disclaimer = { en: '' }; }, 'compliance.disclaimer');
  assert.match(reason((p) => { p.entries[0] = { ...p.entries[0], core: { ...p.entries[0].core, decision: 'blocked_by_budget' } }; }, 'compliance.chain'), /cited entry altered/);
  assert.match(reason((p) => { p.segments = []; }, 'compliance.chain'), /not in a verified chain segment/);
  assert.match(reason((p) => { p.segments[0].toSeq = 5; }, 'compliance.chain'), /does not hold its declared range/);
  assert.match(reason((p) => { p.requirements[0].evidence.blocks.cited = [3]; }, 'compliance.citations'), /entry 3 is not evidence of blocks/);
  assert.match(reason((p) => { p.requirements[0].evidence.blocks.cited = [7]; p.requirements[0].evidence.blocks.sealed = 1; }, 'compliance.citations'), /not a verified entry/);
  assert.match(reason((p) => { p.requirements[0].evidence.blocks.sealed = 0; }, 'compliance.citations'), /more blocks entries cited than counted/);
  assert.match(reason((p) => { p.requirements[2].evidence = { 'org-policy': { cited: [], sealed: 1 } }; }, 'compliance.citations'), /only the organisation provides/);
  assert.match(reason((p) => { p.requirements[0].evidence = { unknown: { cited: [] } }; }, 'compliance.citations'), /kind unknown is not in the framework file/);
  assert.match(reason((p) => { p.requirements[0].evidence.heads = { cited: [4], sealed: 1 }; }, 'compliance.citations'), /head 4 cited as heads is not a verified timestamped head/);
  assert.match(reason((p) => { p.requirements[1].evidence.acts = { cited: [], sealed: 0 }; }, 'compliance.coverage'), /REQ-2 is marked covered without verified evidence/);
  assert.match(reason((p) => { p.requirements.pop(); p.scope = []; }, 'compliance.coverage'), /left out of the bundle: REQ-4/);
  assert.match(reason((p) => { p.requirements.push({ id: 'REQ-9', status: 'covered', evidence: {} }); }, 'compliance.coverage'), /REQ-9 is not a requirement/);
  assert.match(reason((p) => { p.scope[0].justificationHash = 'k'.repeat(64); }, 'compliance.coverage'), /REQ-4 is declared out of scope without its sealed declaration/);
  assert.match(reason((p) => { p.context.highRiskUseCases = 1; }, 'compliance.coverage'), /REQ-3 is marked not applicable/);
  fails((p) => { p.summary.covered = 3; }, 'compliance.summary');
  fails((p) => { p.summary.rate = 0.5; }, 'compliance.summary');
  assert.match(reason((p) => { p.heads = [{ journalSeq: 4, file: 'heads/4.tsr' }]; }, 'compliance.head.4'), /heads\/4\.tsr missing/);
  assert.match(reason((p) => { p.segments[0].anchor = { file: 'anchor-4.tsr' }; }, 'compliance.anchor.4'), /anchor-4\.tsr missing/);
  // Entries verified one by one need no segment.
  assert.equal(byId(comply((p) => { p.segments = []; p.integrity = { inclusion: 'individual' }; }), 'compliance.chain').ok, true);
});

test('a compliance bundle\'s rooted heads (source root) are held to Check 18\'s proof: one that does not hold is no evidence', () => {
  const WS = randomUUID();
  const H = (...parts) => { const h = createHash('sha256'); for (const x of parts) h.update(x); return h.digest('hex'); };
  const claims = Buffer.from(JSON.stringify({ v: 2, ws: WS, iat: 1_763_715_600 })).toString('base64url');
  const rooted = (edit = () => {}, extra = {}) => {
    const { pack, files } = bundle((p, d, links) => {
      d.kinds.push({ id: 'rooted', source: 'root' });
      p.workspaceId = WS;
      // A one-leaf tree: its root is the head's leaf hash (RFC 9162), written here with node:crypto.
      const root = H(Uint8Array.of(0), enc(`azoth.journal-head.v1\n${WS}\n4\n${links[3].entryHash}`));
      p.rootedHeads = [{ seq: 4, entryHash: links[3].entryHash, leafIndex: 0, treeSize: 1, path: [], root, hour: '2026-11-21T10:00:00.000Z', token: 'roots/head-root.20261121T10Z.tsr' }];
      p.rootChain = 'roots/head-roots-chain.pem';
      p.requirements[0].evidence.rooted = { cited: [4], sealed: 1 };
      edit(p);
    });
    return verifyCompliancePack(pack, {
      ...files, 'roots/head-root.20261121T10Z.tsr': Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x00), 'roots/head-roots-chain.pem': enc('no certificate here'),
      'signature.jws': enc(`e30.${claims}.sig`), ...extra,
    });
  };
  // The path leads to the root; the token is not one: the head is not verified, its citation refused.
  const tokenless = rooted();
  assert.equal(byId(tokenless, 'compliance.root.4').ok, false);
  assert.match(byId(tokenless, 'compliance.root.4').detail, /the platform root of 2026-11-21T10:00:00\.000Z: /);
  assert.match(byId(tokenless, 'compliance.citations').detail, /head 4 cited as rooted is not a verified head of an hourly root/);
  // Its root altered, a seq the bundle's verified segments do not hold, another workspace's journal.
  assert.match(byId(rooted(p => { p.rootedHeads[0].root = 'b'.repeat(64); }), 'compliance.root.4').detail, /does not lead to the root/);
  assert.match(byId(rooted(p => { p.rootedHeads[0].seq = 7; }), 'compliance.root.7').detail, /seq 7 is not one of the sealed links/);
  assert.match(byId(rooted(p => { p.segments = []; p.integrity = { inclusion: 'individual' }; }), 'compliance.root.4').detail, /seq 4 is not one of the sealed links/);
  assert.match(byId(rooted(p => { p.workspaceId = undefined; }), 'compliance.root.4').detail, /names no workspace/);
  assert.match(byId(rooted(p => { p.rootedHeads[0].seq = 'x'; }), 'compliance.root.?').detail, /not one of the sealed links/);
  // A chain file that is not one, or none at all: the proof is still read, its token still refused.
  assert.equal(byId(rooted(p => { p.rootChain = null; }), 'compliance.root.4').ok, false);
  // No rooted head cited and none shipped: no line, the bundle as before.
  assert.deepEqual(failing(rooted(p => { p.rootedHeads = []; delete p.requirements[0].evidence.rooted; })), []);
});

test('an evidence kind is a predicate over the sealed core', () => {
  const [blocks, acts, external] = FRAMEWORK.kinds;
  assert.equal(matchesKind(blocks, { surface: 'inference', decision: 'blocked_by_law', policy: { ruleId: 'r' } }), true);
  assert.equal(matchesKind(blocks, { surface: 'inference', decision: 'blocked_by_law', policy: { ruleId: null } }), false);
  assert.equal(matchesKind(blocks, { surface: 'governance', decision: 'blocked_by_law', policy: { ruleId: 'r' } }), false);
  assert.equal(matchesKind(blocks, { surface: 'inference', decision: 'allowed', policy: { ruleId: 'r' } }), false);
  assert.equal(matchesKind(acts, { surface: 'governance', decision: 'policy_rule_published', policyVersion: 'v' }), true);
  assert.equal(matchesKind(acts, { surface: 'governance', decision: 'policy_rule_published' }), false);
  assert.equal(matchesKind({ id: 'eq', source: 'journal', match: { surface: 'guard', policy: { mode: { eq: 'enforce' } } } }, { surface: 'guard', policy: { mode: 'observe' } }), false);
  assert.equal(matchesKind({ id: 'eq', source: 'journal', match: { surface: 'guard', policy: { mode: { eq: 'enforce' } } } }, { surface: 'guard', policy: { mode: 'enforce' } }), true);
  assert.equal(matchesKind(external, { surface: 'inference' }), false);
  assert.equal(matchesKind(blocks, null), false);
});

// ── A decision dossier (and the dossiers checked like one) ──────────────────────────────────────

const REF = 'r'.repeat(64);
function decisionPack(edit = () => {}) {
  const policyText = enc('{"rules":[]}');
  const policyHash = sha(policyText);
  const links = chainOf([
    { surface: 'inference', decision: 'allowed', decisionRefHash: REF, policyVersion: policyHash },
    { surface: 'inference', decision: 'allowed' },
    { surface: 'inference', decision: 'blocked_by_policy', decisionRefHash: REF, policyVersion: policyHash, usecaseSnapshotHash: 'u'.repeat(64) },
  ]);
  const pack = {
    kind: 'decision', decisionRefHash: REF,
    segments: [{ fromSeq: 1, toSeq: 3, links: links.map(link) }],
    entries: [entry(links[0]), entry(links[2])],
    policies: { [policyHash]: { file: `policies/${policyHash}.json` } },
  };
  const files = { [`policies/${policyHash}.json`]: policyText };
  edit(pack, files, links);
  return verifyDecisionPack(pack, files);
}

test('a decision dossier: its calls carry its reference, sit in verified segments, under the policy archived with them', () => {
  const ok = decisionPack();
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'decision.chain').detail, /2 calls of this decision, in 1 verified chain segment\(s\) \(3 links\)/);
  assert.equal(byId(ok, 'decision.anchor').level, 'warn');
  assert.equal(ok.find(c => c.id.startsWith('decision.usecase.')).level, 'warn');   // sealed, its text not archived
  const reason = (edit) => byId(decisionPack(edit), 'decision.chain').detail;
  assert.match(reason((p, f, l) => { p.entries.push(entry(l[1])); }), /entry 2 does not carry this dossier's decision reference/);
  assert.match(reason((p) => { p.entries[0] = { ...p.entries[0], core: { ...p.entries[0].core, decision: 'blocked_by_budget' } }; }), /listed entry altered/);
  assert.match(reason((p) => { p.segments[0].fromSeq = 2; }), /does not hold its declared range/);
  assert.match(reason((p) => { p.segments[0].links[1] = { ...p.segments[0].links[1], entryHash: '0'.repeat(64) }; }), /entry_hash mismatch/);
  assert.match(reason((p) => { p.segments = []; }), /not in a verified chain segment/);
  const policy = decisionPack((p, f) => { for (const k of Object.keys(f)) f[k] = enc('{"rules":["changed"]}'); });
  assert.match(policy.find(c => c.id.startsWith('decision.policy.')).detail, /does not hash to the sealed policy/);
  assert.match(byId(decisionPack((p) => { p.segments[0].anchor = { file: 'heads/3.tsr' }; }), 'decision.anchor.3').detail, /heads\/3\.tsr missing/);
});

test('litigation, exhaustion and footprint dossiers hold only their own acts and designated decisions', () => {
  const links = chainOf([
    { surface: 'inference', decision: 'allowed' },
    { surface: 'governance', decision: 'legal_hold_placed', policy: { holdId: 'hold-1', entriesHash: sha('1') } },
    { surface: 'governance', decision: 'exhaustion_tier_changed', policy: { incidentId: 'incident-1' } },
  ]);
  const segments = [{ fromSeq: 1, toSeq: 3, links: links.map(link) }];
  const lit = verifyDecisionPack({ kind: 'litigation', hold: { id: 'hold-1', seqs: [1], entriesHash: sha('1') }, segments, entries: [entry(links[0]), entry(links[1])] }, {});
  assert.deepEqual(failing(lit), []);
  assert.ok(lit.some(c => c.id === 'litigation.chain'));
  assert.match(byId(verifyDecisionPack({ kind: 'litigation', hold: { id: 'hold-1', seqs: [], entriesHash: sha('') }, segments, entries: [entry(links[0])] }, {}), 'litigation.chain').detail, /neither designated by this hold nor one of its acts/);
  const exh = (id) => verifyDecisionPack({ kind: 'exhaustion', incident: { id }, segments, entries: [entry(links[2])] }, {});
  assert.equal(byId(exh('incident-1'), 'exhaustion.chain').ok, true);
  assert.match(byId(exh('incident-2'), 'exhaustion.chain').detail, /not an act of this exhaustion incident/);
  assert.match(byId(verifyDecisionPack({ kind: 'ai_footprint', attestation: { id: 'statement-1' }, segments, entries: [entry(links[2])] }, {}), 'ai_footprint.chain').detail, /not this AI footprint statement's act/);
});

// ── The sealed fields, client-vault content ─────────────────────────────────────────────────────

test('the time, actor type and trace an entry shows are the ones its core seals', () => {
  const sealed = { seq: 1, occurredAt: '2026-11-14T10:00:00.123+00:00', actorType: 'api_key', traceId: 't-1', core: { occurredAt: '2026-11-14T10:00:00.123Z', actorType: 'api_key', traceId: 't-1' } };
  assert.deepEqual(verifySealedFields({ entries: [sealed] }).map(c => [c.id, c.ok, c.level]), [['sealed.fields', true, undefined]]);
  assert.match(verifySealedFields({ entries: [{ ...sealed, occurredAt: '2026-11-14T10:00:00.124Z' }] })[0].detail, /occurredAt is not the one sealed/);
  assert.match(verifySealedFields({ entries: [{ ...sealed, traceId: 't-2' }] })[0].detail, /traceId is not the one sealed/);
  assert.equal(verifySealedFields({ entries: [{ ...sealed, occurredAt: 'yesterday' }] })[0].ok, false);
  const legacy = { seq: 2, occurredAt: '2026-01-01T00:00:00Z', core: { decision: 'allowed' } };
  assert.match(verifySealedFields({ entries: [sealed, legacy] })[0].detail, /1 of 2 entries carry a sealed time/);
  assert.match(verifySealedFields({ entries: [legacy] })[0].detail, /none of the 1 entries carries a sealed time/);
  assert.deepEqual(verifySealedFields({ entries: [] }), []);
  // In an incident dossier, the journal read for completeness: its time as sealed.
  const l = { seq: 3, occurredAt: '2026-11-14T11:00:00+01:00', coreCanonical: canonicalCore({ occurredAt: '2026-11-14T10:00:00Z' }) };
  assert.equal(verifySealedFields({ entries: [sealed], impact: { completeness: { links: [l] } } })[0].ok, true);
});

test('client-vault content matches the plaintext or the envelope a sealed receipt hashed', () => {
  const plain = enc('the decrypted call'), cipher = enc('the stored envelope');
  const pack = { entries: [{ seq: 4, traceId: 't-4', core: { decision: 'vault_receipt', policy: { vaultPlaintextHash: sha(plain), vaultCiphertextHash: sha(cipher) } } }] };
  const out = verifyVaultContents(pack, [{ name: 'a', bytes: plain }, { name: 'b', bytes: cipher }, { name: 'c', bytes: enc('altered') }]);
  assert.deepEqual(out.map(c => [c.id, c.ok]), [['vault.a', true], ['vault.b', true], ['vault.c', false]]);
  assert.match(out[1].detail, /the stored envelope sealed by the receipt at seq 4/);
  assert.deepEqual(verifyVaultContents({ entries: [] }, [{ name: 'a', bytes: plain }]).map(c => [c.id, c.ok]), [['vault.a', false], ['vault', false]]);
});

// ── The dossier: its manifest, evidence and what it dispatches to ───────────────────────────────

function dossier(evidence, extra = {}) {
  const files = { 'evidence.json': enc(JSON.stringify(evidence)), ...extra };
  const list = Object.entries(files).map(([path, bytes]) => ({ path, sha256: sha(bytes) }));
  return { ...files, 'manifest.json': enc(JSON.stringify({ format_version: 1, files: list, root_hash: sha(list.map(f => f.sha256).sort().join('')) })) };
}

test('the manifest: every file hashes to it, its root hash to the files; a dossier without a signature never verifies', () => {
  const links = chainOf([{ decision: 'allowed' }, { decision: 'blocked_by_policy' }]);
  const files = dossier({ entries: links.map(entry) });
  const r = verifyDossier(files);
  assert.equal(r.ok, false);                                 // no signature.jws: nothing binds it to a key
  assert.equal(byId(r.checks, 'manifest.root_hash').ok, true);
  assert.match(byId(r.checks, 'chain').detail, /chain intact \(2 sealed decisions\)/);
  assert.equal(failing(r.checks).every(id => id.startsWith('signature')), true, failing(r.checks).join(', '));
  const altered = { ...files, 'evidence.json': enc(JSON.stringify({ entries: [entry(links[1])] })) };
  assert.match(byId(verifyDossier(altered).checks, 'file.evidence.json').detail, /sha256 mismatch/);
  const { 'evidence.json': _, ...without } = files;
  assert.equal(byId(verifyDossier(without).checks, 'file.evidence.json').detail, 'listed in manifest but absent');
  assert.equal(byId(verifyDossier(without).checks, 'chain').detail, 'evidence.json missing');
  const m = JSON.parse(new TextDecoder().decode(files['manifest.json'])); m.root_hash = '0'.repeat(64);
  assert.equal(byId(verifyDossier({ ...files, 'manifest.json': enc(JSON.stringify(m)) }).checks, 'manifest.root_hash').ok, false);
  assert.deepEqual(verifyDossier({}).checks.map(c => c.id), ['manifest.present']);
  assert.deepEqual(verifyDossier({ 'manifest.json': enc('{not json') }).checks.map(c => c.id), ['manifest.parse']);
  assert.equal(byId(verifyDossier(dossier({ entries: [] }, {}), {}).checks, 'chain').ok, true);
  const bad = { ...files, 'evidence.json': enc('{not json') };
  assert.equal(byId(verifyDossier(bad).checks, 'chain').detail, 'evidence.json is not valid JSON');
});

test('the dossier dispatches each kind to its check, and refuses a TSA root it cannot read', () => {
  const platform = verifyDossier(dossier(platformPack()));
  assert.equal(byId(platform.checks, 'platform.chain').ok, true);
  assert.equal(byId(platform.checks, 'platform.counts').ok, true);
  const aggregate = verifyDossier(dossier({ kind: 'risk_profile', figures: {} }));
  assert.match(byId(aggregate.checks, 'aggregate').detail, /risk profile: aggregate figures/);
  const footprint = verifyDossier(dossier({ ...footprintPack(), segments: [] }));
  assert.equal(byId(footprint.checks, 'ai_footprint').ok, true);
  const { pack, files } = bundle();
  assert.equal(byId(verifyDossier(dossier(pack, files)).checks, 'compliance.coverage').ok, true);
  const plain = dossier({ entries: [] });
  assert.equal(byId(verifyDossier(plain, { tsaRootPem: 'no certificate here' }).checks, 'timestamp.root').detail, '--tsa-root holds no certificate');
  assert.match(byId(verifyDossier(plain, { tsaRootPem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----' }).checks, 'timestamp').detail, /carries no RFC 3161 token/);
});

// ── An incident dossier ─────────────────────────────────────────────────────────────────────────

const SCOPE = { model: 'model-a', from: '2026-11-01T00:00:00Z' };
const REPORT = enc('# Draft report\n');

function incident(edit = () => {}) {
  const scopeCanonical = canonicalCore(SCOPE);
  const scopeHash = sha(scopeCanonical);
  const act = (decision, policy) => ({ surface: 'governance', decision, policy: { incidentId: 'incident-1', scopeHash, ...policy } });
  const calls = chainOf([
    { surface: 'inference', decision: 'allowed', model: 'model-a' },
    { surface: 'inference', decision: 'allowed', model: 'model-b' },
  ]);
  const declared = chainOf([act('incident_declared', { incidentStep: 1, scope: scopeCanonical })], { from: 3, prev: calls[1].entryHash });
  const scoped = chainOf([act('incident_scoped', { incidentStep: 2, matched: 1, throughSeq: 3, setHash: sha(calls[0].entryHash) })], { from: 4, prev: declared[0].entryHash });
  const drafted = chainOf([act('incident_report_drafted', { incidentStep: 3, draftId: 'draft-0001', sha256: sha(REPORT) })], { from: 5, prev: scoped[0].entryHash });
  const at = '2026-11-02T08:00:00Z';
  const journal = [...calls, ...declared, ...scoped, ...drafted];
  const pack = {
    kind: 'incident', incidentId: 'incident-1', scopeHash, scope: SCOPE,
    segments: [{ fromSeq: 3, toSeq: 5, links: journal.slice(2).map(link) }],
    entries: journal.slice(2).map(entry),
    impact: {
      decisions: [{ seq: 1, entryHash: calls[0].entryHash }],
      entries: [{ ...entry(calls[0]), occurredAt: at }],
      completeness: { links: journal.slice(0, 3).map(l => ({ ...link(l), occurredAt: at })) },
    },
    reports: { 'draft-0001': { file: 'reports/draft.md' } },
  };
  const files = { 'reports/draft.md': REPORT };
  edit(pack, files, journal);
  return verifyIncidentPack(pack, files);
}

test('an incident dossier: its actions in order, its scope as declared, the matched set complete over the journal', () => {
  const ok = incident();
  assert.deepEqual(failing(ok), []);
  assert.match(byId(ok, 'incident.impact').detail, /1 matched decisions up to seq 3: the set sealed at step 2/);
  assert.match(byId(ok, 'incident.completeness').detail, /no other sealed decision matches the scope/);
  assert.match(byId(ok, 'incident.report.draft-00').detail, /is the draft sealed at step 3/);
  assert.equal(byId(ok, 'incident.anchor').level, 'warn');
});

test('an incident dossier fails on every altered action, scope, set or draft', () => {
  const reason = (edit, id) => byId(incident(edit), id)?.detail;
  assert.match(reason((p) => { p.entries[0] = { ...p.entries[0], core: { ...p.entries[0].core, decision: 'incident_closed' } }; }, 'incident.actions'), /action altered/);
  assert.match(reason((p, f, j) => { p.entries.unshift(entry(j[1])); }, 'incident.actions'), /entry 2 is not an incident action/);
  assert.match(reason((p) => { p.incidentId = 'incident-2'; }, 'incident.actions'), /does not name this incident/);
  assert.match(reason((p) => { p.segments = []; }, 'incident.actions'), /not in a verified chain segment/);
  assert.match(reason((p) => { p.segments[0].toSeq = 6; }, 'incident.actions'), /does not hold its declared range/);
  assert.equal(byId(incident((p) => { p.entries = []; p.segments = []; }), 'incident.actions').detail, 'no sealed action');
  assert.match(reason((p) => { p.entries.pop(); p.entries.push({ ...p.entries[1] }); }, 'incident.order'), /an action is missing or duplicated/);
  assert.equal(byId(incident((p) => { p.scope = { model: 'model-b' }; }), 'incident.scope').ok, false);
  assert.match(reason((p, f, j) => { p.impact.decisions = [{ seq: 1, entryHash: j[1].entryHash }]; }, 'incident.impact'), /do not hash to the sealed set/);
  assert.match(reason((p, f, j) => { p.impact.entries = [{ ...entry(j[1]), occurredAt: '2026-11-02T08:00:00Z' }]; }, 'incident.matched'), /entry 2 is not in the sealed matched set/);
  assert.match(reason((p) => { p.impact.entries[0] = { ...p.impact.entries[0], occurredAt: '2026-10-01T00:00:00Z' }; }, 'incident.matched'), /does not match the scope/);
  assert.match(reason((p) => { p.impact.entries[0] = { ...p.impact.entries[0], core: { surface: 'inference' } }; }, 'incident.matched'), /matched entry 1 altered/);
  assert.match(reason((p) => { p.impact.completeness.links = p.impact.completeness.links.slice(1); }, 'incident.completeness'), /is not seq 1–3/);
  assert.match(reason((p) => { for (const l of p.impact.completeness.links) l.occurredAt = '2026-10-01T00:00:00Z'; }, 'incident.completeness'), /matches 0 entries of the journal, the sealed set holds 1/);
  assert.match(reason((p, f) => { f['reports/draft.md'] = enc('# Edited\n'); }, 'incident.report.draft-00'), /does not hash to the sealed draft/);
  assert.equal(byId(incident((p) => { p.reports = {}; }), 'incident.report.draft-00').level, 'warn');
  assert.equal(byId(incident((p) => { delete p.impact.decisions; }), 'incident.impact').level, 'warn');
  assert.equal(byId(incident((p) => { delete p.impact.completeness; }), 'incident.completeness').level, 'warn');
  assert.match(reason((p) => { p.segments[0].anchor = { file: 'heads/5.tsr' }; }, 'incident.anchor.5'), /heads\/5\.tsr missing/);
});

test('the incident scope is a predicate over the sealed core and the capture time', () => {
  const core = { surface: 'inference', model: 'model-a', agentId: 'agent-1', tools: [{ name: 'search' }], dataSources: [{ type: 'crm', id: 'crm-1' }] };
  const at = '2026-11-02T08:00:00Z';
  assert.equal(matchesScope(core, at, { model: 'model-a', agentId: 'agent-1' }), true);
  assert.equal(matchesScope(core, at, { agentId: 'agent-2' }), false);
  assert.equal(matchesScope(core, at, { tool: 'search' }), true);
  assert.equal(matchesScope(core, at, { tool: 'mail' }), false);
  assert.equal(matchesScope(core, at, { dataSource: { type: 'crm' } }), true);
  assert.equal(matchesScope(core, at, { dataSource: { type: 'crm', id: 'crm-2' } }), false);
  assert.equal(matchesScope(core, at, { to: '2026-11-02T08:00:00Z' }), false);   // the end is excluded
  assert.equal(matchesScope({ surface: 'governance', decision: 'blocked_by_policy' }, at, { refusalDecisions: ['blocked_by_policy'] }), true);
  assert.equal(matchesScope({ surface: 'governance', decision: 'policy_rule_published' }, at, {}), false);
  assert.equal(matchesScope(null, at, {}), true);
});

test('a key its producer declared compromised: refused at or after its instant, a warning before — one rule (keys.mjs)', () => {
  const key = { status: 'compromised', compromised_at: '2026-11-17T10:00:00.000Z', compromise_declared_at: '2026-11-17T12:00:00.000Z' };
  const at = (iso) => Math.floor(Date.parse(iso) / 1000);
  assert.equal(keyTrustAt(key, at('2026-11-17T10:00:00.000Z')).ok, false);                       // at the instant
  assert.match(keyTrustAt(key, at('2026-11-17T11:00:00.000Z')).detail, /declared it compromised/);
  const before = keyTrustAt(key, at('2026-11-17T09:59:59.000Z'));
  assert.equal(before.ok, true);
  assert.match(before.warn, /signer's own claim/);
  // Fail-closed: no readable instant, an unknown status, an unreadable date.
  assert.equal(keyTrustAt({ status: 'compromised' }, at('2000-01-01T00:00:00.000Z')).ok, false);
  assert.equal(keyTrustAt({ status: 'revoked' }, at('2000-01-01T00:00:00.000Z')).ok, false);
  assert.equal(keyTrustAt(key, NaN).ok, false);
  // An active, retired or status-less key (an older producer) is trusted as before.
  for (const status of ['active', 'retired', undefined]) assert.deepEqual(keyTrustAt({ status }, at('2026-11-17T11:00:00.000Z')), { ok: true });
});
