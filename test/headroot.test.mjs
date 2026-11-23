// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Check 18 — the hourly platform root (SPEC.md): the leaf and node encoding recomputed here with node:crypto, never
 * with the module under test; a tree built here, from SPEC.md's rules, for every size from 1 to 20 — every leaf's
 * path walks to its root, a wrong index, sibling or leaf does not; and a dossier's head-roots.json refused for every
 * way it can be wrong before its token is even read. A real token's verification is Check 4's (timestamp.test.mjs).
 * `node --test`, nothing to install.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import {
  headLeafHash, headLeafHex, headNodeHash, rootFromPath, verifyHeadRoots, HEAD_ROOTS_FILE,
  rootDates, verifyRootsClaim, newestSealed, span, ROOT_CLOCK_TOLERANCE_MS, LATE_ROOT_MS,
  readPublishedRoots, comparePublished, publishedConflicts, PUBLISHED_ROOTS_FORMAT, signedAt, verifyRootProof,
  ROOTS_STATED_FROM, verifyRootsStatement, verifyPublishedCoverage, exportedAt,
} from '../src/headroot.mjs';
import { carried } from '../src/signature.mjs';

const H = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return new Uint8Array(h.digest()); };
const sha = (s) => createHash('sha256').update(s).digest('hex');
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const WS = randomUUID();
const leafOf = (subject, seq, entryHash) => H(Uint8Array.of(0), enc(`azoth.journal-head.v1\n${subject}\n${seq}\n${entryHash}`));

/** RFC 9162 §2.1.1 and §2.1.3.1, written here: the largest power of two below n on the left. */
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (d) => (d.length === 1 ? d[0] : H(Uint8Array.of(1), mth(d.slice(0, split(d.length))), mth(d.slice(split(d.length)))));
const path = (m, d) => {
  if (d.length === 1) return [];
  const k = split(d.length);
  return m < k ? [...path(m, d.slice(0, k)), mth(d.slice(k))] : [...path(m - k, d.slice(k)), mth(d.slice(0, k))];
};

test('the leaf is SHA-256(0x00 ‖ "azoth.journal-head.v1" LF subject LF seq LF entryHash); a node SHA-256(0x01 ‖ left ‖ right)', () => {
  const e = sha('e');
  assert.equal(hex(headLeafHash(WS, 42, e)), hex(leafOf(WS, 42, e)));
  assert.equal(hex(headLeafHash('platform', 7, e)), hex(leafOf('platform', 7, e)));
  assert.equal(headLeafHex(WS, 42, e), hex(leafOf(WS, 42, e)));
  const [a, b] = [leafOf(WS, 1, e), leafOf(WS, 2, e)];
  assert.equal(hex(headNodeHash(a, b)), hex(H(Uint8Array.of(1), a, b)));
  assert.throws(() => headLeafHash(`ws-${WS}`, 1, e));
  assert.throws(() => headLeafHash(`${WS.slice(0, -1)}G`, 1, e));
  assert.throws(() => headLeafHash(WS, 0, e));
  assert.throws(() => headLeafHash(WS, 1, e.toUpperCase()));
});

test('every leaf of every tree from 1 to 20 leaves walks to its root; a wrong index, sibling or leaf does not', () => {
  for (let n = 1; n <= 20; n++) {
    const d = Array.from({ length: n }, (_, i) => leafOf(WS, i + 1, sha(`l${i}`)));
    const root = hex(mth(d));
    for (let m = 0; m < n; m++) {
      const p = path(m, d);
      assert.equal(hex(rootFromPath(d[m], m, n, p)), root, `leaf ${m} of ${n}`);
      if (n > 1) {
        assert.notEqual(hex(rootFromPath(d[(m + 1) % n], m, n, p) ?? new Uint8Array()), root);
        const bent = p.map((x, i) => (i === 0 ? H(enc('x')) : x));
        assert.notEqual(hex(rootFromPath(d[m], m, n, bent) ?? new Uint8Array()), root);
      }
    }
    assert.equal(rootFromPath(d[0], n, n, path(0, d)), null);
  }
});

// A dossier pack with seq 1–3, and a proof built here for its head at seq 3 in a 3-leaf tree.
const links = [1, 2, 3].map(seq => ({ seq, entryHash: sha(`link${seq}`) }));
const pack = { workspaceId: WS, entries: links };
const others = [randomUUID(), randomUUID()];
const d = [leafOf(WS, 3, links[2].entryHash), ...others.map((s, i) => leafOf(s, 9, sha(`o${i}`)))];
const proof = { seq: 3, entryHash: links[2].entryHash, leafIndex: 0, treeSize: 3, path: path(0, d).map(hex), root: hex(mth(d)), hour: '2026-11-21T10:00:00.000Z', token: 'head-root.20261121T10Z.tsr' };
const files = (edit = (x) => x, extra = {}) => ({
  [HEAD_ROOTS_FILE]: enc(JSON.stringify(edit({ v: 1, leaf: 'azoth.journal-head.v1', subject: WS, chain: null, proofs: [{ ...proof, path: [...proof.path] }] }))),
  'head-root.20261121T10Z.tsr': Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x00),
  ...extra,
});
const only = (f, p = pack) => verifyHeadRoots(f, p).checks;

test('no head-roots.json: nothing to check', () => {
  assert.deepEqual(verifyHeadRoots({}, pack), { proofs: 0, checks: [] });
});

test('a proof that holds reaches the token — here a malformed one, refused by Check 4\'s reader', () => {
  const [c] = only(files());
  assert.equal(c.ok, false);
  assert.match(c.detail, /the platform root of 2026-11-21T10:00:00.000Z: anchor\.tsr unreadable|platform root/);
});

test('refused before the token: another seq, another workspace, a seq the dossier does not carry, a path, a root', () => {
  const detail = (edit, p) => only(files(edit), p)[0].detail;
  assert.match(detail(x => { x.proofs[0].seq = 2; delete x.proofs[0].entryHash; return x; }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].entryHash = sha('other'); return x; }), /names another hash/);
  assert.match(detail(x => { x.proofs[0].seq = 9; return x; }), /not one of the sealed links/);
  assert.match(detail(x => { x.proofs[0].subject = others[0]; return x; }), /the dossier is/);
  assert.match(detail(x => x, { ...pack, workspaceId: others[0] }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].path[0] = sha('x'); return x; }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].path.push(sha('x')); return x; }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].root = sha('x'); return x; }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].leafIndex = 1; return x; }), /does not lead to the root/);
  assert.match(detail(x => { x.proofs[0].path = ['nothex']; return x; }), /sha-256 hex/);
  assert.match(only(files(x => x), { entries: links })[0].detail, /names no workspace/);
  assert.match(only({ ...files(), 'head-root.20261121T10Z.tsr': undefined })[0].detail, /missing/);
  assert.match(only({ [HEAD_ROOTS_FILE]: enc('{"v":2}') })[0].detail, /not a version 1 list/);
});

test('the workspace is read from the signature when the pack does not name it; a platform package is the platform journal', () => {
  const claims = Buffer.from(JSON.stringify({ v: 2, ws: WS })).toString('base64url');
  const signed = { ...files(), 'signature.jws': enc(`e30.${claims}.sig`) };
  assert.match(only(signed, { entries: links })[0].detail, /platform root/);   // reached the token
  const platform = only(files(x => { x.proofs[0].subject = 'platform'; return x; }), { kind: 'platform', chain: links })[0];
  assert.match(platform.detail, /does not lead to the root/);   // the leaf is the platform journal's, not WS's
});

// ── Step 4: the dates. Times in ms; a token's own dating is Check 4's, so the rule is tested on its inputs. ──
const HOUR = 3_600_000;
const AT = Date.parse('2026-11-21T10:00:00.000Z');
const entry = (ms, seq = 3) => ({ seq, ms, sealedAt: new Date(ms).toISOString() });

test('a root dated in its hour, after the entries it covers and before the signature: nothing to say', () => {
  assert.deepEqual(rootDates({ genTime: AT + 4 * 60_000, hour: AT, newest: entry(AT - 20 * 60_000), signed: AT + HOUR }), { fail: null, warns: [] });
  assert.deepEqual(rootDates({ genTime: AT, hour: AT }), { fail: null, warns: [] });   // no entry sealed its time, no signature
  // The edges: the tolerance on each side, two hours exactly.
  assert.equal(rootDates({ genTime: AT - ROOT_CLOCK_TOLERANCE_MS, hour: AT }).fail, null);
  assert.equal(rootDates({ genTime: AT, hour: AT, newest: entry(AT + ROOT_CLOCK_TOLERANCE_MS) }).fail, null);
  assert.equal(rootDates({ genTime: AT, hour: AT, signed: AT - ROOT_CLOCK_TOLERANCE_MS }).fail, null);
  assert.deepEqual(rootDates({ genTime: AT + LATE_ROOT_MS, hour: AT, newest: entry(AT) }).warns, []);
  assert.equal(rootDates({ genTime: AT, hour: AT, signed: Number.NaN }).fail, null);
});

test('refuses an hour that is none, a token before its hour, before an entry it covers, after the signature', () => {
  assert.match(rootDates({ genTime: AT, hour: Number.NaN }).fail, /the proof’s hour is not the start of an hour/);
  assert.match(rootDates({ genTime: AT, hour: AT + 1 }).fail, /not the start of an hour/);
  assert.match(rootDates({ genTime: AT - ROOT_CLOCK_TOLERANCE_MS - 1, hour: AT }).fail, /dated 2026-11-21T09:54:59\.999Z, before the hour its proof names \(2026-11-21T10:00:00\.000Z\) began: it is not that hour’s root/);
  assert.match(rootDates({ genTime: AT + 10 * 60_000, hour: AT, newest: entry(AT + 16 * 60_000, 7) }).fail, /before entry 7 it covers was sealed \(2026-11-21T10:16:00\.000Z\): a root cannot date an entry made after it/);
  assert.match(rootDates({ genTime: AT + 10 * 60_000, hour: AT, signed: AT + 4 * 60_000 }).fail, /after the dossier was signed \(2026-11-21T10:04:00\.000Z\): the export that signed it cannot have shipped it — the proof was added later/);
  // Several contradictions at once are said together.
  const both = rootDates({ genTime: AT - HOUR, hour: AT, newest: entry(AT), signed: AT - 2 * HOUR });
  assert.match(both.fail, /before the hour its proof names.*; .*before entry 3 it covers.*; .*after the dossier was signed/);
});

test('says a root dated late for its hour, or for the entries it covers (re-rooted, or retried)', () => {
  const late = rootDates({ genTime: AT + 14 * 24 * HOUR, hour: AT, newest: entry(AT - 30 * 60_000), signed: AT + 15 * 24 * HOUR });
  assert.equal(late.fail, null);
  assert.equal(late.warns.length, 2);
  assert.match(late.warns[0], /14 days after the hour its proof names \(2026-11-21T10:00:00\.000Z\) began — dated late/);
  assert.match(late.warns[1], /dated 14 days after the newest entry it covers \(seq 3, sealed 2026-11-21T09:30:00\.000Z\) — rooted late/);
  assert.deepEqual(rootDates({ genTime: AT + 2 * HOUR + 60_000, hour: AT }).warns.length, 1);
});

test('a span reads as days, or hours and minutes', () => {
  assert.equal(span(3 * 24 * HOUR + 5), '3 days');
  assert.equal(span(5 * HOUR + 7 * 60_000), '5 h 07 min');
  assert.equal(span(-1), '0 h 00 min');
});

test('the newest sealed time at or before a seq; the links read their sealed time from core, else coreCanonical', () => {
  const read = carried({
    entries: [{ seq: 1, entryHash: 'a', core: { occurredAt: '2026-11-21T09:00:00.000Z' } }, { seq: 2, entryHash: 'b', core: {} }],
    chain: [{ seq: 3, entryHash: 'c', coreCanonical: '{"occurredAt":"2026-11-21T09:30:00.000Z"}' }, { seq: 4, entryHash: 'd', coreCanonical: 'not json' }, { seq: 5, entryHash: 'e' }],
  });
  assert.deepEqual(read.map(l => l.sealedAt), ['2026-11-21T09:00:00.000Z', null, '2026-11-21T09:30:00.000Z', null, null]);
  assert.deepEqual(newestSealed(read, 5), { seq: 3, ms: Date.parse('2026-11-21T09:30:00.000Z'), sealedAt: '2026-11-21T09:30:00.000Z' });
  assert.equal(newestSealed(read, 2).seq, 1);
  assert.equal(newestSealed(read).seq, 3);
  assert.equal(newestSealed(read, 0), null);
  assert.equal(newestSealed([{ seq: 1, sealedAt: 'not a time' }]), null);
});

// ── Step 5: what the signature says of the roots. ──
const SINCE = '2026-11-01T00:00:00.000Z';
const sealedLinks = [{ seq: 1, sealedAt: '2026-11-20T08:00:00.000Z' }, { seq: 2, sealedAt: '2026-11-20T09:00:00.000Z' }];
const raw = enc('{"v":1}');

test('a producer that predates the claim, or none to read: nothing said', () => {
  assert.deepEqual(verifyRootsClaim(undefined, null, sealedLinks), []);
  assert.deepEqual(verifyRootsClaim(raw, { v: 2, ws: WS }, sealedLinks), []);
  assert.deepEqual(verifyRootsClaim(undefined, { roots: null }, sealedLinks), []);   // the producer had dated no head
});

test('a claim of another shape is refused', () => {
  for (const roots of [{}, { since: 'yesterday', proofs: null }, { since: '2026-11-01T00:30:00.000Z', proofs: null }, { since: SINCE, proofs: 'ab' }, 'x', { since: SINCE }]) {
    const [c] = verifyRootsClaim(undefined, { roots }, sealedLinks);
    assert.equal(c.ok, false, JSON.stringify(roots));
    assert.match(c.detail, /roots must be null or \{ since/);
  }
});

test('head-roots.json against the hash the signature commits: the same is silent, another refused, one added said', () => {
  assert.deepEqual(verifyRootsClaim(raw, { roots: { since: SINCE, proofs: sha(raw) } }, sealedLinks), []);
  const [changed] = verifyRootsClaim(raw, { roots: { since: SINCE, proofs: sha('another') } }, sealedLinks);
  assert.equal(changed.ok, false);
  assert.match(changed.detail, /head-roots\.json is not the file the export shipped \(the signature commits sha256 [0-9a-f]{12}…, this one is [0-9a-f]{12}…\): it was changed after the export/);
  for (const roots of [{ since: SINCE, proofs: null }, null]) {
    const [added] = verifyRootsClaim(raw, { roots }, sealedLinks);
    assert.deepEqual([added.ok, added.level], [true, 'warn']);
    assert.match(added.detail, /the export shipped no head-roots\.json: this one was added after it/);
  }
});

test('head-roots.json missing: removed after the export, or never dated although sealed after rooting began — warnings', () => {
  const [removed] = verifyRootsClaim(undefined, { roots: { since: SINCE, proofs: sha(raw) } }, sealedLinks);
  assert.deepEqual([removed.ok, removed.level], [true, 'warn']);
  assert.match(removed.detail, /the signature says the export shipped head-roots\.json \(sha256 [0-9a-f]{12}…\): it is missing — removed after the export/);
  const [none] = verifyRootsClaim(undefined, { roots: { since: SINCE, proofs: null } }, sealedLinks);
  assert.deepEqual([none.ok, none.level], [true, 'warn']);
  assert.match(none.detail, /no hourly root dates this dossier: its newest entry \(seq 2, sealed 2026-11-20T09:00:00\.000Z\) is later than 2026-11-01T00:00:00\.000Z, when the producer began dating journal heads/);
  // Sealed before rooting began, or no link seals its time: nothing to say.
  assert.deepEqual(verifyRootsClaim(undefined, { roots: { since: '2026-11-21T00:00:00.000Z', proofs: null } }, sealedLinks), []);
  assert.deepEqual(verifyRootsClaim(undefined, { roots: { since: SINCE, proofs: null } }, [{ seq: 1, sealedAt: null }]), []);
});

test('Check 18 says what the signature states, with head-roots.json or without it', () => {
  const sign = (claims) => enc(`e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`);
  const hr = files();
  // Without head-roots.json: the warning only.
  const gone = verifyHeadRoots({ 'signature.jws': sign({ v: 2, ws: WS, iat: 1, roots: { since: SINCE, proofs: sha(hr[HEAD_ROOTS_FILE]) } }) }, pack);
  assert.deepEqual(gone.proofs, 0);
  assert.deepEqual(gone.checks.map(c => [c.id, c.ok, c.level]), [['head-roots', true, 'warn']]);
  // Changed: refused, and the proof still checked on its own (here it reaches the malformed token).
  const changed = verifyHeadRoots({ ...hr, 'signature.jws': sign({ v: 2, ws: WS, iat: 1, roots: { since: SINCE, proofs: sha('x') } }) }, pack);
  assert.deepEqual(changed.checks.map(c => [c.id, c.ok]), [['head-roots', false], ['head-root.3', false]]);
  // The same file: nothing more than the proof's own line.
  const same = verifyHeadRoots({ ...hr, 'signature.jws': sign({ v: 2, ws: WS, iat: 1, roots: { since: SINCE, proofs: sha(hr[HEAD_ROOTS_FILE]) } }) }, pack);
  assert.deepEqual(same.checks.map(c => c.id), ['head-root.3']);
  // A malformed head-roots.json beside a claim: both said.
  const bad = verifyHeadRoots({ [HEAD_ROOTS_FILE]: enc('{"v":2}'), 'signature.jws': sign({ v: 2, ws: WS, iat: 1, roots: null }) }, pack);
  assert.deepEqual(bad.checks.map(c => [c.id, c.ok]), [['head-roots', true], ['head-root', false]]);
});

// Step 6 — the roots the producer published, compared with each proof's root. The full path (a real token, the
// dates) runs on dossiers the producer builds; here, the reading and the comparison.
const published = (roots, edit = (x) => x) => enc(JSON.stringify(edit({
  format: 'azoth.head-roots.published/1', leaf: 'azoth.journal-head.v1', from: '2026-11-21T00:00:00.000Z', to: '2026-11-21T23:00:00.000Z', roots,
})));
const token = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x00);
const at10 = { hour: '2026-11-21T10:00:00.000Z', root: proof.root, treeSize: 3, status: 'anchored', token: Buffer.from(token).toString('base64'), genTime: '2026-11-21T10:00:05.000Z' };

test('reads a published roots file; refuses one of another format, hour, root, size or token', () => {
  assert.equal(PUBLISHED_ROOTS_FORMAT, 'azoth.head-roots.published/1');
  const read = readPublishedRoots(published([at10, { ...at10, hour: '2026-11-21T11:00:00.000Z', root: sha('r11'), status: 'pending', token: null, genTime: null }]));
  assert.deepEqual(read.roots.map(r => [r.hour, r.root.slice(0, 6), r.treeSize, r.token && hex(r.token)]),
    [[Date.parse('2026-11-21T10:00:00.000Z'), proof.root.slice(0, 6), 3, hex(token)], [Date.parse('2026-11-21T11:00:00.000Z'), sha('r11').slice(0, 6), 3, null]]);
  assert.deepEqual(readPublishedRoots(published([])), { roots: [] });
  assert.match(readPublishedRoots(enc('nope')).error, /not JSON/);
  assert.match(readPublishedRoots(published([at10], d => ({ ...d, format: 'other/1' }))).error, /not a list of published roots/);
  assert.match(readPublishedRoots(published([at10], d => ({ ...d, leaf: 'other' }))).error, /not a list of published roots/);
  for (const bad of [{ ...at10, hour: '2026-11-21T10:30:00.000Z' }, { ...at10, root: 'AB' }, { ...at10, treeSize: 0 }, { ...at10, treeSize: '3' }]) {
    assert.match(readPublishedRoots(published([bad])).error, /^root 1: an hour/);
  }
  assert.match(readPublishedRoots(published([{ ...at10, token: '%%%' }])).error, /^root 1: its token is not base64/);
});

test('the same root, size and token: a pass; another root, size or token: a failure; no copy of the hour: not compared', () => {
  const { roots } = readPublishedRoots(published([at10]));
  const ok = comparePublished('head-root.3', proof, token, roots);
  assert.deepEqual([ok.id, ok.ok, ok.level], ['head-root.3.published', true, undefined]);
  assert.match(ok.detail, /the root of 2026-11-21T10:00:00\.000Z is the one the producer published \(3 leaves, the same token\)/);
  // Published while pending (no token): the root and the size are enough.
  const pending = readPublishedRoots(published([{ ...at10, status: 'pending', token: null, genTime: null }])).roots;
  assert.equal(comparePublished('head-root.3', proof, token, pending).ok, true);
  const rerooted = comparePublished('head-root.3', proof, token, readPublishedRoots(published([{ ...at10, root: sha('another') }])).roots);
  assert.equal(rerooted.ok, false);
  assert.match(rerooted.detail, /the producer published another root for 2026-11-21T10:00:00\.000Z .* rooted again after the publication/);
  assert.equal(comparePublished('head-root.3', proof, token, readPublishedRoots(published([{ ...at10, treeSize: 4 }])).roots).ok, false);
  const otherToken = comparePublished('head-root.3', proof, token, readPublishedRoots(published([{ ...at10, token: Buffer.from('x').toString('base64') }])).roots);
  assert.equal(otherToken.ok, false);
  assert.match(otherToken.detail, /another token/);
  const absent = comparePublished('head-root.3', proof, token, readPublishedRoots(published([{ ...at10, hour: '2026-11-21T09:00:00.000Z' }])).roots);
  assert.deepEqual([absent.ok, absent.level], [true, 'warn']);
  assert.match(absent.detail, /^not compared: the published roots given do not cover 2026-11-21T10:00:00\.000Z — save the producer's \/api\/proof\/head-roots\?from=2026-11-21T10:00:00\.000Z&to=2026-11-21T10:00:00\.000Z/);
});

test('two published copies of one hour that disagree fail once; a pending copy and its anchored copy agree', () => {
  const a = readPublishedRoots(published([at10])).roots;
  const pendingCopy = readPublishedRoots(published([{ ...at10, status: 'pending', token: null, genTime: null }])).roots;
  assert.deepEqual(publishedConflicts([...a, ...pendingCopy, ...a]), []);
  const changed = readPublishedRoots(published([{ ...at10, root: sha('again') }])).roots;
  const conflicts = publishedConflicts([...a, ...changed, ...changed]);
  assert.deepEqual(conflicts.map(c => [c.id, c.ok]), [['head-roots.published', false]]);
  assert.match(conflicts[0].detail, /disagree on 2026-11-21T10:00:00\.000Z/);
});

test('published roots given to a dossier without head-roots.json: said, nothing compared; with it, the conflicts first', () => {
  const roots = readPublishedRoots(published([at10])).roots;
  assert.deepEqual(verifyHeadRoots({}, pack, { published: roots }).checks.map(c => [c.id, c.ok, c.level]), [['head-roots.published', true, 'warn']]);
  // A proof refused before step 6 (here, its malformed token) is not compared: its own line says why.
  assert.deepEqual(verifyHeadRoots(files(), pack, { published: roots }).checks.map(c => [c.id, c.ok]), [['head-root.3', false]]);
  const changed = readPublishedRoots(published([{ ...at10, root: sha('again') }])).roots;
  assert.deepEqual(verifyHeadRoots(files(), pack, { published: [...roots, ...changed] }).checks.map(c => [c.id, c.ok]), [['head-roots.published', false], ['head-root.3', false]]);
});

test('two hours whose published copies disagree: each said once, in the order of the hours', () => {
  const at11 = { ...at10, hour: '2026-11-21T11:00:00.000Z' };
  const first = readPublishedRoots(published([at11, at10])).roots;
  const changed = readPublishedRoots(published([{ ...at11, root: sha('again 11') }, { ...at10, root: sha('again 10') }])).roots;
  const conflicts = publishedConflicts([...first, ...changed]);
  assert.deepEqual(conflicts.map(c => [c.id, c.ok]), [['head-roots.published', false], ['head-roots.published', false]]);
  assert.match(conflicts[0].detail, /disagree on 2026-11-21T10:00:00\.000Z/);
  assert.match(conflicts[1].detail, /disagree on 2026-11-21T11:00:00\.000Z/);
});

test('signedAt: the instant the signature states (its iat, in milliseconds), or null', () => {
  const sign = (claims) => enc(`e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`);
  assert.equal(signedAt({ 'signature.jws': sign({ v: 2, ws: WS, iat: 1_763_715_600 }) }), 1_763_715_600_000);
  assert.equal(signedAt({ 'signature.jws': sign({ v: 2, ws: WS }) }), null);
  assert.equal(signedAt({ 'signature.jws': sign({ v: 2, ws: WS, iat: 1.5 }) }), null);
  assert.equal(signedAt({ 'signature.jws': enc('not a signature') }), null);
  assert.equal(signedAt({}), null);
});

test('verifyRootProof: one proof, Check 18 steps 1 to 4, under the id its caller gives (Check 8 runs it too)', () => {
  const ctx = (over = {}) => ({
    id: 'compliance.root.3', subject: WS, hashes: new Map(links.map(l => [l.seq, l.entryHash])), links: carried(pack), files: files(), ...over,
  });
  const no = (r) => { assert.equal(r.passed, false); assert.equal(r.trusted, false); assert.equal(r.token, null); assert.equal(r.checks.length, 1); assert.equal(r.checks[0].ok, false); return r.checks[0]; };
  assert.equal(no(verifyRootProof(proof, ctx())).id, 'compliance.root.3');
  assert.match(no(verifyRootProof(proof, ctx())).detail, /the platform root of 2026-11-21T10:00:00\.000Z: /);   // the token is not one
  assert.match(no(verifyRootProof(proof, ctx({ subject: null }))).detail, /names no workspace/);
  assert.match(no(verifyRootProof({ ...proof, subject: randomUUID() }, ctx())).detail, /the proof is of .*’s journal/);
  assert.match(no(verifyRootProof({ ...proof, seq: 9 }, ctx())).detail, /seq 9 is not one of the sealed links/);
  assert.match(no(verifyRootProof({ ...proof, entryHash: sha('other') }, ctx())).detail, /another hash for seq 3/);
  assert.match(no(verifyRootProof({ ...proof, root: 'x' }, ctx())).detail, /root and path are sha-256 hex/);
  assert.match(no(verifyRootProof({ ...proof, root: sha('elsewhere') }, ctx())).detail, /does not lead to the root/);
  assert.match(no(verifyRootProof({ ...proof, token: 'gone.tsr' }, ctx())).detail, /gone\.tsr missing/);
});

// ── Step 5, what the signature had to state (verifier 2.4.0): from ROOTS_STATED_FROM, every Azoth producer states the
//    roots in each dossier it signs. An insider who signs again without them — or says the producer dated nothing —
//    is said, never passed in silence. ──
const FROM = Date.parse(ROOTS_STATED_FROM);
const sealedAtMs = (ms) => ({ seq: 5, ms, sealedAt: new Date(ms).toISOString() });

test('a signature that states nothing of the roots, on a dossier dated after ROOTS_STATED_FROM: said', () => {
  assert.equal(ROOTS_STATED_FROM, '2026-11-22T00:00:00.000Z');
  assert.deepEqual(verifyRootsStatement(null, { newest: sealedAtMs(FROM + HOUR) }), []);
  // Dated before it, by every time it carries: an older producer, nothing to say.
  assert.deepEqual(verifyRootsStatement({ iat: (FROM - HOUR) / 1000 }, { newest: sealedAtMs(FROM - 2 * HOUR), tokenTimes: [FROM - HOUR] }), []);
  // Dated after it by its signature, an entry it carries, or a token it ships (a fresh anchor.tsr).
  for (const dated of [{ iat: (FROM + HOUR) / 1000 }, { iat: 1, newest: sealedAtMs(FROM + 1) }, { iat: 1, tokenTimes: [FROM + 3 * HOUR] }]) {
    const { iat, ...rest } = dated;
    const [line] = verifyRootsStatement({ iat }, rest);
    assert.deepEqual([line.id, line.ok, line.level], ['head-roots', true, 'warn']);
    assert.match(line.detail, /^the signature states nothing of the hourly roots, although the dossier is dated .* — after 2026-11-22T00:00:00\.000Z, from when every Azoth producer states them in each dossier it signs: it was signed again without that statement, or by an older producer/);
  }
  // Stated: step 5's own lines say the rest.
  assert.deepEqual(verifyRootsStatement({ iat: (FROM + HOUR) / 1000, roots: { since: SINCE, proofs: null } }, { newest: sealedAtMs(FROM) }), []);
});

test('« the producer dated no head » and nothing else dates the dossier: said; a token that verifies: nothing to say', () => {
  const claims = { iat: (FROM + HOUR) / 1000, roots: null };
  const [line] = verifyRootsStatement(claims, {});
  assert.deepEqual([line.id, line.ok, line.level], ['head-roots', true, 'warn']);
  assert.match(line.detail, /the producer had dated no journal head when it exported this dossier, and nothing in it is dated by a third party \(no anchor\.tsr, no root’s token\): what it holds and when it was signed are only the word of whoever holds the workspace’s key/);
  assert.deepEqual(verifyRootsStatement(claims, { dated: true }), []);
  assert.deepEqual(verifyRootsStatement({ ...claims, iat: (FROM - HOUR) / 1000 }, {}), []);
});

test('exportedAt: the later of the signature and its anchor.tsr', () => {
  assert.equal(exportedAt(FROM, FROM + 60_000), FROM + 60_000);
  assert.equal(exportedAt(FROM, null), FROM);
  assert.equal(exportedAt(null, null), null);
});

// Step 6 against the statement and the head: a published copy saved by the reader, its window answered for.
const E = Date.parse('2026-11-25T09:20:00.000Z');
const windowOf = (from, to) => ({ from: from ?? '2026-11-25T00:00:00.000Z', to: to ?? '2026-11-25T23:00:00.000Z' });
const pub = (roots, w = windowOf()) => readPublishedRoots(enc(JSON.stringify({ format: PUBLISHED_ROOTS_FORMAT, leaf: 'azoth.journal-head.v1', ...w, roots }))).roots;
const anchoredRoot = (hour, genTime) => ({ hour, root: sha(hour), treeSize: 4, status: 'anchored', token: Buffer.from(token).toString('base64'), genTime });
const hoursAfter = [
  anchoredRoot('2026-11-25T09:00:00.000Z', '2026-11-25T09:01:00.000Z'),
  anchoredRoot('2026-11-25T10:00:00.000Z', '2026-11-25T10:01:00.000Z'),
  anchoredRoot('2026-11-25T11:00:00.000Z', '2026-11-25T11:01:00.000Z'),
  anchoredRoot('2026-11-25T12:00:00.000Z', '2026-11-25T12:01:00.000Z'),
];
const EXPORTED = Date.parse('2026-11-25T15:00:00.000Z');
const headClaims = (roots) => ({ iat: EXPORTED / 1000, head: { seq: 5, hash: sha('h5') }, ...(roots === undefined ? {} : { roots }) });

test('readPublishedRoots keeps the producer’s token time and the hours its file answers for', () => {
  const [r] = pub([anchoredRoot('2026-11-25T10:00:00.000Z', '2026-11-25T10:01:00.000Z')]);
  assert.equal(r.genTime, Date.parse('2026-11-25T10:01:00.000Z'));
  assert.deepEqual(r.window, { from: Date.parse('2026-11-25T00:00:00.000Z'), to: Date.parse('2026-11-25T23:00:00.000Z') });
  assert.equal(pub([{ ...anchoredRoot('2026-11-25T10:00:00.000Z', null), token: null, status: 'pending' }])[0].genTime, null);
  assert.equal(pub([anchoredRoot('2026-11-25T10:00:00.000Z', '2026-11-25T10:01:00.000Z')], { from: 'x', to: 'y' })[0].window, null);
});

test('the signature’s statement against the roots published before the export: disagreeing, it fails', () => {
  const published = pub(hoursAfter);
  const nul = verifyPublishedCoverage(headClaims(null), published, { exported: EXPORTED });
  assert.deepEqual(nul.map(c => [c.id, c.ok]), [['head-roots.published', false]]);
  assert.match(nul[0].detail, /says the producer had dated no journal head when it exported this dossier \(2026-11-25T15:00:00\.000Z\), but it published a root of 2026-11-25T09:00:00\.000Z dated 2026-11-25T09:01:00\.000Z: its statements disagree/);
  const late = verifyPublishedCoverage(headClaims({ since: '2026-11-25T10:00:00.000Z', proofs: null }), published, { exported: EXPORTED });
  assert.deepEqual(late.map(c => [c.id, c.ok]), [['head-roots.published', false]]);
  assert.match(late[0].detail, /began dating journal heads at 2026-11-25T10:00:00\.000Z, but it published a root of 2026-11-25T09:00:00\.000Z/);
  // Honest statements, roots published after the export, and no published copy: nothing to say.
  assert.deepEqual(verifyPublishedCoverage(headClaims({ since: '2026-11-25T09:00:00.000Z', proofs: null }), published, { exported: EXPORTED }), []);
  assert.deepEqual(verifyPublishedCoverage(headClaims(null), published, { exported: Date.parse('2026-11-25T09:03:00.000Z') }), []);
  assert.deepEqual(verifyPublishedCoverage(headClaims(null), [], { exported: EXPORTED }), []);
  assert.deepEqual(verifyPublishedCoverage(null, published, { exported: EXPORTED }), []);
});

test('the journal’s head the dossier carries, rooted before the export by the published roots: its proof is required', () => {
  const claims = headClaims({ since: '2026-11-25T09:00:00.000Z', proofs: null });
  const newest = { seq: 5, ms: E, sealedAt: new Date(E).toISOString() };
  // 12:01 is dated two hours or more after 09:20 and before 15:00; every hour from 09:00 to 12:00 answered for, anchored.
  const [fail] = verifyPublishedCoverage(claims, pub(hoursAfter), { newest, exported: EXPORTED });
  assert.deepEqual([fail.id, fail.ok], ['head-roots.published', false]);
  assert.match(fail.detail, /the journal’s head when the dossier was exported — seq 5, sealed 2026-11-25T09:20:00\.000Z — was dated by a root the producer published before the export \(the root of 2026-11-25T12:00:00\.000Z, dated 2026-11-25T12:01:00\.000Z, and every hour before it answered for\).*removed after the export/);
  // A proof that holds at the head (or after it): nothing to say.
  assert.deepEqual(verifyPublishedCoverage(claims, pub(hoursAfter), { newest, exported: EXPORTED, rootedFrom: 5 }), []);
  // The export came before a root could date the head: nothing to say.
  assert.deepEqual(verifyPublishedCoverage(claims, pub(hoursAfter), { newest, exported: Date.parse('2026-11-25T10:21:00.000Z') }), []);
  // The newest entry is not the head the signature commits — the head was a later entry when the root was made: a warning.
  const [notHead] = verifyPublishedCoverage({ ...claims, head: { seq: 9, hash: sha('h9') } }, pub(hoursAfter), { newest, exported: EXPORTED });
  assert.deepEqual([notHead.ok, notHead.level], [true, 'warn']);
  assert.match(notHead.detail, /no proof of the dossier dates that entry or a later one: that entry was not the journal’s head when the export signed, or the proof was removed after the export/);
  // An hour between them the published roots do not answer for, or one still pending: a warning, never a failure.
  const gap = verifyPublishedCoverage(claims, pub(hoursAfter, windowOf('2026-11-25T10:00:00.000Z')), { newest, exported: EXPORTED });
  assert.deepEqual(gap.map(c => [c.ok, c.level]), [[true, 'warn']]);
  assert.match(gap[0].detail, /an hour between them is not answered for by the published roots given/);
  const pending = [{ ...hoursAfter[0], token: null, status: 'pending', genTime: null }, ...hoursAfter.slice(1)];
  assert.deepEqual(verifyPublishedCoverage(claims, pub(pending), { newest, exported: EXPORTED }).map(c => [c.ok, c.level]), [[true, 'warn']]);
});

test('Check 18 over a dossier: the statement and the published head, with the proofs it carries', () => {
  const sign = (claims) => enc(`e30.${Buffer.from(JSON.stringify({ v: 2, ws: WS, ...claims })).toString('base64url')}.sig`);
  const sealed = { workspaceId: WS, entries: [{ seq: 5, entryHash: sha('h5'), core: { occurredAt: new Date(E).toISOString() } }] };
  const headOf = { seq: 5, hash: sha('h5') };
  // An insider signed again, stated nothing, shipped no proof: said.
  const silent = { 'signature.jws': sign({ iat: EXPORTED / 1000, head: headOf }) };
  assert.deepEqual(verifyHeadRoots(silent, sealed).checks.map(c => [c.id, c.ok, c.level]), [['head-roots', true, 'warn']]);
  // The same, with the roots the reader saved: the statement is said, the head's missing proof fails.
  assert.deepEqual(verifyHeadRoots(silent, sealed, { published: pub(hoursAfter) }).checks.map(c => [c.id, c.ok]), [['head-roots', true], ['head-roots.published', false]]);
  // « The producer dated no head »: said without a token, refused against the roots published before the export.
  const nul = { 'signature.jws': sign({ iat: EXPORTED / 1000, head: headOf, roots: null }) };
  assert.deepEqual(verifyHeadRoots(nul, sealed).checks.map(c => [c.id, c.ok, c.level]), [['head-roots', true, 'warn']]);
  assert.deepEqual(verifyHeadRoots(nul, sealed, { anchorAt: EXPORTED + 1000 }).checks, []);
  assert.deepEqual(verifyHeadRoots(nul, sealed, { published: pub(hoursAfter) }).checks.map(c => [c.id, c.ok]), [['head-roots', true], ['head-roots.published', false], ['head-roots.published', false]]);
  // A signature backdated to just after its newest entry: the roots published before it still contradict « none »; a
  // fresh anchor.tsr dates the export, and the head's missing proof fails too.
  const backdated = { 'signature.jws': sign({ iat: Date.parse('2026-11-25T09:21:00.000Z') / 1000, head: headOf, roots: null }) };
  assert.deepEqual(verifyHeadRoots(backdated, sealed, { published: pub(hoursAfter) }).checks.map(c => [c.id, c.ok, c.level]), [['head-roots', true, 'warn'], ['head-roots.published', false, undefined]]);
  assert.deepEqual(verifyHeadRoots(backdated, sealed, { published: pub(hoursAfter), anchorAt: EXPORTED }).checks.map(c => [c.id, c.ok]), [['head-roots.published', false], ['head-roots.published', false]]);
  // Backdated before the entry it carries: an export signs what it read.
  const before = verifyHeadRoots({ 'signature.jws': sign({ iat: Date.parse('2026-11-25T09:00:00.000Z') / 1000, head: headOf, roots: null }) }, sealed);
  assert.deepEqual(before.checks.map(c => [c.id, c.ok]), [['signature.dates', false], ['head-roots', true]]);
  assert.match(before.checks[0].detail, /signed 2026-11-25T09:00:00\.000Z, before entry 5 it carries was sealed \(2026-11-25T09:20:00\.000Z\): an export signs what it has read — the signature’s instant was moved back/);
  // Within the clocks' tolerance: nothing to say.
  assert.deepEqual(verifyHeadRoots({ 'signature.jws': sign({ iat: (E - ROOT_CLOCK_TOLERANCE_MS) / 1000, head: headOf, roots: null }) }, sealed, { dated: true }).checks, []);
});
