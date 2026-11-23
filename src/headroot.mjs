// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * azoth-verify — the hourly platform root (SPEC.md, Check 18).
 *
 * Every hour, Azoth puts the chain head of every journal that moved — each workspace's, and Azoth's own platform
 * journal — into one Merkle tree, and one RFC 3161 token dates its root. A dossier ships, outside its manifest, the
 * inclusion proof of a head it carries (`head-roots.json`, the root's token beside it). This check recomputes the
 * leaf from the dossier's OWN workspace and link, walks the path to the root, and verifies the root's token as
 * Check 4 does (timestamp.mjs): the head — and every entry the chain links before it — existed at the token's time,
 * without trusting the producer.
 *
 * Then the dates (SPEC.md, Check 18 steps 4 and 5): a root's token can be dated neither before the hour its proof
 * names, nor before an entry it covers was sealed, nor after the export signed the dossier — and one dated long after
 * either is said. A dossier without `head-roots.json` is said too, when its signature states that the producer was
 * dating journal heads by then, or that the export shipped one.
 *
 * Then, when the reader gives the roots the producer published (SPEC.md, Check 18 step 6 — a file saved from its
 * /api/proof/head-roots, read here from disk: the verifier fetches nothing), each proof's root is compared with the
 * root published for its hour: whoever holds the producer's database could rewrite a chain and root it again, but
 * not the copy the reader already holds.
 *
 * The encoding is RFC 9162's (§2.1), written here from SPEC.md, not shared with the producer:
 *   leaf data   UTF-8 of  "azoth.journal-head.v1" LF subject LF seq LF entryHash
 *   leaf hash   SHA-256(0x00 || leaf data)        node hash   SHA-256(0x01 || left || right)
 *   proof       the sibling hashes, deepest first, verified with the leaf's index and the tree's size (§2.1.3.2)
 */
import { concat, equal, fromBase64, fromHex, fromUtf8, hex, utf8 } from './bytes.mjs';
import { digest } from './crypto.mjs';
import { checkTimestamp, readPem } from './timestamp.mjs';
import { carried, kindOf, SIGNATURE_FILE } from './signature.mjs';

export const HEAD_ROOTS_FILE = 'head-roots.json';
/** The format of the roots a producer publishes (its /api/proof/head-roots answer), as `--published-roots` reads it. */
export const PUBLISHED_ROOTS_FORMAT = 'azoth.head-roots.published/1';
export const HEAD_LEAF_DOMAIN = 'azoth.journal-head.v1';
export const PLATFORM_SUBJECT = 'platform';

const HOUR_MS = 3_600_000;
/**
 * How far a root's token time may fall on the wrong side of a time the producer wrote, without contradiction: the
 * authority's clock against the producer's servers and database (each kept to UTC, but never exactly), plus the
 * worker's run between the token and the record of its hour (one minute at most). Five minutes: every FAIL below is
 * a contradiction no clock explains.
 */
export const ROOT_CLOCK_TOLERANCE_MS = 5 * 60_000;
/**
 * A root is dated within minutes of its hour, and within the hour after the head it covers was sealed: the producer
 * roots every hour. Dated more than two hours after either, it is late — an authority retried, a worker that did not
 * run, or a head rooted again — and is said (a warning): it proves the head existed then, not earlier.
 */
export const LATE_ROOT_MS = 2 * HOUR_MS;
/**
 * From this instant, every dossier an Azoth producer signs states the hourly roots (the claims' `roots`, Check 18 step
 * 5): producers from version 0.14.1 on (2026-11-21) do, and none signs without it since. A dossier dated after it — by
 * its signature, an entry it carries or a token it ships — whose signature states nothing was signed again without that
 * statement, or by an older producer: said (SPEC.md, Check 18 step 5). Pinned here, never read from the dossier.
 */
export const ROOTS_STATED_FROM = '2026-11-22T00:00:00.000Z';
/**
 * The producer roots every journal that moved at the next hour: a root dated two hours or more after an entry was sealed
 * was made after it was appended (the journal's outbox lag included), so it dates a head at or after that entry
 * (SPEC.md, Check 18 step 6).
 */
export const ROOTED_WITHIN_MS = LATE_ROOT_MS;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const isSubject = s => s === PLATFORM_SUBJECT || UUID.test(String(s));

/** The leaf hash of a journal head (SPEC.md, Check 18). Throws outside the encoding. */
export function headLeafHash(subject, seq, entryHash) {
  if (!isSubject(subject)) throw new Error('the subject is a lowercase workspace id or "platform"');
  if (!Number.isSafeInteger(seq) || seq < 1) throw new Error('seq is a positive integer');
  if (!HEX64.test(String(entryHash))) throw new Error('entryHash is 64 lowercase hex characters');
  return digest('sha256', concat(Uint8Array.of(0x00), utf8(`${HEAD_LEAF_DOMAIN}\n${subject}\n${seq}\n${entryHash}`)));
}

export const headNodeHash = (left, right) => digest('sha256', concat(Uint8Array.of(0x01), left, right));

/** The root an inclusion path leads to (RFC 9162 §2.1.3.2), or null when index, size and path cannot belong together. */
export function rootFromPath(leaf, index, size, path) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return null;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (!(p instanceof Uint8Array) || p.length !== 32 || sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      r = headNodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = headNodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : null;
}

/** The claims of the dossier's signature.jws, unverified (Check 12 verifies them), or null when unreadable. */
function claimsOf(files) {
  try {
    const claims = JSON.parse(fromUtf8(fromBase64(fromUtf8(files[SIGNATURE_FILE]).trim().split('.')[1])));
    return claims && typeof claims === 'object' ? claims : null;
  } catch {
    return null;
  }
}

/** The instant the dossier was signed (its signature's `iat`, in milliseconds), or null when it states none. */
export function signedAt(files) {
  const claims = claimsOf(files);
  return Number.isInteger(claims?.iat) ? claims.iat * 1000 : null;
}

/** The journal the dossier is of: Azoth's platform journal, or the workspace its pack — else its signature — names. */
function subjectOf(pack, claims) {
  if (kindOf(pack) === 'platform') return PLATFORM_SUBJECT;
  if (typeof pack?.workspaceId === 'string') return pack.workspaceId;
  return typeof claims?.ws === 'string' ? claims.ws : null;
}

const iso = s => { const d = new Date(String(s)); return Number.isNaN(d.getTime()) ? String(s) : d.toISOString(); };
const at = ms => new Date(ms).toISOString();
const isHour = s => typeof s === 'string' && Number.isFinite(Date.parse(s)) && Date.parse(s) % HOUR_MS === 0;

/** A duration as a reader says it: « 3 days », « 5 h 07 min ». */
export function span(ms) {
  const m = Math.max(0, Math.round(ms / 60_000));
  if (m >= 2 * 24 * 60) return `${Math.floor(m / (24 * 60))} days`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min`;
}

/**
 * The newest time sealed by a link the dossier carries at or before `seq` — what a head at `seq` vouches for, since
 * every link commits to the one before it — or null when none of them seals its time.
 * @param {Array<{ seq: number, sealedAt: string | null }>} links
 */
export function newestSealed(links, seq = Infinity) {
  let best = null;
  for (const l of links) {
    const ms = l.sealedAt ? Date.parse(l.sealedAt) : NaN;
    if (l.seq <= seq && Number.isFinite(ms) && (!best || ms > best.ms)) best = { seq: l.seq, ms, sealedAt: l.sealedAt };
  }
  return best;
}

/**
 * Check 18's dates for one root (SPEC.md, step 4), every time in milliseconds since the epoch: the token's `genTime`
 * against the start of the `hour` its proof names, the `newest` entry it covers ({ seq, ms, sealedAt }, or null when
 * none seals its time) and the instant the dossier was `signed` (its signature's `iat`, or null).
 * @returns {{ fail: string | null, warns: string[] }}
 */
export function rootDates({ genTime, hour, newest = null, signed = null }) {
  const fails = [];
  const warns = [];
  const g = at(genTime);
  if (!Number.isFinite(hour) || hour % HOUR_MS !== 0) {
    fails.push('the proof’s hour is not the start of an hour (ISO 8601)');
  } else if (genTime < hour - ROOT_CLOCK_TOLERANCE_MS) {
    fails.push(`its token is dated ${g}, before the hour its proof names (${at(hour)}) began: it is not that hour’s root`);
  } else if (genTime > hour + LATE_ROOT_MS) {
    warns.push(`its token is dated ${g}, ${span(genTime - hour)} after the hour its proof names (${at(hour)}) began — dated late (its authority retried), or the proof’s hour is not the token’s`);
  }
  if (newest && genTime < newest.ms - ROOT_CLOCK_TOLERANCE_MS) {
    fails.push(`its token is dated ${g}, before entry ${newest.seq} it covers was sealed (${newest.sealedAt}): a root cannot date an entry made after it`);
  } else if (newest && genTime > newest.ms + LATE_ROOT_MS) {
    warns.push(`it is dated ${span(genTime - newest.ms)} after the newest entry it covers (seq ${newest.seq}, sealed ${newest.sealedAt}) — rooted late: it proves the head existed at ${g}, not when its entries were sealed`);
  }
  if (signed !== null && Number.isFinite(signed) && genTime > signed + ROOT_CLOCK_TOLERANCE_MS) {
    fails.push(`its token is dated ${g}, after the dossier was signed (${at(signed)}): the export that signed it cannot have shipped it — the proof was added later`);
  }
  return { fail: fails.length ? fails.join('; ') : null, warns };
}

/**
 * What the signature says about the hourly roots (SPEC.md, Check 18 step 5), against the head-roots.json the dossier
 * holds (or not). `roots` is absent from a producer that predates it — nothing is said then.
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyRootsClaim(raw, claims, links) {
  if (!claims || !Object.hasOwn(claims, 'roots')) return [];
  const roots = claims.roots;
  const id = 'head-roots';
  if (roots !== null && !(roots && typeof roots === 'object' && isHour(roots.since) && (roots.proofs === null || HEX64.test(String(roots.proofs))))) {
    return [{ id, ok: false, detail: `${SIGNATURE_FILE}: roots must be null or { since: the start of an hour (ISO 8601), proofs: a sha-256 hex or null }` }];
  }
  const shipped = roots?.proofs ?? null;
  if (raw) {
    if (shipped === null) return [{ id, ok: true, level: 'warn', detail: `the signature says the export shipped no ${HEAD_ROOTS_FILE}: this one was added after it — each proof in it is checked on its own` }];
    const got = hex(digest('sha256', raw));
    return got === shipped ? [] : [{ id, ok: false, detail: `${HEAD_ROOTS_FILE} is not the file the export shipped (the signature commits sha256 ${shipped.slice(0, 12)}…, this one is ${got.slice(0, 12)}…): it was changed after the export` }];
  }
  if (shipped !== null) {
    return [{ id, ok: true, level: 'warn', detail: `the signature says the export shipped ${HEAD_ROOTS_FILE} (sha256 ${shipped.slice(0, 12)}…): it is missing — removed after the export, so nothing here dates the journal’s head outside the producer’s database; ask for the dossier as it was exported` }];
  }
  const newest = roots ? newestSealed(links) : null;
  if (!newest || newest.ms < Date.parse(roots.since)) return [];
  return [{ id, ok: true, level: 'warn', detail: `no hourly root dates this dossier: its newest entry (seq ${newest.seq}, sealed ${newest.sealedAt}) is later than ${iso(roots.since)}, when the producer began dating journal heads, but none of its links was a dated head when it was exported — outside the producer’s database, only anchor.tsr (when present) dates it` }];
}

/**
 * When the dossier left its producer, as far as the dossier says (SPEC.md, Check 18 step 5): the later of its signature's
 * `iat` and the time of its anchor.tsr (a token the export asks for right after it signs) — null when it states neither.
 */
export function exportedAt(signed, anchorAt = null) {
  const times = [signed, anchorAt].filter(t => t !== null && Number.isFinite(t));
  return times.length ? Math.max(...times) : null;
}

/**
 * Whether the signature had to state the roots (SPEC.md, Check 18 step 5): the dossier is dated at or after
 * ROOTS_STATED_FROM — by its signature, the newest time a link it carries seals, or a token it ships.
 */
function statedFromBy({ signed, newest, tokenTimes }) {
  const from = Date.parse(ROOTS_STATED_FROM);
  const times = [signed, newest?.ms ?? null, ...tokenTimes].filter(t => t !== null && Number.isFinite(t));
  const late = times.filter(t => t >= from);
  return late.length ? Math.max(...late) : null;
}

/**
 * What the signature had to state of the roots, and could not hide (SPEC.md, Check 18 step 5, verifier 2.4.0): a
 * dossier dated after ROOTS_STATED_FROM whose signature states nothing; one that says the producer dated no head and
 * that nothing else dates. Warnings: a producer older than that date signs no statement, and a deployment without a
 * time-stamping authority dates nothing.
 *   claims      the signature's claims (unverified here: Check 12 verifies them), or null
 *   newest      the newest time a link the dossier carries seals ({ seq, ms, sealedAt }), or null
 *   tokenTimes  the time of every token of the dossier that verifies (anchor.tsr, a root's, a journal head's)
 *   dated       whether a token of the dossier verifies at all
 * @returns {Array<{ id: string, ok: boolean, detail: string, level: 'warn' }>}
 */
export function verifyRootsStatement(claims, { newest = null, tokenTimes = [], dated = false } = {}) {
  if (!claims) return [];
  const signed = Number.isInteger(claims.iat) ? claims.iat * 1000 : null;
  const after = statedFromBy({ signed, newest, tokenTimes });
  if (after === null) return [];
  const id = 'head-roots';
  if (!Object.hasOwn(claims, 'roots')) {
    return [{ id, ok: true, level: 'warn', detail: `the signature states nothing of the hourly roots, although the dossier is dated ${at(after)} — after ${ROOTS_STATED_FROM}, from when every Azoth producer states them in each dossier it signs: it was signed again without that statement, or by an older producer. Nothing says whether the producer was dating journal heads, nor whether a proof was removed: outside the producer’s database, only a token (anchor.tsr, a root’s) dates it` }];
  }
  if (claims.roots === null && !dated) {
    return [{ id, ok: true, level: 'warn', detail: `the signature says the producer had dated no journal head when it exported this dossier, and nothing in it is dated by a third party (no anchor.tsr, no root’s token): what it holds and when it was signed are only the word of whoever holds the workspace’s key` }];
  }
  return [];
}

/** The published roots that hold a token the producer said was dated at or before `until` (ms). */
const datedBy = (published, until) => published.filter(r => r.token && r.genTime !== null && r.genTime <= until);

/**
 * The roots the reader gave, against what the signature states and the head the dossier carries (SPEC.md, Check 18
 * step 6, verifier 2.4.0) — whatever head-roots.json holds:
 *   - the signature says the producer had dated no head (`roots: null`), or began at an hour later than one it had
 *     published a root for, while that root was dated before the export: the producer's statements disagree (FAIL);
 *   - the producer published a root dated two hours or more after the newest entry the dossier carries, and before the
 *     export, but no proof at or after that entry holds: a FAIL when that entry is the journal's head the signature
 *     commits and the published roots answer for every hour from its own to that root's, all of them dated before the
 *     export — every journal that moves is a leaf of the next hourly root, so the export shipped its proof and it was
 *     removed; else a warning (the entry was not a head when the root was made, or an hour is not answered for).
 * @returns {Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }>}
 */
export function verifyPublishedCoverage(claims, published, { newest = null, exported = null, rootedFrom = null } = {}) {
  if (!claims || !published?.length || exported === null) return [];
  const id = 'head-roots.published';
  const out = [];
  const before = datedBy(published, exported - ROOT_CLOCK_TOLERANCE_MS).sort((a, b) => a.hour - b.hour);
  const roots = Object.hasOwn(claims, 'roots') ? claims.roots : undefined;
  if (roots === null && before.length) {
    const r = before[0];
    out.push({ id, ok: false, detail: `the signature says the producer had dated no journal head when it exported this dossier (${at(exported)}), but it published a root of ${at(r.hour)} dated ${at(r.genTime)}: its statements disagree — the dossier was signed again, or the published copy is not the producer’s` });
  } else if (roots && isHour(roots.since)) {
    const earlier = before.find(r => r.hour < Date.parse(roots.since));
    if (earlier) out.push({ id, ok: false, detail: `the signature says the producer began dating journal heads at ${iso(roots.since)}, but it published a root of ${at(earlier.hour)}, dated ${at(earlier.genTime)}, before this dossier was exported: its statements disagree — the dossier was signed again, or the published copy is not the producer’s` });
  }
  if (!newest) return out;
  // A root dated two hours or more after the newest entry, and before the export, dates a head at or after it.
  const after = before.filter(r => r.genTime >= newest.ms + ROOTED_WITHIN_MS);
  if (!after.length || (rootedFrom !== null && rootedFrom >= newest.seq)) return out;
  const first = after[0];
  const own = Math.floor(newest.ms / HOUR_MS) * HOUR_MS;
  const answered = h => published.some(r => r.window && r.window.from <= h && h <= r.window.to);
  let whole = true;
  for (let h = own; h <= first.hour && whole; h += HOUR_MS) {
    const inHour = published.filter(r => r.hour === h);
    whole = answered(h) && inHour.every(r => r.token && r.genTime !== null && r.genTime <= exported - ROOT_CLOCK_TOLERANCE_MS);
  }
  const head = claims.head && Number.isSafeInteger(claims.head.seq) ? claims.head.seq : null;
  const root = `the root of ${at(first.hour)}, dated ${at(first.genTime)}`;
  if (head === newest.seq && whole) {
    out.push({ id, ok: false, detail: `the journal’s head when the dossier was exported — seq ${newest.seq}, sealed ${newest.sealedAt} — was dated by a root the producer published before the export (${root}, and every hour before it answered for): every journal that moves is a leaf of the next hourly root, so the export shipped the proof of its head — the dossier carries none that holds: removed after the export` });
  } else {
    out.push({ id, ok: true, level: 'warn', detail: `the producer published ${root} — two hours or more after the newest entry this dossier carries (seq ${newest.seq}, sealed ${newest.sealedAt}) and before it was exported — but no proof of the dossier dates that entry or a later one: ${head === newest.seq ? 'an hour between them is not answered for by the published roots given' : 'that entry was not the journal’s head when the export signed'}, or the proof was removed after the export` });
  }
  return out;
}

/**
 * The roots a file saved from the producer's /api/proof/head-roots holds (SPEC.md, Check 18 step 6):
 * `{ format: "azoth.head-roots.published/1", leaf, from, to, roots: [{ hour, root, treeSize, status, token, genTime }] }`.
 * Returns `{ roots: [{ hour (ms), root, treeSize, token (bytes or null) }] }`, or `{ error }` when the file is not one.
 * @param {Uint8Array | string} raw
 */
export function readPublishedRoots(raw) {
  let doc;
  try { doc = JSON.parse(typeof raw === 'string' ? raw : fromUtf8(raw)); } catch { return { error: 'not JSON' }; }
  if (doc?.format !== PUBLISHED_ROOTS_FORMAT || doc?.leaf !== HEAD_LEAF_DOMAIN || !Array.isArray(doc?.roots)) {
    return { error: `not a list of published roots (format "${PUBLISHED_ROOTS_FORMAT}" of "${HEAD_LEAF_DOMAIN}" leaves)` };
  }
  // The hours the file answers for (its from and to): an hour inside them with no root had none — no journal moved.
  const from = isHour(doc.from) ? Date.parse(doc.from) : null;
  const to = isHour(doc.to) ? Date.parse(doc.to) : null;
  const window = from !== null && to !== null && from <= to ? { from, to } : null;
  const roots = [];
  for (const [i, r] of doc.roots.entries()) {
    const hour = isHour(r?.hour) ? Date.parse(r.hour) : NaN;
    if (!Number.isFinite(hour) || !HEX64.test(String(r?.root)) || !Number.isSafeInteger(r?.treeSize) || r.treeSize < 1) {
      return { error: `root ${i + 1}: an hour (the start of an hour, ISO 8601), a root (sha-256 hex) and a tree size (a positive integer)` };
    }
    let token = null;
    if (r.token !== null && r.token !== undefined) {
      try { token = typeof r.token === 'string' && r.token.length ? fromBase64(r.token) : null; } catch { token = null; }
      if (!token) return { error: `root ${i + 1}: its token is not base64` };
    }
    // The token's time as the producer published it (its statement, compared with its other statements — never trust).
    const g = typeof r.genTime === 'string' ? Date.parse(r.genTime) : NaN;
    roots.push({ hour, root: r.root, treeSize: r.treeSize, token, genTime: token && Number.isFinite(g) ? g : null, window });
  }
  return { roots };
}

/** Two published copies of one hour's root that cannot both be the producer's: another root, size or token. */
const disagree = (a, b) => a.root !== b.root || a.treeSize !== b.treeSize || (!!a.token && !!b.token && !equal(a.token, b.token));

/**
 * The roots the reader gave, against each other: one hour, one root. Two copies that disagree (files saved at
 * different times) mean the producer changed a root it had published — said once per hour (a failure).
 * @returns {Array<{ id: string, ok: boolean, detail: string }>}
 */
export function publishedConflicts(published) {
  const seen = new Map();
  const hours = new Set();
  for (const r of published) {
    const first = seen.get(r.hour);
    if (!first) seen.set(r.hour, r);
    else if (disagree(first, r)) hours.add(r.hour);
  }
  return [...hours].sort((a, b) => a - b).map(h => ({
    id: 'head-roots.published', ok: false,
    detail: `the published roots given disagree on ${at(h)}: two different roots (or tokens) for one hour — the producer changed a root it had published`,
  }));
}

/**
 * Check 18 step 6 for one proof that holds: its root against the roots published for its hour. The same root and
 * tree size (and token, when the copy holds one): a pass; another: a failure; none for that hour: not compared.
 * @param {string} id  the proof's line (`head-root.<seq>`)
 * @param {{ root: string, treeSize: number, hour: string }} proof
 * @param {Uint8Array} token  the dossier's token of that root
 * @param {Array<{ hour: number, root: string, treeSize: number, token: Uint8Array | null }>} published
 * @returns {{ id: string, ok: boolean, detail: string, level?: 'warn' }}
 */
export function comparePublished(id, proof, token, published) {
  const hour = Date.parse(proof.hour);
  const same = published.filter(r => r.hour === hour);
  const line = `${id}.published`;
  if (!same.length) {
    return { id: line, ok: true, level: 'warn', detail: `not compared: the published roots given do not cover ${at(hour)} — save the producer's /api/proof/head-roots?from=${at(hour)}&to=${at(hour)} and give it with --published-roots` };
  }
  const other = same.find(r => r.root !== proof.root);
  if (other) {
    return { id: line, ok: false, detail: `the producer published another root for ${at(hour)} (${other.root.slice(0, 12)}…, ${other.treeSize} leaves) than the one this proof leads to (${String(proof.root).slice(0, 12)}…): the head was rooted again after the publication, or the proof is not the producer's` };
  }
  const size = same.find(r => r.treeSize !== Number(proof.treeSize));
  if (size) return { id: line, ok: false, detail: `the root of ${at(hour)} was published with ${size.treeSize} leaves; the proof says ${Number(proof.treeSize)}` };
  const tokened = same.filter(r => r.token);
  if (tokened.some(r => !equal(r.token, token))) return { id: line, ok: false, detail: `the producer published another token for the root of ${at(hour)} than the one this dossier ships` };
  return { id: line, ok: true, detail: `the root of ${at(hour)} is the one the producer published (${same[0].treeSize} leaves${tokened.length ? ', the same token' : ''}): it was not made again since` };
}

/**
 * One proof of an hourly root (SPEC.md, Check 18 steps 1 to 4): the head is the dossier's, its path leads to the root,
 * the root's token verifies (trusted only through a pinned root), its dates hold. Check 18 runs it on each proof of
 * head-roots.json; Check 8 on each journal head a compliance bundle cites as rooted (`rootedHeads`, compliance.mjs).
 *
 *   p        `{ seq, entryHash?, subject?, leafIndex, treeSize, path, root, hour, token }` — head-roots.json's format
 *   subject  the dossier's journal (a workspace id, or "platform"), never the proof's
 *   hashes   the entry hash of each sealed link the dossier carries, by seq — the leaf is recomputed from it
 *   links    those links with the time each seals ({ seq, sealedAt }, for newestSealed)
 *   files    the dossier's files: the token, by name
 *   chain    certificates the proof's producer ships to help build the authority's path (never trust)
 *   signed   the instant the dossier was signed (ms), or null
 *
 * `passed`: steps 1 to 4 hold; `trusted`: the token's path ends on a pinned root (false without one); `token`: its
 * bytes when step 3 was reached. Its lines are `<id>` and, when the root is late, `<id>.dates`.
 * @returns {{ passed: boolean, trusted: boolean, genTime: Date | null, token: Uint8Array | null, checks: Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }> }}
 */
export function verifyRootProof(p, { id, subject, hashes, links, files, shipped = [], chain = [], pinned = null, signed = null }) {
  const no = detail => ({ passed: false, trusted: false, genTime: null, token: null, checks: [{ id, ok: false, detail }] });
  const seq = Number(p?.seq);
  if (!subject || !isSubject(subject)) return no('the dossier names no workspace whose journal the proof could be of');
  if (typeof p?.subject === 'string' && p.subject !== subject) return no(`the proof is of ${p.subject}’s journal; the dossier is ${subject}’s`);
  const entryHash = hashes.get(seq);
  if (entryHash === undefined) return no(`seq ${p?.seq} is not one of the sealed links the dossier carries`);
  if (p.entryHash !== undefined && p.entryHash !== entryHash) return no(`the proof names another hash for seq ${seq} than the dossier’s link`);
  if (!HEX64.test(String(p.root)) || !Array.isArray(p.path) || !p.path.every(h => HEX64.test(String(h)))) return no('the proof’s root and path are sha-256 hex');
  let leaf;
  try { leaf = headLeafHash(subject, seq, entryHash); } catch (err) { return no(`the head cannot be a leaf: ${err.message}`); }
  const r = rootFromPath(leaf, Number(p.leafIndex), Number(p.treeSize), p.path.map(h => fromHex(h)));
  if (!r || !equal(r, fromHex(p.root))) return no(`the inclusion path of seq ${seq} does not lead to the root the token dates (proof altered, or another head)`);
  const tsr = typeof p.token === 'string' ? files[p.token] : undefined;
  if (!tsr) return no(`${p.token ?? 'the root’s token'} missing`);
  const t = checkTimestamp(tsr, p.root, { shipped: [...shipped, ...chain], pinned, what: 'this root' });
  if (!t.ok) return no(`the platform root of ${iso(p.hour)}: ${t.detail}`);
  const dates = rootDates({ genTime: t.genTime.getTime(), hour: typeof p.hour === 'string' ? Date.parse(p.hour) : NaN, newest: newestSealed(links, seq), signed });
  if (dates.fail) return no(`the platform root of ${iso(p.hour)}: ${dates.fail}`);
  const journal = subject === PLATFORM_SUBJECT ? 'Azoth’s platform journal' : 'the workspace’s journal';
  const where = `leaf ${Number(p.leafIndex) + 1} of ${Number(p.treeSize)} of the platform root of ${iso(p.hour)}`;
  const checks = [];
  const trusted = !!pinned && t.trusted;
  if (pinned) {
    checks.push(t.trusted
      ? { id, ok: true, detail: `the head of ${journal} at seq ${seq} — and every entry the chain links before it — existed at ${t.genTime.toISOString()} (${t.tsa}): ${where}` }
      : { id, ok: false, detail: 'the TSA chain of the platform root does not end on the root given with --tsa-root' });
  } else {
    checks.push({ id, ok: true, level: 'warn', detail: `the head of ${journal} at seq ${seq} existed at ${t.genTime.toISOString()} (${where}) — pin the TSA's root with --tsa-root to trust it` });
  }
  if (dates.warns.length) checks.push({ id: `${id}.dates`, ok: true, level: 'warn', detail: `the platform root of ${iso(p.hour)}: ${dates.warns.join('; ')}` });
  return { passed: true, trusted, genTime: t.genTime, token: tsr, checks };
}

/**
 * Check 18 over a dossier's files and its parsed evidence.json: each proof of head-roots.json, its dates, what the
 * signature says — and had to say — about the roots and, with `published` (the roots readPublishedRoots read from the
 * files the reader gave), each proof's root against the one published for its hour and the published roots against
 * what the dossier states and carries (step 6). `anchorAt`: the time of the dossier's anchor.tsr when its token
 * verifies (Check 4); `dated`: another token of the dossier verified (a journal head's, Check 5; a cited root's,
 * Check 8). No head-roots.json, nothing the signature had to state and no published roots: no line.
 * @returns {{ proofs: number, checks: Array<{ id: string, ok: boolean, detail: string, level?: 'warn' }> }}
 */
export function verifyHeadRoots(files, pack, { shipped = [], pinned = null, published = null, anchorAt = null, dated = false } = {}) {
  const raw = files[HEAD_ROOTS_FILE];
  const claims = claimsOf(files);
  const links = carried(pack).filter(l => Number.isFinite(l.seq));
  const newest = newestSealed(links);
  const signed = Number.isInteger(claims?.iat) ? claims.iat * 1000 : null;
  const checks = [...verifyRootsClaim(raw, claims, links), ...(published ? publishedConflicts(published) : [])];
  const rooted = { times: [], top: null };
  let proofs = 0;
  if (raw) {
    let doc;
    try { doc = JSON.parse(fromUtf8(raw)); } catch { doc = null; }
    if (doc?.v !== 1 || doc?.leaf !== HEAD_LEAF_DOMAIN || !Array.isArray(doc?.proofs) || doc.proofs.length === 0) {
      checks.push({ id: 'head-root', ok: false, detail: `${HEAD_ROOTS_FILE} is not a version 1 list of proofs of "${HEAD_LEAF_DOMAIN}" leaves` });
    } else {
      proofs = doc.proofs.length;
      const subject = subjectOf(pack, claims);
      let chainCerts = [];
      if (typeof doc.chain === 'string' && files[doc.chain]) {
        try { chainCerts = readPem(fromUtf8(files[doc.chain])); } catch { chainCerts = []; }
      }
      const hashes = new Map(links.map(l => [l.seq, l.entryHash]));
      for (const p of doc.proofs) {
        const seq = Number(p?.seq);
        const id = `head-root.${Number.isFinite(seq) ? seq : '?'}`;
        const r = verifyRootProof(p, { id, subject, hashes, links, files, shipped, chain: chainCerts, pinned, signed });
        checks.push(...r.checks);
        if (!r.passed) continue;
        rooted.times.push(r.genTime.getTime());
        rooted.top = Math.max(rooted.top ?? seq, seq);
        if (published) checks.push(comparePublished(id, p, r.token, published));
      }
    }
  }
  // Step 5: the export signs after it read what it lists — a signature older than an entry it carries was made again
  // with its instant moved back — and what the signature had to state, whatever the dossier ships.
  if (signed !== null && newest && signed < newest.ms - ROOT_CLOCK_TOLERANCE_MS) {
    checks.push({ id: 'signature.dates', ok: false, detail: `the dossier says it was signed ${at(signed)}, before entry ${newest.seq} it carries was sealed (${newest.sealedAt}): an export signs what it has read — the signature’s instant was moved back` });
  }
  const tokenTimes = [...(anchorAt !== null ? [anchorAt] : []), ...rooted.times];
  checks.push(...verifyRootsStatement(claims, { newest, tokenTimes, dated: dated || tokenTimes.length > 0 }));
  // Step 6: the published roots against what the signature states and the head the dossier carries.
  if (published) {
    const covered = verifyPublishedCoverage(claims, published, { newest, exported: exportedAt(signed, anchorAt), rootedFrom: rooted.top });
    checks.push(...covered);
    if (!raw && !covered.length) checks.push({ id: 'head-roots.published', ok: true, level: 'warn', detail: `published roots given, but the dossier carries no ${HEAD_ROOTS_FILE}: nothing to compare` });
  }
  return { proofs, checks };
}


/** For callers that want the leaf as hex (tests, tooling). */
export const headLeafHex = (subject, seq, entryHash) => hex(headLeafHash(subject, seq, entryHash));
