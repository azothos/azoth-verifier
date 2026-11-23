# Changelog

All notable changes to `@azothos/verifier`. The version follows [Semantic Versioning](https://semver.org/);
the compatibility policy is in [`README.md`](README.md#compatibility).

## 2.4.1 — 2026-11-23

What 2.4.0 holds, published. The 2.4.0 snapshot was refused by the export's own secret scan before it reached the
public repository or npm — gitleaks read two test identifiers as keys (a check's id and the file name of a fixture's
timestamp token, beside the word « token ») — so 2.4.0 was never published. The package's `.gitleaks.toml` lists
those two shapes, by their exact value; no check, no output and no file of the package changes otherwise.

## 2.4.0 — 2026-11-22 (never published: see 2.4.1)

### Added

- The hourly roots, against the ones the producer published (Check 18, step 6): `--published-roots <file>`,
  repeatable. Azoth now publishes every hourly root the moment it is recorded — per hour, the root, its number of
  leaves, its RFC 3161 token and the token's time, never a leaf, a workspace or a head — at
  `/api/proof/head-roots?from=<hour>&to=<hour>` (format `azoth.head-roots.published/1`). The roots live in the
  producer's database: whoever holds it could rewrite a chain whole, root its new head again within the same hour and
  have it dated, and Check 18's steps 1 to 5 would hold. A file a reader saved before — anyone may keep and pass it
  on — no longer matches: a proof whose root, tree size or token differs from the one published for its hour fails
  (`head-root.<seq>.published`); two copies given that disagree on one hour fail once (`head-roots.published`); an
  hour the files do not cover is a warning (« not compared »). The verifier reads the files from disk and fetches
  nothing; without the option, nothing changes. The web page takes the same files (a second file input).
  `readPublishedRoots`, `comparePublished` and `publishedConflicts` in `src/headroot.mjs`; `verifyDossier` takes
  `publishedRoots`.
- A compliance bundle may cite a journal head of an hourly platform root as evidence (Check 8, a kind of source
  `root`): the bundle carries its proof in `evidence.json` (`rootedHeads`, the format of a `head-roots.json` proof)
  with the root's token in its manifest, and the verifier holds each one to Check 18's steps 1 to 4 — the leaf
  recomputed from the bundle's workspace and a verified link, the path to the root, the token, the dates; with
  `--tsa-root`, a root whose path ends elsewhere counts nothing (`compliance.root.<seq>`). A requirement marked
  covered on such a head whose proof or token does not verify fails (`compliance.citations`, `compliance.coverage`).
  A verifier before 2.4.0 refuses a bundle that cites one (it reads the kind as a journal predicate no entry meets).
  `verifyRootProof` and `signedAt` in `src/headroot.mjs` (Check 18 runs the same function on each proof).
- What the signature had to state of the hourly roots (Check 18, step 5). Every Azoth producer states `roots` in each
  dossier it signs from 2026-11-22T00:00:00Z (`ROOTS_STATED_FROM`, pinned here). Whoever holds the workspace's key
  could sign a rewritten dossier again, ship no root proof and leave the statement out — or say the producer dated
  no head — and the verifier said nothing. Now: a signature that states nothing on a dossier dated after that
  instant — by its signature, an entry it carries or a token it ships — is a warning; `roots: null` on such a dossier
  that no token dates is a warning; a signature older than an entry it lists fails (`signature.dates`: an export
  signs what it has read); an `anchor.tsr` dated more than 2 hours after the signature is a warning
  (`timestamp.dates`: it was added later). Warnings, so that a dossier that verified keeps verifying.
  `verifyRootsStatement` and `exportedAt` in `src/headroot.mjs`; `verifyHeadRoots` takes `anchorAt` and `dated`.
- The published roots against what the signature states and the head the dossier carries (Check 18, step 6, with
  `--published-roots`): `roots: null`, or a `since` later than an hour, while the producer published an anchored root
  dated before the export, fails (`head-roots.published`); the journal's head the signature commits, carried by the
  dossier and dated by a root the producer published before the export — every hour from the head's to that root's
  answered for by the files given — with no proof of it that holds, fails: the export shipped it and it was removed;
  otherwise such a root without a proof at or after the newest entry is a warning. `readPublishedRoots` keeps each
  root's `genTime` and its file's `from`–`to`; `verifyPublishedCoverage` in `src/headroot.mjs`.

## 2.3.0 — 2026-11-19

2.2.1 was never published: its fix ships in this version.

### Added

- A signed JSON evidence pack (Check 17): `azoth-verify export <body.json> --signature <token | file> --keys
  <jwks.json> [--workspace <id>]`. Azoth answers the journal's JSON evidence pack with an
  `X-Azoth-Export-Signature` header, a compact JWS (EdDSA, typ `azoth-journal-export+jws`) by the workspace's
  key over the sha256 of the exact body and what it covers. The verifier checks that the body is the one
  signed byte for byte, that the key is one of those given and may sign at that instant (the same key rules
  as Checks 10 and 12), that the pack, the signature and — when the keys or `--workspace` say it — the keys
  are the same workspace's, that the pack lists what the signature commits (its kind, the chain's head, the
  count and range of its entries, its filters), then the pack itself: its chain (Check 3), its retention
  checkpoint (Check 15), each decision's law and cost decided again from its seal (Checks 11 and 13) and its
  sealed time, actor type and trace (Check 16). The signature may be given as the token, or as a file holding
  it or the header line. The web page checks a pack too, under the keys chosen. A module export,
  `@azothos/verifier/export` (`verifyExport`).
- An entry that carries its `coreCanonical` beside its `core` must state the same canonical form (Check 3):
  the core a reader sees is the core sealed. No producer writes both today; one that does is held to it.
- The hourly platform root (Check 18). Azoth now dates, every hour, the chain head of every workspace whose
  journal moved — whatever its plan — and of its own platform journal, in one Merkle tree whose root an RFC 3161
  authority signs. A dossier that carries a rooted head ships `head-roots.json` (the inclusion proof: leaf index,
  tree size, sibling path, root) and the root's token beside the manifest. The verifier recomputes the leaf from the
  dossier's own workspace and sealed link (RFC 9162 hashing: `SHA-256(0x00 || "azoth.journal-head.v1" LF subject LF
  seq LF entryHash)`, nodes behind `0x01`), walks the path to the root, and verifies the token with Check 4's rules
  — trusted only through `--tsa-root`, a warning without it. A proof for another workspace, a seq the dossier does
  not carry, an altered path, root or token fails. The web page runs the same check. A module, `src/headroot.mjs`.
- Check 18 holds each root's dates (step 4): a root's token dated before the hour its proof names, before an entry
  it covers was sealed (the `occurredAt` its core seals) or after the dossier was signed (`iat`) fails — a tolerance
  of 5 minutes for the clocks; one dated more than 2 hours after its hour or after the newest entry it covers is a
  warning (`head-root.<seq>.dates`): late, it proves only that the head existed then. An `hour` that is not the start
  of an hour fails.
- What the signature says of the roots (Check 18 step 5, Check 12's optional claim `roots`): `{ since, proofs }` —
  the hour the producer began dating heads, the sha256 of the `head-roots.json` the export ships (or `null`) — or
  `null`. A `head-roots.json` that is not the one committed fails; one missing although committed, one added
  although none was, and a dossier sealed after rooting began that ships none are warnings. A missing
  `head-roots.json` never fails a dossier; a producer that leaves the claim out gets no line, as before.
  `carried` (`src/signature.mjs`) also reads the time each link's core seals (`sealedAt`).

## 2.2.1 — 2026-11-19

### Fixed

- Check 4 builds the time-stamping authority's certification path as RFC 4158 does. An authority may
  ship in its token a copy of its root cross-signed by another root (DigiCert's tokens carry « DigiCert
  Trusted Root G4 » issued by « DigiCert Assured ID Root CA »). The verifier followed the first
  certificate that named the right issuer and never stopped on the pinned root: a genuine timestamp
  failed with `--keys` alone and with the authority's root as `--tsa-root`, and passed only with the
  intermediate pinned, while `openssl ts -verify` accepted it. Now a certificate whose subject and public
  key are a pinned root's is that root, every candidate issuer is tried whatever order the certificates
  come in, and a path that ends on a pinned root is preferred to any other (SPEC.md, Check 4, step 6).
  Trust still comes only from a pinned certificate: a certificate with the root's name and another key
  is never the root, and a timestamp no path brings to a pinned root is not trusted. No well-formed
  timestamp that passed fails; a chain that loops, or that does not end on a self-signed certificate
  within 8 issuers, used to pass with a warning and now fails as incomplete.

## 2.2.0 — 2026-11-17

### Added

- A key its producer declared compromised. A workspace's or Azoth's platform keys may now carry the
  status `compromised`, with `compromised_at` — from when its signatures are not to be trusted — and
  `compromise_declared_at`. A dossier's or a platform package's signature (Check 12) and a receipt
  (Check 10) made under such a key fail when they are dated at or after `compromised_at`, and pass with
  a warning when dated before (the date is the signer's own claim; a trusted timestamp, Check 4, is what
  shows the content existed then). A compromised key without a readable instant, or a key status the
  verifier does not know, refuses every signature. One rule for the command line and the web page
  (`src/keys.mjs`, `keyTrustAt`); keys without a status verify as before (SPEC.md, « Keys and signatures »).

## 2.1.1 — 2026-11-16

### Fixed

- The command line and the web page give the same verdict on every signature. The command line
  (node:crypto) verified a signature under its key's own algorithm, whatever the scheme named: an
  ECDSA-SHA256 or an RSA PKCS #1 v1.5 signature labelled Ed25519 — or an RSA signature labelled
  ECDSA, a PSS one labelled PKCS #1 v1.5 under an `id-RSASSA-PSS` key — passed there and failed in
  the browser. A signature now verifies only when the scheme it names is its key's type, in both.
- The same keys and signatures are refused in both (SPEC.md, « Keys and signatures »): an ECDSA
  signature that is not strict DER (trailing bytes, padded or negative integers), a compressed or
  hybrid EC point, a curve other than P-256, P-384 and P-521, an RSA signature shorter than the
  modulus, an RSA exponent below 3 or even, an Ed25519 key in a non-canonical encoding or with
  parameters, a key whose encoding has trailing bytes, a hash other than SHA-1/256/384/512.
- A signature that cannot be checked is a verdict, never an exception: both cryptographies answer
  `false` for a key of another type, a malformed key or signature, an unknown hash; the command
  line used to throw where the page answered `false`.
- Check 4: RSASSA-PSS parameters must name the SignerInfo's digest algorithm (RFC 4056), and a
  mask generation function on another hash than the signature's is refused instead of misread.

## 2.1.0 — 2026-11-14

### Added

- Check 16 of [`SPEC.md`](SPEC.md): an entry's time, actor type and trace. An entry whose sealed core
  carries `occurredAt`, `actorType` or `traceId` must show the same in its readable fields — the time as
  the same instant, to the microsecond — else the dossier fails, naming the entry. These fields used to
  sit beside the core, outside the hash: an entry's date, its kind of actor or its trace could be changed
  in `evidence.json` without breaking the chain. Entries sealed before carry none of them and verify as
  before; the dossier says how many entries carry a sealed time (a warning when some do not).

## 2.0.0 — 2026-11-14

### Changed (breaking)

- The dossier's signature (Check 12) is **required**. A dossier or a platform package without
  `signature.jws` fails: nothing bound its content to a key, so its latest or first entries could
  be removed, or its whole chain rewritten, with the manifest recomputed — and it used to pass.
- The signing key must be one given with `--keys` (the keys the producer publishes). A signature
  checked only against the dossier's own `keys.jwks.json` fails: such a dossier vouches for itself,
  and anyone can rebuild one and sign it with a key of their own. The web page asks for the keys
  in the same way. `azoth-verify receipt --dossier` without `--keys` checks the receipt against the
  dossier's keys, and fails the dossier's signature for the same reason.

### Added

- Format 2 of the signature's claims commits what the dossier covers: its kind, the chain's head
  when it was exported (seq and entry hash), the count and seq range of the entries it lists, and
  the export's filters. `evidence.json` must match them (entries cut from the start or the end
  fail), and a `coverage` line states what the dossier covers and how many later entries it does
  not hold. A format 1 signature still verifies, with a warning that it states none of this.
- Platform evidence packages are signed by Azoth's platform key, published at
  `/api/proof/platform-keys`, and ship its public keys as `keys.jwks.json`.
- Check 15 of [`SPEC.md`](SPEC.md): the journal retention checkpoint. A dossier whose kept chain
  starts after the genesis — the oldest entries removed under the workspace's retention — verifies
  when its first entry links to the checkpoint shipped in `evidence.json` (`retention`), and each
  sealed `journal_retention_applied` act declares the checkpoint shipped for it.

## 1.0.0 — 2026-11-07

The first public version, under the Apache-2.0 license.

### Added

- Checks 1 to 14 of [`SPEC.md`](SPEC.md): the manifest and its root hash, the sealed decision
  chain and its segments, the RFC 3161 timestamp, decision, incident, compliance, platform,
  litigation, exhaustion, risk-profile, regulator and AI footprint dossiers, client-vault
  content, call receipts, the applicable law and the sealed cost of each decision, and the
  dossier's signature.
- `azoth-verify receipt` — a call's receipt, against the workspace's keys or a dossier.
- `web/azoth-verify.html` — the same checks in one offline browser page, with no network access.
- `examples/` — a demo dossier, its keys and a receipt, built by Azoth's export code with a demo
  key that was never written down.
- A `node:test` suite (`npm test`) over the examples and the page.
- Package entry points: `@azothos/verifier`, `@azothos/verifier/receipt`, `@azothos/verifier/zip`.

### Changed

- `azoth-verify receipt --dossier <d> --keys <k>` checks the dossier's signature against the keys
  given, not only the receipt's; so does the web page with the keys chosen.
