# Changelog

All notable changes to `@azothos/verifier`. The version follows [Semantic Versioning](https://semver.org/);
the compatibility policy is in [`README.md`](README.md#compatibility).

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
