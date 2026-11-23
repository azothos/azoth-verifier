# Azoth dossier verification spec

This is the authoritative, source-independent specification the verifier
implements. It is reimplementable from this document alone — you do **not** need
Azoth's source code, and the verifier deliberately shares none of it.

An audit dossier is a ZIP (STORED / uncompressed) containing `evidence.json`,
`dossier.html`, `manifest.json`, and `VERIFY.md` — and, when the producer has a
trusted time-stamping authority, `anchor.tsr` and `tsa-chain.pem` (Check 4). A
dossier may also carry `dossier.pdf`, the same synthesis as `dossier.html`: it is
listed in `manifest.files` and checked by Check 1 like any file, and so may
`keys.jwks.json`, the keys that sign the receipts of its calls (Check 10) and the
dossier itself, `jurisdiction-packs.json` (Check 11), `model-catalog.json`
(Check 13) and the plain-language notices `how-to-verify.html`,
`comment-verifier.html` and `how-to-verify.<es|zh|ar>.html`. A dossier's
readable files (`*.html`, `*.pdf`, in any language) restate `evidence.json`:
Check 1 covers them like any file, and no check reads them. `signature.jws` (Check 12), like `anchor.tsr`, is
outside the manifest: it signs the manifest's `root_hash`. Every dossier and
every platform package must carry it, signed by a key the verifier was given:
without it nothing binds the content to a key, and whoever handed the dossier
over could have removed entries and recomputed the manifest.

A journal export may also come as a **JSON evidence pack**: the same pack as a dossier's
`evidence.json`, answered as the body of an HTTP response whose `X-Azoth-Export-Signature` header
signs it. Check 17 verifies it.

What the checks prove is integrity, order, origin, coverage and time: the files
are the ones sealed, chained in that order, signed by the workspace's key, they
hold what the signature says they cover — and, with a timestamp, that they
existed at that time. They never prove that a decision
was right or that what a sealed fact states is true.

## Hash primitive

`sha256(x)` = SHA-256 over the UTF-8 bytes of `x` (or the raw bytes if `x` is
binary), rendered lowercase hexadecimal.

## Keys and signatures

Every signature a check meets — a dossier's (Check 12), a receipt's (Check 10), a
catalog version's (Check 13), a timestamp token's and its certificates' (Check 4) —
is verified under these rules. Whatever does not meet them is an **invalid
signature**: a check reports it as a failure, never as an error of the verifier.

- **The scheme is the key's.** The scheme a signature names — a JWS `alg`, a
  certificate's or a SignerInfo's signature algorithm — must be the type of the
  key it is checked with: RSASSA-PKCS1-v1_5 an `rsaEncryption` key; RSASSA-PSS an
  `rsaEncryption` or `id-RSASSA-PSS` key; ECDSA an `id-ecPublicKey` key; EdDSA an
  Ed25519 key. A signature is never verified under the key's own algorithm in
  place of the one named: an ECDSA signature labelled EdDSA is invalid, even when
  the key holder made it.
- **Hashes.** SHA-1, SHA-256, SHA-384 or SHA-512 for RSA and ECDSA; Ed25519 hashes
  with SHA-512 itself and takes none.
- **Public keys** (`SubjectPublicKeyInfo`, DER: minimal lengths, nothing after the
  last element, no unused bit in the key's BIT STRING):
  - RSA: parameters NULL or absent (`rsaEncryption`); for `id-RSASSA-PSS`, absent,
    or RFC 4055 parameters whose hash and MGF1 hash are the signature's (the trailer
    field 1; the minimum salt length is not enforced, see below). A modulus of 512
    to 16384 bits, odd; an exponent odd, at least 3, below the modulus, of at most
    64 bits.
  - EC: a named curve — P-256, P-384 or P-521 — and an uncompressed point
    (`0x04 ‖ x ‖ y`, RFC 5480), each coordinate below the field prime, on the curve.
    Compressed and hybrid points are refused.
  - Ed25519: no parameters (RFC 8410), 32 bytes in canonical form (RFC 8032
    §5.1.3: `y` below `2^255 − 19`; no sign bit on `x = 0`). A JWK's `x` is the
    same 32 bytes, base64url.
- **Signatures.**
  - RSA: exactly as many bytes as the modulus, its value below it (RFC 8017
    §8.1.2, §8.2.2). PKCS #1 v1.5: the DigestInfo encoding, compared in full.
    PSS: MGF1 with the signature's hash; the salt length is recovered from the
    signature (any length).
  - ECDSA: DER `SEQUENCE { INTEGER r, INTEGER s }`, minimal, nothing after it,
    `1 ≤ r, s < n`. The digest is truncated to the order's bit length, whatever
    the curve and the hash.
  - Ed25519: 64 bytes, `S < L` (RFC 8032 §5.1.7); verified without the cofactor.

**A producer's key, at the instant it signed.** A workspace's keys (Checks 10, 12) and Azoth's platform
keys (Check 12) are published as a JWKS whose keys carry a `status`: `active`, `retired` — or
`compromised`, with `compromised_at` (from when its signatures are not to be trusted) and
`compromise_declared_at` (when its producer declared it). Under a key declared compromised, a
signature whose `iat` is at or after `compromised_at` is **refused** — anyone holding the key could
have made it. One dated before stands with a **warning**: its date is the signer's own claim, which
whoever holds the key can write; only a trusted timestamp (Check 4) shows the content existed then. A
`compromised` key without a readable `compromised_at`, or a `status` other than these three, refuses
every signature. A key with no `status` (an older producer) is trusted as before. What a verifier
knows of a key is what the JWKS it was given says: fetch the producer's keys again to learn of a
compromise declared since.

The reference implementation reads keys and signatures in one module,
`src/keys.mjs`, for both of its cryptographies — node:crypto (`src/crypto.mjs`)
and plain JavaScript (`src/crypto-web.mjs`, the web page's) — so the command line
and the page give the same verdict on the same bytes.

## Check 1 — file integrity (`manifest.json`)

`manifest.json`:

```
{ "format_version": 1, "generated_at": "...", "regulatory_mapping_version": "...",
  "files": [ { "path": "...", "sha256": "..." }, ... ], "root_hash": "..." }
```

For each entry in `files`, `sha256(bytes of that file)` must equal `sha256`.
`manifest.json` is the index — it is **not** in its own `files` list.

## Check 2 — `root_hash`

1. Collect the `sha256` hex strings from `manifest.files`.
2. Sort them **ascending** (lexicographic, byte order).
3. Concatenate them with **no separator** into one string.
4. `root_hash` must equal `sha256(that string)`.

## Check 3 — sealed decision chain (`evidence.json`)

`evidence.json` has an `entries` array. Each entry has `seq` (number),
`prevHash`, `entryHash`, and a non-personal `core` object (hashes + metadata,
never prompt/response content). An entry also shows readable fields beside its
core — `occurredAt`, `actorType`, `actorId`, `traceId` — which the hash does not
cover; a core sealed with the time, actor type and trace binds them (Check 16).

**Canonical form of an entry's core:**

`core_canonical = JSON.stringify(sortKeys(core))`, where `sortKeys`:

- for an **object**: emit keys in **ascending sort order**, recursively, and
  **omit any key whose value is `undefined`**;
- for an **array**: map `sortKeys` over the elements, **preserving order**;
- for a **primitive**: pass through unchanged.

"Ascending sort order" is exact JavaScript semantics, which a reimplementation in another language
must reproduce:

- keys are compared by **UTF-16 code units** (the default of `Array.prototype.sort()`), not by code
  point and not by locale: a key holding a character outside the Basic Multilingual Plane sorts by
  its surrogate pair;
- `JSON.stringify` then emits **integer-like keys first** (`"0"`, `"9"`, `"10"`, … in numeric order),
  before every other key, whatever the sort gave — so `{"10":…,"9":…}` is written `{"9":…,"10":…}`;
- the sorted object is built by **assignment**, so a key named `__proto__` is not kept.

**Entry hash:** `entryHash == sha256(prevHash + core_canonical)`. The
concatenation is plain string concatenation (no separator byte). The genesis
entry's `prevHash` is the empty string `""`.

**The core shown is the core sealed.** A listed entry is hashed from its `core`, so the core a reader
sees is the one the chain holds. An entry that also carries the producer's `coreCanonical` beside its
`core` must have `coreCanonical == core_canonical(core)`; otherwise it fails, as an altered entry. This
applies wherever an entry is listed (Checks 3, 5, 7, 8 and 17).

**Linkage:** order the entries by `seq` ascending; seqs must follow each other
(n, n+1, …) and each entry's `prevHash` must equal the previous entry's
`entryHash`. Any insertion, removal, reorder, or edit breaks one of these
invariants.

**Segments.** A dossier for a period starts after the genesis: its first entry
is verified on its own hash, and its `prevHash` is where the segment attaches to
the earlier chain (an entry at `seq` 1 must have `prevHash == ""`). The segment
is intact from there on; what precedes it is out of the dossier. Once the
workspace's journal retention removed the oldest entries, the kept chain itself
starts after the genesis: `evidence.json` then carries the retention checkpoint
the first kept entry links to (Check 15).

**Filtered dossiers.** When `entries` lists only part of the segment (a use-case,
actor or refusal filter), `evidence.json` also carries `chain`: every link of the
segment as `{ seq, prevHash, entryHash, coreCanonical }`. The linkage rules apply
to `chain` (the entry hash recomputes from `prevHash + coreCanonical`); then each
listed entry must recompute to its own `entryHash` and equal the `chain` link of
the same `seq` (same `entryHash` and `prevHash`).

## Check 4 — trusted timestamp (`anchor.tsr`, optional)

Present only when the dossier was timestamped. `anchor.tsr` is an RFC 3161
`TimeStampResp`, DER, exactly as the time-stamping authority (TSA) returned it;
`tsa-chain.pem` holds PEM certificates the producer ships to help build the TSA
chain. Neither file is in `manifest.files`: the timestamp signs
`manifest.root_hash`, so it cannot be one of the hashed files.

1. **Response.** `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }`.
   `status.status` must be `0` (granted) or `1` (grantedWithMods), and the
   token present.
2. **Token.** The token is a CMS `ContentInfo` whose `contentType` is
   `signedData` (`1.2.840.113549.1.7.2`, RFC 5652 §5). Its
   `encapContentInfo.eContentType` must be `id-ct-TSTInfo`
   (`1.2.840.113549.1.9.16.1.4`); `eContent` (an OCTET STRING) holds the DER
   `TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, … }`.
3. **Imprint.** `messageImprint.hashAlgorithm` must be SHA-256
   (`2.16.840.1.101.3.4.2.1`) and `messageImprint.hashedMessage` must equal the
   32 bytes that `manifest.root_hash` (hex) stands for. Together with Check 2,
   this binds the timestamp to every file of the manifest: a file changed after
   the timestamp, even with a re-computed manifest, gives another `root_hash`.
4. **Signature.** Take the (single) `SignerInfo`. With `signedAttrs` present:
   its `content-type` attribute must be `id-ct-TSTInfo`, and its
   `message-digest` attribute must equal `H(TSTInfo DER)`, `H` being the
   SignerInfo `digestAlgorithm` (SHA-256/384/512). The signature is computed over
   the `signedAttrs` DER **with its tag rewritten from `[0]` (0xA0) to SET (0x31)**
   (RFC 5652 §5.4). Without `signedAttrs`, it is over the TSTInfo DER. It must
   verify with the public key of the signer certificate — the certificate whose
   serial number is the `sid` serial, taken from the token's `certificates`,
   `tsa-chain.pem` or the pinned roots. RSA PKCS#1 v1.5, RSA-PSS, ECDSA and Ed25519
   are accepted, under the rules of « Keys and signatures »: the SignerInfo's
   signature algorithm must be the signer key's type, and RSASSA-PSS parameters
   must name the SignerInfo's digest algorithm (RFC 4056 §2).
5. **Signer.** The signer certificate must carry the extended key usage
   `id-kp-timeStamping` (`1.3.6.1.5.5.7.3.8`), and `genTime` must fall within its
   validity period.
6. **Chain.** From the signer, follow issuers: a certificate whose subject is
   the issuer Name (byte for byte) and whose key verifies the signature, taken
   from the token's `certificates`, `tsa-chain.pem` and the pinned certificates,
   in any order. Every such candidate is tried in turn — a candidate that leads
   nowhere is backtracked from (RFC 4158), the pinned ones first — up to 8
   issuers above the signer, one subject and key never twice in a path, 64
   signatures checked at most. A path ends on:
   - **a trust anchor**: a certificate whose subject Name and public key
     (`subjectPublicKeyInfo`, byte for byte) are those of a certificate the
     verifier pinned itself (`--tsa-root`, the TSA's published root). A copy of
     that root cross-signed by another root — same subject and key, another
     issuer, as some TSAs ship in their tokens — is the root: the path ends
     there, trusted. A pinned intermediate is an anchor too;
   - otherwise **a self-signed certificate** (its subject is its issuer and its
     own key verifies it), untrusted.

   **Trust:** the timestamp is trusted only if a path ends on a trust anchor;
   such a path is preferred to any other. Certificates shipped in the dossier help
   build the path but never establish trust: without a pinned root the check
   **warns** (it does not fail), and with one, a path that ends elsewhere fails.
   No path at all (an issuer nowhere to be found) fails.

`genTime` is then the time, attested by the TSA, at which `root_hash` — hence
every file and every sealed decision of the dossier — existed.

The same check with OpenSSL, as a second independent implementation:

```
openssl ts -verify -digest <manifest.root_hash> -in anchor.tsr -CAfile tsa-root.pem -untrusted tsa-chain.pem
```

## Check 5 — decision dossier (`evidence.json` kind `"decision"`)

A decision dossier gathers every sealed entry carrying one decision-reference
hash (an HMAC of the client's own reference — the reference itself is printed
only in the readable `decision.*.html`). It replaces Check 3:

1. **Entries.** Each entry of `entries` recomputes to its `entryHash` (Check 3's
   rule) and carries `core.decisionRefHash == decisionRefHash`.
2. **Segments.** Each `segments[i]` holds `links` `{ seq, prevHash, entryHash,
   coreCanonical }` covering `fromSeq`…`toSeq`: Check 3's linkage rules apply to
   each segment on its own (it attaches to the earlier chain by its first
   `prevHash`). Every entry must equal the link of its `seq` in some segment.
3. **Timestamped heads.** A segment with `anchor` ends on a journal head an RFC
   3161 authority timestamped: `anchor.file` is a TimeStampResp whose imprint
   must equal the `entryHash` of the segment's last link, verified as in Check 4
   (signature, signer, chain; trusted only through a pinned root). Since every
   link commits to the previous one, every entry of the segment existed,
   unaltered, at the token's `genTime`. A segment without `anchor` links the
   entries without dating them (a warning).
4. **Policy in force.** For each distinct `core.policyVersion` of the entries,
   `policies[hash].file` must have `sha256 == hash` (the canonical rule set
   evaluated); likewise `core.usecaseSnapshotHash` and `usecases[hash].file`
   (the use-case snapshot, with its approved version). A hash whose file is not
   in the dossier is a warning: sealed, not archived.

`inclusion` in `integrity` says which proof the dossier carries: `anchored`
(every segment ends on a timestamped head), `contiguous` (linked, not dated by a
third party), `individual` (entries verified alone; too far apart to ship the
chain between them).

## Check 6 — client-vault content (optional, supplied by the client)

For a use case in vault mode, the content of a call is kept by the client only,
encrypted with the client's key in the client's storage; Azoth seals a receipt:
an entry with `core.decision == "vault_receipt"` whose `core.policy` carries
`vaultPlaintextHash`, `vaultCiphertextHash` and `vaultKeyId`, under the call's
`traceId` (and its `decisionRefHash`).

- **Plaintext document**: the UTF-8 bytes of
  `canonical({ v: 1, traceId, request, response })` (keys sorted recursively, as
  for `core`), `request` and `response` being the call as sent and as received.
- **Envelope** (what the client stores): the UTF-8 bytes of
  `{ "v": 1, "alg": "A256GCM", "keyId", "traceId", "iv", "ciphertext" }` —
  AES-256-GCM of the plaintext under the client's key, 12-byte `iv`, `traceId` as
  the additional authenticated data, `iv` and `ciphertext` (with its 16-byte tag
  appended) in base64.

Given a file the client supplies (`--vault-content`), its `sha256` must equal the
`vaultPlaintextHash` (a decrypted document) or the `vaultCiphertextHash` (the
stored envelope) of a receipt in the dossier. Any change to the content — one
character — gives another hash and fails. The check needs no key: whoever holds
the key decrypts; whoever holds the dossier verifies.

## Check 7 — incident dossier (`evidence.json` kind `"incident"`)

An incident dossier gathers the actions sealed for one incident (a governance
entry each, `core.decision` starting with `incident_`, the incident id as trace
id), the scope it was declared with, and the decisions the scope matched. It
replaces Check 3:

1. **Actions.** Each entry of `entries` recomputes to its `entryHash` (Check 3's
   rule), has `core.surface == "governance"`, and its `core.policy` names the
   incident: `incidentId == incidentId`, `scopeHash == scopeHash`. Each is a link
   of a verified segment, and a segment with `anchor` is closed by its RFC 3161
   token — exactly as Check 5, steps 2 and 3.
2. **Order.** `core.policy.incidentStep` over the entries is 1, 2, … n, each once.
   When the steps do not follow the seq order (an action sealed late, through
   the producer's queue), the step says where it belongs (a warning).
3. **Scope.** The entry of step 1 is `incident_declared`; its `core.policy.scope`
   (a string) equals `canonical(scope)` — keys sorted, as for `core` — and
   `sha256(core.policy.scope) == scopeHash`.
4. **Impact.** The `incident_scoped` entry with the highest step sealed
   `matched`, `setHash` and `throughSeq`. `impact.decisions` lists that many
   `{ seq, entryHash }`, strictly increasing seqs, none above `throughSeq`, and
   `sha256(entryHash₁ + "\n" + … + "\n" + entryHashₙ) == setHash`. A dossier too
   large to list them carries `impact.decisions: null` (a warning).
5. **Matched entries.** Each entry of `impact.entries` recomputes, is the entry
   of its seq in `impact.decisions`, and **matches the scope**: every criterion
   the scope holds must hold on the entry —
   - `core.surface == "governance"` only for a refusal: `core.decision` is one of
     `scope.refusalDecisions`;
   - `model`, `modelVersion`, `policyVersion`, `agentId`, `mandateVersion`,
     `usecaseId`: equal to the core field of the same name;
   - `tool`: some `core.tools[i].name` equals it;
   - `dataSource` `{ type, id? }`: some `core.dataSources[i]` has that `type`
     (and that `id` when given);
   - `from` / `to`: `from <= occurredAt < to` — `occurredAt` is the capture
     time recorded with the entry, outside the hash unless its core seals it
     (Check 16 then holds it to the sealed time).
6. **Completeness.** When `impact.completeness.links` is shipped — every link
   `{ seq, prevHash, entryHash, coreCanonical, occurredAt }` from seq 1 to
   `throughSeq` — the links verify from the genesis (Check 3's rule), and the
   scope applied to every link (`core` = `JSON.parse(coreCanonical)`) matches
   exactly the entries of `impact.decisions`: no more, no less. Without it, the
   set is committed by its sealed hash but its completeness rests on the
   producer (a warning).
7. **Report drafts.** For each `incident_report_drafted` entry,
   `reports[core.policy.draftId].file` has `sha256 == core.policy.sha256`. A
   draft is a draft: nothing in the dossier says it was sent.

## Check 8 — compliance bundle (`evidence.json` kind `"compliance"`)

A compliance bundle maps the requirements of a framework (EU AI Act, NIST AI RMF,
ISO/IEC 42001) to sealed evidence, for a period. It is a tool to prepare an audit,
not a certification: `disclaimer.fr` and `disclaimer.en` say so and must be present.
It replaces Check 3:

1. **Framework.** `framework.file` (in the manifest) hashes to `framework.sha256`.
   It holds `framework` (id, version, `mappingStatus`, `requirements`: each with
   `id`, `applicability` — `always` or `high_risk` — and `required`, a list of
   groups, each a list of kind ids), `kinds` and the texts the index shows.
   `mappingStatus` other than `validated` is a warning: the mapping is still to be
   reviewed by an expert.
2. **Entries.** Each entry of `entries` recomputes to its `entryHash` (Check 3's
   rule) and, unless `integrity.inclusion` is `individual`, is a link of a
   `segments[i]` verified as in Check 5 (step 2), a segment with `anchor` closed by
   its RFC 3161 token (step 3).
3. **Heads.** Each `heads[i]` is a journal head an RFC 3161 authority timestamped:
   `heads[i].file` is a TimeStampResp whose imprint equals the `entryHash` of the
   link at `journalSeq`, verified as in Check 4.
   **Rooted heads** (added in verifier 2.4.0). Each `rootedHeads[i]` is a journal head
   that was a leaf of an hourly platform root, in the format of a proof of
   `head-roots.json` (Check 18): `{ seq, entryHash, leafIndex, treeSize, path, root,
   hour, token }`, its `token` a file of the bundle (in the manifest), `rootChain` (when
   not null) a file of PEM certificates that help build the authority's path. Each is
   checked as Check 18 checks a proof, steps 1 to 4: the subject is the bundle's
   `workspaceId`, the leaf is recomputed from the `entryHash` of the link at `seq` of a
   **verified** segment (step 2), the path leads to `root`, the token verifies over
   `root` (Check 4), its dates hold (`iat` of `signature.jws` as *S*). Lines
   `compliance.root.<seq>` (and `.dates`). With a pinned root (`--tsa-root`), a token
   whose path ends elsewhere fails and the head is not verified; without one, the
   head is verified with a warning.
4. **Predicates.** A kind is `{ id, source }` with `source` one of `journal`,
   `anchor`, `root`, `external`. A `journal` kind has `match`:
   `surface` (equal to `core.surface`); `decisions` and/or `decisionPrefixes`
   (when either is given, `core.decision` is one of `decisions` or starts with one
   of `decisionPrefixes`); `policy` (`{ key: { present: true } }` — `core.policy[key]`
   is neither absent nor null — or `{ key: { eq: v } }` — strictly equal to `v`);
   `corePresent` (each named `core` field neither absent nor null). Every
   condition must hold.
5. **Citations.** For each requirement and each kind of `requirements[i].evidence`:
   an `external` kind has `sealed == 0` and cites nothing; `cited.length <= sealed`;
   each cited seq is a verified entry matching the kind's predicate (an `anchor`
   kind: a verified head of step 3; a `root` kind: a verified rooted head of step 3).
6. **Coverage.** Every requirement of the framework is listed. A requirement with
   `status == "covered"` has, for **each** group of `required`, at least one kind
   with a valid citation. `status == "out_of_scope"` with `reason ==
   "declared_out_of_scope"` names a `scope[j]` whose `seq` is a verified
   governance entry `compliance_scope_declared` with `policy.requirementId`,
   `policy.frameworkId` and `policy.justificationHash` equal to the declaration's;
   with `reason == "not_applicable"`, the requirement's `applicability` is
   `high_risk` and `context.highRiskUseCases == 0` (stated by the producer: a
   warning).
7. **Summary.** `summary` recomputes from the statuses: `total`, `covered`,
   `partial`, `notCovered`, `outOfScope`, `applicable = total − outOfScope`,
   `rate = covered / applicable` (0 when nothing applies).

Counts beyond the citations (`sealed`) and rows the producer marks `attested` (in
its database, not sealed) are the producer's statement: they never make a
requirement covered.

## Check 9 — platform evidence package (`evidence.json` kind `"platform"`)

A package one producer (Azoth) makes about ITS OWN controls, one calendar month
(UTC) at a time, for its auditor: the month's segment of its platform journal — a
chain in the same format as Check 3 (deployments, restore drills, staff access,
break-glass, access reviews, administrator grants).

```
{ "kind": "platform", "formatVersion": 1, "format": "azoth.platform-evidence/1",
  "period": { "from": "YYYY-MM-01", "to": "YYYY-MM-01" },        // to exclusive
  "previous": { "toSeq": n, "entryHash": "..." } | null,
  "chain": [ { "seq", "prevHash", "entryHash", "coreCanonical" }, ... ],
  "counts": { "<act>": n, ... },
  "snapshot": { "attested": true, ... } }
```

Each `coreCanonical` is a JSON object with at least `act` (string) and
`occurredAt` (ISO-8601). The package ships Azoth's platform public keys as
`keys.jwks.json` (in the manifest) and is signed like a dossier (Check 12) by
Azoth's platform key — claims `ws` `"platform"`, kind `"platform"`, the platform
journal's head when the package was made, the links of `chain` and the period as
filters. Its keys are published at `/api/proof/platform-keys`.

1. **Links.** The chain verifies as in Check 3 (`entryHash ==
   sha256(prevHash + coreCanonical)`, seqs follow each other, each `prevHash` is
   the previous `entryHash`). An empty chain is valid: nothing was sealed.
2. **Seam.** With `previous`, the first link's `seq == previous.toSeq + 1` and its
   `prevHash == previous.entryHash`; without it, the first link is the genesis
   (`seq` 1, `prevHash == ""`). Packages tile the journal: each starts right after
   the previous package's last link, so, with the previous month's package at
   hand, its last link's `seq` and `entryHash` must equal this one's `previous` —
   together the packages hold every entry once.
3. **Canonical form and dates.** `JSON.stringify(sortKeys(JSON.parse(coreCanonical)))
   == coreCanonical`, and every `occurredAt` is before `period.to`. A link dated
   before `period.from` is allowed: sealed after the previous package was made, it
   opens this one rather than being lost.
4. **Counts.** `counts[act]` equals the number of links whose core has that `act`,
   for every `act` of either side.

`snapshot` (who holds administrator rights, the serving commit, the whole chain's
verification when the package was made) is the producer's statement, not sealed:
it is reported, never checked.

## Check 10 — a call's receipt (`X-Azoth-Receipt`)

Every answer of the gateway, served or blocked, carries a **receipt**: a compact
JWS (RFC 7515), `header.claims.signature`, each part base64url without padding.

```
header { "alg": "EdDSA", "typ": "azoth-receipt+jws", "kid": "<key id>" }
claims { "v": 1, "ws": "<workspace id>", "trace": "<trace id>",
         "core": "<sha256 hex>", "out": "allowed|blocked|rerouted|held|failed|act",
         "ref": "<sha256 hex, optional>", "iat": <seconds> }
```

`core` is `sha256(core_canonical)` of the decision the receipt certifies — the same
`core_canonical` Check 3 hashes into the chain. `ref` is the business decision
reference's HMAC when the call carried one (Check 5). A receipt never holds content.

The workspace's keys are a JWKS — `{ "keys": [ { "kty": "OKP", "crv": "Ed25519",
"x", "kid", "alg": "EdDSA", "use": "sig", "status", "created_at", "retired_at",
"compromised_at", "compromise_declared_at" } ] }` —
published by the producer and archived in each of its dossiers as `keys.jwks.json`
(listed in the manifest, so Check 1 covers it). A retired key stays listed.

1. **Format**: three base64url parts; the header and claims parse as above.
2. **Key**: a key of the JWKS has the header's `kid`, is Ed25519, and its `kid`
   equals its RFC 7638 thumbprint, `base64url(sha256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))`.
   A receipt signed more than 10 minutes after its key's `retired_at` is a warning. Under a key declared
   compromised, a receipt whose `iat` is at or after its `compromised_at` fails; one before it is a
   warning (« Keys and signatures »).
3. **Signature**: Ed25519 over the ASCII bytes of `header.claims` (the first two
   parts and the dot between them) verifies under that key.
4. **Decision** (with a dossier): some entry of `evidence.json` — a listed entry
   (`sha256(canonicalCore(core))`) or a chain link (`sha256(coreCanonical)`) — has
   the receipt's `core`; when that entry names its trace, it is the receipt's
   `trace`. The dossier's own checks (1–9) must pass for this to mean the decision
   is in a verified chain. No match: the decision is outside the dossier's period,
   or missing from its chain.

## Check 11 — each decision's applicable law, decided again

An entry's `core.jurisdiction` seals the law its call was decided under: the **facts** (`factors`:
where the people concerned are, where the operating entities are, where the model ran, the provider,
the sectors, the data categories, the AI Act class, the automated-decision flag, the population, the
transfer mechanisms declared, the ICT register, and — from `v: 2` — the day, the mandate's dated
evidence and allowed zones), the **packs** that covered it (`packs`, `id@version`), their hash
(`packSet`), the deciding rule (`rule`, `effect`, `reason`) and a conflict (`conflict`), if any. The
dossier ships the pack documents as `jurisdiction-packs.json` (in the manifest, so Check 1 covers
it): `{ "format": "azoth.jurisdiction.packs/1", "packs": [ { "ref", "sha256", "document" } ] }`,
`document` being the pack's canonical JSON `{ "format": "azoth.jurisdiction.pack/1", "pack": … }`.

1. **Documents**: each `sha256(document)` equals its `sha256`, and its pack's `id@version` its `ref`.
2. **Pack set**: `packSet == sha256(lines.join("\n"))`, `lines` = the sealed `packs` sorted, each
   as `ref:sha256`. A `v: 1` seal (the seal's first version, without the day) is checked this far only.
3. **Decided again** (`v: 2`): from the sealed facts and the shipped packs, the packs whose scope
   covers the facts (a standard only if the seal names it) must be the sealed `packs`, in registry
   order; among their rules whose provision is `adopted` and in force on the day
   (`effectiveFrom <= day < effectiveUntil`) and whose condition holds, each unmet requirement calls
   for its effect — a hosting zone (or a declared mechanism), the ICT register, a piece of evidence
   at most `maxAgeDays` old, or never; the mandate's allowed zones are a hosting requirement of their
   own. Localisation requirements without a mechanism are intersected: none left is a conflict,
   blocking, unless a conflict rule the seal applied (`conflictRules`, `A>B`) sets B's aside. The
   strictest effect wins — block > approval > reroute > allow, equals in registry order — and must be
   the sealed `rule`, `effect` and `reason`; the conflict must be the sealed one.

What Azoth *applied* (`applied`, `enforced`) depends on the governance mode and on the workspace's
adoptions and overrides, which a seal does not carry: it is not decided again. A decision naming a
pack version the dossier does not ship is a warning. Zones: a country (ISO 3166-1), a subdivision
under it, a city under that, or the groups `EU` and `EEA` (EU + IS, LI, NO).

## Check 12 — the dossier's signature; litigation, exhaustion, risk-profile and regulator dossiers

**Signature.** Every dossier carries `signature.jws` — outside the manifest, like `anchor.tsr`: it
bears on the manifest's `root_hash`, which covers every other file. A dossier without it **fails**:
nothing would bind its content to a key, and its latest (or first) entries could be removed, or its
whole chain rewritten, with the manifest recomputed to match. It is a compact JWS: header
`{ "alg": "EdDSA", "typ": "azoth-dossier+jws", "kid" }`, claims (format 2)

```
{ "v": 2, "ws", "root", "iat",
  "kind":    "audit" | "decision" | "incident" | "compliance" | "litigation" | "regulator"
             | "risk_profile" | "exhaustion" | "ai_footprint" | "platform",
  "head":    { "seq", "hash" } | null,              // the chain's last entry when the dossier was made
  "entries": { "count", "first", "last" },          // what evidence.json lists (seqs; null when none)
  "filters": { "<name>": string | number | boolean | null, ... },
  "roots":   { "since", "proofs" } | null }         // optional: the hourly roots (Check 18, step 5)
```

`kind` is `evidence.json`'s `kind`, `audit` when it has none (a journal export). `entries` counts
`evidence.json`'s `entries` — a platform package's `chain` — with the smallest and the largest `seq`.
`filters` are the export's own selection (a period, a decision reference's hash, an incident…).
`roots`, which a producer that predates it leaves out, states what the export ships of the hourly
platform roots — Check 18 reads it; every Azoth producer states it from 2026-11-22T00:00:00Z, and a dossier
dated after that whose claims leave it out is said (Check 18, step 5). The claims stay format 2: a verifier
before 2.4.0 refuses any other `v`, and would refuse every dossier made since. Format 1 claims are
`{ "v": 1, "ws", "root", "iat" }` only.

1. `root` equals the manifest's `root_hash`; when `evidence.json` names its `workspaceId`, it equals
   `ws`; a platform package's `ws` is `"platform"`.
2. The key `kid` is an Ed25519 JWK (`kty` `OKP`, `crv` `Ed25519`, `x`) among the keys **given to the
   verifier** (`--keys`): the workspace's keys as the producer publishes them at
   `/api/proof/keys/<workspace>` — Azoth's platform keys at `/api/proof/platform-keys` for a platform
   package. `kid` is the key's RFC 7638 thumbprint,
   `base64url(sha256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))`. A key found only in the dossier's
   own `keys.jwks.json` **fails**: the dossier vouches for itself, so anyone could rebuild a dossier
   and sign it with a key of their own. A key its producer declared compromised **fails** a signature
   whose `iat` is at or after its `compromised_at`, and warns on one before it (« Keys and signatures »).
3. The Ed25519 signature verifies over `<header>.<claims>` (ASCII).
4. **Coverage** (format 2). `kind` equals the pack's kind; `entries` equals the count, first and last
   `seq` recomputed from `evidence.json`; with `head`, no link the pack carries (`entries`, `chain`,
   `segments[].links`, `impact.entries`, `impact.completeness.links`) has a `seq` above `head.seq`, and
   one at `head.seq` has `entryHash == head.hash`; with `head` null, the pack carries no link. Any
   difference fails. Then the verifier states what the dossier covers — the entries listed, the
   chain's head at export (hence how many later entries it does not hold) and the filters — so the
   reader sees what it leaves out. A format 1 signature binds every file but states none of this (a
   warning).

**Litigation dossier** (`evidence.json` kind `"litigation"`): Check 5 applies, its entries being
the decisions a litigation hold designates (`hold.seqs`) and the hold's own sealed acts
(`core.decision` `legal_hold_*`, `core.policy.holdId == hold.id`). Moreover:

1. `hold.entriesHash == sha256(hold.seqs ascending, joined with ",")`;
2. every seq of `hold.seqs` is an entry of the dossier;
3. the `legal_hold_placed` entry's `core.policy.entriesHash` equals `hold.entriesHash` — the hold
   designated exactly these decisions when it was placed (absent: a warning).

**Exhaustion incident dossier** (`evidence.json` kind `"exhaustion"`): Check 5
applies, its entries being the incident's own sealed acts — every one has `core.decision`
`exhaustion_*` and `core.policy.incidentId == incident.id`. The figures of `incident` (refused calls,
visitors counted, the avoided cost) restate those acts; the avoided cost and the visitors are
estimates, `method` says how.

**Risk profile and regulator dossier** (kinds `"risk_profile"`, `"regulator"`): aggregate figures
restated from the workspace's records; no sealed entry is listed. Checks 1, 2, 4 and 12 apply: the
signature commits the chain's head when the dossier was made and the period it covers.

## Check 13 — each decision's cost, recomputed from its sealed price

An inference decision that carries tokens seals `core.pricing`: `{ "v": 1, "src", "catalog"?, "key"?,
"in"?, "out"?, "cacheRead"?, "cacheWrite"?, "eurUsd"? }` — where its price came from, the unit prices
in USD per 1M tokens, the prompt-cache multipliers (a cache-read or cache-write token as a multiple of
`in`, only when the call used the cache: `core.policy.cacheReadTokens` / `cacheWriteTokens`), and the
EUR→USD rate the cost was converted at. `src` is one of:

| `src` | Meaning | Checked |
|---|---|---|
| `catalog` | a published version of Azoth's model catalog (`catalog` = its number) | the cost recomputes; the price is that version's when the dossier ships it |
| `matrix` | the code's fallback copy of the prices (catalog version 1) | the cost recomputes |
| `declared` | the price the operator declares for a model it hosts | the cost recomputes |
| `none` | no price: the cost is sealed at 0, never guessed | `costEur` is 0 |
| `cache` | answered from the cache | `costEur` is 0 |
| `provider` | no price here; a cost the provider reported | — |
| `reported` | a cost no price in force explains (said, never invented) | — |

1. **Recomputed**: `usd = round8(tokensIn / 1e6 × in + tokensOut / 1e6 × out)`; with the cache,
   `usd = round8(usd + (cacheReadTokens × cacheRead + cacheWriteTokens × cacheWrite) / 1e6 × in)`;
   `usd / eurUsd` equals the sealed `costEur` (to 1e-9 relative). `round8(x) = round(x × 1e8) / 1e8`.
2. **The catalog version**: the dossier ships `model-catalog.json`
   `{ "format": "azoth.model.catalog.versions/1", "versions": [ { "version", "sha256", "document" } ] }`,
   `document` being the version's canonical string `{ "format": "azoth.model.catalog/1", "version",
   "entries": [ … ] }` (keys sorted, entries by provider then model). Each `sha256(document)` equals its
   `sha256`; a price sealed from version `catalog` equals the `inputPer1M` / `outputPer1M` of its entry
   (`provider`, `key`). A sealed `cacheRead` is that entry's cache-read multiple —
   `round(cachedInputPer1M / inputPer1M × 1e12) / 1e12`, or 0.1 when the entry gives no cached-input
   price (or its input is free) — or 0.1, the fixed multiple every seal carried before Azoth read the
   catalog's cached-input price. A version the dossier does not ship is a warning.

3. **The catalog's signature**: a shipped version may carry `signature`, a compact
   JWS (`{ "alg": "EdDSA", "typ": "azoth-catalog+jws", "kid" }`, claims `{ "v": 1, "catalog", "sha256",
   "iat" }`) by one of the keys pinned in this verifier (`CATALOG_SIGNING_KEYS`, kid = the RFC 7638
   thumbprint). A signature that does not verify fails; a version without one this verifier can check
   is a warning — its prices are Azoth's word.

A price changed in a later version changes no cost already sealed: the price is in the seal.

## Check 14 — an AI footprint statement (`evidence.json` kind `"ai_footprint"`)

A repository's AI footprint as it was attested: `attestation` holds its frozen `findings` — each
`{ sha, committedAt, ruleId, tool, strength, surface, seenVia }`, a commit and the detection rule it
matched, **never an author** —, their `findingsHash`, the `totals` and the `config` files. Check 5
applies to its entry: the statement's own act, `core.decision` `ai_footprint_attested` with
`core.policy.attestationId == attestation.id`. Moreover:

1. every finding has a 40-hex `sha`, a `ruleId`, a `strength` among `declared`, `marker`, `config`,
   and no author field;
2. `sha256(lines.sort().join("\n"))`, `lines` = each finding as `sha:ruleId`, equals
   `attestation.findingsHash` and the act's `core.policy.findingsHash`;
3. recomputed from the findings — `findings` (their number), `declared` and `markers` (distinct commits
   with a finding of that strength) — and `config` (the number of files) equal `attestation.totals` and
   the act's `core.policy`.

What a finding says is in `reading`: `declared`, the commit says a tool took part; `marker`, a line a
tool writes — anyone can write it, **never a proof**; `config`, the repository is set up for a tool.

## Check 15 — the journal retention checkpoint (`evidence.json` `retention`)

A workspace's plan keeps its sealed journal for a limited time. The producer removes only the
**oldest contiguous prefix** of the chain — entries `1…T`, all sealed before the retention's
cutoff — and never the head. Before removing it, in the same transaction, it appends a governance
act to the chain, `core.decision == "journal_retention_applied"`, whose `core.policy` declares the
removal: `fromSeq`, `throughSeq` (= `T`), `throughHash` (the `entryHash` of entry `T`), `removed`
(`T − fromSeq + 1`), `retentionDays`, `floorMonths`. It keeps a **checkpoint** of each removal.
No hash is recomputed: the first kept entry, `T + 1`, still has `prevHash` equal to entry `T`'s
`entryHash` — the checkpoint's `throughHash`.

A pack whose chain starts after the genesis because of such a removal carries

```
"retention": { "checkpoints": [ { "fromSeq": 1, "throughSeq": T, "throughHash": "<64 hex>",
  "removed": T, "actSeq": A, "actHash": "<64 hex>", "retentionDays": 30, "floorMonths": 0,
  "appliedAt": "..." }, ... ] }
```

— the latest checkpoint (largest `throughSeq`) and every checkpoint whose act (`actSeq`) is among
the pack's links. Checks 3, 5, 7 or 8 have verified each link; then, over every link the pack
carries (`entries`, `chain`, `segments[].links`), the first one by `seq`:

1. **Shape.** Every checkpoint has integer seqs ≥ 1 with `fromSeq ≤ throughSeq < actSeq`,
   `removed == throughSeq − fromSeq + 1`, and 64-hex `throughHash` / `actHash`.
2. **Start.** With `L` the latest checkpoint: the first link's `seq` must be greater than
   `L.throughSeq` (an entry the checkpoint says was removed cannot be in the dossier). When it is
   exactly `L.throughSeq + 1`, its `prevHash` must equal `L.throughHash` — the kept chain is the
   continuation of what was removed. A later first link attaches to kept entries (Check 3).
3. **Acts.** Each link whose core is a `journal_retention_applied` act at seq `A` declares the
   checkpoint shipped with `actSeq == A`: same `fromSeq`, `throughSeq`, `throughHash`, `removed`,
   and the link's `entryHash == actHash`. An act whose checkpoint is not shipped, or a latest
   checkpoint whose act is outside the pack, is a warning.

A pack with no `retention` and no such act is not concerned. The checkpoint proves the removal was
declared in the chain before it took place and where the kept chain starts; it does not hold the
removed entries, which are no longer evidence.

## Check 16 — the time, the actor type and the trace an entry seals

Added in verifier 2.1.0. An entry sealed by a producer that binds them carries, in its `core`:

- `occurredAt` — when the decision was taken, an ISO 8601 instant in UTC with milliseconds
  (`2026-11-14T10:00:00.123Z`), the same value the producer stores as the entry's time;
- `actorType` — `api_key`, `user` or `system`;
- `actorRef` (optional) — the actor as a keyed hash the producer computes with a secret of the
  workspace (64 hex), never its identifier: it lets the producer show who acted without the chain
  naming a person, and cannot be checked without that secret;
- `traceId` — the call or act the entry belongs to.

They are hashed with the rest of the core (Check 3), so they cannot change without breaking the
chain. The readable fields of the entry must state them:

1. For each entry of `entries` — and, in an incident dossier (Check 7), of `impact.entries` — whose
   `core` has the key: `occurredAt` is the same instant as `core.occurredAt` (compared to the
   microsecond, whatever the zone notation: `…Z`, `…+00:00`), `actorType == core.actorType`,
   `traceId == core.traceId`. Any difference fails, naming the entry's `seq`.
2. For each link of an incident's `impact.completeness.links` whose `JSON.parse(coreCanonical)` has
   `occurredAt`: the link's `occurredAt` is that instant.

An entry sealed before these keys existed carries none of them: its readable fields are the
producer's columns, outside the hash, and it verifies as before. The verifier counts the entries that
carry a sealed time; when some do not, it says so (a warning).

## Check 17 — a signed JSON evidence pack (`X-Azoth-Export-Signature`)

Added in verifier 2.3.0. Azoth answers the journal export without making a ZIP — `GET
/api/v1/journal/export` — with a body that is the pack a dossier's `evidence.json` holds (Check 3,
no `kind`: an `audit` pack) and the header `X-Azoth-Export-Signature`, a compact JWS: header
`{ "alg": "EdDSA", "typ": "azoth-journal-export+jws", "kid" }`, claims

```
{ "v": 1, "ws", "body", "iat",
  "kind":    "audit",
  "head":    { "seq", "hash" } | null,
  "entries": { "count", "first", "last" },
  "filters": { "<name>": string | number | boolean | null, ... } }
```

`body` is `sha256` of the exact bytes of the response body as sent (after any transport encoding is
undone); `kind`, `head`, `entries` and `filters` are what a dossier's format 2 signature commits
(Check 12). The reader keeps the body **exactly as received** — re-indented or re-encoded, it is
another body. The signature is given as the header's value (a text that holds the header line,
`X-Azoth-Export-Signature: <token>`, names the same token).

1. **Form.** Three base64url parts; the header and the claims as above, `iat` an integer number of
   seconds, the coverage well formed (Check 12, format 2).
2. **Body.** `sha256(body bytes) == body`.
3. **Key.** The key `kid` is an Ed25519 JWK among the keys **given to the verifier** — the workspace's
   keys as published at `/api/proof/keys/<workspace>`; the pack ships none, so without keys given the
   check fails. `kid` is its RFC 7638 thumbprint; the Ed25519 signature verifies over
   `<header>.<claims>` (ASCII); a key declared compromised refuses a signature whose `iat` is at or
   after its `compromised_at` and warns on one before it (« Keys and signatures »).
4. **Workspace.** The pack's `workspaceId` equals `ws`. When the keys given name their workspace (a
   top-level `workspaceId` in the JWKS) or the reader names it, it equals `ws` too; when nothing names
   it, a warning: the reader confirms they fetched the keys for that workspace.
5. **Coverage.** As Check 12's step 4, over the pack: `kind` is the pack's (`audit`), `entries` its
   count, first and last `seq`, no link it carries above `head.seq`, the link at `head.seq` (if any) with
   `entryHash == head.hash`. Moreover the pack's own `filters`, as signed — a list joined with `,`, an
   object or an absent value dropped — are `filters`, name for name.
6. **The pack.** Check 3 over its `entries` (and `chain`, when it is filtered), Check 15 when it carries
   `retention` or a retention act, Checks 11 and 13 for the entries that carry their seal (without the
   files only a dossier ships: the law is then said, not decided again, and a catalog price is not
   matched to its signed version), Check 16 for every entry whose core seals its time, actor type or
   trace.

## Check 18 — the hourly platform root (`head-roots.json`)

Added in verifier 2.3.0. Every hour, Azoth puts the chain head — `seq` and `entryHash` — of every journal that
moved since its last root (each workspace's decision journal, whatever its plan, and Azoth's platform journal) into
ONE Merkle tree, and an RFC 3161 time-stamping authority signs its root. A dossier that carries a rooted head ships,
outside the manifest (the proof bears on the chain, not on a hashed file), `head-roots.json`:

```
{ "v": 1, "leaf": "azoth.journal-head.v1", "subject": "<workspace id>" | "platform",
  "chain": "head-roots-chain.pem" | null,
  "proofs": [ { "seq", "entryHash", "leafIndex", "treeSize", "path": ["<hex>", ...], "root": "<hex>",
                "hour": "<ISO 8601>", "token": "head-root.<yyyymmddThh>Z.tsr" }, ... ] }
```

one proof per run of consecutive links the dossier carries (the newest rooted head in it), each `token` file a
TimeStampResp DER as the authority returned it, `chain` the authority's certificates (they help build its path, as
`tsa-chain.pem` does; they never establish trust).

**Encoding** — RFC 9162 (Certificate Transparency 2.0) §2.1, with this leaf:

- *leaf data*: the UTF-8 bytes of `azoth.journal-head.v1` LF *subject* LF *seq* LF *entryHash* — *subject* the
  workspace's id (a lowercase UUID) or `platform` for Azoth's platform journal, *seq* in decimal without sign or
  leading zero, *entryHash* 64 lowercase hex characters;
- *leaf hash*: `SHA-256(0x00 || leaf data)`; *node hash*: `SHA-256(0x01 || left || right)` — the prefixes keep an
  interior node from passing for a leaf;
- *tree*: the leaves sorted by subject (byte order), each subject once; the root is RFC 9162's MTH (for n > 1 leaves,
  k the largest power of two below n: `node(MTH(first k), MTH(the rest))`) — an odd count is neither padded nor a
  leaf duplicated;
- *path*: RFC 9162's PATH (§2.1.3.1), the sibling hashes from the leaf up.

For each proof:

1. **The head is the dossier's.** The subject is the dossier's: `platform` for a platform package (Check 9), else
   `evidence.json`'s `workspaceId` — or, when it names none, `ws` of `signature.jws`'s claims (Check 12 binds it).
   A proof that names another subject fails. The dossier must carry a sealed link at `seq` — among `entries`,
   `chain`, `segments[].links`, `impact.entries` and `impact.completeness.links` — and the leaf is recomputed from
   that link's `entryHash`, never from the proof's (a proof's `entryHash` that differs fails).
2. **The path leads to the root.** RFC 9162 §2.1.3.2 with `leafIndex` and `treeSize`: from the leaf hash, each path
   element taken on the left or the right as the index says; the result must equal `root` (64 hex), the path
   ending at the top (`sn == 0`). Otherwise it fails.
3. **The root is dated.** The `token` file verifies as in Check 4 — imprint SHA-256 equal to `root`, the signature,
   the signer, its path — trusted only through a pinned root (`--tsa-root`): pinned and its path ending elsewhere
   fails; without a pinned root, a warning.
4. **The dates hold.** With *T* the token's `genTime`, *H* the start of the hour the proof names (`hour`, which must
   be the start of an hour, else it fails), *E* the newest time sealed by a link the dossier carries at or before
   `seq` (the `occurredAt` of its `core`, else of its `coreCanonical`; none sealed: no *E*) and *S* the instant the
   dossier was signed (`iat` of `signature.jws`'s claims, in seconds), each with a tolerance *t* of 5 minutes:
   - *T* < *H* − *t* fails: the token is not that hour's root;
   - *T* < *E* − *t* fails: a root cannot date an entry made after it;
   - *T* > *S* + *t* fails: the export that signed the dossier cannot have shipped a root dated after it — the
     proof was added later;
   - *T* > *H* + 2 h, or *T* > *E* + 2 h, is a warning (one line, `head-root.<seq>.dates`): the producer roots
     every hour, so such a root is late — its authority retried, its worker did not run, or the head was rooted
     again — and proves only that the head existed at *T*, not when its entries were sealed.

   The tolerance covers what no reader controls: the authority's clock against the producer's servers and
   database (each kept to UTC, never exactly), and the worker's run between the token and the record of its hour
   (one minute at most). Every failure of this step is a contradiction no clock explains.

Since every link of the chain commits to the one before (Check 3), the head — and every entry the dossier links
before it — existed, unaltered, at the token's `genTime`, whoever holds the producer's database. When the dossier
carries such a proof, `--tsa-root` given and no `anchor.tsr` is not a failure of Check 4: the root given is the one
Check 18 pins.

Once per dossier, whether or not it carries `head-roots.json`:

5. **What the signature says of the roots.** The producer reads the roots before it signs, ships only those dated
   at or before the signature's second, and states them in the claims (Check 12): `roots`, either `null` — the
   producer had dated no journal head when the dossier was exported — or `{ "since", "proofs" }`, `since` the
   start of the hour of the producer's first dated root (ISO 8601, when it began dating heads) and `proofs` the
   SHA-256 (hex) of the `head-roots.json` the export ships, `null` when it ships none. A claim of another shape
   fails (line `head-roots`). Then:
   - `proofs` names a hash and `head-roots.json` is missing: a warning — it was removed after the export, and
     nothing in the dossier dates the journal's head outside the producer's database;
   - `proofs` names a hash and `head-roots.json` hashes to another: it fails — the file was changed after the
     export (its proofs are still checked one by one);
   - `proofs` is `null` (or `roots` is) and `head-roots.json` is present: a warning — it was added after the
     export; each proof is checked on its own, step 4 refusing one dated after the signature;
   - `proofs` is `null`, `head-roots.json` is missing and the newest time sealed by a link the dossier carries is
     at or after `since`: a warning — the dossier was sealed after the producer began dating heads, but none of its
     links was a dated head when it was exported (it was exported before the next hourly root, or it carries no
     link that was a head at an hour): outside the producer's database, only `anchor.tsr` (when present) dates it.

   A missing `head-roots.json` never fails a dossier: a producer without a time-stamping authority dates no head.

   What the signature **had** to state (added in verifier 2.4.0). Every Azoth producer states `roots` in each dossier
   it signs from **2026-11-22T00:00:00Z** (`ROOTS_STATED_FROM`, pinned in the verifier, never read from a dossier).
   With *S* the signature's `iat`, *E* the newest time sealed by a link the dossier carries and *A* the `genTime` of
   its `anchor.tsr` (when its token verifies, Check 4):
   - *S* < *E* − *t* **fails** (line `signature.dates`): an export signs what it has read, so a signature older than
     an entry it lists was made again with its instant moved back;
   - the claims carry no `roots` while *S*, *E*, *A* or the `genTime` of a root's token the dossier ships is at or
     after `ROOTS_STATED_FROM`: a warning (line `head-roots`) — the dossier was signed again without the statement,
     or by an older producer; nothing then says whether a proof was removed;
   - `roots` is `null` (« the producer had dated no head ») and no token of the dossier verifies — no `anchor.tsr`, no
     root's token, no journal head's (Check 5), no cited root's (Check 8) — while the dossier is dated after
     `ROOTS_STATED_FROM`: a warning — what it holds and when it was signed are only the word of whoever holds the
     workspace's key.

   These are warnings, never failures, so that a dossier that verified keeps verifying (README, « Compatibility »):
   an insider who holds the workspace's key, removes the proofs and the statement, is said — and fails when the
   reader pins the authority's root without the dossier carrying any token (Check 4), or gives the published roots
   (step 6). Check 4 also says (a warning, line `timestamp.dates`) an `anchor.tsr` dated more than 2 hours after *S*:
   the export timestamps the manifest the moment it signs it, so such a token was added later — it proves the dossier
   existed then, not when it was signed.

6. **The root is the one published** (added in verifier 2.4.0; only when the reader gives published roots). The
   roots live in the producer's database: whoever holds it could rewrite a chain whole, root its new head again in
   the same hour and have it dated — steps 1 to 5 would hold. So the producer publishes every root the moment it is
   recorded, at `GET /api/proof/head-roots?from=<ISO 8601>&to=<ISO 8601>` (public, read-only; each end taken to the
   start of its hour; by default the last 24 hours; a week at most per answer):

   ```
   { "format": "azoth.head-roots.published/1", "leaf": "azoth.journal-head.v1", "from", "to",
     "roots": [ { "hour": "<ISO 8601>", "root": "<hex>", "treeSize", "status": "anchored" | "pending" | "failed",
                  "token": "<base64 TimeStampResp>" | null, "genTime": "<ISO 8601>" | null }, ... ] }
   ```

   — never a leaf, a workspace's id or a head. A reader saves these answers as they come (anyone may keep and pass
   them on: an auditor, an insurer, an archive), and gives the files to the verifier (`--published-roots <file>`,
   repeatable; the web page takes them as files too). The verifier reads them from disk: it fetches nothing. A file
   of another `format` or `leaf`, or a root without an `hour` at the start of an hour, a 64-hex `root`, a positive
   integer `treeSize`, or with a `token` that is not base64, is a usage error. Then:
   - two published copies of one hour that hold different roots, tree sizes or tokens (a copy published while
     pending holds no token: it agrees with its anchored copy) **fail** once (`head-roots.published`): the producer
     changed a root it had published;
   - for each proof that passed steps 1 to 4 (`head-root.<seq>.published`): a published root of its `hour` with
     another `root`, or another `treeSize`, or another token than the dossier's `token` file (when the copy holds
     one), **fails** — the head was rooted again after the publication, or the proof is not the producer's; the same
     root and tree size passes; no published copy of that hour is a warning: not compared;
   - published roots given to a dossier without `head-roots.json`: a warning, nothing compared — unless one of the
     lines below says more.

   Then the published roots against what the signature states and the head the dossier carries (added in verifier
   2.4.0). The answer's `genTime` is the producer's statement of its token's time: it is compared with its other
   statements, never trusted as a date. With *X* the later of *S* and *A* (the export's instant) and *t* the tolerance:
   - `roots` is `null`, and the producer published an anchored root whose `genTime` ≤ *X* − *t*: it **fails** (line
     `head-roots.published`) — the producer's statements disagree;
   - `roots.since` is later than the `hour` of an anchored root published with `genTime` ≤ *X* − *t*: it **fails** —
     the same;
   - an anchored root is published with `genTime` at least two hours after *E* and ≤ *X* − *t*, and no proof of
     `head-roots.json` that holds (steps 1 to 4) is at or after the seq of that newest entry: every journal that moves
     is a leaf of the next hourly root, so a head at or after that entry was dated before the export. When that entry
     is the chain's head the signature commits (`head.seq`) and the published files answer for every hour from the
     entry's own to that root's (each file's `from`–`to`), each of their roots anchored with `genTime` ≤ *X* − *t*, it
     **fails**: the export shipped the head's proof (the producer reads the roots before it signs) and it was removed.
     Otherwise a warning: that entry was not the journal's head when the dossier was exported, or an hour is not
     answered for.

   What it proves is bounded by the copy: a root published — and saved by someone outside the producer — before the
   chain was rewritten no longer matches. A reader who saves the roots only after a rewrite saves the rewritten ones.

## Verdict

A dossier **verifies** iff all of the following pass — a warning never fails it:

- Check 1 and Check 2;
- the check of its kind: Check 3 (an audit dossier, no `kind`), Check 5 (`decision`, and
  `litigation`, `exhaustion`, `ai_footprint` as Checks 12 and 14 extend it), Check 7 (`incident`),
  Check 8 (`compliance`), Check 9 (`platform`); the aggregate kinds of Check 12 list no entry;
- Check 4 when `anchor.tsr` is present, or when a TSA root is pinned and the dossier carries no other token
  (Check 5's or Check 18's);
- Check 6 for every file supplied;
- Check 11 and Check 13 for every entry that carries their seal;
- Check 12, always: `signature.jws` present, by a key given to the verifier, its coverage matching
  `evidence.json` — an unsigned dossier, or one signed only by a key it ships, does not verify;
- Check 14 for an `ai_footprint` dossier;
- Check 15 when the pack carries `retention` or a journal retention act;
- Check 16 for every entry whose core seals its time, actor type or trace;
- Check 18 for every proof `head-roots.json` carries, and for the signature's `roots` when it states them (their
  shape, and the hash of `head-roots.json` when they name one), the signature no older than an entry it lists; with
  published roots given, step 6 (each proof's root the one published for its hour, the copies agreeing with each
  other, the signature's statement agreeing with them, the head the dossier carries proven when they dated it
  before the export).

A receipt (Check 10) verifies iff its format, key and signature pass; given a dossier, the
dossier must verify too and hold the decision the receipt certifies.

A JSON evidence pack (Check 17) verifies iff every step of Check 17 passes — a warning never fails it.

The checks keep their numbers: a new check takes the next one.

## Usage

```
node bin/azoth-verify.mjs dossier.zip --keys keys.jwks.json          # PASS/FAIL per check, exit 0/1
node bin/azoth-verify.mjs dossier.zip --keys keys.jwks.json --json   # machine-readable
node bin/azoth-verify.mjs ./unzipped-dossier/ --keys keys.jwks.json  # a directory also works
node bin/azoth-verify.mjs dossier.zip --keys keys.jwks.json --tsa-root tsa-root.pem   # pin the TSA root (Check 4)
node bin/azoth-verify.mjs dossier.zip --keys keys.jwks.json --tsa-root tsa-root.pem --published-roots roots.json   # Check 18, step 6
node bin/azoth-verify.mjs dossier.zip --vault-content ./decrypted/  # client-vault content (Check 6)
node bin/azoth-verify.mjs receipt receipt.txt --dossier dossier.zip    # a call's receipt (Check 10)
node bin/azoth-verify.mjs receipt <token> --keys keys.jwks.json        # its signature only
node bin/azoth-verify.mjs export pack.json --signature signature.txt --keys keys.jwks.json --workspace <id>   # a JSON evidence pack (Check 17)
```

**Without Node.js** — `web/azoth-verify.html`: one self-contained page that runs these same
checks entirely in a browser (open it from a file, or at `/azoth-verify.html` on an Azoth
deployment). Its policy allows no connection (`connect-src 'none'`); its cryptography is
`src/crypto-web.mjs` (plain JavaScript: SHA-1/256/384/512, RSA PKCS #1 v1.5 and PSS, ECDSA
P-256/P-384/P-521, Ed25519) instead of `src/crypto.mjs` (node:crypto) — every other module is
the CLI's, read without a Node API, `src/keys.mjs` included: which keys and signatures are
acceptable is decided there for both. `node scripts/build-web.mjs` rebuilds it from the sources.

The verifier makes no network call: the TSA is never contacted, revocation is
not checked online (a qualified TSA's certificate status can be checked
separately, against its trust-list entry).
