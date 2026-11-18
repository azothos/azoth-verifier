# @azothos/verifier — `azoth-verify`

Verify an Azoth OS evidence dossier, or the receipt of a single call, **without Azoth**: no
dependency, no network call, and no code shared with the producer. Its verdict does not rest on
trusting the party that produced the evidence.

Azoth OS seals each decision it takes about an AI call — served, blocked, rerouted, held for a
person — in a hash-chained journal, signs a receipt for every answer, and exports dossiers of
those decisions. This package checks them. Each check is specified in [`SPEC.md`](SPEC.md), which
is enough to write another verifier from scratch.

## What a passing check proves — and what it does not

A passing check proves:

- **integrity** — every file of the dossier is the one listed in its manifest, byte for byte;
- **order** — the sealed decisions form an unbroken hash chain: none was removed, inserted,
  reordered or edited;
- **origin** — the dossier, and each receipt, is signed by the workspace's Ed25519 key — the one
  you pin with `--keys`. The signature is required: an unsigned dossier, or one signed only by a
  key it ships itself, does not verify;
- **coverage** — the signature commits what the dossier covers: its kind, the chain's head when it
  was exported, the count and range of the entries it lists and the export's filters. Entries cut
  from the start or the end fail, and the verifier says what the dossier leaves out;
- **time** — with an RFC 3161 timestamp and the time-stamping authority's root pinned with
  `--tsa-root`, the files existed, unchanged, at the time the authority attests;
- **consistency** — what can be decided again from the seals is decided again: each sealed cost
  from its sealed price, each decision's applicable law from its sealed facts, a compliance
  bundle's coverage from the entries it cites.

It never proves that a decision was right, that a model's answer was true, or that a sealed fact
describes the world correctly. It is technical evidence, not a judgement, a certification or
legal advice.

## Try it on the examples

[`examples/`](examples) holds a demo dossier of five synthetic decisions, the demo workspace's
public keys and the receipt of one of its calls. They were produced by Azoth's own export code,
signed with a demo key made in memory whose private half was never written down.

In a clone of this repository (or with the three files downloaded into `examples/`):

```sh
npx -y @azothos/verifier examples/demo-dossier.zip --keys examples/demo-keys.jwks.json
npx -y @azothos/verifier receipt examples/receipt.txt --dossier examples/demo-dossier.zip --keys examples/demo-keys.jwks.json
```

From a clone, with nothing installed:

```sh
node bin/azoth-verify.mjs examples/demo-dossier.zip --keys examples/demo-keys.jwks.json
```

Change one byte of `demo-dossier.zip` and run it again: it fails, and says which check broke.

## In a browser

[`web/azoth-verify.html`](web/azoth-verify.html) is one self-contained page that runs the same
checks in the browser. Its own content security policy forbids any network access
(`connect-src 'none'`): open it from a file, choose a dossier and the workspace's published keys
(and, optionally, the authority's root), and nothing leaves the page. The page does not embed an example —
it would change the page's hash — so download `examples/demo-dossier.zip` and drop it in.

The page is built from the same modules as the command line, with `src/crypto-web.mjs` (plain
JavaScript) in place of `src/crypto.mjs` (`node:crypto`). Both read keys and signatures through
`src/keys.mjs` (SPEC.md, « Keys and signatures »), so they give the same verdict on the same bytes:
a signature checked under a scheme that is not its key's type fails in both. `node scripts/build-web.mjs --check`
confirms that the page is exactly what these sources build. The repository's `pages.yml` workflow
publishes the same file on GitHub Pages, so the page can be opened from outside Azoth's domain.

## Usage

```text
azoth-verify <dossier.zip | dossier-dir> --keys <jwks.json> [--json] [--tsa-root <root.pem>] [--vault-content <file|dir>]
azoth-verify receipt <token | file> [--dossier <dossier>] [--keys <jwks.json>] [--json]
```

| Option | What it does |
|---|---|
| `--keys <jwks.json>` | Pins the workspace's public keys (Azoth's platform keys, for a platform package): the dossier's signature and the receipts must be signed by one of them. Required for a dossier to verify: without it, the signature can only be checked against the keys the dossier ships, which vouch for nothing — the dossier fails, and says so. |
| `--tsa-root <root.pem>` | Pins the root certificate of the time-stamping authority: a timestamp is trusted only if its chain ends there. Without it, a valid timestamp is reported with a warning. |
| `--vault-content <file\|dir>` | Content you decrypted from your own vault (or its stored envelope): each file must hash to a sealed vault receipt. Repeatable. |
| `--dossier <dossier>` | With `receipt`: the dossier must verify, and hold the decision the receipt certifies. |
| `--json` | Machine-readable output, for a pipeline. |

**Exit codes**: `0` — every check passed (warnings allowed); `1` — a check failed, or the command
could not run (a usage error, an unreadable file).

**Where the trust anchors come from.** A workspace's public keys are published by the Azoth
deployment that holds it, at `/api/proof/keys/<workspaceId>` (on Azoth's SaaS:
`https://www.azothos.ai/api/proof/keys/<workspaceId>`), and archived in each of its dossiers as
`keys.jwks.json`. Fetch them yourself, keep them, and pin them with `--keys`. Azoth's own platform
evidence packages are signed by its platform key, published at `/api/proof/platform-keys`. The
authority's root comes from the authority itself, never from the dossier.

## The checks

The numbers are stable: a new check takes the next number.

| # | Check |
|---|---|
| 1 | Every file against the manifest |
| 2 | The manifest's root hash |
| 3 | The sealed decision chain (`evidence.json`), whole or as a segment |
| 4 | The RFC 3161 trusted timestamp (`anchor.tsr`) |
| 5 | A decision dossier: every call of one business decision, in verified chain segments |
| 6 | Client-vault content, supplied by the client |
| 7 | An incident dossier: the decisions an incident's scope matched, and its steps |
| 8 | A compliance bundle: each covered requirement backed by a verified citation |
| 9 | A platform evidence package (Azoth's own controls, for its auditor) |
| 10 | A call's receipt (`X-Azoth-Receipt`) |
| 11 | Each decision's applicable law, decided again from its seal |
| 12 | The dossier's signature (required) and the coverage it commits; litigation, exhaustion, risk-profile and regulator dossiers |
| 13 | Each decision's cost, recomputed from its sealed price |
| 14 | An AI footprint statement |
| 15 | The journal retention checkpoint: where the kept chain starts once the oldest entries were removed |
| 16 | Each entry's time, actor type and trace, as its core seals them |

## As a library

```js
import { verifyDossier } from '@azothos/verifier';
import { readZip } from '@azothos/verifier/zip';
import { verifyReceipt } from '@azothos/verifier/receipt';

const result = verifyDossier(readZip(bytes), { keys: jwks });   // { ok, checks: [{ id, ok, detail, level? }] }
```

## Requirements

Node.js 18 or later, for the command line. Any current browser, for the page. Nothing else.

## Compatibility

The version follows [Semantic Versioning](https://semver.org/):

- a **major** version for a change that makes a dossier fail that passed before, or that changes
  the exit codes, the options or the shape of the `--json` output;
- a **minor** version for a new check, a new kind of dossier or a new option;
- a **patch** version for a fix that changes no verdict on a well-formed dossier.

A dossier that passed keeps passing with every later version of the same major version.

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Contributing

This repository is a snapshot, published once per version from Azoth's own repository, where the
verifier is tested against the code that produces the dossiers. Issues and pull requests are
welcome here: a change is applied upstream, with those tests, and ships in the next snapshot.

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE).
