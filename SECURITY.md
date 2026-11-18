# Security policy

## Reporting a vulnerability

Write to **security@azothos.ai**, in English or French. Please do not open a public issue for a
vulnerability.

Azoth's disclosure policy is published at <https://www.azothos.ai/legal/security>, and its
contact at <https://www.azothos.ai/.well-known/security.txt> (RFC 9116).

Useful in a report: the version (`npm ls @azothos/verifier`, or `version` in `package.json`), the
command you ran, and — when you can share it — a dossier or a receipt that reproduces the problem.
A dossier holds hashes and codes, never the content of a call; remove anything you would not send.

## What counts as a vulnerability here

The verifier's whole purpose is to refuse what does not verify. The most serious report is
therefore a **false pass**: a dossier, a receipt or a timestamp that was altered, or signed by
another key, and that the verifier still reports as passing. A check that fails a genuine dossier
is a bug too, and is welcome as an ordinary issue.

The verifier makes no network call and handles no secret: a report about the network or about
key storage most likely concerns the Azoth service, not this package — the address above covers
both.

## Supported versions

The latest minor version of the current major version receives fixes.
