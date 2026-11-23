// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * azoth-verify — RFC 3161 trusted timestamp check (SPEC.md, Check 4).
 *
 * Zero dependencies, zero network, and no Azoth code: the DER reader (der.mjs),
 * the certificate reader (x509.mjs) and the token checks below are written from
 * SPEC.md and the RFCs (3161 time-stamp protocol, 5652 CMS, 5280 X.509), so a
 * third party can verify a dossier's timestamp without trusting the producer —
 * from the CLI (node:crypto) or the offline web page (crypto-web.mjs).
 */
import { tlv, items, oidOf, intOf, timeOf } from './der.mjs';
import { concat, equal, fromHex } from './bytes.mjs';
import { digest, verifySignature } from './crypto.mjs';
import { parseCertificate, readPemCertificates, signatureScheme, certificationPath } from './x509.mjs';

// ── Token ────────────────────────────────────────────────────────────────────

const HASHES = { '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };
const SIGNED_DATA = '1.2.840.113549.1.7.2';
const TST_INFO = '1.2.840.113549.1.9.16.1.4';
const CONTENT_TYPE = '1.2.840.113549.1.9.3';
const MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const TIME_STAMPING = '1.3.6.1.5.5.7.3.8';

/** TimeStampResp (anchor.tsr) → the parts Check 4 needs. Throws on a malformed or refused response. */
export function readTimestampResponse(der) {
  const [statusInfo, token] = items(tlv(der));
  const status = Number(intOf(items(statusInfo)[0]));
  if (status !== 0 && status !== 1) throw new Error(`the TSA refused the request (status ${status})`);
  if (!token) throw new Error('no token in the response');
  const [type, wrapped] = items(token);
  if (oidOf(type) !== SIGNED_DATA) throw new Error('the token is not CMS SignedData');
  const sd = items(items(wrapped)[0]);
  const [eType, eWrapped] = items(sd[2]);
  if (oidOf(eType) !== TST_INFO) throw new Error('the signed content is not a TSTInfo');
  const tstInfo = items(eWrapped)[0].body;
  const certs = [];
  let signerInfos = null;
  for (const n of sd.slice(3)) {
    if (n.tag === 0xa0) for (const c of items(n)) if (c.tag === 0x30) certs.push(parseCertificate(c.whole));
    if (n.tag === 0x31) signerInfos = n;
  }
  if (!signerInfos) throw new Error('no SignerInfo');
  const si = items(items(signerInfos)[0]);
  const sidSerial = si[1].tag === 0x30 ? intOf(items(si[1])[1]) : null;
  let i = 3;
  const signedAttrs = si[i]?.tag === 0xa0 ? si[i++] : null;
  const t = items(tlv(tstInfo));
  const [imAlg, imHash] = items(t[2]);
  return {
    tstInfo,
    imprintAlg: oidOf(items(imAlg)[0]),
    imprint: imHash.body,
    genTime: timeOf(t[4]),
    digestAlg: oidOf(items(si[2])[0]),
    signedAttrs,
    sigAlg: oidOf(items(si[i])[0]),
    sigParams: items(si[i])[1] ?? null,
    signature: si[i + 1].body,
    sidSerial,
    certs,
  };
}

function signatureHolds(t, cert) {
  const hash = HASHES[t.digestAlg];
  if (!hash) return false;
  let input = t.tstInfo;
  if (t.signedAttrs) {
    const attrs = items(t.signedAttrs);
    const find = id => attrs.find(a => oidOf(items(a)[0]) === id);
    const md = find(MESSAGE_DIGEST);
    const ct = find(CONTENT_TYPE);
    if (!md || !ct || oidOf(items(items(ct)[1])[0]) !== TST_INFO) return false;
    const want = items(items(md)[1])[0].body;
    if (!equal(digest(hash, t.tstInfo), want)) return false;
    // RFC 5652 §5.4: the signature covers the attributes DER-encoded as a SET (tag 0x31).
    input = concat(Uint8Array.of(0x31), t.signedAttrs.whole.subarray(1));
  }
  const s = signatureScheme(t.sigAlg, t.sigParams, hash);
  // The digest algorithm of the SignerInfo is the signature's hash (RFC 5652 §5.4); RSASSA-PSS
  // parameters must name the same one (RFC 4056 §2).
  if (!s || (s.scheme === 'rsa-pss' && s.hash !== hash)) return false;
  return verifySignature({ scheme: s.scheme, hash: s.scheme === 'ed25519' ? null : hash, spki: cert.spki, data: input, signature: t.signature });
}

/** PEM bundle → certificates. */
export const readPem = readPemCertificates;

/**
 * Check 4: does `tsr` (anchor.tsr bytes) timestamp exactly `rootHashHex`, under a
 * valid TSA signature — and does its chain end on a certificate in `pinned` (or on a
 * copy of one cross-signed by another root: the same subject and key)?
 * `shipped` = the certificates the dossier itself carries (tsa-chain.pem); `what` names the hash in a refusal
 * (Check 18 dates a platform root with the same check).
 * @returns {{ ok: boolean, detail: string, genTime?: Date, tsa?: string, trusted?: boolean, root?: string }}
 */
export function checkTimestamp(tsr, rootHashHex, { shipped = [], pinned = null, what = 'this manifest root_hash' } = {}) {
  let t;
  try { t = readTimestampResponse(tsr); } catch (err) { return { ok: false, detail: `anchor.tsr unreadable: ${err.message}` }; }
  let want;
  try { want = fromHex(rootHashHex); } catch { want = new Uint8Array(0); }
  if (t.imprintAlg !== '2.16.840.1.101.3.4.2.1' || !equal(t.imprint, want)) {
    return { ok: false, detail: `the timestamp does not cover ${what}` };
  }
  const pool = [...t.certs, ...shipped, ...(pinned ?? [])];
  const signer = pool.find(c => t.sidSerial !== null && c.serial === t.sidSerial)
    ?? pool.find(c => { try { return signatureHolds(t, c); } catch { return false; } });
  if (!signer) return { ok: false, detail: 'no certificate for the TSA signer' };
  let holds = false;
  try { holds = signatureHolds(t, signer); } catch { holds = false; }
  if (!holds) return { ok: false, detail: 'invalid TSA signature' };
  if (!signer.eku.includes(TIME_STAMPING)) return { ok: false, detail: 'the signer is not a time-stamping certificate' };
  if (t.genTime < signer.notBefore || t.genTime > signer.notAfter) {
    return { ok: false, detail: 'genTime outside the signer certificate validity' };
  }
  // The path ends on a pinned root — a copy of it cross-signed by another root included — or, untrusted,
  // on a self-signed certificate; every candidate issuer is tried (x509.mjs, certificationPath).
  const path = certificationPath(signer, [...t.certs, ...shipped], pinned ?? []);
  if (!path) return { ok: false, detail: 'incomplete certificate chain for the TSA' };
  const tsa = signer.subject.replace(/\n/g, ', ');
  return { ok: true, genTime: t.genTime, tsa, trusted: path.trusted, root: path.end.subject.replace(/\n/g, ', '), detail: `signed by ${tsa} at ${t.genTime.toISOString()}` };
}
