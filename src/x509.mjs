// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * X.509 certificates read from their DER (RFC 5280) — what the timestamp check needs to find the
 * TSA signer and walk its chain, with no Node API: it runs in the CLI and in the web verifier.
 */
import { tlv, items, oidOf, intOf, timeOf, stringOf } from './der.mjs';
import { equal, fromBase64, hex } from './bytes.mjs';
import { digest, verifySignature } from './crypto.mjs';
import { pssParams } from './keys.mjs';

const NAMES = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '2.5.4.97': 'organizationIdentifier', '1.2.840.113549.1.9.1': 'emailAddress',
};
const EKU = '2.5.29.37';

/** A Name rendered one attribute per line, `CN=…`, in the certificate's order. */
function nameOf(node) {
  const out = [];
  for (const rdn of items(node)) for (const atv of items(rdn)) {
    const [type, value] = items(atv);
    out.push(`${NAMES[oidOf(type)] ?? oidOf(type)}=${stringOf(value)}`);
  }
  return out.join('\n');
}

/** A certificate's parts: serial, names, validity, public key, extended key usages, signature. */
export function parseCertificate(der) {
  const cert = tlv(der);
  const [tbsNode, sigAlgNode, sigNode] = items(cert);
  const tbs = items(tbsNode);
  let i = tbs[0].tag === 0xa0 ? 1 : 0;   // [0] version
  const serial = intOf(tbs[i++]);
  i++;                                    // signature (repeated outside the tbs)
  const issuer = tbs[i++];
  const [notBefore, notAfter] = items(tbs[i++]);
  const subject = tbs[i++];
  const spki = tbs[i++];
  const eku = [];
  for (const n of tbs.slice(i)) {
    if (n.tag !== 0xa3) continue;
    for (const ext of items(items(n)[0])) {
      const parts = items(ext);
      if (oidOf(parts[0]) !== EKU) continue;
      for (const o of items(tlv(parts[parts.length - 1].body))) eku.push(oidOf(o));
    }
  }
  const [alg, params] = items(sigAlgNode);
  return {
    der: cert.whole, tbs: tbsNode.whole, serial,
    issuerRaw: issuer.whole, subjectRaw: subject.whole, issuer: nameOf(issuer), subject: nameOf(subject),
    notBefore: timeOf(notBefore), notAfter: timeOf(notAfter), spki: spki.whole, eku,
    sigAlg: oidOf(alg), sigParams: params ?? null, signature: sigNode.body.subarray(1),   // BIT STRING: unused-bits byte first
    fingerprint256: hex(digest('sha256', cert.whole)),
  };
}

/** PEM bundle → certificates. */
export function readPemCertificates(text) {
  return (String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [])
    .map(p => parseCertificate(fromBase64(p.replace(/-----(BEGIN|END) CERTIFICATE-----/g, ''))));
}

const RSA_WITH = {
  '1.2.840.113549.1.1.5': 'sha1', '1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384', '1.2.840.113549.1.1.13': 'sha512',
};
const ECDSA_WITH = {
  '1.2.840.10045.4.1': 'sha1', '1.2.840.10045.4.3.2': 'sha256', '1.2.840.10045.4.3.3': 'sha384', '1.2.840.10045.4.3.4': 'sha512',
};
const RSA = '1.2.840.113549.1.1.1';
export const RSA_PSS = '1.2.840.113549.1.1.10';
const ED25519 = '1.3.101.112';

/**
 * The scheme and hash of a signature algorithm. `digestHash`: a CMS SignerInfo's digest algorithm,
 * for the plain `rsaEncryption` and `id-ecPublicKey` identifiers that leave the hash to it.
 */
export function signatureScheme(oid, params, digestHash = null) {
  if (RSA_WITH[oid]) return { scheme: 'rsa-pkcs1', hash: RSA_WITH[oid] };
  if (oid === RSA && digestHash) return { scheme: 'rsa-pkcs1', hash: digestHash };
  if (ECDSA_WITH[oid]) return { scheme: 'ecdsa', hash: ECDSA_WITH[oid] };
  if (oid === '1.2.840.10045.2.1' && digestHash) return { scheme: 'ecdsa', hash: digestHash };
  if (oid === ED25519) return { scheme: 'ed25519', hash: null };
  if (oid === RSA_PSS) {
    // RSASSA-PSS-params (RFC 4055; absent: the defaults, SHA-1). Both cryptographies compute MGF1
    // with the signature's hash, so a mask on another hash is refused rather than misread; the salt
    // length is recovered when verifying.
    const p = pssParams(params && params.tag === 0x30 ? params : null);
    return p && p.mgf1Hash === p.hash ? { scheme: 'rsa-pss', hash: p.hash } : null;
  }
  return null;
}

/** `child` names `parent` as its issuer (the issuer Name, byte for byte). */
export const issuedBy = (child, parent) => equal(child.issuerRaw, parent.subjectRaw);

/** `parent`'s key signed `child`. */
export function signedBy(child, parent) {
  // verifySignature answers false, never throws — the guard is for a certificate this reader misread.
  try {
    const s = signatureScheme(child.sigAlg, child.sigParams);
    return !!s && verifySignature({ ...s, spki: parent.spki, data: child.tbs, signature: child.signature });
  } catch {
    return false;
  }
}
