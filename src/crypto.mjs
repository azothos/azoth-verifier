// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The verifier's cryptography — the CLI's: node:crypto. The offline web verifier swaps this module
 * for crypto-web.mjs (the same three functions in plain JavaScript); every check
 * goes through these, so both run the same rules.
 *
 *   digest(alg, bytes)                                   'sha1' | 'sha256' | 'sha384' | 'sha512'
 *   verifySignature({ scheme, hash, spki, data, signature })   scheme 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'ed25519'
 *   verifyEd25519(x, data, signature)                    x: the public key, base64url (a JWK's `x`)
 *
 * Which key, scheme, hash and signature encoding are acceptable is decided by keys.mjs, for both
 * cryptographies. node:crypto picks the algorithm from the key it is given (an Ed25519 "scheme"
 * over a P-256 key would verify ECDSA-SHA256), so it is only ever given a key keys.mjs read and
 * found to be the scheme's, rebuilt from its parts — never the key's own encoding. A signature is a
 * verdict, never an exception: anything that does not verify is `false`, as in crypto-web.mjs.
 */
import { createHash, createPublicKey, verify, constants } from 'node:crypto';
import { base64url } from './bytes.mjs';
import { signedWith, ed25519Signed } from './keys.mjs';

export const digest = (alg, data) => new Uint8Array(createHash(alg).update(data).digest());

/** keys.mjs's key, as node:crypto's own: a JWK built from its parts. */
function keyObject(key) {
  const jwk = key.type === 'ed25519' ? { kty: 'OKP', crv: 'Ed25519', x: base64url(key.key) }
    : key.type === 'ec' ? { kty: 'EC', crv: key.curve.name, x: base64url(key.point.subarray(1, 1 + key.curve.size)), y: base64url(key.point.subarray(1 + key.curve.size)) }
      : { kty: 'RSA', n: base64url(key.bytes.n), e: base64url(key.bytes.e) };
  return createPublicKey({ key: jwk, format: 'jwk' });
}

export function verifySignature({ scheme, hash, spki, data, signature }) {
  try {
    const fit = signedWith({ scheme, hash, spki, signature });
    if (!fit) return false;
    const key = keyObject(fit.key);
    if (scheme === 'rsa-pkcs1') return verify(fit.hash, data, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
    if (scheme === 'rsa-pss') return verify(fit.hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_AUTO }, signature);
    if (scheme === 'ecdsa') return verify(fit.hash, data, { key, dsaEncoding: 'der' }, signature);
    return verify(null, data, key, signature);
  } catch {
    return false;
  }
}

export function verifyEd25519(x, data, signature) {
  try {
    const key = ed25519Signed(x, signature);
    return key ? verify(null, data, keyObject({ type: 'ed25519', key }), signature) : false;
  } catch {
    return false;
  }
}
