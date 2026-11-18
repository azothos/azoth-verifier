// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * DER reader (definite lengths, low tag numbers — all RFC 3161, RFC 5652 and X.509 need), written
 * from the standards, shared by the timestamp check (Check 4) and the certificate reader.
 * Zero dependencies, no Node API: it runs in the CLI and in the offline web verifier.
 */
import { hex, fromLatin1, fromUtf8 } from './bytes.mjs';

/** One TLV at `at`: its tag, the whole encoding and the value. */
export function tlv(buf, at = 0) {
  if (at + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[at];
  let len = buf[at + 1];
  let p = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error('unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > buf.length) throw new Error('truncated DER');
  return { tag, whole: buf.subarray(at, p + len), body: buf.subarray(p, p + len) };
}

/** The TLVs inside a constructed node. */
export function items(node) {
  const out = [];
  for (let o = 0; o < node.body.length;) { const c = tlv(node.body, o); out.push(c); o += c.whole.length; }
  return out;
}

export function oidOf(node) {
  const b = node.body;
  const arcs = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0n;
  for (let i = 1; i < b.length; i++) {
    v = (v << 7n) | BigInt(b[i] & 0x7f);
    if (!(b[i] & 0x80)) { arcs.push(v); v = 0n; }
  }
  return arcs.join('.');
}

/** An INTEGER's value (unsigned reading of its bytes, as serials and key parts are). */
export const intOf = node => BigInt(`0x${hex(node.body) || '0'}`);

/** UTCTime (0x17) or GeneralizedTime (0x18). */
export function timeOf(node) {
  const s = fromLatin1(node.body);
  const m = node.tag === 0x17
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
  if (!m) throw new Error(`unsupported time ${s}`);
  const y = node.tag === 0x17 ? (Number(m[1]) < 50 ? 2000 : 1900) + Number(m[1]) : Number(m[1]);
  return new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
}

/** A directory string (UTF8String, PrintableString, IA5String, T61String, BMPString). */
export function stringOf(node) {
  if (node.tag === 0x1e) {   // BMPString: UTF-16BE
    let s = '';
    for (let i = 0; i + 1 < node.body.length; i += 2) s += String.fromCharCode((node.body[i] << 8) | node.body[i + 1]);
    return s;
  }
  return node.tag === 0x0c ? fromUtf8(node.body) : fromLatin1(node.body);
}
