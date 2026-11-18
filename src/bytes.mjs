// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Bytes, without Node's Buffer — so the same checks run in the CLI and in a browser
 * (the offline web verifier). Plain Uint8Array, TextEncoder/TextDecoder.
 */

const enc = new TextEncoder();
const utf8Dec = new TextDecoder('utf-8');
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** UTF-8 bytes of a string. */
export const utf8 = s => enc.encode(s);
/** A string from UTF-8 bytes. */
export const fromUtf8 = b => utf8Dec.decode(b);
/** A string from bytes read one per character (latin1: what DER times and names in printable form use). */
export const fromLatin1 = b => { let s = ''; for (const x of b) s += String.fromCharCode(x); return s; };

/** Lowercase hex. */
export const hex = b => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };

/** Bytes from hex (an odd or invalid digit throws). */
export function fromHex(h) {
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error('not hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Bytes from base64 or base64url, padded or not (whitespace ignored). */
export function fromBase64(s) {
  const t = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (/[^A-Za-z0-9+/]/.test(t) || t.length % 4 === 1) throw new Error('not base64');
  const out = new Uint8Array(Math.floor((t.length * 3) / 4));
  let o = 0; let acc = 0; let bits = 0;
  for (const ch of t) {
    acc = (acc << 6) | B64.indexOf(ch); bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
  }
  return out.subarray(0, o);
}

/** base64url without padding. */
export function base64url(b) {
  let s = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < b.length ? B64[(n >> 6) & 63] : '') + (i + 2 < b.length ? B64[n & 63] : '');
  }
  return s.replace(/\+/g, '-').replace(/\//g, '_');
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function equal(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Bytes of a string (UTF-8), or the bytes as given. */
export const bytesOf = data => (typeof data === 'string' ? utf8(data) : data);
