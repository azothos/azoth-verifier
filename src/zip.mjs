// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal zero-dependency ZIP reader — STORED (method 0) only.
 *
 * Reads the dossier archives Azoth produces, which are always
 * STORED (uncompressed). We parse the End-of-Central-Directory record, walk the
 * central directory, and slice each file's raw bytes out of its local header.
 * A DEFLATE decoder is intentionally omitted — the writer never compresses, and
 * a decompressor would be another dependency the auditor must trust.
 */

const U16 = (dv, o) => dv.getUint16(o, true);
const U32 = (dv, o) => dv.getUint32(o, true);

/**
 * @param {Uint8Array} bytes  the whole .zip file
 * @returns {Record<string, Uint8Array>}  path → file bytes
 */
export function readZip(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // Locate the End of Central Directory record (signature 0x06054b50), scanning
  // back from the end (there is no trailing comment in our archives).
  let eocd = -1;
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (U32(dv, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip archive (no end-of-central-directory record)');

  const total = U16(dv, eocd + 10);
  let p = U32(dv, eocd + 16); // central directory offset

  const out = {};
  const dec = new TextDecoder();
  for (let n = 0; n < total; n++) {
    if (U32(dv, p) !== 0x02014b50) throw new Error('corrupt central directory');
    const method   = U16(dv, p + 10);
    const compSize = U32(dv, p + 20);
    const nameLen  = U16(dv, p + 28);
    const extraLen = U16(dv, p + 30);
    const cmtLen   = U16(dv, p + 32);
    const localOff = U32(dv, p + 42);
    const name = dec.decode(bytes.subarray(p + 46, p + 46 + nameLen));

    if (method !== 0) throw new Error(`unsupported compression (method ${method}) for ${name} — verifier expects STORED`);

    // Local header: read its own name/extra lengths (may differ from central).
    if (U32(dv, localOff) !== 0x04034b50) throw new Error(`corrupt local header for ${name}`);
    const lNameLen  = U16(dv, localOff + 26);
    const lExtraLen = U16(dv, localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    out[name] = bytes.subarray(dataStart, dataStart + compSize);

    p += 46 + nameLen + extraLen + cmtLen;
  }
  return out;
}
