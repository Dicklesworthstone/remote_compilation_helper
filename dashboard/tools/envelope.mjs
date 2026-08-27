/**
 * Snapshot transport codec — the ONE place the envelope's `compression` field
 * is defined, on the Node side.
 *
 * WHY COMPRESS AT ALL, AND WHY HERE
 *
 * `public/data/fleet.enc.json` is base64 of AES-GCM ciphertext. Ciphertext is
 * incompressible by construction, so gzip at the CDN, `Content-Encoding` from
 * the origin, and the browser's own transfer decoding can all do exactly
 * nothing for it — and base64 then adds 33% on top of bytes nothing can shrink.
 * The only layer where this payload is still compressible is the PLAINTEXT,
 * before it is encrypted. Snapshot JSON of this shape (repeated keys, positional
 * tuples, a string table) compresses about 5.4x.
 *
 * ORDER: compress THEN encrypt. The reverse achieves nothing.
 *
 * ON CRIME/BREACH. Compressing before encrypting is the setup for that class of
 * attack, so it deserves a real answer rather than a shrug. Those attacks need
 * two things at once: an attacker who can inject CHOSEN plaintext into the same
 * compression context as a secret, and an ORACLE that re-compresses on demand so
 * the resulting length can be measured against many guesses. Neither exists
 * here. The snapshot is assembled by `tools/snapshot.mjs` from `rch` output on
 * machines the operator owns; no request parameter, header, or third-party
 * string is echoed into it, so there is no injection channel. And it is
 * compressed ONCE per collection (a cron tick, minutes apart) with the identical
 * bytes then served to everyone — an attacker cannot make the collector run
 * again with a guess embedded, so there is nothing to iterate against. The
 * published length was always public and always a function of the plaintext's
 * size; compression changes what that length is a function of, but no secret in
 * the snapshot is guessable from it one byte at a time, which is the property
 * CRIME actually breaks. `api/fleet.mjs` reflects nothing from the request into
 * its response body, so the HTTP-response variant (BREACH) has no foothold
 * either.
 *
 * CODEC CHOICE: gzip. The browser's only native decompressor is
 * `DecompressionStream`, which implements gzip / deflate / deflate-raw and NOT
 * brotli or zstd. Measured on a real 51,156B snapshot:
 *
 *     gzip -9      9,502B   (5.38x)   0.77ms compress   0.045ms decompress
 *     deflate -9   9,490B   (5.39x)   0.61ms            0.049ms
 *     brotli -11   7,739B   (6.61x)  58.32ms            0.084ms
 *     zstd -3     10,031B   (5.10x)   0.13ms            0.061ms
 *
 * brotli is 1,763B (18.6%) better but has no native browser decoder, so it would
 * mean shipping a JS/WASM one in the bundle — a large new dependency and a large
 * new correctness surface in front of the only path that renders the dashboard,
 * to save bytes on a file already down to ~12.7KB. deflate's 12-byte edge over
 * gzip is its shorter header; gzip keeps a CRC32 and length trailer for the same
 * price and is the most broadly supported `DecompressionStream` format. Taking
 * gzip at level 9 over level 6 costs 0.27ms of collector CPU for 168 bytes.
 */

import { gzipSync, gunzipSync } from "node:zlib";

/** What the collector writes into `envelope.compression`. */
export const SNAPSHOT_COMPRESSION = "gzip";

/**
 * Codecs a reader accepts. `null`/absent and `"none"` both mean "the ciphertext
 * is UTF-8 JSON", which is what every envelope written before this existed is —
 * so an old envelope keeps decoding with no special case at the call sites.
 */
const IDENTITY = new Set([undefined, null, "", "none", "identity"]);

export function isIdentityCompression(compression) {
  return IDENTITY.has(compression);
}

export function isSupportedCompression(compression) {
  return isIdentityCompression(compression) || compression === "gzip";
}

/** Snapshot JSON string -> the bytes that get encrypted. */
export function compressPlaintext(text) {
  return gzipSync(Buffer.from(text, "utf8"), { level: 9 });
}

/**
 * Decrypted bytes -> the snapshot JSON string.
 *
 * Throws a NAMED error on a codec this build does not implement. That matters:
 * every caller here treats a decrypt failure as "wrong passphrase", and a future
 * envelope written with a codec this reader has never heard of must not be
 * reported as an authentication problem — nor silently handed to `JSON.parse` as
 * mojibake.
 */
export function decompressPlaintext(bytes, compression) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (isIdentityCompression(compression)) return buf.toString("utf8");
  if (compression === "gzip") return gunzipSync(buf).toString("utf8");
  throw new Error(`unsupported snapshot compression: ${String(compression)}`);
}
