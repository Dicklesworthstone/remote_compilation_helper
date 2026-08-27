/**
 * Client-side decryption + session persistence.
 *
 * The published snapshot is AES-256-GCM ciphertext. The key is derived from the
 * operator's passphrase with PBKDF2-HMAC-SHA256. Nothing here is a cosmetic
 * "if (password === ...)" gate: without the passphrase the payload is
 * indistinguishable from random bytes, which is what makes it safe to host the
 * fleet inventory on a PUBLIC GitHub Pages site.
 *
 * The plaintext is gzip'd before it is encrypted, and the envelope names the
 * codec in `compression`. That order is the only one that helps: ciphertext is
 * incompressible, so nothing downstream of `encrypt` — CDN, origin, or transfer
 * encoding — can shrink this file. See `inflate()` below.
 *
 * Session persistence deliberately stores the DERIVED KEY, never the
 * passphrase. A stolen cookie is then scoped to exactly one thing — reading
 * snapshots encrypted under that one salt — and the passphrase itself is not
 * sitting in `document.cookie` for two months.
 *
 * Everything crossing the WebCrypto boundary is a plain `ArrayBuffer`. Since
 * TypeScript 5.7 `Uint8Array` is generic over its backing buffer, and the
 * `Uint8Array<ArrayBufferLike>` that `atob`/`TextEncoder` produce does not
 * satisfy `BufferSource`. Converting once here keeps the call sites clean.
 */

import { rehydrateStrings } from "./derive";
import type { Snapshot } from "./types";

export interface Envelope {
  format: string;
  kdf: { name: string; hash: string; iterations: number; salt: string };
  cipher: { name: string; iv: string };
  /**
   * Codec applied to the plaintext BEFORE encryption. Absent means none — every
   * envelope written before compression existed is plain UTF-8 JSON and must
   * keep opening without a special case.
   */
  compression?: string | null;
  ciphertext: string;
}

const COOKIE_NAME = "rch_dash_key";
/** 60 days, as requested. */
export const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 60;

/** base64 -> ArrayBuffer */
function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}

/** ArrayBuffer -> base64 */
function bufToB64(buf: ArrayBuffer): string {
  const view = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s);
}

/** utf-8 string -> ArrayBuffer */
function utf8ToBuf(s: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(s);
  const buf = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buf).set(encoded);
  return buf;
}

/** Iteration ceiling. The collector writes 600k; anything far above that is a payload trying to hang the browser. */
const MAX_KDF_ITERATIONS = 5_000_000;
const ALLOWED_KDF_HASHES = ["SHA-256", "SHA-384", "SHA-512"];

/**
 * Absent / "none" mean the ciphertext is UTF-8 JSON, which is what every
 * envelope published before compression existed is. Keeping the identity case
 * inside the same table is what makes an old bundle-vs-new-payload mismatch a
 * NAMED error rather than a `JSON.parse` accident on mojibake.
 */
function isIdentityCompression(c: string | null | undefined): boolean {
  return c == null || c === "" || c === "none" || c === "identity";
}

function isSupportedCompression(c: string | null | undefined): boolean {
  return isIdentityCompression(c) || c === "gzip";
}

/**
 * Validate the envelope's KDF parameters before deriving.
 *
 * `iterations` and `hash` are read straight out of a fetched file, and PBKDF2
 * runs for however long it is told. An absurd iteration count is an
 * indefinite freeze of the main thread with no error and no way out.
 */
export function assertUsableEnvelope(env: Envelope): void {
  if (!env?.ciphertext || typeof env.ciphertext !== "string") throw new Error("envelope has no ciphertext");
  if (!env?.cipher?.iv || typeof env.cipher.iv !== "string") throw new Error("envelope has no cipher IV");
  if (!env?.kdf?.salt || typeof env.kdf.salt !== "string") throw new Error("envelope has no KDF salt");
  const iters = env.kdf.iterations;
  if (!Number.isInteger(iters) || iters < 1 || iters > MAX_KDF_ITERATIONS) {
    throw new Error(`envelope KDF iterations out of range: ${String(iters)}`);
  }
  if (!ALLOWED_KDF_HASHES.includes(env.kdf.hash)) {
    throw new Error(`unsupported envelope KDF hash: ${String(env.kdf.hash)}`);
  }
  // Reject a codec this build cannot inflate BEFORE spending 600k PBKDF2
  // iterations on it. The gate then reports the real problem instead of
  // charging the operator 400ms to be told nothing useful.
  if (!isSupportedCompression(env.compression)) {
    throw new Error(
      `this snapshot is compressed with "${String(env.compression)}", which this page cannot read — reload to pick up the current app`,
    );
  }
}

/** Derive the AES key from a passphrase + the envelope's salt/iterations. */
export async function deriveKey(passphrase: string, env: Envelope): Promise<CryptoKey> {
  assertUsableEnvelope(env);
  const base = await crypto.subtle.importKey("raw", utf8ToBuf(passphrase), "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64ToBuf(env.kdf.salt),
      iterations: env.kdf.iterations,
      hash: env.kdf.hash,
    },
    base,
    { name: "AES-GCM", length: 256 },
    // Extractable so the session cookie can hold the key rather than the
    // passphrase. The key never leaves this origin.
    true,
    ["decrypt"],
  );
}

/**
 * Undo the snapshot's string-table transport encoding.
 *
 * The collector replaces the heavily repeated build/hint strings with indices
 * into one snapshot-level table (24.4KB of a 77.1KB payload — the same hint
 * text is reported by all ten dispatchers about the same shared worker). The
 * table belongs to the SNAPSHOT, but the UI consumes it one dispatcher at a
 * time via `snap.dispatchers.map(classifyDispatcher)`, which has no argument to
 * carry it. Undoing the encoding here — the single point every snapshot enters
 * the app through — means nothing downstream has to know the table exists.
 *
 * Costs one extra parse plus one stringify per FETCH (about 0.4ms for a
 * 10-machine fleet, once per 5-minute refresh) against 24.4KB less to download,
 * decrypt and authenticate.
 *
 * A payload with no table is returned as the untouched original string, so an
 * older snapshot — or a hand-written one — costs a substring scan and nothing
 * else. A payload this cannot parse is also returned untouched, so the caller's
 * own `JSON.parse` reports the real error rather than one from in here.
 */
function expandSnapshotStrings(text: string): string {
  // Fast path. Correctness never rests on this: a message containing the
  // literal `"strings":[` just falls through to the parse, which decides.
  if (!text.includes('"strings":[')) return text;
  try {
    const snap = JSON.parse(text) as Snapshot;
    if (!Array.isArray(snap?.strings) || snap.strings.length === 0) return text;
    // Drop the table once it has been spent. It is 12KB on a 10-machine fleet
    // and every one of its entries is now sitting in the tuples, so carrying it
    // into the string the caller re-parses would hand `JSON.parse` 12KB of dead
    // weight on every refresh — measurably more than the rehydration costs.
    const { strings: _spent, ...rest } = rehydrateStrings(snap);
    return JSON.stringify(rest);
  } catch {
    return text;
  }
}

/**
 * Undo the collector's transport compression.
 *
 * The published file is base64 of AES-GCM ciphertext, so gzip at the CDN, at the
 * origin, or in the browser's transfer decoding can do NOTHING for it —
 * ciphertext is incompressible by construction and base64 then adds 33% on top.
 * Compressing the plaintext before encryption is the only layer that shrinks
 * what actually crosses the wire, and this snapshot deflates about 5.4x.
 *
 * `DecompressionStream` is the browser's native gzip, and the reason the codec
 * is gzip rather than the ~19% smaller brotli: no browser exposes a brotli
 * decoder to script, so brotli would mean shipping a JS/WASM one in front of the
 * only path that renders this app. Support is Chrome/Edge 80+, Firefox 113+,
 * Safari 16.4+ — a superset of everything that runs the ES2022 bundle Vite
 * emits, except Safari 15.0–16.3, which is why the absence check below exists
 * and says what to do rather than throwing an undefined-constructor TypeError.
 */
async function inflate(bytes: ArrayBuffer, compression: string): Promise<string> {
  if (typeof DecompressionStream === "undefined") {
    throw new Error(
      `this browser cannot decompress the snapshot (no DecompressionStream) — needs Safari 16.4+, Firefox 113+, or Chrome 80+`,
    );
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(compression as "gzip"));
  // Response.text() decodes UTF-8 as it drains the stream, so the decompressed
  // bytes are never materialised as a second copy.
  return new Response(stream).text();
}

/** Decrypt an envelope. Throws on a wrong key (GCM auth tag failure). */
export async function decryptEnvelope(env: Envelope, key: CryptoKey): Promise<string> {
  // Checked here as well as in assertUsableEnvelope: a restored session key goes
  // straight here without ever calling deriveKey, so this is the only guard on
  // the "stay unlocked for 60 days" path.
  if (!isSupportedCompression(env.compression)) {
    throw new Error(
      `this snapshot is compressed with "${String(env.compression)}", which this page cannot read — reload to pick up the current app`,
    );
  }
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(env.cipher.iv) },
    key,
    b64ToBuf(env.ciphertext),
  );
  const text = isIdentityCompression(env.compression)
    ? new TextDecoder().decode(plain)
    : await inflate(plain, env.compression as string);
  return expandSnapshotStrings(text);
}

// ------------------------------------------------------------------- cookie

function cookieAttrs(maxAge: number): string {
  // `Secure` is correct on any real deployment (Vercel and GitHub Pages are
  // both https) but would silently drop the cookie on a plain-http localhost
  // dev server, so only set it when the page itself is secure.
  const secure = location.protocol === "https:" ? "; Secure" : "";
  // Scope to the app's base path, NOT `location.pathname`. Using the raw
  // pathname breaks on any deep link (`/index.html`, a sub-route): the cookie
  // would be written for that exact path and then be invisible at the app root,
  // so "stay unlocked" would appear to work and silently fail on return.
  const base = import.meta.env.BASE_URL || "/";
  return `; Max-Age=${maxAge}; Path=${base}; SameSite=Strict${secure}`;
}

export async function persistKey(key: CryptoKey): Promise<void> {
  const raw = await crypto.subtle.exportKey("raw", key);
  document.cookie =
    `${COOKIE_NAME}=${encodeURIComponent(bufToB64(raw))}` +
    cookieAttrs(COOKIE_MAX_AGE_SECONDS);
}

export function clearKey(): void {
  document.cookie = `${COOKIE_NAME}=${cookieAttrs(0)}`;
}

export async function loadPersistedKey(): Promise<CryptoKey | null> {
  const match = document.cookie.split("; ").find((c) => c.startsWith(`${COOKIE_NAME}=`));
  if (!match) return null;
  try {
    const raw = b64ToBuf(decodeURIComponent(match.slice(COOKIE_NAME.length + 1)));
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, true, [
      "decrypt",
    ]);
  } catch {
    return null;
  }
}
