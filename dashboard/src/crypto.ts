/**
 * Client-side decryption + session persistence.
 *
 * The published snapshot is AES-256-GCM ciphertext. The key is derived from the
 * operator's passphrase with PBKDF2-HMAC-SHA256. Nothing here is a cosmetic
 * "if (password === ...)" gate: without the passphrase the payload is
 * indistinguishable from random bytes, which is what makes it safe to host the
 * fleet inventory on a PUBLIC GitHub Pages site.
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

export interface Envelope {
  format: string;
  kdf: { name: string; hash: string; iterations: number; salt: string };
  cipher: { name: string; iv: string };
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

/** Decrypt an envelope. Throws on a wrong key (GCM auth tag failure). */
export async function decryptEnvelope(env: Envelope, key: CryptoKey): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(env.cipher.iv) },
    key,
    b64ToBuf(env.ciphertext),
  );
  return new TextDecoder().decode(plain);
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
