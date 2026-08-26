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

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** Derive the AES key from a passphrase + the envelope's salt/iterations. */
export async function deriveKey(passphrase: string, env: Envelope): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64ToBytes(env.kdf.salt),
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
    { name: "AES-GCM", iv: b64ToBytes(env.cipher.iv) },
    key,
    b64ToBytes(env.ciphertext),
  );
  return new TextDecoder().decode(plain);
}

// ------------------------------------------------------------------- cookie

function cookieAttrs(maxAge: number): string {
  // `Secure` is correct on GitHub Pages (always https) but would silently drop
  // the cookie on a plain-http localhost dev server, so only set it when the
  // page itself is secure.
  const secure = location.protocol === "https:" ? "; Secure" : "";
  return `; Max-Age=${maxAge}; Path=${location.pathname}; SameSite=Strict${secure}`;
}

export async function persistKey(key: CryptoKey): Promise<void> {
  const raw = await crypto.subtle.exportKey("raw", key);
  const value = bytesToB64(new Uint8Array(raw));
  document.cookie = `${COOKIE_NAME}=${encodeURIComponent(value)}${cookieAttrs(COOKIE_MAX_AGE_SECONDS)}`;
}

export function clearKey(): void {
  document.cookie = `${COOKIE_NAME}=${cookieAttrs(0)}`;
}

export async function loadPersistedKey(): Promise<CryptoKey | null> {
  const match = document.cookie
    .split("; ")
    .find((c) => c.startsWith(`${COOKIE_NAME}=`));
  if (!match) return null;
  try {
    const raw = b64ToBytes(decodeURIComponent(match.slice(COOKIE_NAME.length + 1)));
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, true, [
      "decrypt",
    ]);
  } catch {
    return null;
  }
}
