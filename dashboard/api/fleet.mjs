/**
 * GET /api/fleet — fleet state as TOON (default) or JSON, for LLM/agent use.
 *
 * Auth is the passphrase itself, supplied by the CALLER:
 *
 *     Authorization: Bearer <passphrase>
 *     X-Fleet-Key: <passphrase>
 *     ?key=<passphrase>            (last resort; ends up in logs/history)
 *
 * The passphrase is never stored on the host — not on disk, and not in memory
 * beyond the request that carried it. It is used in-request to derive the AES
 * key and decrypt the bundled snapshot. A wrong passphrase fails the GCM auth
 * tag and returns 401 — there is no separate credential to leak, and no way to
 * get plaintext out of this endpoint without already being able to decrypt the
 * published snapshot yourself. A key that HAS decrypted is held, as a
 * non-extractable CryptoKey under a keyed hash of the passphrase, for a bounded
 * window; see the KDF cache block below.
 *
 * Query:
 *   format = toon | json                       (default toon — ~65% fewer characters)
 *   view   = summary | problems | full | diagnose | help   (default summary)
 *   target = <dev machine id | worker id>       filters to one entity; required by diagnose
 *
 * `view=help` needs no key: it is the contract (params, problem kinds, what
 * `on`/`action` mean) and carries no fleet data.
 *
 * Responses: 200 body | 401 wrong/missing key | 404 unknown target (body lists
 * the known ids) | 405 wrong method | 400 bad format/view/target | 500 no
 * snapshot, or a snapshot this build cannot decode (an unknown `compression`
 * codec — a deployment-skew problem, never a credential one, so it must not
 * masquerade as a 401).
 * Errors are single-line text so an agent can branch on them cheaply.
 *
 * Cost note: a WRONG passphrase always runs the full 600k PBKDF2 iterations
 * (~80ms of CPU). That is the brute-force cost and it is deliberately not
 * cached — see the KDF cache block below for exactly which derivations are
 * reused and why that cannot help a guesser. A *correct* passphrase pays that
 * price once per process (per 5-minute window); repeats are ~2ms. This is still
 * a poor thing to leave open to anonymous traffic — keep the host's own access
 * gate (e.g. Vercel Deployment Protection) in front of it.
 */

import { webcrypto as crypto, createHmac, randomBytes } from "node:crypto";
import {
  buildLlmView, encodeView, contentType, helpView, UnknownTarget, VIEWS, FORMATS,
} from "../tools/llm-view.mjs";
import { decompressPlaintext, isSupportedCompression } from "../tools/envelope.mjs";
// Bundled at build time so the function has no filesystem or network dependency.
import envelope from "../public/data/fleet.enc.json" with { type: "json" };

function b64ToBuf(b64) {
  const b = Buffer.from(b64, "base64");
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

/* ─── KDF cache ────────────────────────────────────────────────────────────
 *
 * PBKDF2 at 600k iterations was 97.7% of this endpoint's request CPU. It cannot
 * simply be made cheaper: there is no stored credential here, so "did AES-GCM
 * authenticate?" IS the auth check, and the iteration count IS the brute-force
 * cost. The only safe saving is to stop re-deriving a key that has *already
 * proved itself* against this exact envelope.
 *
 * The invariant that keeps brute force expensive:
 *
 *   A derivation is inserted ONLY after AES-GCM has authenticated the envelope
 *   with it. A wrong passphrase therefore never writes an entry, and — because
 *   an entry can only exist for a passphrase that already decrypted — never
 *   reads one either. Every wrong guess, first or millionth, near-miss or not,
 *   runs the full 600k iterations. There is no negative cache and no early
 *   exit: a miss falls straight through to `deriveKey`.
 *
 * Index: HMAC-SHA-256 over the envelope's KDF parameters (salt, iterations,
 * hash) plus its IV plus the passphrase, under a per-process random secret.
 *   - The passphrase never appears in the index in plaintext.
 *   - The secret means the index is not a bare passphrase digest that could be
 *     ground offline if a heap dump ever escaped, and denies an attacker any
 *     ability to steer Map-lookup timing by choosing inputs.
 *   - Binding the salt/iterations/hash makes the entry valid only for the
 *     parameters that produced it, so a hit returns bit-identical key material
 *     to what a fresh derivation would have produced. Binding the IV pins it to
 *     this exact ciphertext framing too.
 *   - Fields are length-prefixed so no two distinct tuples share a pre-image.
 *
 * Bounds: at most KDF_CACHE_MAX entries (LRU eviction) and an absolute TTL from
 * insertion, not refreshed on use, so key material has a hard lifetime in
 * memory. Only holders of a valid passphrase can insert, so the size bound is
 * not attacker-reachable in the first place; it exists so multiple valid
 * passphrases (e.g. mid-rotation) still cannot grow the map without limit.
 *
 * Timing: a correct passphrase does get faster once warm. That leaks nothing —
 * the response already announces correctness with 200 vs 401. What matters is
 * that the *wrong* path is untouched, which the invariant above guarantees.
 */
const KDF_CACHE_MAX = 8;
const KDF_CACHE_TTL_MS = 5 * 60_000;
const KDF_CACHE_SECRET = randomBytes(32);
/** @type {Map<string, { key: CryptoKey, expiresAt: number }>} insertion order = LRU order */
const kdfCache = new Map();

function cacheIndex(env, passphrase) {
  const h = createHmac("sha256", KDF_CACHE_SECRET);
  for (const part of [env.kdf.salt, String(env.kdf.iterations), env.kdf.hash, env.cipher.iv, passphrase]) {
    const b = Buffer.from(String(part), "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    h.update(len);
    h.update(b);
  }
  return h.digest("hex");
}

function cacheGet(index, now) {
  const hit = kdfCache.get(index);
  if (!hit) return null;
  if (hit.expiresAt <= now) {
    kdfCache.delete(index);
    return null;
  }
  // Refresh LRU recency without extending the absolute TTL.
  kdfCache.delete(index);
  kdfCache.set(index, hit);
  return hit.key;
}

function cachePut(index, key, now) {
  kdfCache.delete(index);
  kdfCache.set(index, { key, expiresAt: now + KDF_CACHE_TTL_MS });
  // Sweep on write, since a serverless instance may see no timers between
  // requests: expiry first (an idle process must not hold key material past
  // its TTL), then LRU eviction so the size bound holds even if nothing aged.
  for (const [k, v] of kdfCache) if (v.expiresAt <= now) kdfCache.delete(k);
  while (kdfCache.size > KDF_CACHE_MAX) kdfCache.delete(kdfCache.keys().next().value);
}

async function deriveKey(env, passphrase) {
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(env.kdf.salt), iterations: env.kdf.iterations, hash: env.kdf.hash },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
}

/**
 * Authenticate + decrypt, and return the RAW plaintext bytes.
 *
 * Deliberately stops at the AES-GCM boundary. The caller treats a throw from
 * here as "wrong passphrase", which is only true while the only thing that can
 * throw is the auth tag. Decompression and JSON parsing happen outside, so a
 * snapshot written by a newer collector — a codec this deployment does not
 * implement — is reported as a broken payload rather than as a credential
 * failure. Blaming the caller's passphrase for the publisher's format is exactly
 * the kind of misdirection that costs an hour.
 */
async function decryptToBytes(env, passphrase) {
  const now = Date.now();
  const index = cacheIndex(env, passphrase);
  const open = (key) => crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(env.cipher.iv) }, key, b64ToBuf(env.ciphertext),
  );

  const cached = cacheGet(index, now);
  if (cached) {
    // Only reachable for a passphrase that already authenticated this envelope
    // under these exact KDF parameters, so this cannot fail where a fresh
    // derivation would have succeeded.
    return open(cached);
  }
  const key = await deriveKey(env, passphrase);
  const plain = await open(key); // throws on a wrong passphrase — nothing is cached
  cachePut(index, key, now);
  return plain;
}

/**
 * Raw plaintext bytes -> snapshot object.
 *
 * The collector gzips the snapshot JSON before encrypting it (ciphertext is
 * incompressible, so this is the only layer where the payload can shrink — see
 * tools/envelope.mjs). An envelope with no `compression` field predates that and
 * is plain UTF-8, which `decompressPlaintext` handles as the identity case.
 */
function decodeSnapshot(bytes, env) {
  return JSON.parse(decompressPlaintext(Buffer.from(bytes), env.compression));
}

/**
 * The passphrase from whichever channel carries it, trimmed.
 *
 * Every channel is trimmed the same way, matching the collector, the CLI and
 * the browser gate — `curl -H "X-Fleet-Key: $(cat secret)"` and a shell heredoc
 * both bring a trailing newline, and an untrimmed one would fail the GCM tag
 * against a passphrase that is otherwise correct.
 *
 * An empty channel falls through to the next rather than short-circuiting: a
 * blank `Authorization: Bearer` used to be returned as "" and shadow a
 * perfectly good `X-Fleet-Key` further down.
 */
function extractKey(req, url) {
  const auth = req.headers?.authorization ?? req.headers?.Authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    const bearer = auth.slice(7).trim();
    if (bearer) return bearer;
  }
  const hdr = req.headers?.["x-fleet-key"];
  if (typeof hdr === "string" && hdr.trim()) return hdr.trim();
  const q = url.searchParams.get("key");
  return q && q.trim() ? q.trim() : null;
}

export default async function handler(req, res) {
  // Never let a CDN or browser cache a decrypted fleet view. Set before any
  // parsing so an early rejection still carries them.
  res.setHeader("Cache-Control", "no-store, max-age=0, must-revalidate");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("X-Content-Type-Options", "nosniff");

  // The Host header is attacker-controlled and only used to satisfy the URL
  // parser. An empty or malformed one made `new URL` throw before any handler
  // logic ran, turning a bad request into an opaque 500. Only the path and
  // query are ever read, so fall back to a fixed base.
  let url;
  for (const [target, base] of [
    [req.url ?? "/", `https://${req.headers?.host || "localhost"}`],
    [req.url ?? "/", "https://localhost"],
    ["/", "https://localhost"],
  ]) {
    try {
      url = new URL(target, base);
      break;
    } catch {
      /* try the next, progressively less attacker-influenced, form */
    }
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("Allow", "GET, HEAD");
    return res.end("405 method not allowed\n");
  }

  const format = (url.searchParams.get("format") ?? "toon").toLowerCase();
  const view = (url.searchParams.get("view") ?? "summary").toLowerCase();
  const target = (url.searchParams.get("target") ?? "").trim() || null;
  if (!FORMATS.includes(format)) {
    res.statusCode = 400;
    return res.end(`400 format must be one of ${FORMATS.join("|")}; see ?view=help\n`);
  }
  if (!VIEWS.includes(view)) {
    res.statusCode = 400;
    return res.end(`400 view must be one of ${VIEWS.join("|")}; see ?view=help\n`);
  }

  // The help view carries no fleet data — it is the contract, and an agent
  // holding only the URL must be able to read it before it has the key.
  if (view === "help") {
    res.statusCode = 200;
    res.setHeader("Content-Type", contentType(format));
    if (req.method === "HEAD") return res.end();
    return res.end(encodeView(helpView(), format) + "\n");
  }
  if (view === "diagnose" && !target) {
    res.statusCode = 400;
    return res.end("400 view=diagnose needs target=<dev machine id | worker id>; ?view=summary lists the ids\n");
  }

  const key = extractKey(req, url);
  if (!key) {
    res.statusCode = 401;
    res.setHeader("WWW-Authenticate", 'Bearer realm="rch-fleet"');
    return res.end("401 supply the fleet passphrase via Authorization: Bearer <passphrase>; ?view=help needs no key\n");
  }

  if (!envelope?.ciphertext) {
    res.statusCode = 500;
    return res.end("500 no snapshot bundled with this deployment\n");
  }

  // A codec this build cannot inflate is a deployment-skew problem, not a
  // credential one. Answer before the 600k-iteration derivation, so the failure
  // is both honest and cheap.
  if (!isSupportedCompression(envelope.compression)) {
    res.statusCode = 500;
    return res.end(`500 snapshot uses an unsupported compression: ${String(envelope.compression)}\n`);
  }

  let plain;
  try {
    plain = await decryptToBytes(envelope, key);
  } catch {
    res.statusCode = 401;
    return res.end("401 wrong passphrase for this snapshot\n");
  }

  let snap;
  try {
    snap = decodeSnapshot(plain, envelope);
  } catch (e) {
    // Authenticated, so the bytes are genuinely ours — they just did not decode.
    res.statusCode = 500;
    return res.end(`500 snapshot decrypted but could not be decoded: ${e?.message ?? "unknown error"}\n`);
  }

  let viewObj;
  try {
    viewObj = buildLlmView(snap, { view, target });
  } catch (e) {
    if (e instanceof UnknownTarget) {
      // Name the ids that WOULD have worked: an agent that guessed wrong
      // should not need a second round-trip to find the right spelling.
      res.statusCode = 404;
      return res.end(
        `404 unknown target "${e.target}"; dev machines: ${e.known.dev_machines.join(",")}; ` +
        `workers: ${e.known.workers.join(",")}\n`,
      );
    }
    throw e;
  }
  const body = encodeView(viewObj, format);
  res.statusCode = 200;
  res.setHeader("Content-Type", contentType(format));
  if (req.method === "HEAD") return res.end();
  return res.end(body + "\n");
}
