/**
 * GET /api/fleet — fleet state as TOON (default) or JSON, for LLM/agent use.
 *
 * Auth is the passphrase itself, supplied by the CALLER:
 *
 *     Authorization: Bearer <passphrase>
 *     X-Fleet-Key: <passphrase>
 *     ?key=<passphrase>            (last resort; ends up in logs/history)
 *
 * The passphrase is never stored on the host. It is used only, in-request, to
 * derive the AES key and decrypt the bundled snapshot. A wrong passphrase fails
 * the GCM auth tag and returns 401 — there is no separate credential to leak,
 * and no way to get plaintext out of this endpoint without already being able
 * to decrypt the published snapshot yourself.
 *
 * Query:
 *   format = toon | json      (default toon — ~65% fewer characters)
 *   view   = summary | full   (default summary)
 *
 * Responses: 200 body | 401 wrong/missing key | 405 wrong method | 500 no snapshot.
 * Errors are single-line text so an agent can branch on them cheaply.
 */

import { webcrypto as crypto } from "node:crypto";
import { buildLlmView, encodeView, contentType } from "../tools/llm-view.mjs";
// Bundled at build time so the function has no filesystem or network dependency.
import envelope from "../public/data/fleet.enc.json" with { type: "json" };

function b64ToBuf(b64) {
  const b = Buffer.from(b64, "base64");
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

async function decrypt(env, passphrase) {
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(env.kdf.salt), iterations: env.kdf.iterations, hash: env.kdf.hash },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(env.cipher.iv) }, key, b64ToBuf(env.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

function extractKey(req, url) {
  const auth = req.headers?.authorization ?? req.headers?.Authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  const hdr = req.headers?.["x-fleet-key"];
  if (typeof hdr === "string" && hdr.trim()) return hdr.trim();
  const q = url.searchParams.get("key");
  return q && q.trim() ? q.trim() : null;
}

export default async function handler(req, res) {
  const url = new URL(req.url ?? "/", `https://${req.headers?.host ?? "localhost"}`);

  // Never let a CDN or browser cache a decrypted fleet view.
  res.setHeader("Cache-Control", "no-store, max-age=0, must-revalidate");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("Allow", "GET, HEAD");
    return res.end("405 method not allowed\n");
  }

  const format = (url.searchParams.get("format") ?? "toon").toLowerCase();
  const view = (url.searchParams.get("view") ?? "summary").toLowerCase();
  if (!["toon", "json"].includes(format)) {
    res.statusCode = 400;
    return res.end("400 format must be toon or json\n");
  }
  if (!["summary", "full"].includes(view)) {
    res.statusCode = 400;
    return res.end("400 view must be summary or full\n");
  }

  const key = extractKey(req, url);
  if (!key) {
    res.statusCode = 401;
    res.setHeader("WWW-Authenticate", 'Bearer realm="rch-fleet"');
    return res.end("401 supply the fleet passphrase via Authorization: Bearer <passphrase>\n");
  }

  if (!envelope?.ciphertext) {
    res.statusCode = 500;
    return res.end("500 no snapshot bundled with this deployment\n");
  }

  let snap;
  try {
    snap = await decrypt(envelope, key);
  } catch {
    res.statusCode = 401;
    return res.end("401 wrong passphrase for this snapshot\n");
  }

  const body = encodeView(buildLlmView(snap, { view }), format);
  res.statusCode = 200;
  res.setHeader("Content-Type", contentType(format));
  if (req.method === "HEAD") return res.end();
  return res.end(body + "\n");
}
