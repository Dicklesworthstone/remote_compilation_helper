#!/usr/bin/env node
/**
 * Print the fleet state as TOON (default) or JSON, for an LLM/agent to read.
 *
 * This is the LOCAL path: an agent already running on a fleet machine has the
 * passphrase (env, .env, or Vault) and does not need to go over the network or
 * negotiate deployment-protection tokens. For the HTTP path see
 * `api/fleet.mjs` (`GET /api/fleet`).
 *
 * Usage:
 *   node tools/fleet-llm.mjs                      # summary, TOON
 *   node tools/fleet-llm.mjs --format json        # summary, JSON
 *   node tools/fleet-llm.mjs --view full          # everything
 *   node tools/fleet-llm.mjs --in path/to.enc.json
 *   node tools/fleet-llm.mjs --url https://host/data/fleet.enc.json
 *
 * Passphrase resolution order: RCH_DASH_PASSPHRASE -> ./.env -> Vault
 * (secret/rch-fleet-dashboard). Exits non-zero with a one-line reason on stderr
 * so a calling agent can branch on it.
 */

import { readFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { buildLlmView, encodeView } from "./llm-view.mjs";
import { decompressPlaintext, isSupportedCompression } from "./envelope.mjs";

const execFileAsync = promisify(execFile);

function parseArgs(argv) {
  const a = { format: "toon", view: "summary", in: "public/data/fleet.enc.json", url: null };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const next = () => argv[++i];
    if (k === "--format" || k === "-F") a.format = next();
    else if (k === "--view") a.view = next();
    else if (k === "--in") a.in = next();
    else if (k === "--url") a.url = next();
    else if (k === "--json") a.format = "json";
    else if (k === "--help" || k === "-h") {
      console.log(
        "usage: node tools/fleet-llm.mjs [--format toon|json] [--view summary|full]\n" +
          "                               [--in <file>] [--url <https://.../fleet.enc.json>]",
      );
      process.exit(0);
    } else { console.error(`unknown argument: ${k}`); process.exit(2); }
  }
  if (!["toon", "json"].includes(a.format)) { console.error("--format must be toon or json"); process.exit(2); }
  if (!["summary", "full"].includes(a.view)) { console.error("--view must be summary or full"); process.exit(2); }
  return a;
}

async function resolvePassphrase() {
  if (process.env.RCH_DASH_PASSPHRASE) return process.env.RCH_DASH_PASSPHRASE;
  try {
    const env = await readFile(".env", "utf8");
    const m = env.match(/^RCH_DASH_PASSPHRASE\s*=\s*['"]?([^'"\n]+)['"]?/m);
    if (m) return m[1];
  } catch { /* no .env — fall through to Vault */ }
  try {
    const { stdout } = await execFileAsync(
      "vault",
      ["kv", "get", "-field=passphrase", "secret/rch-fleet-dashboard"],
      {
        timeout: 15_000,
        env: {
          ...process.env,
          VAULT_ADDR: process.env.VAULT_ADDR ?? "https://127.0.0.1:8200",
          VAULT_CACERT: process.env.VAULT_CACERT ?? `${process.env.HOME}/.vault-ca.crt`,
        },
      },
    );
    if (stdout.trim()) return stdout.trim();
  } catch { /* no vault */ }
  return null;
}

function b64ToBuf(b64) {
  const b = Buffer.from(b64, "base64");
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

/**
 * Authenticate + decrypt, returning the RAW plaintext bytes.
 *
 * Stops at the AES-GCM boundary on purpose: the caller reports a throw from here
 * as "wrong passphrase", and that is only accurate while the auth tag is the
 * only thing that can fail. Inflating and parsing happen separately so a
 * snapshot written by a newer collector is not blamed on the operator's
 * passphrase.
 */
export async function decryptToBytes(env, passphrase) {
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(env.kdf.salt), iterations: env.kdf.iterations, hash: env.kdf.hash },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(env.cipher.iv) }, key, b64ToBuf(env.ciphertext),
  );
}

/**
 * Decrypt and decode. The collector gzips the snapshot JSON before encrypting it
 * — ciphertext is incompressible, so that is the only layer where this payload
 * can shrink (see tools/envelope.mjs). An envelope with no `compression` field
 * predates that and is plain UTF-8.
 */
export async function decryptEnvelope(env, passphrase) {
  const plain = await decryptToBytes(env, passphrase);
  return JSON.parse(decompressPlaintext(Buffer.from(plain), env.compression));
}

async function main() {
  const args = parseArgs(process.argv);

  const passphrase = await resolvePassphrase();
  if (!passphrase) {
    console.error("no passphrase: set RCH_DASH_PASSPHRASE, add .env, or unseal Vault");
    process.exit(2);
  }

  let envelope;
  try {
    if (args.url) {
      const res = await fetch(args.url, { cache: "no-store" });
      // Without this a 404 HTML page becomes an opaque JSON parse error.
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${args.url}`);
      envelope = await res.json();
    } else {
      envelope = JSON.parse(await readFile(args.in, "utf8"));
    }
  } catch (e) {
    console.error(`cannot read snapshot: ${e.message}`);
    process.exit(3);
  }
  if (!envelope?.ciphertext) { console.error("not an encrypted snapshot envelope"); process.exit(3); }
  // Skew guard: a codec this build cannot inflate is an unreadable snapshot
  // (exit 3), not a bad passphrase (exit 4). Checked before the 600k-iteration
  // derivation so the wrong answer is never even computed.
  if (!isSupportedCompression(envelope.compression)) {
    console.error(`cannot read snapshot: unsupported compression ${String(envelope.compression)} — update this tool`);
    process.exit(3);
  }

  let plain;
  try {
    plain = await decryptToBytes(envelope, passphrase);
  } catch {
    console.error("decryption failed — wrong passphrase for this snapshot");
    process.exit(4);
  }

  let snap;
  try {
    snap = JSON.parse(decompressPlaintext(Buffer.from(plain), envelope.compression));
  } catch (e) {
    console.error(`cannot read snapshot: decrypted but could not decode — ${e?.message ?? "unknown error"}`);
    process.exit(3);
  }

  process.stdout.write(encodeView(buildLlmView(snap, { view: args.view }), args.format) + "\n");
}

// Only run the CLI when this file IS the program, exactly as tools/snapshot.mjs
// guards its collector. Without it, `import`ing this module for its exported
// `decryptToBytes`/`decryptEnvelope` runs main() against the HOST's argv: it
// resolves the passphrase (which can shell out to `vault kv get` and block for
// up to 15s), spends a 600k-iteration PBKDF2 decrypting the live snapshot,
// writes the whole fleet inventory to stdout, and calls process.exit() on any
// unrecognised flag the host happened to be passing. That makes the exports
// untestable and turns a stray import into an fleet-inventory disclosure.
const invokedDirectly =
  process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main().catch((e) => { console.error(e?.message ?? String(e)); process.exit(1); });
}
