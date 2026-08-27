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
 * price and is the most broadly supported `DecompressionStream` format.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * LEVEL: FIXED AT 9, and deliberately not adaptive.
 *
 * This is the one stage in the whole pipeline that is super-linear in its OWN
 * input — zlib's level-9 match search costs ~n^0.6 per byte — so it is the only
 * place where "right at today's fleet" and "right at ten times the fleet" could
 * genuinely differ, and the only reason a fixed constant here needs defending
 * rather than assuming. `node tools/scaling.mjs --gzip-levels` regenerates every
 * synthetic row below — the whole point of that mode is that this block never
 * has to be believed on trust, or kept current by hand, the way the one-line
 * note it replaced was not. (The `live` row is the real published snapshot and
 * needs the passphrase, so it is the one number the sweep cannot reproduce; it
 * is here as the calibration point that says the synthetic n=10 fleet is within
 * 6% of the real one.)
 *
 * Synthetic fleets from `tools/scaling.mjs` (d dispatchers over a shared pool of
 * 1.6d workers), plus the real published snapshot as the calibration point. Byte
 * counts are exact and identical run to run; CPU is the median across five runs
 * of 25 repetitions each, because this host carries an agent swarm and a single
 * sample of a sub-millisecond stage is mostly scheduler noise. "B/ms" is the
 * exchange rate: bytes surrendered per millisecond of collector CPU bought by
 * dropping 9 -> 6.
 *
 *   fleet           plaintext   L9 bytes    L9 cpu   L6 costs    L6 saves   B/ms
 *   live 10x16         52,013      9,554    0.56ms      +156B    -0.19ms     808
 *   n=10   (16w)       55,041      7,467    0.58ms      +199B    -0.18ms   1,082
 *   n=25   (40w)      112,132     15,709    2.51ms      +759B    -1.29ms     587
 *   n=50   (80w)      218,070     31,624    8.37ms    +1,720B    -5.16ms     333
 *   n=100 (160w)      469,472     72,017   27.71ms    +4,019B   -18.27ms     220
 *   n=200 (320w)    1,134,502    189,101  122.08ms   +11,504B   -86.24ms     133
 *   n=500 (800w)    4,388,356    805,946  958.90ms   +52,169B  -777.61ms      67
 *
 * The crossover is real and it is in that last column: from n=25 up, the
 * exchange rate improves roughly nine-fold (587 -> 67), so a bigger fleet gives
 * up steadily fewer bytes per millisecond saved. (It is not monotone across the first two rows —
 * at 0.56ms and 0.58ms the CPU delta is smaller than the noise floor of the box
 * measuring it, which is itself the finding for those rows.) The crossover is
 * also IRRELEVANT, because both sides stay negligible against what they are
 * actually competing with:
 *
 *   - At the live fleet gzip -9 costs 0.56ms TOTAL. That is 0.07% of the
 *     collector's 755ms of CPU, 0.02% of its 2.77s wall, and 0.0002% of the
 *     five-minute cron interval it runs on. Level 6 recovers 0.19ms of it.
 *     There is no load average at which 0.19ms every five minutes is worth a
 *     branch, let alone worth 156 bytes.
 *   - Even at n=500 — fifty times the fleet, 800 workers, far past any plausible
 *     target — gzip -9 is 959ms against an ssh fan-out of ~32 waves over a
 *     measured 1.45-1.59s handshake floor at the collector's `--max-parallel 16`.
 *     Under 2% of the run's wall, on the stage that is 74% of it.
 *
 * And the two costs are not paid the same number of times. The collector
 * compresses ONCE per cron tick. Every open tab re-fetches the artifact on its
 * own five-minute timer, every reload fetches it again, and `api/fleet.mjs`
 * bundles the envelope at build time so the bytes are in every serverless cold
 * start too. Bytes are paid F>=1 times per tick and CPU exactly once, on a
 * machine the operator already owns, at a duty cycle of 2e-6. When both sides
 * are this small the tie goes to the side that is paid once: level 9.
 *
 * So NO ADAPTIVE RULE. The most generous threshold that could still be argued
 * for — let gzip cost no more than the ~55ms the collector's single 600k PBKDF2
 * already costs and which nobody complains about — lands, via the fitted
 * cpu ~ B^1.6, at roughly 720KB of plaintext: about 145 dispatchers and 230
 * workers. The fleet is at 10 and 16, and gained two machines in the days before
 * this was written, so it does move — but not by 14x. That branch would never
 * have executed, which makes it untested code on the only path that publishes
 * the dashboard, buying a saving nothing is waiting on. An adaptive rule that
 * never fires is strictly worse than the comment it replaces.
 *
 * If the constraint ever does change — a metered CPU runtime, or a cron interval
 * short enough for a run to overlap the next — the fallback is level SEVEN, not
 * the level 6 the first look at this reached for. From n=25 up, level 7 captures
 * 79-94% of level 6's CPU saving for 34-47% of its byte cost:
 *
 *   n=25    L7  -1.02ms /    +256B    vs   L6  -1.29ms /    +759B
 *   n=100   L7 -15.72ms /  +1,675B    vs   L6 -18.27ms /  +4,019B
 *   n=500   L7 -714.6ms / +24,526B    vs   L6 -777.6ms / +52,169B
 *
 * Other zlib knobs were measured on the same ladder and none dominates the
 * defaults: `memLevel: 9` buys 0 bytes at the live size and 21 at n=100 while
 * costing 2.7ms there, and `Z_FILTERED` is 18 bytes WORSE live, better at n=25,
 * and 6.8ms slower at n=100. There is nothing free left in the encoder.
 *
 * NOTHING DOWNSTREAM DEPENDS ON THIS NUMBER, which is what makes it safe to pin.
 * A gzip stream is self-terminating, and the level is not recoverable from it:
 * zlib records it only in the advisory XFL header byte (2 for level 9, 4 for
 * level 1, 0 for every level in between, so 2..8 are indistinguishable), and
 * every inflater ignores it. `decompressPlaintext`, `api/fleet.mjs`,
 * `tools/fleet-llm.mjs` and the browser's `DecompressionStream("gzip")` are all
 * handed a codec NAME and never a level. This constant can therefore be changed
 * — or made a function of the input — without touching a single reader or the
 * envelope format. `tests/snapshot.mjs` and `tests/e2e.mjs` pin that property
 * directly, in Node and in real Chromium, so the claim is checked rather than
 * asserted here.
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

/**
 * The deflate level the collector compresses at. Fixed, not a function of input
 * size — see the LEVEL block above for the measurements that settle it. Exported
 * so the tests can pin both the value and the fact that no reader can observe it.
 */
export const SNAPSHOT_GZIP_LEVEL = 9;

/** Snapshot JSON string -> the bytes that get encrypted. */
export function compressPlaintext(text) {
  return gzipSync(Buffer.from(text, "utf8"), { level: SNAPSHOT_GZIP_LEVEL });
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
