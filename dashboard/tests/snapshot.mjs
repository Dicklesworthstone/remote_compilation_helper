/**
 * Collector tests — tools/snapshot.mjs.
 *
 * This file had zero coverage while holding the most consequential logic in the
 * dashboard: the cross-dispatcher merge, the encryption envelope, and the
 * aggregate arithmetic every KPI is built from. Each case below is pinned to a
 * defect that actually shipped, so the comments say what broke, not what the
 * code does.
 *
 *   node tests/snapshot.mjs
 */
import { webcrypto as crypto } from "node:crypto";
import { writeFile, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  statusRank, circuitRank, pressureIsBetter,
  isLocalDispatcher, dispatcherId,
  encrypt, existingSalt, internSnapshotStrings,
} from "../tools/snapshot.mjs";
import { expandBuilds, expandHints } from "../tools/llm-view.mjs";

let failures = 0;
const chk = (name, cond, detail = "") => {
  if (cond) console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ""}`);
  else { failures++; console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`); }
};

// ------------------------------------------------------ worker status ranking

// WorkerStatus in rch-common/src/types.rs:
//   healthy | degraded | unreachable | draining | drained | disabled
// `drained` was absent from the table and fell into the default bucket, ranking
// it as low as a busy worker — so a worker that had finished draining and was
// accepting nothing lost the merge against any healthy observation.
chk("healthy is the least alarming status", statusRank("healthy") === 0);
chk("degraded outranks healthy", statusRank("degraded") > statusRank("healthy"));
chk("draining outranks degraded", statusRank("draining") > statusRank("degraded"));
chk("drained outranks draining", statusRank("drained") > statusRank("draining"),
  `drained=${statusRank("drained")} draining=${statusRank("draining")}`);
chk("unreachable is the most alarming", statusRank("unreachable") > statusRank("disabled"));
chk("status ranking is case-insensitive", statusRank("DRAINED") === statusRank("drained"));
chk("a missing status ranks below every real reading", statusRank(null) < statusRank("healthy"));
chk("an unknown label still beats no reading", statusRank("weird") > statusRank(null));

chk("circuit closed < half_open < open",
  circuitRank("closed") < circuitRank("half_open") && circuitRank("half_open") < circuitRank("open"));
chk("a missing circuit state ranks below closed", circuitRank(null) < circuitRank("closed"));

// ---------------------------------------------------------- pressure ranking

const P = (state, age = 10) => ({ state, telemetry_age_secs: age });

// rch emits a fourth state, `telemetry_gap`. It was missing from the rank table,
// so it scored -1 — BELOW healthy — and a dispatcher explicitly reporting "I
// have no telemetry for this worker" lost to any other dispatcher's stale
// healthy reading.
chk("telemetry_gap beats healthy in the merge", pressureIsBetter(P("telemetry_gap"), P("healthy")));
chk("warning beats telemetry_gap", pressureIsBetter(P("warning"), P("telemetry_gap")));
chk("critical beats warning", pressureIsBetter(P("critical"), P("warning")));
chk("healthy never displaces critical", !pressureIsBetter(P("healthy"), P("critical")));
chk("a stale healthy never displaces a live critical",
  !pressureIsBetter(P("healthy", 1), P("critical", 9999)));
chk("at equal severity the fresher reading wins",
  pressureIsBetter(P("warning", 5), P("warning", 500)));
chk("at equal severity the staler reading loses",
  !pressureIsBetter(P("warning", 500), P("warning", 5)));
chk("any reading beats no reading", pressureIsBetter(P("healthy"), null));
chk("no reading never displaces a reading", !pressureIsBetter(null, P("healthy")));

// ------------------------------------------------------ local host detection

// os.hostname() returns the mixed-case name while the ssh alias people write is
// lowercase, so a case-sensitive Set made the collecting machine ssh to itself.
const short = (await import("node:os")).hostname().split(".")[0];
chk("`local` is this machine", isLocalDispatcher("local"));
chk("`localhost` is this machine", isLocalDispatcher("localhost"));
chk("own short hostname is this machine", isLocalDispatcher(short));
chk("hostname match ignores case", isLocalDispatcher(short.toUpperCase()));
chk("user@ prefix still resolves to this machine", isLocalDispatcher(`ubuntu@${short}`));
chk("a real remote is not this machine", isLocalDispatcher("hz3") === false);
chk("surrounding whitespace is tolerated", isLocalDispatcher(`  ${short} `));

// `local`, `localhost` and the bare hostname all name one machine. Collecting
// each separately double-counted dispatchers, builds and active jobs.
chk("aliases collapse to one dispatcher id",
  dispatcherId("local") === dispatcherId("localhost") && dispatcherId("localhost") === dispatcherId(short),
  dispatcherId("local"));
chk("a remote keeps its own id", dispatcherId("hz3") === "hz3");

// -------------------------------------------------------- string interning

// The build/hint strings duplicate massively ACROSS dispatchers — every box
// reports the same remediation advice about the same shared worker — so the
// collector folds them into one snapshot-level table at serialization time
// (-24,415B, -31.7% of a 77,095B payload on the live fleet). This is the
// emitting half; `tests/parity.mjs` proves the two expanders undo it identically.
{
  const dev = (builds, hints) => ({ id: "d", builds, hints });
  const B = (project, command, location, worker) =>
    [project, command, location, worker, 100, 0, "2026-08-26T11:58:00.000Z"];
  const H = (worker, severity, message, action, reason) => [worker, severity, message, action, reason];

  const input = [
    dev([B("rch", "cargo build", "Remote", "hz3")],
        [H("hz3", "critical", "disk 96% full", "run sbh reclaim", "disk_low")]),
    // The SAME advice about the SAME worker from a second dispatcher: this
    // repetition is the entire reason the table exists.
    dev([B("rch", "cargo build", "Remote", "hz3"), B("beads", "cargo test", "Local", null)],
        [H("hz3", "critical", "disk 96% full", "run sbh reclaim", "disk_low"),
         H(null, "warn", "telemetry stale", null, "")]),
  ];
  // Deep-copy: the collector must not mutate what it was handed, and the
  // literal form below is the oracle we compare against.
  const literal = JSON.parse(JSON.stringify(input));
  const { strings, dispatchers } = internSnapshotStrings(JSON.parse(JSON.stringify(input)));

  chk("the table holds every distinct non-empty interned string",
    strings.length === new Set(["rch", "cargo build", "hz3", "disk 96% full", "run sbh reclaim",
      "disk_low", "beads", "cargo test", "telemetry stale"]).size,
    `${strings.length}: ${JSON.stringify(strings)}`);
  chk("the table has no duplicates", new Set(strings).size === strings.length);
  // Hottest first, so the most repeated strings get the shortest indices —
  // worth 303B on the live fleet. "hz3" occurs 4 times (two builds, two hints),
  // more than anything else.
  chk("the table is ordered hottest-first", strings[0] === "hz3", JSON.stringify(strings.slice(0, 3)));
  // Ties break on first appearance, so the same input always yields the same
  // bytes — a table that reshuffled between runs would be a diff nightmare and
  // would make the A/B below meaningless.
  chk("interning is deterministic",
    JSON.stringify(internSnapshotStrings(JSON.parse(JSON.stringify(input)))) ===
      JSON.stringify(internSnapshotStrings(JSON.parse(JSON.stringify(input)))));

  // `location` and `severity` must survive as literal strings. `location` is
  // read positionally off the raw tuple by classifyDev() and `.toLowerCase()`d
  // by four consumers, so an index there is a TypeError in any bundle that
  // predates the table; `severity` is compared against "critical" to pick an
  // alarm colour, and an index would silently downgrade it to a warn pill.
  chk("location is never interned",
    dispatchers[0].builds[0][2] === "Remote" && dispatchers[1].builds[1][2] === "Local",
    JSON.stringify([dispatchers[0].builds[0][2], dispatchers[1].builds[1][2]]));
  chk("severity is never interned",
    dispatchers[0].hints[0][1] === "critical" && dispatchers[1].hints[1][1] === "warn");
  // A timestamp never repeats, so a table entry for it costs more than the
  // string it replaces.
  chk("completed_at is never interned", typeof dispatchers[0].builds[0][6] === "string");
  chk("numeric slots are untouched",
    dispatchers[0].builds[0][4] === 100 && dispatchers[0].builds[0][5] === 0);

  // The trap: a missing value must never become table entry 0.
  chk("a null slot stays null",
    dispatchers[1].builds[1][3] === null && dispatchers[1].hints[1][0] === null,
    JSON.stringify([dispatchers[1].builds[1][3], dispatchers[1].hints[1][0]]));
  chk("an empty string stays \"\", not an index",
    dispatchers[1].hints[1][4] === "", JSON.stringify(dispatchers[1].hints[1][4]));
  chk("every interned slot that had a value is now an index",
    typeof dispatchers[0].builds[0][0] === "number" &&
    typeof dispatchers[0].hints[0][2] === "number");

  // The round trip, element-wise, through the same expanders the browser and
  // the LLM view use.
  let roundTripped = true;
  for (let i = 0; i < literal.length; i++) {
    if (JSON.stringify(expandBuilds(dispatchers[i].builds, strings)) !==
        JSON.stringify(expandBuilds(literal[i].builds))) roundTripped = false;
    if (JSON.stringify(expandHints(dispatchers[i].hints, strings)) !==
        JSON.stringify(expandHints(literal[i].hints))) roundTripped = false;
  }
  chk("interning round-trips to the identical records", roundTripped,
    JSON.stringify(expandHints(dispatchers[1].hints, strings)));

  // It really is smaller — the whole point.
  const before = JSON.stringify(literal).length;
  const after = JSON.stringify({ dispatchers, strings }).length;
  chk("interning shrinks the payload on repeated data", after < before, `${before}B -> ${after}B`);

  // A dispatcher that failed collection has no builds and no hints at all.
  const empty = internSnapshotStrings([{ id: "x", builds: [], hints: [] }, { id: "y" }]);
  chk("a dispatcher with no builds or hints yields an empty table",
    empty.strings.length === 0 && empty.dispatchers.length === 2 &&
    empty.dispatchers[1].builds.length === 0 && empty.dispatchers[1].hints.length === 0);
}

// ------------------------------------------------- encryption + session reuse

const PASS = "test-passphrase-that-is-long-enough";
const b64ToU8 = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function deriveFrom(env, passphrase) {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToU8(env.kdf.salt), iterations: env.kdf.iterations, hash: env.kdf.hash },
    base, { name: "AES-GCM", length: 256 }, true, ["decrypt"],
  );
}
async function decryptWith(env, key) {
  const out = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToU8(env.cipher.iv) }, key, b64ToU8(env.ciphertext),
  );
  return new TextDecoder().decode(out);
}

const env1 = await encrypt(JSON.stringify({ hello: "fleet" }), PASS);
const key1 = await deriveFrom(env1, PASS);
chk("envelope round-trips", JSON.parse(await decryptWith(env1, key1)).hello === "fleet");
chk("envelope declares its KDF", env1.kdf.iterations === 600000 && env1.kdf.hash === "SHA-256");

// THE regression this suite exists for.
//
// The browser's "stay unlocked for 60 days" stores the DERIVED KEY (the
// passphrase is never persisted). A key derived under salt A cannot decrypt a
// payload encrypted under salt B, so minting a fresh salt every collection
// invalidated the saved session on every run — a wall-mounted tab logged itself
// out on each cron tick, which is the exact case the feature exists for.
const env2 = await encrypt(JSON.stringify({ hello: "later" }), PASS, b64ToU8(env1.kdf.salt));
chk("a reused salt is carried into the new envelope", env2.kdf.salt === env1.kdf.salt);
chk("the IV is still unique per encryption", env2.cipher.iv !== env1.cipher.iv,
  "AES-GCM requires a fresh IV even when the key is unchanged");

let survived = false;
try {
  survived = JSON.parse(await decryptWith(env2, key1)).hello === "later";
} catch { survived = false; }
chk("a saved session key still opens the NEXT snapshot", survived,
  "this is the 60-day cookie working across a collection");

// And the negative: a genuinely rotated salt must invalidate the old key, so a
// passphrase change really does lock everyone out.
const env3 = await encrypt(JSON.stringify({ hello: "rotated" }), PASS);
let rotatedRejected = false;
if (env3.kdf.salt === env1.kdf.salt) {
  rotatedRejected = false; // a fresh call must not reuse by accident
} else {
  try { await decryptWith(env3, key1); } catch { rotatedRejected = true; }
}
chk("a rotated salt invalidates the old key", rotatedRejected);

const wrongKey = await deriveFrom(env1, "definitely-not-the-passphrase");
let wrongRejected = false;
try { await decryptWith(env1, wrongKey); } catch { wrongRejected = true; }
chk("a wrong passphrase fails the GCM tag", wrongRejected);

// ------------------------------------------------------------- existingSalt

const dir = await mkdtemp(join(tmpdir(), "rch-snap-test-"));
const outPath = join(dir, "fleet.enc.json");

chk("no previous file yields no salt", (await existingSalt(outPath)) === null);

await writeFile(outPath, JSON.stringify(env1));
const reused = await existingSalt(outPath);
chk("a previous envelope yields its salt", reused != null && Buffer.from(reused).toString("base64") === env1.kdf.salt);

// Changing KDF parameters must rotate rather than silently reuse a salt that no
// longer matches how the key will be derived.
await writeFile(outPath, JSON.stringify({ ...env1, kdf: { ...env1.kdf, iterations: 1000 } }));
chk("a different iteration count refuses reuse", (await existingSalt(outPath)) === null);
await writeFile(outPath, JSON.stringify({ ...env1, kdf: { ...env1.kdf, hash: "SHA-512" } }));
chk("a different hash refuses reuse", (await existingSalt(outPath)) === null);
await writeFile(outPath, JSON.stringify({ ...env1, kdf: { ...env1.kdf, salt: Buffer.alloc(8).toString("base64") } }));
chk("a wrong-length salt refuses reuse", (await existingSalt(outPath)) === null);
await writeFile(outPath, "{ not json");
chk("a corrupt previous file refuses reuse", (await existingSalt(outPath)) === null);

// ------------------------------------------------------- published artifacts

// The collector must never leave a readable plaintext snapshot next to the
// ciphertext: `public/` is copied verbatim into `dist/` and published.
const liveEnvelope = JSON.parse(await readFile(new URL("../public/data/fleet.enc.json", import.meta.url), "utf8"));
chk("the published file is an envelope, not plaintext",
  liveEnvelope.format === "rch.dashboard.enc.v1" && typeof liveEnvelope.ciphertext === "string");
chk("the published envelope exposes no fleet fields",
  !("workers" in liveEnvelope) && !("dispatchers" in liveEnvelope) && !("totals" in liveEnvelope));

console.log(failures === 0 ? "\nALL SNAPSHOT CHECKS PASSED" : `\n${failures} SNAPSHOT CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
