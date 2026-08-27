/**
 * Scaling-law harness — how every pure stage of the snapshot pipeline behaves
 * as the FLEET grows, not as the clock ticks.
 *
 *     node tools/scaling.mjs                 # 1, 10, 50, 100, 500 dispatchers
 *     node tools/scaling.mjs --n 1,10,100    # pick the ladder
 *     node tools/scaling.mjs --json out.json # machine-readable, for diffing runs
 *
 * WHY THIS EXISTS
 *
 * Seven optimisation passes profiled this pipeline at ONE fleet size: 10
 * dispatchers, 16 workers. Every measurement said "irreducible", and every one
 * of them was a measurement of a single point. A quadratic term is invisible at
 * n=10 — it is a rounding error next to the constants — and it is the whole
 * cost at n=100. The fleet gained two machines in the two days before this file
 * was written, so n=10 is not a fixed point; it is a sample of a moving one.
 *
 * WHAT IS MEASURED, AND WHAT IS DELIBERATELY NOT
 *
 * Only PURE, in-process code. No ssh, no network, no disk. The collector's
 * wall-clock is dominated by fan-out to real machines, which is a bandwidth and
 * latency question and scales with however many connections you are willing to
 * open; that is a different investigation. This one asks a narrower question
 * with a definite answer: does the CODE contain a super-linear term?
 *
 * HOW TIME IS MEASURED, AND WHY NOT WALL-CLOCK
 *
 * The development host runs an agent swarm — load average 100-300 on 14 cores.
 * Wall-clock there measures how many other processes wanted the CPU, not how
 * much work this code did; the same stage can vary 10x between runs. So the
 * headline number is PROCESS CPU TIME (`process.cpuUsage()`, user+system, µs
 * resolution), which counts only cycles this process was actually scheduled
 * for. Wall is still recorded, and the report prints wall/cpu per stage: a
 * ratio near 1.0 means the box was quiet and the two agree; a large ratio means
 * the box was busy and the wall column should be ignored, not the run.
 *
 * MAD/median (median absolute deviation over the repetitions) is the second
 * validity check. A stage whose MAD is a large fraction of its median was not
 * measured cleanly, and the fitted exponent for it should not be believed
 * without a re-run. Both checks are printed with the results rather than
 * summarised away.
 *
 * THE SYNTHETIC FLEET
 *
 * Workers are SHARED, which is the whole point. In a real rch deployment every
 * dev machine lists the same worker pool in its `workers.toml`, so d
 * dispatchers each reporting w workers produce d x w observations of only w
 * distinct machines. That duplication is exactly what the merge and the string
 * table exist to absorb, so a generator that gave every dispatcher its own
 * private workers would measure neither. The pool grows with the fleet
 * (WORKERS_PER_DISPATCHER, calibrated to the live 10-dispatcher/16-worker
 * fleet), each dispatcher sees a deterministic ~VISIBILITY share of it, and the
 * shapes match what `dispatcherFromProbe()` actually emits, field for field.
 *
 * Everything is driven by a seeded PRNG, so two runs of the same ladder build
 * byte-identical fleets and the payload column is exactly reproducible.
 */

import { webcrypto } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  mergeWorkers, computeTotals, projectDispatchers, internSnapshotStrings,
} from "./snapshot.mjs";
import { compressPlaintext, decompressPlaintext, SNAPSHOT_COMPRESSION } from "./envelope.mjs";
import { buildLlmView, encodeView } from "./llm-view.mjs";

// ------------------------------------------------------------------- fleet gen

/** Live fleet, 2026-08-27: 16 workers across 10 dispatchers. */
const WORKERS_PER_DISPATCHER = 1.6;
/**
 * Share of the pool a given dispatcher can see. Not 1.0: real dispatchers
 * disagree about the pool (a worker can be disabled in one `workers.toml`, or
 * newly added and not yet rolled out), and a merge that never sees a worker it
 * has not already got would not exercise the insert path past the first
 * dispatcher.
 */
const VISIBILITY = 0.8;
/** `dispatcherFromProbe()` caps these; the collector cannot emit more. */
const BUILDS_PER_DISPATCHER = 25;
const HINTS_PER_DISPATCHER = 12;

/** mulberry32 — 32 bits of state, uniform enough for fixtures and exactly reproducible. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (r, xs) => xs[Math.floor(r() * xs.length) % xs.length];

const STATUSES = ["healthy", "healthy", "healthy", "degraded", "draining", "drained", "unreachable", "disabled"];
const CIRCUITS = ["closed", "closed", "closed", "half_open", "open"];
const PRESSURE = ["healthy", "healthy", "warning", "critical", "telemetry_gap"];
const POSTURES = ["remote_ready", "remote_ready", "remote_ready", "degraded", "local_only"];
const RUSTC = ["1.94.0-nightly (a1b2c3d4e 2026-08-01)", "1.93.0 (9f0c1e2ab 2026-07-11)", "1.92.1 (33ef00212 2026-06-02)"];
const TAGS = ["fast", "big-mem", "avx2", "nvme", "arch", "ubuntu-dispatch", "outlet"];
/**
 * Project names grow SUBLINEARLY with the fleet (a bigger fleet compiles a
 * similar set of repos), which is what makes the string table pay. Hint
 * messages are drawn from a fixed template set for the same reason — every
 * dispatcher reports the same advice about the same shared worker.
 */
const PROJECTS = [
  "remote_compilation_helper", "franken_sqlite", "beads_rust", "smartedgar", "asupersync",
  "franken_markdown", "franken_ocr", "coding_agent_search", "doodlestein_self_releaser",
  "agent_mail", "frankenterm", "franken_whisper", "franken_tui", "atp", "eidetic_engine",
];
const COMMANDS = [
  "cargo build --release", "cargo test --workspace", "cargo check --all-targets",
  "cargo clippy --all-targets -- -D warnings", "cargo build", "cargo nextest run",
];
const HINT_MESSAGES = [
  "Disk is above the pressure threshold and rchd has derated this worker to zero slots.",
  "Consecutive probe failures have opened the circuit breaker for this worker.",
  "Pressure telemetry has not refreshed within the freshness window.",
  "Load average per core is sustained above 2x; builds will queue behind local work.",
  "The projects root is not writable, so transfers will fail before compilation starts.",
];
const HINT_ACTIONS = [
  "Run `rch workers probe <id>` and check `df -h /data` on the host.",
  "Clear the circuit with `rch workers reset <id>` once the host answers again.",
  "Restart rchd on the worker so telemetry resumes.",
  "Drain the worker, or raise CARGO_BUILD_JOBS pressure limits in /etc/environment.",
  "Fix ownership on the projects root and re-run `rch doctor`.",
];
const HINT_REASONS = ["disk_pressure", "circuit_open", "telemetry_stale", "load_high", "projects_root"];
const SEVERITIES = ["critical", "warn", "info"];

function synthWorker(r, id, nowUnix) {
  const total = pick(r, [4, 8, 16, 16, 32, 64]);
  const state = pick(r, PRESSURE);
  const diskTotal = pick(r, [220, 400, 900, 1800]);
  return {
    id,
    host: `${id}.fleet.internal`,
    user: pick(r, ["root", "ubuntu", "builder"]),
    status: pick(r, STATUSES),
    circuit_state: pick(r, CIRCUITS),
    used_slots: Math.floor(r() * (total + 1)),
    total_slots: total,
    speed: Math.round(r() * 1000) / 10,
    last_error: r() < 0.2 ? "ssh: connect to host port 22: Connection refused" : null,
    consecutive_failures: r() < 0.25 ? Math.floor(r() * 5) : 0,
    failure_history: Array.from({ length: 20 }, () => r() < 0.15),
    pressure: {
      state,
      reason: state === "healthy" ? null : pick(r, HINT_REASONS),
      disk_free_gb: Math.round(r() * diskTotal),
      disk_total_gb: diskTotal,
      disk_io_util_pct: Math.round(r() * 1000) / 10,
      memory_pressure: Math.round(r() * 1000) / 10,
      telemetry_age_secs: Math.floor(r() * 600),
      telemetry_fresh: r() < 0.9,
    },
    latency_ms: Math.round(r() * 4000) / 10,
    last_seen_unix: nowUnix - Math.floor(r() * 900),
    caps: {
      num_cpus: pick(r, [8, 16, 32, 64]),
      load_avg_1: Math.round(r() * 800) / 10,
      load_avg_5: Math.round(r() * 800) / 10,
      load_avg_15: Math.round(r() * 800) / 10,
      cpu_microarch_level: pick(r, [2, 3, 4]),
      rustc_version: pick(r, RUSTC),
      bun_version: "1.3.9",
      node_version: "v24.9.0",
      go_version: "go1.25.1",
      zig_version: "0.15.2",
      projects_root_ok: r() < 0.95,
    },
    tags: Array.from({ length: Math.floor(r() * 3) }, () => pick(r, TAGS)),
    priority: pick(r, [40, 85, 100, 110, 120]),
  };
}

/**
 * One synthetic fleet, in exactly the shape `dispatcherFromProbe()` returns.
 *
 * @returns {{dispatchers: object[], pool: number, observations: number}}
 */
export function synthFleet(n, seed = 0x5eed) {
  const r = rng(seed + n);
  const nowUnix = Math.floor(Date.UTC(2026, 7, 27, 2, 0, 0) / 1000);
  const poolSize = Math.max(1, Math.round(n * WORKERS_PER_DISPATCHER));
  const pool = Array.from({ length: poolSize }, (_, i) =>
    synthWorker(r, `wkr-${String(i).padStart(4, "0")}`, nowUnix));

  const visible = Math.max(1, Math.round(poolSize * VISIBILITY));
  let observations = 0;
  const dispatchers = Array.from({ length: n }, (_, di) => {
    const id = `dev-${String(di).padStart(4, "0")}`;
    // A contiguous rotating window: deterministic, and every dispatcher sees a
    // DIFFERENT slice, so the merge's insert path keeps firing past the first
    // dispatcher instead of degenerating into "everything is already there".
    const start = Math.floor((di * poolSize) / Math.max(1, n));
    const workers = Array.from({ length: visible }, (_, k) => {
      const w = pool[(start + k) % poolSize];
      // Each observer derates independently — that per-observer disagreement is
      // the reason `slots_by_dispatcher` exists at all.
      return { ...w, used_slots: Math.floor(r() * (w.total_slots + 1)), total_slots: Math.max(0, w.total_slots - Math.floor(r() * 4)) };
    });
    observations += workers.length;

    const reachable = r() < 0.92;
    const builds = Array.from({ length: reachable ? BUILDS_PER_DISPATCHER : 0 }, (_, bi) => [
      pick(r, PROJECTS),
      pick(r, COMMANDS),
      r() < 0.75 ? "Remote" : "Local",
      pool[Math.floor(r() * poolSize)].id,
      Math.floor(r() * 300000),
      r() < 0.9 ? 0 : 101,
      new Date((nowUnix - bi * 37) * 1000).toISOString(),
    ]);
    const hints = Array.from({ length: reachable ? HINTS_PER_DISPATCHER : 0 }, () => {
      const k = Math.floor(r() * HINT_MESSAGES.length);
      return [
        pool[Math.floor(r() * poolSize)].id,
        pick(r, SEVERITIES),
        HINT_MESSAGES[k],
        HINT_ACTIONS[k],
        HINT_REASONS[k],
      ];
    });

    const totalBuilds = 100 + Math.floor(r() * 5000);
    const remote = Math.floor(totalBuilds * (0.4 + r() * 0.6));
    return {
      id,
      reachable,
      collection_errors: reachable ? [] : ["ssh: connect to host port 22: Connection timed out"],
      config_degraded: !reachable,
      posture: reachable ? pick(r, POSTURES) : null,
      posture_description: reachable ? "workers reachable and above the slot floor" : null,
      daemon: reachable
        ? {
            version: pick(r, ["1.0.57", "1.0.58"]),
            uptime_secs: Math.floor(r() * 900000),
            pid: 1000 + Math.floor(r() * 60000),
            workers_total: visible,
            workers_healthy: Math.floor(visible * (0.5 + r() * 0.5)),
            slots_total: visible * 8,
            slots_available: Math.floor(visible * 8 * r()),
          }
        : null,
      build_stats: reachable
        ? {
            total: totalBuilds,
            remote,
            local: totalBuilds - remote,
            success: Math.floor(totalBuilds * 0.95),
            failure: Math.ceil(totalBuilds * 0.05),
            avg_duration_ms: Math.floor(r() * 120000),
          }
        : null,
      saved_time_ms: reachable ? Math.floor(r() * 9e8) : null,
      active_builds: Math.floor(r() * 6),
      queued_builds: Math.floor(r() * 4),
      builds,
      hints,
      workers,
    };
  });

  return { dispatchers, pool: poolSize, observations };
}

// --------------------------------------------------------------- measurement

/**
 * Median and MAD over a sample. Median, not mean: one GC pause or one scheduler
 * preemption on a loaded box moves a mean and does not move a median, and this
 * host is never quiet.
 */
function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
function mad(xs) {
  const m = median(xs);
  return median(xs.map((x) => Math.abs(x - m)));
}

/**
 * Time one stage.
 *
 * @param setup runs OUTSIDE the timed region, once per repetition — for stages
 *   whose input is consumed or mutated (`rehydrateStrings` writes back into the
 *   tuples it resolves, so a second repetition over the same object would
 *   measure a no-op).
 */
function timeStage(fn, { reps = 7, setup = null } = {}) {
  const cpu = [];
  const wall = [];
  let out;
  // One untimed pass so the shapes are known to the JIT and the first
  // repetition is not paying for the last stage's garbage.
  const warm = setup ? setup() : undefined;
  out = fn(warm);
  for (let i = 0; i < reps; i++) {
    const arg = setup ? setup() : undefined;
    const c0 = process.cpuUsage();
    const w0 = performance.now();
    out = fn(arg);
    const w1 = performance.now();
    const c1 = process.cpuUsage(c0);
    cpu.push((c1.user + c1.system) / 1000);
    wall.push(w1 - w0);
  }
  return {
    cpuMs: median(cpu), cpuMad: mad(cpu),
    wallMs: median(wall), wallMad: mad(wall),
    out,
  };
}

// ------------------------------------------------------------------ the ladder

const AES_KEY = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const IV = webcrypto.getRandomValues(new Uint8Array(12));

/** Bytes of a sub-structure, measured the way the wire measures it. */
const bytesOf = (v) => Buffer.byteLength(JSON.stringify(v ?? null));

async function runOne(n, reps, browser) {
  const { dispatchers, pool, observations } = synthFleet(n);
  const stages = {};

  // ---- collector
  const merge = timeStage(() => mergeWorkers(dispatchers), { reps });
  stages.merge = merge;
  const workers = merge.out;

  stages.totals = timeStage(() => computeTotals(workers, dispatchers), { reps });
  const totals = stages.totals.out;

  stages.project = timeStage(() => projectDispatchers(dispatchers, workers), { reps });
  const emitted = stages.project.out;

  stages.intern = timeStage(() => internSnapshotStrings(emitted), { reps });
  const { dispatchers: internedDispatchers, strings } = stages.intern.out;

  const snapshot = {
    schema: "rch.dashboard.snapshot.v2",
    label: "scaling",
    generated_at: new Date(Date.UTC(2026, 7, 27, 2, 0, 0)).toISOString(),
    totals,
    dispatchers: internedDispatchers,
    workers,
    strings,
    // `historyMax` in tools/snapshot.mjs — a FIXED 96 rows regardless of fleet
    // size, so this block is a constant in n and belongs in the measurement as
    // one: it is the floor every other component is compared against.
    history: Array.from({ length: 96 }, (_, i) => ({
      t: new Date(Date.UTC(2026, 7, 20) + i * 3e5).toISOString(),
      slots_total: totals.slots, slots_used: totals.slots_used, workers: totals.workers,
      disk_free_gb: Math.round(totals.disk_free_gb),
      builds_remote: totals.builds_remote, builds_local: totals.builds_local,
      dispatchers_remote_ready: totals.dispatchers_remote_ready,
    })),
  };

  stages.stringify = timeStage(() => JSON.stringify(snapshot), { reps });
  const plain = stages.stringify.out;

  stages.gzip = timeStage(() => compressPlaintext(plain), { reps });
  const gz = stages.gzip.out;

  const aesIn = new Uint8Array(gz);
  const cipher = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: IV }, AES_KEY, aesIn);
  {
    // WebCrypto is async, so it cannot go through timeStage(); same protocol,
    // inline. PBKDF2 is deliberately NOT here: 600k iterations is a constant,
    // independent of fleet size, and pass 1 already cached it.
    const cpu = [], wall = [];
    await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: IV }, AES_KEY, aesIn);
    for (let i = 0; i < reps; i++) {
      const c0 = process.cpuUsage(); const w0 = performance.now();
      await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: IV }, AES_KEY, aesIn);
      wall.push(performance.now() - w0);
      const c1 = process.cpuUsage(c0);
      cpu.push((c1.user + c1.system) / 1000);
    }
    stages.aes_gcm = { cpuMs: median(cpu), cpuMad: mad(cpu), wallMs: median(wall), wallMad: mad(wall) };
  }
  const envelope = {
    format: "rch.dashboard.enc.v1",
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: 600000, salt: "AAAAAAAAAAAAAAAAAAAAAA==" },
    cipher: { name: "AES-GCM", iv: Buffer.from(IV).toString("base64") },
    compression: SNAPSHOT_COMPRESSION,
    ciphertext: Buffer.from(cipher).toString("base64"),
  };

  // ---- browser
  stages.gunzip = timeStage(() => decompressPlaintext(gz, SNAPSHOT_COMPRESSION), { reps });
  const wireText = stages.gunzip.out;

  // `expandSnapshotStrings()` in src/crypto.ts, verbatim: parse, rehydrate in
  // place, drop the spent table, re-stringify for the caller's own parse.
  stages.rehydrate = timeStage(
    (text) => {
      const snap = JSON.parse(text);
      const { strings: _spent, ...rest } = browser.rehydrateStrings(snap);
      return JSON.stringify(rest);
    },
    { reps, setup: () => wireText },
  );
  const appText = stages.rehydrate.out;

  stages.parse = timeStage(() => JSON.parse(appText), { reps });
  const appSnap = stages.parse.out;

  stages.classifyAll = timeStage(() => browser.classifyAll(appSnap), { reps });
  stages.classifyDispatchers = timeStage(
    () => appSnap.dispatchers.map((d) => browser.classifyDispatcher(d)),
    { reps },
  );

  // ---- LLM endpoint (api/fleet.mjs + tools/fleet-llm.mjs)
  const llmSnap = JSON.parse(plain);
  stages.llm_summary = timeStage(() => buildLlmView(llmSnap, { view: "summary", now: Date.now() }), { reps });
  stages.llm_full = timeStage(() => buildLlmView(llmSnap, { view: "full", now: Date.now() }), { reps });
  stages.toon = timeStage(() => encodeView(stages.llm_summary.out, "toon"), { reps });

  const payload = {
    plaintext: Buffer.byteLength(plain),
    gzip: gz.length,
    envelope: Buffer.byteLength(JSON.stringify(envelope, null, 2)),
    llm_toon: Buffer.byteLength(stages.toon.out),
    // Where the plaintext actually goes. Anything under `(dispatcher x worker)`
    // below is a PRODUCT of both fleet counts; everything else is a sum of one
    // of them, and only the products can bend the curve.
    k_workers: bytesOf(snapshot.workers),
    k_dispatchers: bytesOf(snapshot.dispatchers),
    k_strings: bytesOf(snapshot.strings),
    k_history: bytesOf(snapshot.history),
    k_pool_slots: snapshot.dispatchers.reduce((b, d) => b + bytesOf(d.pool_slots), 0),
    k_slots_by_dispatcher: snapshot.workers.reduce((b, w) => b + (w.slots_by_dispatcher ? bytesOf(w.slots_by_dispatcher) : 0), 0),
    k_seen_by: snapshot.workers.reduce((b, w) => b + (w.seen_by ? bytesOf(w.seen_by) : 0), 0),
    k_worker_slots: snapshot.dispatchers.reduce((b, d) => b + (d.worker_slots ? bytesOf(d.worker_slots) : 0), 0),
    k_builds: snapshot.dispatchers.reduce((b, d) => b + bytesOf(d.builds), 0),
    k_hints: snapshot.dispatchers.reduce((b, d) => b + bytesOf(d.hints), 0),
  };

  return {
    n, pool, observations,
    workers: workers.length,
    strings: strings.length,
    payload,
    stages: Object.fromEntries(Object.entries(stages).map(([k, v]) => [k, {
      cpuMs: v.cpuMs, cpuMad: v.cpuMad, wallMs: v.wallMs, wallMad: v.wallMad,
    }])),
  };
}

// ---------------------------------------------------------------- curve fitting

/**
 * Least-squares slope of log(y) against log(n) — the exponent k in y ~ n^k.
 *
 * Fitted over the ladder ABOVE the smallest point. n=1 is dominated by
 * one-off costs (a Map allocation, a first JIT tier-up) that have nothing to do
 * with growth, and including it drags every exponent toward zero.
 */
function fitExponent(points) {
  const usable = points.filter((p) => p.n > 1 && p.y > 0.005);
  if (usable.length < 3) return null;
  const xs = usable.map((p) => Math.log(p.n));
  const ys = usable.map((p) => Math.log(p.y));
  const mx = xs.reduce((a, b) => a + b, 0) / xs.length;
  const my = ys.reduce((a, b) => a + b, 0) / ys.length;
  let num = 0, den = 0;
  for (let i = 0; i < xs.length; i++) { num += (xs[i] - mx) * (ys[i] - my); den += (xs[i] - mx) ** 2; }
  if (den === 0) return null;
  const k = num / den;
  // R^2, so a nonsense fit over noisy sub-millisecond stages announces itself.
  const ssTot = ys.reduce((a, y) => a + (y - my) ** 2, 0);
  const ssRes = ys.reduce((a, y, i) => a + (y - (my + k * (xs[i] - mx))) ** 2, 0);
  return { k, r2: ssTot === 0 ? 1 : 1 - ssRes / ssTot };
}

/**
 * Name the curve. The bands are deliberately generous on the low side (a stage
 * with a fixed cost fits BELOW 1.0) and tight at the top: the question this
 * harness exists to answer is "is anything above ~1.2", and a false negative
 * there is the expensive mistake.
 */
function nameCurve(fit) {
  if (!fit) return "flat/too-fast";
  const k = fit.k;
  if (k < 0.2) return "constant";
  if (k < 0.85) return "sub-linear";
  if (k < 1.18) return "linear";
  if (k < 1.45) return "n log n";
  if (k < 1.75) return "super-linear";
  if (k < 2.35) return "QUADRATIC";
  return "WORSE THAN QUADRATIC";
}

// ------------------------------------------------------------------- reporting

const pad = (s, w) => String(s).padStart(w);
const padr = (s, w) => String(s).padEnd(w);
const ms = (v) => (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(3));
const kb = (b) => (b >= 1048576 ? `${(b / 1048576).toFixed(1)}M` : b >= 1024 ? `${(b / 1024).toFixed(1)}K` : `${b}`);

/**
 * `[label, unit]`, where `unit` is the size of the stage's OWN INPUT.
 *
 * The distinction that matters. A stage can fit n^2 for two completely
 * different reasons: it contains a quadratic algorithm, or it is a perfectly
 * linear pass over an input that is itself quadratic. Only the first is a
 * defect, and the exponent alone cannot tell them apart. Dividing by the input
 * size does: a per-unit exponent near 0 means the stage is linear in what it
 * was handed, and any growth left belongs to whatever produced the input.
 *
 *   cell  one (dispatcher, worker) observation — grows as d x w
 *   byte  bytes of snapshot plaintext
 *   row   dispatchers + distinct workers — the sum, not the product
 */
const STAGE_LABELS = {
  merge: ["mergeWorkers", "cell"],
  totals: ["computeTotals", "row"],
  project: ["projectDispatchers", "cell"],
  intern: ["internSnapshotStrings", "row"],
  stringify: ["JSON.stringify", "byte"],
  gzip: ["gzip -9", "byte"],
  aes_gcm: ["AES-GCM encrypt", "byte"],
  gunzip: ["gunzip (browser inflate)", "byte"],
  rehydrate: ["rehydrateStrings (+parse/stringify)", "byte"],
  parse: ["JSON.parse (app)", "byte"],
  classifyAll: ["classifyAll", "cell"],
  classifyDispatchers: ["classifyDispatcher x d", "row"],
  llm_summary: ["buildLlmView summary", "row"],
  llm_full: ["buildLlmView full", "cell"],
  toon: ["encodeView toon", "row"],
};

const unitSize = (run, unit) =>
  unit === "cell" ? run.observations
  : unit === "byte" ? run.payload.plaintext
  : run.n + run.workers;

const PAYLOAD_LABELS = {
  plaintext: "plaintext JSON", gzip: "gzip'd", envelope: "envelope on disk",
  llm_toon: "llm view (toon)", k_workers: "  workers[]", k_dispatchers: "  dispatchers[]",
  k_strings: "  strings[]", k_history: "  history[]",
  k_pool_slots: "  (dxw) .pool_slots",
  k_slots_by_dispatcher: "  (dxw) .slots_by_dispatcher",
  k_seen_by: "  (dxw) .seen_by",
  k_worker_slots: "  (dxw) .worker_slots (legacy)",
  k_builds: "    .builds", k_hints: "    .hints",
};

function report(runs) {
  const ns = runs.map((r) => r.n);
  const w0 = 36;
  const cw = 11;

  console.log(`\nFLEET SHAPE (workers shared across dispatchers, ${VISIBILITY * 100}% visibility)`);
  console.log(padr("", w0) + ns.map((n) => pad(`n=${n}`, cw)).join(""));
  for (const [label, key] of [["dispatchers", "n"], ["distinct workers", "workers"],
    ["worker observations (dxw)", "observations"], ["string-table entries", "strings"]]) {
    console.log(padr(label, w0) + runs.map((r) => pad(r[key], cw)).join(""));
  }

  console.log(`\nCPU TIME PER STAGE (ms, median of reps, process user+system)`);
  console.log(padr("stage", w0) + ns.map((n) => pad(`n=${n}`, cw)).join("") + "   exponent  curve");
  const fits = {};
  for (const key of Object.keys(STAGE_LABELS)) {
    const pts = runs.map((r) => ({ n: r.n, y: r.stages[key].cpuMs }));
    const fit = fitExponent(pts);
    fits[key] = fit;
    console.log(
      padr(STAGE_LABELS[key][0], w0) +
      pts.map((p) => pad(ms(p.y), cw)).join("") +
      pad(fit ? fit.k.toFixed(2) : "—", 11) + "  " + nameCurve(fit) +
      (fit && fit.r2 < 0.9 ? `  (R²=${fit.r2.toFixed(2)} — noisy)` : ""),
    );
  }

  console.log(`\nCOST PER UNIT OF INPUT (ns per cell / per byte / per row)`);
  console.log(`  exponent ~0 = the stage is LINEAR in what it was handed; any growth is its INPUT's`);
  console.log(padr("stage", w0) + ns.map((n) => pad(`n=${n}`, cw)).join("") + "   exponent  verdict");
  for (const key of Object.keys(STAGE_LABELS)) {
    const [label, unit] = STAGE_LABELS[key];
    const pts = runs.map((r) => ({ n: r.n, y: (r.stages[key].cpuMs * 1e6) / Math.max(1, unitSize(r, unit)) }));
    const fit = fitExponent(pts.map((p) => ({ n: p.n, y: p.y / 1000 })));
    const k = fit?.k ?? 0;
    console.log(
      padr(`${label} [/${unit}]`, w0) +
      pts.map((p) => pad(p.y >= 100 ? p.y.toFixed(0) : p.y.toFixed(1), cw)).join("") +
      pad(fit ? k.toFixed(2) : "—", 11) + "  " +
      (!fit || Math.abs(k) < 0.25 ? "linear in its input"
        : k >= 0.25 ? "SUPER-LINEAR IN ITS OWN INPUT" : "amortises (fixed cost fading)"),
    );
  }

  console.log(`\nVALIDITY  wall/cpu ratio (1.0 = quiet box)  ·  MAD/median (0.0 = repeatable)`);
  console.log(padr("stage", w0) + ns.map((n) => pad(`n=${n}`, cw)).join(""));
  for (const key of Object.keys(STAGE_LABELS)) {
    console.log(padr(STAGE_LABELS[key][0], w0) + runs.map((r) => {
      const s = r.stages[key];
      const ratio = s.cpuMs > 0 ? s.wallMs / s.cpuMs : 0;
      const rel = s.cpuMs > 0 ? s.cpuMad / s.cpuMs : 0;
      return pad(`${ratio.toFixed(1)}/${rel.toFixed(2)}`, cw);
    }).join(""));
  }

  console.log(`\nPAYLOAD BYTES`);
  console.log(padr("component", w0) + ns.map((n) => pad(`n=${n}`, cw)).join("") + "   exponent  curve");
  for (const key of Object.keys(PAYLOAD_LABELS)) {
    const pts = runs.map((r) => ({ n: r.n, y: r.payload[key] }));
    const fit = fitExponent(pts);
    console.log(
      padr(PAYLOAD_LABELS[key], w0) +
      pts.map((p) => pad(kb(p.y), cw)).join("") +
      pad(fit ? fit.k.toFixed(2) : "—", 11) + "  " + nameCurve(fit),
    );
  }

  const worst = Object.entries(fits)
    .filter(([, f]) => f && f.k >= 1.18 && f.r2 >= 0.85)
    .sort((a, b) => b[1].k - a[1].k);
  console.log(`\nSUPER-LINEAR STAGES (exponent >= 1.18, R² >= 0.85)`);
  if (!worst.length) console.log("  none — every stage fits at or below linear");
  for (const [key, f] of worst) {
    console.log(`  ${padr(STAGE_LABELS[key][0], w0)} n^${f.k.toFixed(2)}  (R²=${f.r2.toFixed(3)})`);
  }
  console.log();
}

// ------------------------------------------------------------------------ main

function parseArgs(argv) {
  const out = { ns: [1, 10, 50, 100, 500], reps: 7, json: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--n") out.ns = argv[++i].split(",").map((s) => Number(s.trim())).filter((x) => x > 0);
    else if (a === "--reps") out.reps = Math.max(3, Number(argv[++i]) || 7);
    else if (a === "--json") out.json = argv[++i];
    else if (a === "--help" || a === "-h") { console.log("node tools/scaling.mjs [--n 1,10,50,100,500] [--reps 7] [--json out.json]"); process.exit(0); }
  }
  return out;
}

/**
 * The browser stages live in TypeScript (`src/derive.ts`), which Node cannot
 * import directly. Bundle it to a temp module with the esbuild that already
 * ships in this project's devDependencies — the SAME source the browser bundle
 * is built from, so what is measured here is what actually runs in the tab.
 */
async function loadBrowserModule() {
  const { mkdtemp } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join, resolve } = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const dir = await mkdtemp(join(tmpdir(), "rch-scaling-"));
  const outfile = join(dir, "derive.mjs");
  const entry = resolve(import.meta.dirname, "../src/derive.ts");
  execFileSync(
    resolve(import.meta.dirname, "../node_modules/.bin/esbuild"),
    [entry, "--bundle", "--platform=node", "--format=esm", `--outfile=${outfile}`],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  return import(outfile);
}

// Guarded so `synthFleet()` can be imported — by tests, or by a one-off
// verification script — without launching a ten-minute measurement run.
//
// `import.meta.main` only exists from Node 24.2; on anything older it is
// `undefined`, and a bare check would make this file silently do NOTHING when
// run directly. The argv comparison is the fallback that keeps it honest.
const RUN_DIRECTLY =
  import.meta.main ??
  (process.argv[1] ? import.meta.url === pathToFileURL(process.argv[1]).href : false);

if (RUN_DIRECTLY) {
  const args = parseArgs(process.argv);
  const browser = await loadBrowserModule();
  const runs = [];
  for (const n of args.ns) {
    process.stderr.write(`  measuring n=${n} ...`);
    const t0 = performance.now();
    runs.push(await runOne(n, args.reps, browser));
    process.stderr.write(` ${((performance.now() - t0) / 1000).toFixed(1)}s\n`);
  }
  report(runs);
  if (args.json) {
    await writeFile(args.json, JSON.stringify({ generated_at: new Date().toISOString(), runs }, null, 2));
    console.log(`wrote ${args.json}`);
  }
}
