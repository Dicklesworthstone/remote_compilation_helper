#!/usr/bin/env node
/**
 * rch fleet dashboard — snapshot collector.
 *
 * Collects live state from every rch DEV MACHINE (dispatcher) over SSH, folds in
 * the worker pool each one can see, encrypts the result with AES-256-GCM (key
 * derived from a passphrase via PBKDF2-HMAC-SHA256), and writes an encrypted
 * envelope.
 *
 * The encryption is NOT decoration. `remote_compilation_helper` is a PUBLIC
 * repository and this payload contains fleet hostnames, IP addresses and
 * hardware inventory. Everything that reaches disk here is ciphertext; the
 * passphrase never leaves the operator's machine or browser.
 *
 * Primary data source is `rch status --json`, which is far richer than the
 * individual `workers`/`queue` commands:
 *   - `posture`                     -> is this dev machine actually able to offload
 *   - `stats.remote_count/local_count` -> is it in fact offloading, or silently local
 *   - `recent_builds[].location`    -> per-build local-vs-remote with worker id
 *   - `workers[].used_slots/total_slots` -> the REAL derated slot counts
 *                                      (`rch workers list` shows only the
 *                                       CONFIGURED ceiling and hides derating,
 *                                       which is what hid the 2026-08-26
 *                                       admission outage)
 *   - `workers[].pressure_*`        -> disk/mem/io pressure with reason codes
 *   - `remediation_hints`           -> actionable per-worker advice
 *
 * Usage:
 *   RCH_DASH_PASSPHRASE='<long passphrase>' node tools/snapshot.mjs \
 *       --dispatchers builder-a,builder-b,local \
 *       --out public/data/fleet.enc.json
 *
 * `--dispatchers` takes ssh targets that RUN rch. Use `local` for the machine
 * you collect from, so it monitors itself too. Keep your real host list in a
 * gitignored .env rather than in source.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { webcrypto as crypto } from "node:crypto";
import { writeFile, mkdir, readFile, rename } from "node:fs/promises";
import { dirname } from "node:path";
import { hostname } from "node:os";
import { pathToFileURL } from "node:url";

const execFileAsync = promisify(execFile);

const PBKDF2_ITERATIONS = 600_000;
const SCHEMA = "rch.dashboard.snapshot.v2";
const SSH_TIMEOUT_MS = 90_000;
const MAX_BUFFER = 64 * 1024 * 1024;

// ---------------------------------------------------------------- arg parsing

function parseArgs(argv) {
  const args = {
    dispatchers: ["local"],
    out: "public/data/fleet.enc.json",
    historyFile: ".snapshot-history.json",
    historyMax: 96,
    label: "rch fleet",
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    // A trailing flag used to hand `undefined` to .split() and die with a stack
    // trace instead of saying which option was missing its value.
    const next = () => {
      const v = argv[++i];
      if (v === undefined) {
        console.error(`${a} requires a value`);
        process.exit(2);
      }
      return v;
    };
    if (a === "--dispatchers") args.dispatchers = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--out") args.out = next();
    else if (a === "--label") args.label = next();
    else if (a === "--history-file") args.historyFile = next();
    else if (a === "--history-max") {
      const n = Number(next());
      // slice(-0) and slice(-NaN) both return the WHOLE array, so a bad value
      // here silently made history grow without bound.
      if (!Number.isInteger(n) || n < 1) {
        console.error("--history-max must be a positive integer");
        process.exit(2);
      }
      args.historyMax = n;
    }
    else if (a === "--help" || a === "-h") {
      console.log(
        "usage: RCH_DASH_PASSPHRASE=... node tools/snapshot.mjs\n" +
          "  [--dispatchers a,b,c]  ssh targets; use `local` for this machine\n" +
          "  [--out path] [--label name] [--history-file path] [--history-max N]",
      );
      process.exit(0);
    } else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return args;
}

// ------------------------------------------------------------------ ssh layer

const LOCAL_ALIASES = new Set(
  ["local", "localhost", hostname(), hostname().split(".")[0]].map((s) => s.toLowerCase()),
);

/**
 * Is this dispatcher THIS machine? Compared case-insensitively and with any
 * `user@` prefix stripped: `os.hostname()` returns the mixed-case name
 * (`Mac-mini-max`) while the ssh alias people actually write is lowercase, so a
 * case-sensitive match silently made the local box ssh to itself.
 */
export function isLocalDispatcher(host) {
  const h = String(host).trim().toLowerCase();
  const at = h.lastIndexOf("@");
  return LOCAL_ALIASES.has(at === -1 ? h : h.slice(at + 1));
}

/** Canonical dispatcher id, so `local`, `localhost` and `user@host` don't produce duplicate entries for one machine. */
export function dispatcherId(host) {
  return isLocalDispatcher(host) ? hostname().split(".")[0] : String(host).trim();
}

/**
 * Run a command on a dispatcher. `local` (or this machine's own hostname) runs
 * without ssh, so the machine you collect FROM can also be monitored — the macs
 * are dispatchers too. Never throws; returns {ok, stdout, error}.
 */
async function run(host, command) {
  const isLocal = isLocalDispatcher(host);
  try {
    const { stdout } = isLocal
      ? await execFileAsync("bash", ["-lc", command], { timeout: SSH_TIMEOUT_MS, maxBuffer: MAX_BUFFER })
      : await execFileAsync(
          "ssh",
          ["-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
           "-o", "StrictHostKeyChecking=accept-new", host, command],
          { timeout: SSH_TIMEOUT_MS, maxBuffer: MAX_BUFFER },
        );
    return { ok: true, stdout };
  } catch (err) {
    // A non-zero exit still yields useful stdout for some rch subcommands.
    const stdout = err?.stdout ?? "";
    return { ok: stdout.trim().length > 0, stdout, error: String(err?.shortMessage || err?.message || err) };
  }
}

/**
 * Run an rch subcommand that emits the standard `{data: ...}` JSON envelope.
 * Returns `{data, error}` — `data` is null on every failure and `error` says
 * why, so a dead daemon can be told apart from an unreachable host.
 */
async function rchJson(host, subcommand, timeoutSec = 60) {
  const cmd = `export PATH="$HOME/.local/bin:$PATH"; timeout ${timeoutSec} rch ${subcommand} --json 2>/dev/null`;
  const res = await run(host, cmd);
  if (!res.stdout.trim()) {
    return { data: null, error: res.error ? `${subcommand}: ${res.error}` : `${subcommand}: no output` };
  }
  let parsed;
  try {
    // Tolerate leading log noise: take from the first '{' to the last '}'.
    const s = res.stdout;
    const start = s.indexOf("{");
    const end = s.lastIndexOf("}");
    if (start === -1 || end <= start) return { data: null, error: `${subcommand}: no JSON object in output` };
    parsed = JSON.parse(s.slice(start, end + 1));
  } catch (err) {
    return { data: null, error: `${subcommand}: unparseable JSON (${String(err?.message || err).slice(0, 120)})` };
  }

  // The API envelope reports failure in `success`, and omits `data` entirely
  // when it fails. Returning `parsed?.data ?? parsed` handed back the ERROR
  // envelope, which is truthy — so an erroring or dead rchd was recorded as a
  // reachable dispatcher with no posture, and rendered as a benign "idle" box.
  if (parsed && parsed.success === false) {
    const e = parsed.error ?? {};
    const detail = [e.code, e.message].filter(Boolean).join(" ").trim();
    return { data: null, error: `${subcommand}: ${detail || "rch reported failure"}` };
  }
  if (parsed && typeof parsed === "object" && "data" in parsed) {
    return parsed.data == null
      ? { data: null, error: `${subcommand}: envelope carried no data` }
      : { data: parsed.data, error: null };
  }
  return { data: parsed ?? null, error: parsed == null ? `${subcommand}: empty payload` : null };
}

/** Scrape the daemon's Prometheus endpoint for probe latency. */
async function fetchMetrics(host) {
  const res = await run(host, "curl -s --max-time 10 http://127.0.0.1:9100/metrics 2>/dev/null");
  const out = { latency: {}, lastSeen: {}, error: null };
  if (!res.stdout) {
    // Worth surfacing: `last_seen_unix` comes only from here, so losing this
    // endpoint silently disables the "worker has gone dark" rule fleet-wide
    // and everything keeps rendering green.
    out.error = `metrics: ${res.error || "no response from 127.0.0.1:9100"}`;
    return out;
  }
  const sum = {}, count = {};
  for (const line of res.stdout.split("\n")) {
    if (!line || line[0] === "#") continue;
    let m;
    if ((m = line.match(/^rch_worker_latency_ms_sum\{worker="([^"]+)"\}\s+(\S+)/))) sum[m[1]] = Number(m[2]);
    else if ((m = line.match(/^rch_worker_latency_ms_count\{worker="([^"]+)"\}\s+(\S+)/))) count[m[1]] = Number(m[2]);
    else if ((m = line.match(/^rch_worker_last_seen_timestamp\{worker="([^"]+)"\}\s+(\S+)/))) out.lastSeen[m[1]] = Number(m[2]);
  }
  for (const id of Object.keys(sum)) if (count[id] > 0) out.latency[id] = sum[id] / count[id];
  return out;
}

// ------------------------------------------------------------------ collection

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Higher = more alarming, so a max() merge keeps the worst observation. */
// The real vocabulary is WorkerStatus in rch-common/src/types.rs:
// healthy | degraded | unreachable | draining | drained | disabled.
// `drained` was missing entirely and fell into the default bucket, so a worker
// that had finished draining and was accepting nothing ranked as merely "busy"
// and lost every merge against a healthy observation.
export function statusRank(s) {
  switch ((s ?? "").toLowerCase()) {
    case "healthy": return 0;
    case "busy": return 1;          // not emitted by rch, kept for tolerance
    case "degraded": return 2;      // responding slowly, but still serving
    case "draining": return 3;      // finishing current jobs
    case "drained": return 4;       // idle and accepting nothing
    case "disabled": return 5;
    case "unreachable":
    case "down": return 6;
    default: return s ? 1 : -1; // unknown label beats "no reading at all"
  }
}

export function circuitRank(c) {
  switch ((c ?? "").toLowerCase()) {
    case "closed": return 0;
    case "half_open": return 1;
    case "open": return 2;
    default: return -1;
  }
}

// rch emits a fourth state, `telemetry_gap` (rch/src/status_types.rs), which it
// renders as a warning. Omitting it here ranked it -1 — below healthy — so a
// dispatcher explicitly reporting "I have no telemetry for this worker" lost
// the merge to any other dispatcher's stale healthy reading.
const PRESSURE_RANK = { healthy: 0, telemetry_gap: 1, warning: 2, critical: 3 };

/**
 * Prefer the pressure reading that is (a) more alarming, or (b) equally
 * alarming but fresher. A stale "healthy" must never override a live "critical".
 */
export function pressureIsBetter(next, cur) {
  if (!next) return false;
  if (!cur) return true;
  const rn = PRESSURE_RANK[(next.state ?? "").toLowerCase()] ?? -1;
  const rc = PRESSURE_RANK[(cur.state ?? "").toLowerCase()] ?? -1;
  if (rn !== rc) return rn > rc;
  const an = next.telemetry_age_secs ?? Number.POSITIVE_INFINITY;
  const ac = cur.telemetry_age_secs ?? Number.POSITIVE_INFINITY;
  return an < ac;
}

async function collectDispatcher(host) {
  // `rch status` carries runtime state but NOT the static config fields
  // (tags, priority, enabled) — those only exist in `workers list`.
  const [statusRes, capsRes, listRes, metrics] = await Promise.all([
    rchJson(host, "status", 70),
    rchJson(host, "workers capabilities", 70),
    rchJson(host, "workers list", 45),
    fetchMetrics(host),
  ]);

  const status = statusRes.data;
  const caps = capsRes.data;
  const list = listRes.data;

  // Every failure reason, kept rather than collapsed into a bare `false`. SSH
  // auth failure, a missing `rch` binary and a dead daemon used to be
  // indistinguishable on screen.
  const collectionErrors = [statusRes.error, capsRes.error, listRes.error, metrics.error].filter(Boolean);
  const reachable = Boolean(status);
  // `workers list` failing silently blanks every tag and priority; say so
  // instead of rendering an untagged fleet as though that were the config.
  const configDegraded = Boolean(listRes.error);
  const d = status?.daemon?.daemon ?? null;
  const statusWorkers = status?.daemon?.workers ?? [];
  const capsById = new Map((caps?.workers ?? []).map((w) => [w.id, w.capabilities ?? {}]));
  const cfgById = new Map((list?.workers ?? []).map((w) => [w.id, w]));

  const workers = statusWorkers.map((w) => {
    const c = capsById.get(w.id) ?? {};
    const cfg = cfgById.get(w.id) ?? {};
    return {
      id: w.id,
      host: w.host ?? null,
      user: w.user ?? null,
      status: w.status ?? null,
      circuit_state: w.circuit_state ?? null,
      used_slots: num(w.used_slots),
      total_slots: num(w.total_slots),
      speed: num(w.speed_score),
      last_error: w.last_error ?? null,
      consecutive_failures: num(w.consecutive_failures) ?? 0,
      // failure_history is oldest-first booleans; keep it for the sparkline.
      failure_history: Array.isArray(w.failure_history) ? w.failure_history.slice(-20) : [],
      pressure: {
        state: w.pressure_state ?? null,
        reason: w.pressure_reason_code ?? null,
        disk_free_gb: num(w.pressure_disk_free_gb),
        disk_total_gb: num(w.pressure_disk_total_gb),
        disk_io_util_pct: num(w.pressure_disk_io_util_pct),
        memory_pressure: num(w.pressure_memory_pressure),
        telemetry_age_secs: num(w.pressure_telemetry_age_secs),
        telemetry_fresh: w.pressure_telemetry_fresh ?? null,
      },
      latency_ms: num(metrics.latency?.[w.id]),
      last_seen_unix: num(metrics.lastSeen?.[w.id]),
      caps: {
        num_cpus: num(c.num_cpus),
        load_avg_1: num(c.load_avg_1),
        load_avg_5: num(c.load_avg_5),
        load_avg_15: num(c.load_avg_15),
        cpu_microarch_level: num(c.cpu_microarch_level),
        rustc_version: c.rustc_version ?? null,
        bun_version: c.bun_version ?? null,
        node_version: c.node_version ?? null,
        go_version: c.go_version ?? null,
        zig_version: c.zig_version ?? null,
        projects_root_ok: c.projects_root_ok ?? null,
      },
      tags: Array.isArray(cfg.tags) ? cfg.tags : [],
      priority: num(cfg.priority),
    };
  });

  const stats = status?.daemon?.stats ?? null;
  const recent = (status?.daemon?.recent_builds ?? []).slice(-25).map((b) => ({
    project: b.project_id ?? null,
    command: typeof b.command === "string" ? b.command.slice(0, 120) : null,
    location: b.location ?? null,          // "Remote" | "Local"
    worker_id: b.worker_id ?? null,
    duration_ms: num(b.duration_ms),
    exit_code: num(b.exit_code),
    completed_at: b.completed_at ?? null,
  }));

  return {
    id: dispatcherId(host),
    reachable,
    /** Why collection failed, when it did. Empty on a clean run. */
    collection_errors: collectionErrors,
    /** True when `workers list` failed, so tags/priority are missing rather than genuinely unset. */
    config_degraded: configDegraded,
    // The headline dev-machine question: can this box offload at all?
    posture: status?.posture ?? null,
    posture_description: status?.posture_description ?? null,
    daemon: d
      ? {
          version: d.version ?? null,
          uptime_secs: num(d.uptime_secs),
          pid: num(d.pid),
          workers_total: num(d.workers_total),
          workers_healthy: num(d.workers_healthy),
          slots_total: num(d.slots_total),
          slots_available: num(d.slots_available),
        }
      : null,
    // Is it ACTUALLY offloading, or silently building local?
    build_stats: stats
      ? {
          total: num(stats.total_builds) ?? 0,
          remote: num(stats.remote_count) ?? 0,
          local: num(stats.local_count) ?? 0,
          success: num(stats.success_count) ?? 0,
          failure: num(stats.failure_count) ?? 0,
          avg_duration_ms: num(stats.avg_duration_ms),
        }
      : null,
    saved_time_ms: num(status?.daemon?.saved_time?.time_saved_ms),
    active_builds: (status?.daemon?.active_builds ?? []).length,
    queued_builds: (status?.daemon?.queued_builds ?? []).length,
    recent_builds: recent,
    issues: (status?.daemon?.issues ?? []).slice(0, 10),
    alerts: (status?.daemon?.alerts ?? []).slice(0, 10),
    remediation_hints: (status?.remediation_hints ?? []).slice(0, 12).map((h) => ({
      worker_id: h.worker_id ?? null,
      severity: h.severity ?? null,
      message: typeof h.message === "string" ? h.message.slice(0, 240) : null,
      suggested_action: typeof h.suggested_action === "string" ? h.suggested_action.slice(0, 240) : null,
      reason_code: h.reason_code ?? null,
    })),
    workers,
  };
}

// ----------------------------------------------------------------- encryption

/**
 * Read the salt out of an existing envelope so it can be reused.
 *
 * The browser's "stay unlocked for 60 days" stores the DERIVED KEY, not the
 * passphrase (the passphrase is never persisted anywhere). A key derived under
 * salt A cannot decrypt a payload encrypted under salt B, so minting a fresh
 * salt on every collection invalidated the saved session on every run — a
 * wall-mounted tab logged itself out on each cron tick, which is precisely the
 * case the feature exists for.
 *
 * Reusing the salt across snapshots of the SAME deployment is sound: a salt
 * defeats precomputation across *different* secrets, and this passphrase is a
 * single high-entropy random string. The IV is still fresh per encryption,
 * which is the part AES-GCM actually requires to be unique.
 */
export async function existingSalt(outPath) {
  try {
    const prev = JSON.parse(await readFile(outPath, "utf8"));
    const b64 = prev?.kdf?.salt;
    if (typeof b64 !== "string") return null;
    const salt = new Uint8Array(Buffer.from(b64, "base64"));
    // Only reuse a salt that matches the KDF we are about to use, so changing
    // iterations or hash still rotates cleanly.
    if (salt.length !== 16) return null;
    if (prev?.kdf?.iterations !== PBKDF2_ITERATIONS) return null;
    if (prev?.kdf?.hash !== "SHA-256") return null;
    return salt;
  } catch {
    return null;
  }
}

export async function encrypt(plaintext, passphrase, reusableSalt = null) {
  const enc = new TextEncoder();
  const salt = reusableSalt ?? crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  return {
    format: "rch.dashboard.enc.v1",
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS, salt: b64(salt) },
    cipher: { name: "AES-GCM", iv: b64(iv) },
    ciphertext: b64(new Uint8Array(ct)),
  };
}

/**
 * Decrypt what we just encrypted and confirm it round-trips to the same size.
 * Cheap insurance against publishing a payload the passphrase cannot open.
 */
async function verifyRoundTrip(envelope, passphrase, expectedLength) {
  const enc = new TextEncoder();
  const b = (s) => new Uint8Array(Buffer.from(s, "base64"));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b(envelope.kdf.salt), iterations: envelope.kdf.iterations, hash: envelope.kdf.hash },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const out = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b(envelope.cipher.iv) },
    key,
    b(envelope.ciphertext),
  );
  const text = new TextDecoder().decode(out);
  if (text.length !== expectedLength) {
    throw new Error(`round-trip length mismatch: ${text.length} != ${expectedLength}`);
  }
  JSON.parse(text);
}

/** Write via a temp file in the same directory, then rename — readers never see a partial file. */
async function writeFileAtomic(path, contents) {
  const tmp = `${path}.tmp-${process.pid}`;
  await writeFile(tmp, contents);
  await rename(tmp, path);
}

// ----------------------------------------------------------------------- main

async function main() {
  const args = parseArgs(process.argv);
  const passphrase = process.env.RCH_DASH_PASSPHRASE;
  if (!passphrase) {
    console.error("RCH_DASH_PASSPHRASE is not set. Refusing to write an unencrypted snapshot.");
    console.error("This repository is PUBLIC — fleet hosts and IPs must never be committed in clear text.");
    process.exit(2);
  }
  if (passphrase.length < 16) {
    console.error(`RCH_DASH_PASSPHRASE is only ${passphrase.length} chars; use at least 16.`);
    process.exit(2);
  }

  // De-duplicate first: `local`, `localhost` and this box's own hostname all
  // name the same machine, and listing two of them used to double-count
  // dispatchers, builds and active jobs in the totals.
  const seenHosts = new Map();
  for (const host of args.dispatchers) {
    const id = dispatcherId(host);
    if (!seenHosts.has(id)) seenHosts.set(id, host);
    else console.error(`  note: "${host}" is the same machine as "${seenHosts.get(id)}" — collecting once`);
  }
  const targets = [...seenHosts.values()];

  console.error(`collecting from ${targets.length} dev machine(s): ${targets.join(", ")}`);
  // allSettled, not all: this fan-out is the whole snapshot. One dispatcher
  // returning a shape that throws inside the mapper must not abort collection
  // for every other machine — that is the opposite of the resilience the merge
  // below is written for.
  const settled = await Promise.allSettled(
    targets.map(async (host) => {
      const d = await collectDispatcher(host);
      console.error(
        `  ${String(host).padEnd(14)} ${d.reachable ? `ok  posture=${d.posture ?? "?"}  workers=${d.workers.length}` : `UNREACHABLE  ${d.collection_errors[0] ?? ""}`}`,
      );
      return d;
    }),
  );

  const dispatchers = settled.map((r, i) => {
    if (r.status === "fulfilled") return r.value;
    const host = targets[i];
    const reason = String(r.reason?.message || r.reason || "collector threw");
    console.error(`  ${String(host).padEnd(14)} FAILED  ${reason}`);
    // Represent the failure as a real, unreachable dispatcher rather than
    // dropping it, so a box that stops responding cannot quietly vanish from
    // the fleet count.
    return {
      id: dispatcherId(host), reachable: false, collection_errors: [reason], config_degraded: true,
      posture: null, posture_description: null, daemon: null, build_stats: null,
      saved_time_ms: null, active_builds: 0, queued_builds: 0, recent_builds: [],
      issues: [], alerts: [], remediation_hints: [], workers: [],
    };
  });

  if (!dispatchers.some((d) => d.reachable)) {
    console.error("no dispatcher responded — refusing to publish an all-zero snapshot over good data");
    process.exit(1);
  }

  // Union the worker view. A worker is "known" if any dev machine has it, and
  // runtime facts come from whichever machine actually reported them, so one
  // unreachable dispatcher cannot blank the fleet. Slot counts are per-observer
  // (rchd derates independently), so keep the MAX observed capacity plus the
  // per-dispatcher detail.
  const merged = new Map();
  for (const d of dispatchers) {
    for (const w of d.workers) {
      const prev = merged.get(w.id);
      if (!prev) {
        // Copy the nested objects. A shallow spread aliases `caps`, `pressure`,
        // `tags` and `failure_history` to the FIRST dispatcher's own records,
        // and the merge below then mutates them in place — silently rewriting
        // that dispatcher's private per-worker view with values observed
        // elsewhere.
        merged.set(w.id, {
          ...w,
          caps: { ...w.caps },
          pressure: { ...w.pressure },
          tags: [...(w.tags ?? [])],
          failure_history: [...(w.failure_history ?? [])],
          seen_by: [d.id],
          slots_by_dispatcher: { [d.id]: { used: w.used_slots, total: w.total_slots } },
        });
        continue;
      }
      prev.seen_by.push(d.id);
      prev.slots_by_dispatcher[d.id] = { used: w.used_slots, total: w.total_slots };
      if ((w.total_slots ?? 0) > (prev.total_slots ?? 0)) prev.total_slots = w.total_slots;
      if ((w.used_slots ?? 0) > (prev.used_slots ?? 0)) prev.used_slots = w.used_slots;

      // WORST-WINS for anything that signals trouble. Dev machines observe the
      // pool independently and can disagree; taking whichever answered first
      // would let a benign reading mask an alarming one and hide the exact
      // thing this dashboard exists to surface.
      if (statusRank(w.status) > statusRank(prev.status)) prev.status = w.status;
      if (circuitRank(w.circuit_state) > circuitRank(prev.circuit_state)) {
        prev.circuit_state = w.circuit_state;
      }
      if ((w.consecutive_failures ?? 0) > (prev.consecutive_failures ?? 0)) {
        prev.consecutive_failures = w.consecutive_failures;
      }
      // Seen by ANY dispatcher recently means it is not stale, so keep the most
      // recent sighting rather than the first one reported.
      if ((w.last_seen_unix ?? 0) > (prev.last_seen_unix ?? 0)) prev.last_seen_unix = w.last_seen_unix;

      for (const k of ["speed", "latency_ms", "last_error", "priority"]) {
        if (prev[k] == null && w[k] != null) prev[k] = w[k];
      }
      if ((prev.tags?.length ?? 0) === 0 && w.tags?.length) prev.tags = [...w.tags];
      for (const k of Object.keys(w.caps)) if (prev.caps[k] == null && w.caps[k] != null) prev.caps[k] = w.caps[k];

      // Take the pressure block WHOLE from the freshest observer. Merging it
      // field by field could pair disk_free_gb from one dispatcher with
      // disk_total_gb from another and compute a nonsense percentage.
      if (pressureIsBetter(w.pressure, prev.pressure)) prev.pressure = { ...w.pressure };

      if (!prev.failure_history.length && w.failure_history.length) prev.failure_history = [...w.failure_history];
    }
  }
  const workers = [...merged.values()].sort((a, b) => a.id.localeCompare(b.id));

  const reachable = dispatchers.filter((d) => d.reachable);

  // Only count a worker's disk when BOTH halves are present. Summing them
  // independently let a worker with a total but no free reading add to the
  // denominator and nothing to the numerator, inflating fleet "disk used %"
  // with a number no single worker ever reported.
  const diskWorkers = workers.filter(
    (w) => w.pressure.disk_free_gb != null && w.pressure.disk_total_gb != null && w.pressure.disk_total_gb > 0,
  );

  const totals = {
    workers: workers.length,
    slots: workers.reduce((n, w) => n + (w.total_slots ?? 0), 0),
    // Per-observer occupancy (each rchd derates and reserves independently), so
    // this is the worst single observation, never more than capacity.
    slots_used: workers.reduce((n, w) => n + Math.min(w.used_slots ?? 0, w.total_slots ?? Infinity), 0),
    cores: workers.reduce((n, w) => n + (w.caps.num_cpus ?? 0), 0),
    disk_free_gb: diskWorkers.reduce((n, w) => n + w.pressure.disk_free_gb, 0),
    disk_total_gb: diskWorkers.reduce((n, w) => n + w.pressure.disk_total_gb, 0),
    /** How many workers actually reported usable disk telemetry, so the UI can say "of N" honestly. */
    disk_reporting_workers: diskWorkers.length,
    dispatchers_total: dispatchers.length,
    dispatchers_reachable: reachable.length,
    dispatchers_remote_ready: reachable.filter((d) => d.posture === "remote_ready").length,
    builds_remote: reachable.reduce((n, d) => n + (d.build_stats?.remote ?? 0), 0),
    builds_local: reachable.reduce((n, d) => n + (d.build_stats?.local ?? 0), 0),
    active_builds: reachable.reduce((n, d) => n + d.active_builds, 0),
  };

  const generated_at = new Date().toISOString();

  // Rolling history. A PLAINTEXT sidecar is what lets successive runs append,
  // but it must live OUTSIDE `public/` — Vite copies `public/` verbatim into
  // `dist/`, so a history file kept there would be published unencrypted next
  // to the ciphertext. It holds only aggregate counters, no hosts or IPs, but
  // publishing fleet telemetry in the clear defeats the point of encrypting the
  // snapshot at all. It is embedded INTO the encrypted payload for the UI.
  let history = [];
  try {
    const prev = JSON.parse(await readFile(args.historyFile, "utf8"));
    if (Array.isArray(prev)) history = prev;
  } catch {
    history = [];
  }
  history.push({
    t: generated_at,
    slots_total: totals.slots,
    slots_used: totals.slots_used,
    workers: totals.workers,
    disk_free_gb: Math.round(totals.disk_free_gb),
    builds_remote: totals.builds_remote,
    builds_local: totals.builds_local,
    dispatchers_remote_ready: totals.dispatchers_remote_ready,
  });
  history = history.slice(-args.historyMax);

  const snapshot = { schema: SCHEMA, label: args.label, generated_at, totals, dispatchers, workers, history };

  const plain = JSON.stringify(snapshot);
  await mkdir(dirname(args.out), { recursive: true });

  // Reuse the previous salt so a browser session that saved its derived key
  // stays valid across snapshots. See existingSalt().
  const reusedSalt = await existingSalt(args.out);
  const envelope = await encrypt(plain, passphrase, reusedSalt);

  // Prove the payload decrypts under the passphrase we just used, BEFORE
  // replacing the live file. A typo'd passphrase otherwise publishes a snapshot
  // nobody can open, and it is only discovered in the browser as an
  // indistinguishable "wrong passphrase".
  await verifyRoundTrip(envelope, passphrase, plain.length);

  // Atomic publish: `public/data/fleet.enc.json` is served while it is being
  // rewritten, and a plain writeFile hands a browser mid-write truncation.
  await writeFileAtomic(args.out, JSON.stringify(envelope, null, 2));
  await mkdir(dirname(args.historyFile), { recursive: true });
  await writeFileAtomic(args.historyFile, JSON.stringify(history));

  console.error(
    `\nwrote ${args.out}${reusedSalt ? " (salt reused — saved browser sessions stay valid)" : " (new salt)"}\n` +
      `  ${workers.length} workers · ${totals.slots} slots (${totals.slots_used} used) · ${totals.cores} cores\n` +
      `  ${totals.dispatchers_remote_ready}/${totals.dispatchers_reachable} dev machines remote-ready · ` +
      `builds remote ${totals.builds_remote} / local ${totals.builds_local}\n` +
      `  ${(plain.length / 1024).toFixed(1)}KB plaintext -> ${(JSON.stringify(envelope).length / 1024).toFixed(1)}KB ciphertext`,
  );
}

// Only collect when run as a program. Without this guard, importing any helper
// for a test would ssh the whole fleet and overwrite the live snapshot.
const invokedDirectly =
  process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
