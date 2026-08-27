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
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { hostname } from "node:os";

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
    const next = () => argv[++i];
    if (a === "--dispatchers") args.dispatchers = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--out") args.out = next();
    else if (a === "--label") args.label = next();
    else if (a === "--history-file") args.historyFile = next();
    else if (a === "--history-max") args.historyMax = Number(next());
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

const LOCAL_ALIASES = new Set(["local", "localhost", hostname(), hostname().split(".")[0]]);

/**
 * Run a command on a dispatcher. `local` (or this machine's own hostname) runs
 * without ssh, so the machine you collect FROM can also be monitored — the macs
 * are dispatchers too. Never throws; returns {ok, stdout}.
 */
async function run(host, command) {
  const isLocal = LOCAL_ALIASES.has(host);
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

/** Run an rch subcommand that emits the standard `{data: ...}` JSON envelope. */
async function rchJson(host, subcommand, timeoutSec = 60) {
  const cmd = `export PATH="$HOME/.local/bin:$PATH"; timeout ${timeoutSec} rch ${subcommand} --json 2>/dev/null`;
  const res = await run(host, cmd);
  if (!res.stdout.trim()) return null;
  try {
    // Tolerate leading log noise: take from the first '{' to the last '}'.
    const s = res.stdout;
    const start = s.indexOf("{");
    const end = s.lastIndexOf("}");
    if (start === -1 || end <= start) return null;
    const parsed = JSON.parse(s.slice(start, end + 1));
    return parsed?.data ?? parsed;
  } catch {
    return null;
  }
}

/** Scrape the daemon's Prometheus endpoint for probe latency. */
async function fetchMetrics(host) {
  const res = await run(host, "curl -s --max-time 10 http://127.0.0.1:9100/metrics 2>/dev/null");
  const out = { latency: {}, lastSeen: {} };
  if (!res.stdout) return out;
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
function statusRank(s) {
  switch ((s ?? "").toLowerCase()) {
    case "healthy": return 0;
    case "busy": return 1;
    case "draining": return 2;
    case "degraded": return 3;
    case "disabled": return 4;
    case "unreachable":
    case "down": return 5;
    default: return s ? 1 : -1; // unknown label beats "no reading at all"
  }
}

function circuitRank(c) {
  switch ((c ?? "").toLowerCase()) {
    case "closed": return 0;
    case "half_open": return 1;
    case "open": return 2;
    default: return -1;
  }
}

const PRESSURE_RANK = { healthy: 0, warning: 1, critical: 2 };

/**
 * Prefer the pressure reading that is (a) more alarming, or (b) equally
 * alarming but fresher. A stale "healthy" must never override a live "critical".
 */
function pressureIsBetter(next, cur) {
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
  const [status, caps, list, metrics] = await Promise.all([
    rchJson(host, "status", 70),
    rchJson(host, "workers capabilities", 70),
    rchJson(host, "workers list", 45),
    fetchMetrics(host),
  ]);

  const reachable = Boolean(status);
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
      enabled: cfg.enabled !== false,
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
    id: host === "local" ? hostname().split(".")[0] : host,
    reachable,
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

async function encrypt(plaintext, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
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

  console.error(`collecting from ${args.dispatchers.length} dev machine(s): ${args.dispatchers.join(", ")}`);
  const settled = await Promise.all(
    args.dispatchers.map(async (host) => {
      const d = await collectDispatcher(host);
      console.error(
        `  ${host.padEnd(14)} ${d.reachable ? `ok  posture=${d.posture ?? "?"}  workers=${d.workers.length}` : "UNREACHABLE"}`,
      );
      return d;
    }),
  );
  const dispatchers = settled;

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
        merged.set(w.id, { ...w, seen_by: [d.id], slots_by_dispatcher: { [d.id]: { used: w.used_slots, total: w.total_slots } } });
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
      if ((prev.tags?.length ?? 0) === 0 && w.tags?.length) prev.tags = w.tags;
      // A worker disabled anywhere is worth surfacing, so disabled wins.
      if (w.enabled === false) prev.enabled = false;
      for (const k of Object.keys(w.caps)) if (prev.caps[k] == null && w.caps[k] != null) prev.caps[k] = w.caps[k];

      // Take the pressure block WHOLE from the freshest observer. Merging it
      // field by field could pair disk_free_gb from one dispatcher with
      // disk_total_gb from another and compute a nonsense percentage.
      if (pressureIsBetter(w.pressure, prev.pressure)) prev.pressure = w.pressure;

      if (!prev.failure_history.length && w.failure_history.length) prev.failure_history = w.failure_history;
    }
  }
  const workers = [...merged.values()].sort((a, b) => a.id.localeCompare(b.id));

  const reachable = dispatchers.filter((d) => d.reachable);
  const totals = {
    workers: workers.length,
    slots: workers.reduce((n, w) => n + (w.total_slots ?? 0), 0),
    slots_used: workers.reduce((n, w) => n + (w.used_slots ?? 0), 0),
    cores: workers.reduce((n, w) => n + (w.caps.num_cpus ?? 0), 0),
    disk_free_gb: workers.reduce((n, w) => n + (w.pressure.disk_free_gb ?? 0), 0),
    disk_total_gb: workers.reduce((n, w) => n + (w.pressure.disk_total_gb ?? 0), 0),
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
  const envelope = await encrypt(plain, passphrase);
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(envelope, null, 2));
  await mkdir(dirname(args.historyFile), { recursive: true });
  await writeFile(args.historyFile, JSON.stringify(history));

  console.error(
    `\nwrote ${args.out}\n` +
      `  ${workers.length} workers · ${totals.slots} slots (${totals.slots_used} used) · ${totals.cores} cores\n` +
      `  ${totals.dispatchers_remote_ready}/${totals.dispatchers_reachable} dev machines remote-ready · ` +
      `builds remote ${totals.builds_remote} / local ${totals.builds_local}\n` +
      `  ${(plain.length / 1024).toFixed(1)}KB plaintext -> ${(JSON.stringify(envelope).length / 1024).toFixed(1)}KB ciphertext`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
