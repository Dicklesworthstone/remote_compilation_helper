#!/usr/bin/env node
/**
 * rch fleet dashboard — snapshot collector.
 *
 * Collects live fleet state from one or more rch dispatchers over SSH, folds it
 * into a single JSON document, encrypts it with AES-256-GCM (key derived from a
 * passphrase via PBKDF2-HMAC-SHA256), and writes `fleet.enc.json`.
 *
 * The encryption is NOT decoration. `remote_compilation_helper` is a PUBLIC
 * repository and this payload contains fleet hostnames, IP addresses and
 * hardware inventory. Committing it in clear text would publish the topology of
 * the whole build fleet. Everything that reaches disk here is ciphertext; the
 * passphrase never leaves the operator's machine or browser.
 *
 * Usage:
 *   RCH_DASH_PASSPHRASE='<long passphrase>' node tools/snapshot.mjs \
 *       --dispatchers trj,css,ts1,ts2,csd \
 *       --out public/data/fleet.enc.json
 *
 * Data sources (all documented `--json` CLI contracts, so this does not depend
 * on scraping human-readable output):
 *   rch workers list --json          -> configured id/host/user/slots/priority/tags
 *   rch workers capabilities --json  -> cpu count, load avg, disk, toolchain versions
 *   rch queue --json                 -> aggregate slots + active/queued builds
 *   rch daemon status --json         -> daemon liveness + uptime
 *   :9100/metrics                    -> per-worker circuit state, last-seen, latency
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { webcrypto as crypto } from "node:crypto";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";

const execFileAsync = promisify(execFile);

const PBKDF2_ITERATIONS = 600_000;
const SCHEMA = "rch.dashboard.snapshot.v1";
const SSH_TIMEOUT_MS = 60_000;

// ---------------------------------------------------------------- arg parsing

function parseArgs(argv) {
  const args = {
    dispatchers: ["trj"],
    out: "public/data/fleet.enc.json",
    historyFrom: null,
    historyMax: 48,
    label: "rch fleet",
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--dispatchers") args.dispatchers = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--out") args.out = next();
    else if (a === "--label") args.label = next();
    else if (a === "--history-from") args.historyFrom = next();
    else if (a === "--history-max") args.historyMax = Number(next());
    else if (a === "--help" || a === "-h") {
      console.log(
        "usage: RCH_DASH_PASSPHRASE=... node tools/snapshot.mjs " +
          "[--dispatchers a,b,c] [--out path] [--label name] [--history-from plain.json] [--history-max N]",
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

/** Run a command on a dispatcher over SSH. Never throws; returns {ok, stdout}. */
async function ssh(host, command) {
  try {
    const { stdout } = await execFileAsync(
      "ssh",
      [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=12",
        "-o", "StrictHostKeyChecking=accept-new",
        host,
        command,
      ],
      { timeout: SSH_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024 },
    );
    return { ok: true, stdout };
  } catch (err) {
    return { ok: false, stdout: "", error: String(err?.shortMessage || err?.message || err) };
  }
}

/** Run an rch subcommand that emits the standard `{data: ...}` JSON envelope. */
async function rchJson(host, subcommand) {
  const cmd =
    `export PATH="$HOME/.local/bin:$PATH"; timeout 45 rch ${subcommand} --json 2>/dev/null`;
  const res = await ssh(host, cmd);
  if (!res.ok || !res.stdout.trim()) return null;
  try {
    const parsed = JSON.parse(res.stdout);
    return parsed?.data ?? parsed;
  } catch {
    return null;
  }
}

/** Scrape the daemon's Prometheus endpoint for per-worker gauges. */
async function fetchMetrics(host) {
  const res = await ssh(host, "curl -s --max-time 10 http://127.0.0.1:9100/metrics 2>/dev/null");
  if (!res.ok || !res.stdout) return {};
  const out = { circuit: {}, lastSeen: {}, latency: {} };
  const latSum = {};
  const latCount = {};
  for (const line of res.stdout.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    let m;
    if ((m = line.match(/^rch_circuit_state\{worker="([^"]+)"\}\s+(\S+)/))) {
      out.circuit[m[1]] = Number(m[2]);
    } else if ((m = line.match(/^rch_worker_last_seen_timestamp\{worker="([^"]+)"\}\s+(\S+)/))) {
      out.lastSeen[m[1]] = Number(m[2]);
    } else if ((m = line.match(/^rch_worker_latency_ms_sum\{worker="([^"]+)"\}\s+(\S+)/))) {
      latSum[m[1]] = Number(m[2]);
    } else if ((m = line.match(/^rch_worker_latency_ms_count\{worker="([^"]+)"\}\s+(\S+)/))) {
      latCount[m[1]] = Number(m[2]);
    }
  }
  for (const id of Object.keys(latSum)) {
    if (latCount[id] > 0) out.latency[id] = latSum[id] / latCount[id];
  }
  return out;
}

// ------------------------------------------------------------------ collection

async function collectDispatcher(host) {
  const [status, queue, list, caps, metrics] = await Promise.all([
    rchJson(host, "daemon status"),
    rchJson(host, "queue"),
    rchJson(host, "workers list"),
    rchJson(host, "workers capabilities"),
    fetchMetrics(host),
  ]);

  const reachable = Boolean(status || queue || list);
  const configured = list?.workers ?? [];
  const capsById = new Map((caps?.workers ?? []).map((w) => [w.id, w.capabilities ?? {}]));

  // Speed scores need >= 2 ids and are comparatively expensive, so only ask once
  // we know which workers exist.
  let speeds = {};
  const ids = configured.map((w) => w.id).filter(Boolean);
  if (ids.length >= 2) {
    const cmp = await rchJson(host, `workers compare ${ids.join(" ")}`);
    for (const row of cmp?.workers ?? cmp?.comparison ?? []) {
      if (row?.id) speeds[row.id] = row;
    }
  }

  const activeByWorker = new Map();
  for (const b of queue?.active_builds ?? []) {
    const wid = b.worker || b.worker_id || b.id;
    if (!wid) continue;
    activeByWorker.set(wid, (activeByWorker.get(wid) ?? 0) + 1);
  }

  const workers = configured.map((w) => {
    const c = capsById.get(w.id) ?? {};
    const circuit = metrics.circuit?.[w.id];
    return {
      id: w.id,
      host: w.host ?? null,
      user: w.user ?? null,
      tags: w.tags ?? [],
      total_slots: w.total_slots ?? null,
      priority: w.priority ?? null,
      enabled: w.enabled !== false,
      active_builds: activeByWorker.get(w.id) ?? 0,
      circuit_state: circuit === undefined ? null : ["closed", "open", "half_open"][circuit] ?? String(circuit),
      last_seen_unix: metrics.lastSeen?.[w.id] ?? null,
      latency_ms: metrics.latency?.[w.id] ?? null,
      speed: speeds[w.id]?.speed_score ?? speeds[w.id]?.speedscore ?? null,
      caps: {
        num_cpus: c.num_cpus ?? null,
        load_avg_1: c.load_avg_1 ?? null,
        load_avg_5: c.load_avg_5 ?? null,
        load_avg_15: c.load_avg_15 ?? null,
        disk_free_gb: c.disk_free_gb ?? null,
        disk_total_gb: c.disk_total_gb ?? null,
        memory_pressure: c.memory_pressure ?? null,
        cpu_microarch_level: c.cpu_microarch_level ?? null,
        rustc_version: c.rustc_version ?? null,
        bun_version: c.bun_version ?? null,
        node_version: c.node_version ?? null,
        go_version: c.go_version ?? null,
        zig_version: c.zig_version ?? null,
        projects_root_ok: c.projects_root_ok ?? null,
      },
    };
  });

  return {
    id: host,
    reachable,
    daemon_running: status?.running ?? null,
    uptime_seconds: status?.uptime_seconds ?? null,
    queue: queue
      ? {
          queue_depth: queue.queue_depth ?? 0,
          workers_total: queue.workers_total ?? null,
          workers_available: queue.workers_available ?? null,
          workers_busy: queue.workers_busy ?? null,
          workers_offline: queue.workers_offline ?? null,
          workers_healthy: queue.workers_healthy ?? null,
          slots_total: queue.slots_total ?? null,
          slots_available: queue.slots_available ?? null,
          active_builds: queue.active_builds ?? [],
          queued_builds: queue.queued_builds ?? [],
        }
      : null,
    workers,
  };
}

// ----------------------------------------------------------------- encryption

async function encrypt(plaintext, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, [
    "deriveKey",
  ]);
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

  console.error(`collecting from ${args.dispatchers.length} dispatcher(s): ${args.dispatchers.join(", ")}`);
  const dispatchers = [];
  for (const host of args.dispatchers) {
    process.stderr.write(`  ${host} ... `);
    const d = await collectDispatcher(host);
    dispatchers.push(d);
    console.error(d.reachable ? `ok (${d.workers.length} workers)` : "UNREACHABLE");
  }

  // Union the worker view across dispatchers: a worker is "known" if any
  // dispatcher has it configured. Runtime facts come from the first dispatcher
  // that actually reported them, so one unreachable box cannot blank the fleet.
  const merged = new Map();
  for (const d of dispatchers) {
    for (const w of d.workers) {
      const prev = merged.get(w.id);
      if (!prev) {
        merged.set(w.id, { ...w, seen_by: [d.id] });
        continue;
      }
      prev.seen_by.push(d.id);
      for (const k of ["circuit_state", "last_seen_unix", "latency_ms", "speed"]) {
        if (prev[k] == null && w[k] != null) prev[k] = w[k];
      }
      for (const k of Object.keys(w.caps)) {
        if (prev.caps[k] == null && w.caps[k] != null) prev.caps[k] = w.caps[k];
      }
      prev.active_builds = Math.max(prev.active_builds, w.active_builds);
    }
  }
  const workers = [...merged.values()].sort((a, b) => a.id.localeCompare(b.id));

  const totals = {
    workers: workers.length,
    slots: workers.reduce((n, w) => n + (w.total_slots ?? 0), 0),
    cores: workers.reduce((n, w) => n + (w.caps.num_cpus ?? 0), 0),
    disk_free_gb: workers.reduce((n, w) => n + (w.caps.disk_free_gb ?? 0), 0),
    disk_total_gb: workers.reduce((n, w) => n + (w.caps.disk_total_gb ?? 0), 0),
    dispatchers_reachable: dispatchers.filter((d) => d.reachable).length,
    dispatchers_total: dispatchers.length,
  };

  const snapshot = {
    schema: SCHEMA,
    label: args.label,
    generated_at: new Date().toISOString(),
    totals,
    dispatchers,
    workers,
    history: [],
  };

  // Optional rolling history so the UI can draw trends across snapshots.
  if (args.historyFrom) {
    try {
      const prev = JSON.parse(await readFile(args.historyFrom, "utf8"));
      const points = Array.isArray(prev.history) ? prev.history : [];
      points.push({
        t: snapshot.generated_at,
        slots_total: totals.slots,
        slots_available: dispatchers.reduce((n, d) => n + (d.queue?.slots_available ?? 0), 0),
        workers_healthy: dispatchers[0]?.queue?.workers_healthy ?? null,
        disk_free_gb: Math.round(totals.disk_free_gb),
      });
      snapshot.history = points.slice(-args.historyMax);
    } catch {
      snapshot.history = [];
    }
  }

  const plain = JSON.stringify(snapshot);
  const envelope = await encrypt(plain, passphrase);
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(envelope, null, 2));

  console.error(
    `\nwrote ${args.out}  (${workers.length} workers, ${totals.slots} slots, ` +
      `${(plain.length / 1024).toFixed(1)}KB plaintext -> ${(JSON.stringify(envelope).length / 1024).toFixed(1)}KB ciphertext)`,
  );
  console.error("payload is AES-256-GCM encrypted; the passphrase is required to read it.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
