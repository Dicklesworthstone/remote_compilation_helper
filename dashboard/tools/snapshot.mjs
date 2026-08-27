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

import { SNAPSHOT_COMPRESSION, compressPlaintext, decompressPlaintext } from "./envelope.mjs";

const execFileAsync = promisify(execFile);

const PBKDF2_ITERATIONS = 600_000;
const SCHEMA = "rch.dashboard.snapshot.v2";
const SSH_TIMEOUT_MS = 90_000;
const MAX_BUFFER = 64 * 1024 * 1024;

/**
 * How many dispatchers to probe at once.
 *
 * The fan-out used to be unbounded AND four-wide per host: every dispatcher
 * issued `rch status`, `rch workers capabilities`, `rch workers list` and a
 * curl of the metrics endpoint as four independent `ssh` processes, so a
 * 10-machine fleet opened 36 simultaneous TCP connections and paid 36 full
 * key-exchange handshakes — on the COLLECTOR's cpu, which is the machine that
 * is usually already busy. Each host now needs exactly one connection, so the
 * count is N, not 4N; this caps N as well so a 60-machine fleet cannot melt the
 * collector's file-descriptor and process budget.
 *
 * 16 is above every fleet this has run against, so today it throttles nothing
 * and the collection order and output are bit-identical to the unbounded form.
 */
const DEFAULT_MAX_PARALLEL = 16;

// ---------------------------------------------------------------- arg parsing

function parseArgs(argv) {
  const args = {
    dispatchers: ["local"],
    out: "public/data/fleet.enc.json",
    historyFile: ".snapshot-history.json",
    historyMax: 96,
    label: "rch fleet",
    maxParallel: DEFAULT_MAX_PARALLEL,
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
    else if (a === "--max-parallel") {
      const n = Number(next());
      if (!Number.isInteger(n) || n < 1) {
        console.error("--max-parallel must be a positive integer");
        process.exit(2);
      }
      args.maxParallel = n;
    }
    else if (a === "--help" || a === "-h") {
      console.log(
        "usage: RCH_DASH_PASSPHRASE=... node tools/snapshot.mjs\n" +
          "  [--dispatchers a,b,c]  ssh targets; use `local` for this machine\n" +
          "  [--out path] [--label name] [--history-file path] [--history-max N]\n" +
          `  [--max-parallel N]     dispatchers probed at once (default ${DEFAULT_MAX_PARALLEL})`,
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

// --------------------------------------------------------- the combined probe

/**
 * The four questions asked of every dispatcher, in wire order.
 *
 * These used to be FOUR separate `ssh` invocations fired with `Promise.all`,
 * which meant four TCP connections and four full key-exchange handshakes per
 * host — 36 of them on a 10-machine fleet, all racing on the collector's own
 * cpu. They are now one connection per host, and the four commands still run
 * CONCURRENTLY, on the far side.
 *
 * `cmd` is byte-for-byte what each command used to be, including the per-command
 * `timeout` budget and the `2>/dev/null`. That matters more than it looks:
 *   - the budgets genuinely differ (70/70/45/10s) and running them serially in
 *     one shell would let a wedged `rch status` eat the whole run — measured at
 *     p50 2,955ms/host against 834ms for the parallel form, so the far side
 *     must fork, not sequence;
 *   - `timeout(1)` does not exist on a stock macOS, and one dispatcher is a Mac.
 *     It resolves there only because Homebrew's coreutils is on the default
 *     non-login ssh PATH. Keeping the command text identical keeps that working
 *     (and keeps it failing the same recognisable way if Homebrew ever goes).
 *   - the `export PATH` prefix stays INSIDE each rch section's subshell, so it
 *     cannot leak into the `curl` section and change which curl runs.
 */
const PROBE_SECTIONS = [
  { key: "s", cmd: rchProbeCommand("status", 70) },
  { key: "c", cmd: rchProbeCommand("workers capabilities", 70) },
  { key: "l", cmd: rchProbeCommand("workers list", 45) },
  { key: "m", cmd: "curl -s --max-time 10 http://127.0.0.1:9100/metrics 2>/dev/null" },
];

function rchProbeCommand(subcommand, timeoutSec) {
  return `export PATH="$HOME/.local/bin:$PATH"; timeout ${timeoutSec} rch ${subcommand} --json 2>/dev/null`;
}

/**
 * Per-process section marker. Random, because the payload is not ours: a build
 * command string in `rch status` or a Prometheus label could in principle
 * contain any fixed sentinel we picked, and a payload that can forge a frame
 * boundary can move bytes from one section into another. A 16-hex-digit nonce
 * that only exists inside this process cannot be guessed by the data.
 */
const PROBE_NONCE = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

/**
 * One shell script that answers all four questions over a single connection.
 *
 * Shape, and why each piece is the way it is:
 *
 *   d=$(mktemp -d ...)     Temp files are what makes CONCURRENT sections
 *                          possible. Four background jobs cannot share one
 *                          stdout: `rch status --json` is tens of KB and writes
 *                          larger than PIPE_BUF are not atomic, so their bytes
 *                          would interleave and every section would be corrupt.
 *   if [ -n "$d" ] ... else
 *                          If `mktemp` fails — a full /data/tmp is a real
 *                          condition on this fleet — fall back to running the
 *                          four SEQUENTIALLY in the same connection. Slower, but
 *                          a slow dispatcher beats one that reports as dead.
 *   trap '... EXIT'        Removes exactly the four files this script created
 *                          and its own directory. Nothing else is touched, and
 *                          nothing is left behind on the host.
 *   wait $qN; eN=$?        The subcommand's OWN exit status, which is what makes
 *                          per-section failure reporting possible — see
 *                          sectionResult(). The four still ran in parallel;
 *                          waiting for them in order costs nothing.
 *   cat; echo; echo MARKER Content, then exactly one newline, then the marker on
 *                          its own line. splitProbeSections() relies on that
 *                          single added newline to reconstruct each section's
 *                          bytes EXACTLY, including the empty-output case that
 *                          the metrics scraper reports as an error.
 *
 * Everything here is POSIX sh: the fleet's login shells are a mix of bash and
 * zsh and ssh runs the command under whichever one the account has.
 */
export function buildProbeScript(nonce = PROBE_NONCE) {
  const files = PROBE_SECTIONS.map((s) => `"$d/${s.key}"`).join(" ");
  return [
    `d=$(mktemp -d "\${TMPDIR:-/tmp}/rchdash.XXXXXX" 2>/dev/null)`,
    `if [ -n "$d" ]; then`,
    `trap 'rm -f ${files}; rmdir "$d" 2>/dev/null' EXIT`,
    ...PROBE_SECTIONS.map((s, i) => `{ ${s.cmd}; } > "$d/${s.key}" & q${i}=$!`),
    ...PROBE_SECTIONS.map((s, i) =>
      `wait $q${i}; e${i}=$?\ncat "$d/${s.key}"; echo; echo "${nonce}:${s.key}:$e${i}"`),
    `else`,
    ...PROBE_SECTIONS.map((s) => `( ${s.cmd} ); e=$?; echo; echo "${nonce}:${s.key}:$e"`),
    `fi`,
  ].join("\n");
}

/**
 * Split framed probe output back into `key -> {text, rc}`.
 *
 * The reconstruction is exact, not approximate. The emitter writes
 * `<content>\n<marker>\n`; splitting the whole stream on "\n" and re-joining a
 * section's tokens with "\n" consumes precisely the one newline the emitter
 * added, so `text` is the original bytes — `""` stays `""`, and a section whose
 * content already ended in a newline keeps it. That exactness is load-bearing:
 * `parseMetrics` reports "no response from 127.0.0.1:9100" on a FALSY stdout,
 * so a stray newline would silently convert a dead metrics endpoint into a
 * healthy-looking one with no workers in it.
 *
 * Bytes before the first marker belong to the first section, which is where ssh
 * banner noise landed before too — `rch`'s JSON is still located by scanning
 * from the first `{` to the last `}`.
 *
 * First marker for a key wins, so a duplicate frame cannot overwrite a section
 * that already parsed.
 */
export function splitProbeSections(stdout, nonce = PROBE_NONCE) {
  const out = new Map();
  const marker = new RegExp(`^${nonce}:([a-z]+):(-?\\d+)$`);
  let buf = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const m = marker.exec(line);
    if (!m) { buf.push(line); continue; }
    if (!out.has(m[1])) out.set(m[1], { text: buf.join("\n"), rc: Number(m[2]) });
    buf = [];
  }
  return out;
}

/**
 * Turn one section of a probe into the `{stdout, error}` shape the parsers
 * below expect — the same shape `run()` used to hand them per command.
 *
 * This is where the old per-command failure isolation is preserved. The four
 * questions no longer have four exit statuses from four ssh processes, so the
 * far side reports each one's own status and it is reconstructed here:
 *
 *   section present, exit 0    -> {stdout, error: null}      (as before)
 *   section present, exit N!=0 -> {stdout, error: "exited N"} — and if stdout is
 *                                 non-empty the parsers IGNORE the error and use
 *                                 it, exactly as they did when a non-zero ssh
 *                                 still carried usable JSON.
 *   section absent             -> the transport error, or "no output". A section
 *                                 goes missing only when the connection itself
 *                                 failed, or the remote shell died before
 *                                 reaching it — in both cases every section is
 *                                 missing, which is precisely the old
 *                                 all-four-ssh-calls-failed case.
 *
 * So one failing subcommand degrades exactly one section: `workers list`
 * returning nothing still leaves `rch status` parsed, the dispatcher reachable,
 * and `config_degraded` set — see tests/snapshot.mjs.
 */
function sectionResult(probe, key) {
  const sec = probe.sections.get(key);
  if (sec) return { stdout: sec.text, error: sec.rc === 0 ? null : `exited ${sec.rc}` };
  return { stdout: "", error: probe.error || null };
}

/**
 * Built once, so every dispatcher in a run is asked exactly the same question
 * under exactly the same nonce — the script is a pure function of
 * PROBE_SECTIONS and cannot drift between hosts.
 */
const PROBE_SCRIPT = buildProbeScript();

/** One connection per dispatcher. Never throws; returns {sections, error}. */
async function probeDispatcher(host) {
  const res = await run(host, PROBE_SCRIPT);
  return { sections: splitProbeSections(res.stdout), error: res.error ?? null };
}

/**
 * Parse an rch subcommand's standard `{data: ...}` JSON envelope.
 * Returns `{data, error}` — `data` is null on every failure and `error` says
 * why, so a dead daemon can be told apart from an unreachable host.
 */
function parseRchJson(subcommand, res) {
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
function parseMetrics(res) {
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

/**
 * `Promise.allSettled` with a ceiling on how many run at once.
 *
 * Results are written back BY INDEX, so the returned array is in input order
 * and carries the same `{status, value}` / `{status, reason}` shape
 * `Promise.allSettled` returns. That is the isomorphism: with `limit >= n` this
 * is `Promise.allSettled`, and `dispatchers[]` — which is positional, and which
 * the string table and every consumer index into — keeps its order at any limit.
 */
export async function allSettledBounded(items, limit, fn) {
  const out = new Array(items.length);
  const width = Math.max(1, Math.min(limit, items.length));
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        out[i] = { status: "fulfilled", value: await fn(items[i], i) };
      } catch (reason) {
        out[i] = { status: "rejected", reason };
      }
    }
  };
  await Promise.all(Array.from({ length: width }, worker));
  return out;
}

/** One dispatcher, one connection. */
async function collectDispatcher(host) {
  return dispatcherFromProbe(host, await probeDispatcher(host));
}

/**
 * Build a dispatcher record from an already-collected probe.
 *
 * Separate from the ssh call for one reason: this is where per-section failure
 * isolation lives, and isolation you cannot test is isolation you do not have.
 * `tests/snapshot.mjs` hands this function hand-framed probe output — one
 * section failing, the rest healthy — and asserts the surviving sections still
 * populate, which is the property the four-processes-to-one collapse had to
 * keep.
 */
export function dispatcherFromProbe(host, probe) {
  // `rch status` carries runtime state but NOT the static config fields
  // (tags, priority, enabled) — those only exist in `workers list`. All four
  // still run concurrently; they now do it on the far side of ONE connection
  // instead of four. See PROBE_SECTIONS.
  const statusRes = parseRchJson("status", sectionResult(probe, "s"));
  const capsRes = parseRchJson("workers capabilities", sectionResult(probe, "c"));
  const listRes = parseRchJson("workers list", sectionResult(probe, "l"));
  const metrics = parseMetrics(sectionResult(probe, "m"));

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
  // Positional, not named — see `builds` in the returned object below. Field
  // order is the contract: project, command, location, worker, duration,
  // exit code, completed_at. `src/derive.ts` and `tools/llm-view.mjs` expand it.
  const recent = (status?.daemon?.recent_builds ?? []).slice(-25).map((b) => [
    b.project_id ?? null,
    typeof b.command === "string" ? b.command.slice(0, 120) : null,
    b.location ?? null,                    // "Remote" | "Local"
    b.worker_id ?? null,
    num(b.duration_ms),
    num(b.exit_code),
    b.completed_at ?? null,
  ]);

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
    /**
     * Recent builds as `[project, command, location, worker_id, duration_ms,
     * exit_code, completed_at]` tuples.
     *
     * Every one of those seven values is consumed — the drawer renders six of
     * them and uses `command` as the row tooltip, and both classifiers count
     * `location` to decide whether this box is offloading — so nothing can be
     * dropped. What CAN go is the key names: 121 records on a 10-machine fleet
     * repeat the same 84 characters of `"project":"command":"location":…`
     * 121 times, 10.2KB of a 92.3KB payload, for zero information.
     *
     * Named `builds`, not `recent_builds`, deliberately. A browser tab holding
     * the previous bundle would read these arrays through the object accessors
     * and get `undefined` for `location` on every row — which reads as "0% of
     * builds went remote" and paints every dev machine red `local-only`. Under
     * a new key the old bundle simply sees no builds and falls back to the
     * lifetime counters, which is wrong-but-quiet rather than a fleet-wide
     * false alarm.
     */
    builds: recent,
    /**
     * Remediation hints as `[worker_id, severity, message, suggested_action,
     * reason_code]` tuples, same reasoning as `builds` (66 chars of key names
     * × 99 records = 6.5KB). All five are consumed: the drawer renders four and
     * folds `reason_code` into each row's React key.
     */
    hints: (status?.remediation_hints ?? []).slice(0, 12).map((h) => [
      h.worker_id ?? null,
      h.severity ?? null,
      typeof h.message === "string" ? h.message.slice(0, 240) : null,
      typeof h.suggested_action === "string" ? h.suggested_action.slice(0, 240) : null,
      h.reason_code ?? null,
    ]),
    // `daemon.issues[]` and `daemon.alerts[]` used to be collected here and are
    // NOT emitted any more. Nothing ever read them: no component, no
    // `src/derive.ts` path, no `tools/llm-view.mjs` view, no test — only the
    // `unknown[]` declaration in src/types.ts, which is now gone too. They were
    // 8.0KB of a 92.3KB payload (8.7%), re-downloaded whole every 5 minutes and
    // discarded unread. If a future panel wants them, re-add them WITH the
    // consumer, so the payload cost is paid for something that renders.
    workers,
  };
}

// ------------------------------------------------------------ string interning

/**
 * Which tuple slots carry an INTERNED string, by position.
 *
 * These four lists are the whole schema of the string table. `src/derive.ts`
 * (`internedStr`/`rehydrateStrings`) and the mirror in `tools/llm-view.mjs`
 * resolve exactly these positions; `tests/parity.mjs` compares the two and
 * `tests/snapshot.mjs` pins this table's shape.
 *
 * The exclusions are the interesting part — each one is deliberate and was
 * measured on a live 10-machine snapshot (137 builds, 113 hints, 77,095B):
 *
 *   builds[2] `location`   NEVER intern. It is the only tuple slot read
 *       POSITIONALLY off the raw wire, by `classifyDev()` in tools/llm-view.mjs,
 *       and four consumers call `.toLowerCase()` on it (derive.ts
 *       classifyDispatcher, llm-view classifyDev, DevMachineCard,
 *       DevMachineDrawer). An integer there is a TypeError, not a wrong pixel —
 *       and a browser tab still holding the previous bundle would take it.
 *       Worth ~959B; not worth a crash.
 *   builds[6] `completed_at`  Interning it COSTS bytes: 137 distinct values in
 *       137 slots, so the table (5,098B) is larger than the inline strings
 *       (4,961B) before a single index is written. Timestamps do not repeat.
 *   hints[1]  `severity`   The one candidate whose value is read as an ALARM
 *       LEVEL (`h.severity === "critical"` picks the pill colour). Under an old
 *       bundle an index would silently downgrade a critical hint to a warn
 *       pill, and under-reporting an alarm is the failure this dashboard exists
 *       to prevent. Costs ~940B of the ~24.4KB saved — cheap insurance.
 *
 * Everything else in the two tuples repeats heavily across dispatchers (the
 * same hint text for the same worker on all 10 boxes) and is display-only or
 * key material, so an old bundle reading a new snapshot renders a small integer
 * for at most one refresh interval and every VERDICT stays correct.
 */
const INTERNED_BUILD_SLOTS = [0, 1, 3];        // project, command, worker_id
const INTERNED_HINT_SLOTS = [0, 2, 3, 4];      // worker_id, message, suggested_action, reason_code

/**
 * Replace repeated tuple strings with indices into ONE snapshot-level table.
 *
 * Applied at SERIALIZATION time only — the dispatcher records keep their full
 * strings all the way through collection and merging, exactly as the worker and
 * build projections in passes 2-3 do, so nothing upstream has to know about the
 * table.
 *
 * GLOBAL, not per-array, and the choice was measured rather than assumed. Eight
 * per-field tables came to 51,447B against 51,784B for one global table: 337B
 * better, which is 0.44% of the payload and 1.3% of the change. It buys that
 * with eight independent index spaces for `src/derive.ts` and
 * `tools/llm-view.mjs` to keep in lockstep — the exact drift `tests/parity.mjs`
 * exists to catch. One table, one index space, 337B. Per-DISPATCHER tables were
 * never in the running: they save only 1,810B (-2.3%), because the duplication
 * is almost entirely ACROSS dispatchers — every box reports the same hint for
 * the same shared worker — and barely exists within one.
 *
 * Encoding, and the reason a missing value can never be read as entry 0:
 *   number  -> index into `strings`
 *   string  -> a literal that was not interned (an empty string stays "")
 *   null    -> genuinely absent
 * Only NON-EMPTY strings are ever interned, so no table index is the
 * representation of "absent" or "empty", and entry 0 is always a real value.
 */
export function internSnapshotStrings(dispatchers) {
  const count = new Map();
  const firstAt = new Map();
  let seq = 0;
  const scan = (v) => {
    if (typeof v !== "string" || v === "") return;
    count.set(v, (count.get(v) ?? 0) + 1);
    if (!firstAt.has(v)) firstAt.set(v, seq++);
  };
  for (const d of dispatchers) {
    for (const b of d.builds ?? []) for (const i of INTERNED_BUILD_SLOTS) scan(b[i]);
    for (const h of d.hints ?? []) for (const i of INTERNED_HINT_SLOTS) scan(h[i]);
  }

  // Hottest string first. The index is written once per OCCURRENCE and the
  // string once, so putting the most repeated values at the low indices buys a
  // digit on every occurrence — worth 303B on the live fleet for zero risk.
  // Ties break on first appearance, so the table is a pure function of the
  // input and two runs over the same data produce byte-identical output.
  const strings = [...count.keys()].sort(
    (a, b) => count.get(b) - count.get(a) || firstAt.get(a) - firstAt.get(b),
  );
  const index = new Map(strings.map((s, i) => [s, i]));

  const put = (v) => (typeof v === "string" && v !== "" ? index.get(v) : (v ?? null));
  const project = (row, slots) => row.map((v, i) => (slots.includes(i) ? put(v) : v));

  return {
    strings,
    dispatchers: dispatchers.map((d) => ({
      ...d,
      builds: (d.builds ?? []).map((b) => project(b, INTERNED_BUILD_SLOTS)),
      hints: (d.hints ?? []).map((h) => project(h, INTERNED_HINT_SLOTS)),
    })),
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

/**
 * Compress, then encrypt.
 *
 * The order is the only one that does anything: ciphertext is incompressible, so
 * compressing after encryption — or leaving it to the CDN, which only ever sees
 * ciphertext — buys nothing. See tools/envelope.mjs for the codec comparison and
 * for why CRIME/BREACH does not reach this pipeline.
 *
 * `compression` is written into the envelope so the format describes itself. A
 * reader that finds no such field must treat the plaintext as uncompressed —
 * that is exactly what every envelope written before this change is.
 */
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
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, compressPlaintext(plaintext));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  return {
    format: "rch.dashboard.enc.v1",
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS, salt: b64(salt) },
    cipher: { name: "AES-GCM", iv: b64(iv) },
    compression: SNAPSHOT_COMPRESSION,
    ciphertext: b64(new Uint8Array(ct)),
  };
}

/**
 * Decrypt what we just encrypted and confirm it round-trips to the same size.
 * Cheap insurance against publishing a payload the passphrase cannot open — and,
 * since the plaintext is now gzip'd before encryption, against publishing one
 * that decrypts but does not INFLATE. A compression bug would otherwise reach
 * the browser as an indistinguishable "wrong passphrase".
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
  const text = decompressPlaintext(Buffer.from(out), envelope.compression);
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
  // Settled, not all: this fan-out is the whole snapshot. One dispatcher
  // returning a shape that throws inside the mapper must not abort collection
  // for every other machine — that is the opposite of the resilience the merge
  // below is written for.
  const settled = await allSettledBounded(targets, args.maxParallel, async (host) => {
    const d = await collectDispatcher(host);
    console.error(
      `  ${String(host).padEnd(14)} ${d.reachable ? `ok  posture=${d.posture ?? "?"}  workers=${d.workers.length}` : `UNREACHABLE  ${d.collection_errors[0] ?? ""}`}`,
    );
    return d;
  });

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
      saved_time_ms: null, active_builds: 0, queued_builds: 0,
      builds: [], hints: [], workers: [],
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

  // Project the per-dispatcher worker arrays down before they reach the wire.
  //
  // Every dispatcher used to ship a FULL copy of every worker it can see: on a
  // 10-machine fleet that is 142 records, 121.5KB of a 222.8KB payload (54.6%),
  // re-downloaded whole on every 5-minute refresh. All of it was redundant:
  //   - every descriptive field (host, user, caps, pressure, tags, latency,
  //     failure_history, ...) is already in the merged `workers[]` above, folded
  //     worst-wins across observers;
  //   - the only genuinely per-dispatcher fact is the derated slot reading, and
  //     the merge already records that too, as `workers[].slots_by_dispatcher`.
  // The single surviving consumer of the per-dispatcher array is the dev-machine
  // drawer, which sums used/total slots and counts the zero-slot workers to
  // answer "is this box about to go local-only?" — it never reads any other
  // field. So emit the slot readings alone, positionally: the key names cost
  // more than the values at 142 repetitions. `classifyDispatcher()` in
  // src/derive.ts expands them back into `workers` on the DispatcherView the
  // drawer is handed, so the drawer sees exactly what it saw before.
  const emittedDispatchers = dispatchers.map(({ workers: seen, ...rest }) => ({
    ...rest,
    worker_slots: seen.map((w) => [w.used_slots, w.total_slots]),
  }));

  // Fold the repeated build/hint strings into one snapshot-level table. Hints
  // and commands duplicate massively across dispatchers — 113 hints on a
  // 10-machine fleet carry 30 distinct messages and 20 distinct suggested
  // actions, and every box reports the same advice for the same shared worker.
  // See internSnapshotStrings() for the field set and why `location`,
  // `severity` and `completed_at` are excluded from it.
  const { dispatchers: internedDispatchers, strings } = internSnapshotStrings(emittedDispatchers);

  const snapshot = {
    schema: SCHEMA, label: args.label, generated_at, totals,
    dispatchers: internedDispatchers, workers, strings, history,
  };

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
      `  ${(Buffer.byteLength(plain) / 1024).toFixed(1)}KB plaintext -> ` +
      `${(JSON.stringify(envelope).length / 1024).toFixed(1)}KB envelope ` +
      `(${envelope.compression} ${(Buffer.byteLength(plain) / (envelope.ciphertext.length * 0.75)).toFixed(1)}x)` +
      `  ·  string table ${strings.length} entries`,
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
