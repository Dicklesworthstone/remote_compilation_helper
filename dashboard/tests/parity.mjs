/**
 * Parity test: the browser classifier (src/derive.ts) and the LLM/agent
 * classifier (tools/llm-view.mjs) must agree.
 *
 * The two exist separately because one is TypeScript compiled into the browser
 * bundle and the other is plain Node used by the CLI and the serverless
 * function. Duplicated thresholds rot silently, so this transpiles derive.ts
 * with esbuild and runs BOTH over the same fixture matrix, asserting identical
 * health verdicts. If you change a threshold in one and not the other, this
 * fails.
 *
 * Usage: npm run test:llm
 */

import { build } from "esbuild";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { classifyWorker, classifyDev } from "../tools/llm-view.mjs";

const dir = await mkdtemp(join(tmpdir(), "rch-parity-"));
const outfile = join(dir, "derive.mjs");
await build({
  entryPoints: ["src/derive.ts"],
  outfile,
  bundle: true,
  format: "esm",
  platform: "neutral",
  logLevel: "silent",
});
const derive = await import(pathToFileURL(outfile).href);

let fails = 0;
const chk = (name, ok, note = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${note ? " — " + note : ""}`);
  if (!ok) fails++;
};

const SNAP_MS = Date.parse("2026-08-26T12:00:00.000Z");
const SNAP_S = SNAP_MS / 1000;

/** Minimal worker with overridable fields. */
const w = (over = {}) => ({
  id: "w", host: "h", user: "u", status: "healthy", circuit_state: "closed",
  used_slots: 0, total_slots: 8, speed: 50, last_error: null,
  consecutive_failures: 0, failure_history: [],
  pressure: {
    state: "healthy", reason: null, disk_free_gb: 500, disk_total_gb: 1000,
    disk_io_util_pct: 0, memory_pressure: 0, telemetry_age_secs: 5, telemetry_fresh: true,
  },
  latency_ms: 10, last_seen_unix: SNAP_S - 30, priority: 100, enabled: true,
  caps: {
    num_cpus: 8, load_avg_1: 1, load_avg_5: 1, load_avg_15: 1,
    cpu_microarch_level: 3, rustc_version: "1.87.0", bun_version: null,
    node_version: null, go_version: null, zig_version: null, projects_root_ok: true,
  },
  tags: [], ...over,
});

// Boundary matrix — each row targets one threshold, including both sides of it.
const cases = [
  ["baseline healthy", w()],
  ["disabled via status", w({ status: "disabled" })],
  ["disabled via enabled:false", w({ enabled: false })],
  ["status down", w({ status: "down" })],
  ["circuit open", w({ circuit_state: "open" })],
  ["circuit half_open", w({ circuit_state: "half_open" })],
  ["draining", w({ status: "draining" })],
  ["stale just under 1h", w({ last_seen_unix: SNAP_S - 3599 })],
  ["stale just over 1h", w({ last_seen_unix: SNAP_S - 3601 })],
  ["disk 94.9% (under crit)", w({ pressure: { ...w().pressure, disk_free_gb: 51, disk_total_gb: 1000 } })],
  ["disk 95.1% (crit)", w({ pressure: { ...w().pressure, disk_free_gb: 49, disk_total_gb: 1000 } })],
  ["disk 88.1% (warn)", w({ pressure: { ...w().pressure, disk_free_gb: 119, disk_total_gb: 1000 } })],
  ["disk 87.9% (under warn)", w({ pressure: { ...w().pressure, disk_free_gb: 121, disk_total_gb: 1000 } })],
  ["pressure critical flag", w({ pressure: { ...w().pressure, state: "critical", reason: "disk_free_below_critical_gb" } })],
  ["pressure warning flag", w({ pressure: { ...w().pressure, state: "warning", reason: "disk_io_high" } })],
  ["load exactly 2x", w({ caps: { ...w().caps, load_avg_1: 16, num_cpus: 8 } })],
  ["load just under 2x", w({ caps: { ...w().caps, load_avg_1: 15.9, num_cpus: 8 } })],
  ["one consecutive failure (singular)", w({ consecutive_failures: 1 })],
  ["consecutive failures", w({ consecutive_failures: 3 })],
  ["busy", w({ used_slots: 4 })],
  ["projects root bad", w({ caps: { ...w().caps, projects_root_ok: false } })],
  ["no telemetry at all", w({ last_seen_unix: null, caps: { ...w().caps, load_avg_1: null, num_cpus: null },
                             pressure: { ...w().pressure, disk_free_gb: null, disk_total_gb: null } })],
];

for (const [name, worker] of cases) {
  const a = derive.classify(worker, SNAP_MS);
  const b = classifyWorker(worker, SNAP_MS);
  chk(`worker: ${name}`, a.health === b.health, `derive=${a.health} llm=${b.health}`);
  if (a.health !== "healthy" && a.healthReason !== b.reason) {
    chk(`worker reason: ${name}`, false, `derive="${a.healthReason}" llm="${b.reason}"`);
  }
}

// Dev-machine parity.
const d = (over = {}) => ({
  id: "d", reachable: true, posture: "remote_ready", posture_description: "ok",
  daemon: { version: "1", uptime_secs: 60, pid: 1, workers_total: 2, workers_healthy: 2,
            slots_total: 10, slots_available: 10 },
  build_stats: { total: 10, remote: 10, local: 0, success: 10, failure: 0, avg_duration_ms: 100 },
  saved_time_ms: 0, active_builds: 0, queued_builds: 0, recent_builds: [],
  issues: [], alerts: [], remediation_hints: [], workers: [], ...over,
});

const devCases = [
  ["offloading", d()],
  ["unreachable", d({ reachable: false })],
  ["posture degraded", d({ posture: "degraded", posture_description: "partial" })],
  ["posture local_only", d({ posture: "local_only", posture_description: "no workers" })],
  ["idle (no builds)", d({ build_stats: { total: 0, remote: 0, local: 0, success: 0, failure: 0, avg_duration_ms: null } })],
  ["mostly local", d({ build_stats: { total: 10, remote: 2, local: 8, success: 10, failure: 0, avg_duration_ms: 100 } })],
  ["no build_stats", d({ build_stats: null })],
];

for (const [name, dev] of devCases) {
  const a = derive.classifyDispatcher(dev);
  const b = classifyDev(dev);
  chk(`dev: ${name}`, a.level === b.level, `derive=${a.level} llm=${b.level}`);
}

// The stale-clock regression: classifyAll must ignore the caller's clock.
const snap = {
  schema: "x", label: "l", generated_at: new Date(SNAP_MS).toISOString(),
  totals: {}, dispatchers: [], workers: [w()], history: [],
};
const wayLater = SNAP_MS + 6 * 60 * 60 * 1000;
chk(
  "classifyAll ignores reader clock",
  derive.classifyAll(snap, wayLater)[0].health === "healthy",
  "a 6h-old snapshot must not mark a freshly-seen worker offline",
);

await rm(dir, { recursive: true, force: true });
console.log(fails === 0 ? "\nALL PARITY CHECKS PASSED" : `\n${fails} PARITY CHECK(S) FAILED`);
process.exit(fails ? 1 : 0);
