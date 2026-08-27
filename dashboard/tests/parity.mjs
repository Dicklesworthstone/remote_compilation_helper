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
import { classifyWorker, classifyDev, expandBuilds, expandHints } from "../tools/llm-view.mjs";

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
  latency_ms: 10, last_seen_unix: SNAP_S - 30, priority: 100,
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
  ["status down", w({ status: "down" })],
  ["circuit open", w({ circuit_state: "open" })],
  ["circuit half_open", w({ circuit_state: "half_open" })],
  ["draining", w({ status: "draining" })],
  // Real WorkerStatus variants (rch-common/src/types.rs) that both classifiers
  // used to fall through on, rendering a slow or drained worker as healthy.
  ["degraded (responding slowly)", w({ status: "degraded" })],
  ["drained (accepting nothing)", w({ status: "drained" })],
  ["degraded while busy", w({ status: "degraded", used_slots: 4 })],
  ["drained while busy", w({ status: "drained", used_slots: 2 })],
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
  // A broken projects root used to be unreachable whenever the worker was busy,
  // i.e. exactly when a build was running on the broken root.
  ["projects root bad WHILE busy", w({ used_slots: 4, caps: { ...w().caps, projects_root_ok: false } })],
  // rch's fourth pressure state. Ranked below healthy in the old merge and
  // matched by neither classifier, so "I have no telemetry" rendered green.
  ["pressure telemetry_gap", w({ pressure: { ...w().pressure, state: "telemetry_gap" } })],
  ["pressure telemetry_gap with reason", w({ pressure: { ...w().pressure, state: "telemetry_gap", reason: "pressure_telemetry_gap" } })],
  // Pressure events that carry no disk numbers used to render the literal
  // string "disk undefined% full".
  ["critical pressure, no disk numbers", w({ pressure: { ...w().pressure, state: "critical", reason: null, disk_free_gb: null, disk_total_gb: null } })],
  ["warning pressure, no disk numbers", w({ pressure: { ...w().pressure, state: "warning", reason: null, disk_free_gb: null, disk_total_gb: null } })],
  // Healthy-looking verdict derived from stale readings.
  ["stale telemetry, otherwise healthy", w({ pressure: { ...w().pressure, telemetry_fresh: false, telemetry_age_secs: 900 } })],
  ["stale telemetry, no age", w({ pressure: { ...w().pressure, telemetry_fresh: false, telemetry_age_secs: null } })],
  ["stale telemetry while busy", w({ used_slots: 3, pressure: { ...w().pressure, telemetry_fresh: false, telemetry_age_secs: 120 } })],
  ["no telemetry at all", w({ last_seen_unix: null, caps: { ...w().caps, load_avg_1: null, num_cpus: null },
                             pressure: { ...w().pressure, disk_free_gb: null, disk_total_gb: null } })],
];

for (const [name, worker] of cases) {
  const a = derive.classify(worker, SNAP_MS);
  const b = classifyWorker(worker, SNAP_MS);
  chk(`worker: ${name}`, a.health === b.health, `derive=${a.health} llm=${b.health}`);
  // Compare reasons unconditionally. Skipping the healthy case (and only
  // reporting on mismatch) meant a passing reason check was invisible and
  // healthy-path drift went unnoticed entirely.
  chk(`worker reason: ${name}`, a.healthReason === b.reason, `derive="${a.healthReason}" llm="${b.reason}"`);
  // A reason must never interpolate a missing number into the text.
  chk(`worker reason well-formed: ${name}`, !/undefined|NaN|null/.test(a.healthReason), `derive="${a.healthReason}"`);
}

// Dev-machine parity.
const d = (over = {}) => ({
  id: "d", reachable: true, posture: "remote_ready", posture_description: "ok",
  daemon: { version: "1", uptime_secs: 60, pid: 1, workers_total: 2, workers_healthy: 2,
            slots_total: 10, slots_available: 10 },
  build_stats: { total: 10, remote: 10, local: 0, success: 10, failure: 0, avg_duration_ms: 100 },
  saved_time_ms: 0, active_builds: 0, queued_builds: 0,
  // The wire shape the collector actually emits: positional tuples, not objects
  // — `worker_slots` as `[used, total]`, `builds` as
  // `[project, command, location, worker_id, duration_ms, exit_code, completed_at]`
  // and `hints` as `[worker_id, severity, message, suggested_action, reason_code]`.
  // `issues`/`alerts` are gone entirely: nothing ever read them.
  builds: [], hints: [],
  collection_errors: [], config_degraded: false, worker_slots: [], ...over,
});

/** Build a wire build tuple from named parts, so the cases below stay readable. */
const bt = (o = {}) => [
  o.project ?? "proj", o.command ?? "cargo build", o.location ?? "Remote",
  o.worker_id ?? "w1", o.duration_ms ?? 1000, o.exit_code ?? 0,
  o.completed_at ?? "2026-08-26T11:59:00.000Z",
];

const devCases = [
  ["offloading", d()],
  ["unreachable", d({ reachable: false })],
  ["posture degraded", d({ posture: "degraded", posture_description: "partial" })],
  ["posture local_only", d({ posture: "local_only", posture_description: "no workers" })],
  ["idle (no builds)", d({ build_stats: { total: 0, remote: 0, local: 0, success: 0, failure: 0, avg_duration_ms: null } })],
  ["mostly local", d({ build_stats: { total: 10, remote: 2, local: 8, success: 10, failure: 0, avg_duration_ms: 100 } })],
  ["no build_stats", d({ build_stats: null })],
  // The RECENT-window basis, which nothing exercised before the builds array
  // moved to tuples. It is the branch that decides `local-only`, and it reads
  // `location` out of a fixed tuple position — a misread index would count
  // every build as local and paint the whole fleet red.
  ["recent window: all remote", d({ builds: [bt(), bt(), bt()] })],
  ["recent window: all local", d({ builds: [bt({ location: "Local" }), bt({ location: "Local" })] })],
  ["recent window: 50/50 (on the threshold)", d({ builds: [bt(), bt({ location: "Local" })] })],
  ["recent window: 1 of 3 remote", d({ builds: [bt(), bt({ location: "Local" }), bt({ location: "Local" })] })],
  ["recent window beats lifetime counters", d({
    builds: [bt({ location: "Local" }), bt({ location: "Local" })],
    build_stats: { total: 100, remote: 100, local: 0, success: 100, failure: 0, avg_duration_ms: 100 },
  })],
  ["recent window with a null location", d({ builds: [bt({ location: null }), bt()] })],
];

for (const [name, dev] of devCases) {
  const a = derive.classifyDispatcher(dev);
  const b = classifyDev(dev);
  chk(`dev: ${name}`, a.level === b.level, `derive=${a.level} llm=${b.level}`);
  // Compare the whole verdict, not just the label. The reason string embeds the
  // measured percentage AND the window size ("only 33% of the last 3 builds
  // went remote"), so this is what actually catches a classifier that counts a
  // different number of builds than the other one.
  chk(`dev reason: ${name}`, a.levelReason === b.reason, `derive="${a.levelReason}" llm="${b.reason}"`);
  chk(`dev remotePct: ${name}`, a.remotePct === b.remotePct, `derive=${a.remotePct} llm=${b.remotePct}`);
  chk(`dev basis: ${name}`,
    a.remoteBasis === b.remoteBasis && a.remoteCounted === b.remoteCounted,
    `derive=${a.remoteBasis}/${a.remoteCounted} llm=${b.remoteBasis}/${b.remoteCounted}`);
}

// ------------------------------------------------- per-dispatcher slot view
//
// The collector stopped duplicating a full worker record per dispatcher (it was
// 54.6% of the snapshot payload and every field was already in the merged
// `workers[]`). What survives is the one genuinely per-dispatcher fact — this
// machine's derated `[used, total]` reading — which classifyDispatcher expands
// back into `workers` for the dev-machine drawer. The drawer sums those and
// counts the zero-slot entries to answer "is this box about to go local-only?",
// so an expansion that dropped or reordered a pair would silently change that
// verdict.
{
  const pairs = [[0, 16], [4, 8], [null, null], [2, 0]];
  const dv = derive.classifyDispatcher(d({ worker_slots: pairs }));
  chk("slot pairs expand one-for-one", dv.workers.length === pairs.length, `${dv.workers.length} of ${pairs.length}`);
  chk("slot pairs keep their order and values",
    JSON.stringify(dv.workers) ===
      JSON.stringify(pairs.map(([used, total]) => ({ used_slots: used, total_slots: total }))),
    JSON.stringify(dv.workers));
  // The drawer's three numbers, computed exactly as DevMachineDrawer does.
  const ws = dv.workers;
  chk("derated totals survive the round trip",
    ws.reduce((n, x) => n + (x.total_slots ?? 0), 0) === 24 &&
    ws.reduce((n, x) => n + (x.used_slots ?? 0), 0) === 6,
    `total=${ws.reduce((n, x) => n + (x.total_slots ?? 0), 0)} used=${ws.reduce((n, x) => n + (x.used_slots ?? 0), 0)}`);
  // A worker derated to 0 slots is invisible to this machine — the exact
  // condition the drawer exists to surface, and the one `|| null` instead of
  // `?? null` in the expander would erase.
  chk("zero-slot workers stay countable",
    ws.filter((x) => (x.total_slots ?? 0) === 0).length === 2,
    `${ws.filter((x) => (x.total_slots ?? 0) === 0).length} of 2`);
  chk("a dispatcher with no slot view yields no workers",
    derive.classifyDispatcher(d()).workers.length === 0);
  // An older snapshot cached in a browser tab has no `worker_slots` at all.
  const legacy = d();
  delete legacy.worker_slots;
  chk("a pre-projection snapshot renders instead of throwing",
    derive.classifyDispatcher(legacy).workers.length === 0);
}

// ------------------------------------------------ build + hint tuple expansion
//
// `recent_builds[]` and `remediation_hints[]` moved to the wire as positional
// tuples: every value in them is rendered, but the repeated key names were
// 16.7KB of a 92.3KB payload. The dev-machine drawer reads the EXPANDED records
// (`DispatcherView.recent_builds` / `.remediation_hints`), so a wrong index or a
// dropped element is invisible to the type-checker and shows up only as a
// mislabelled build row on a live fleet. Assert the expansion element-wise, in
// both the browser classifier and the LLM one.
{
  const builds = [
    ["rch", "cargo build -p rch", "Remote", "hz3", 12345, 0, "2026-08-26T11:58:00.000Z"],
    // exit_code 0 and duration_ms 0 are the readings `|| null` would erase:
    // 0 means the build SUCCEEDED, not "no exit code".
    ["beads", "cargo test", "Local", null, 0, 0, "2026-08-26T11:59:00.000Z"],
    ["x", null, null, null, null, 101, null],
  ];
  const dv = derive.classifyDispatcher(d({ builds }));
  chk("build tuples expand one-for-one", dv.recent_builds.length === builds.length,
    `${dv.recent_builds.length} of ${builds.length}`);
  chk("build tuples keep order and every field",
    JSON.stringify(dv.recent_builds) === JSON.stringify(builds.map(
      ([project, command, location, worker_id, duration_ms, exit_code, completed_at]) =>
        ({ project, command, location, worker_id, duration_ms, exit_code, completed_at }))),
    JSON.stringify(dv.recent_builds));
  chk("build expansion agrees between derive and llm-view",
    JSON.stringify(dv.recent_builds) === JSON.stringify(expandBuilds(builds)));
  chk("a zero exit code survives as 0, not null",
    dv.recent_builds[1].exit_code === 0 && dv.recent_builds[1].duration_ms === 0,
    `exit=${dv.recent_builds[1].exit_code} ms=${dv.recent_builds[1].duration_ms}`);
  chk("a failing build keeps its exit code", dv.recent_builds[2].exit_code === 101);

  const hints = [
    ["hz4", "critical", "disk 96% full", "run sbh reclaim", "disk_free_below_critical_gb"],
    ["vmi1", "warn", "telemetry stale", null, null],
  ];
  const hv = derive.classifyDispatcher(d({ hints }));
  chk("hint tuples expand one-for-one", hv.remediation_hints.length === hints.length,
    `${hv.remediation_hints.length} of ${hints.length}`);
  chk("hint tuples keep order and every field",
    JSON.stringify(hv.remediation_hints) === JSON.stringify(hints.map(
      ([worker_id, severity, message, suggested_action, reason_code]) =>
        ({ worker_id, severity, message, suggested_action, reason_code }))),
    JSON.stringify(hv.remediation_hints));
  chk("hint expansion agrees between derive and llm-view",
    JSON.stringify(hv.remediation_hints) === JSON.stringify(expandHints(hints)));
  // DevMachineCard prints this count, DevMachineDrawer keys each row off
  // `worker_id|reason_code|message` — so reason_code has to survive the wire
  // even though it is never displayed.
  chk("hint reason_code survives for the drawer's row keys",
    hv.remediation_hints[0].reason_code === "disk_free_below_critical_gb");

  // A snapshot written before this projection, still cached in a browser tab.
  const old = d();
  delete old.builds;
  delete old.hints;
  const ov = derive.classifyDispatcher(old);
  chk("a pre-tuple snapshot renders instead of throwing",
    ov.recent_builds.length === 0 && ov.remediation_hints.length === 0);
  chk("...and falls back to the lifetime counters for its verdict",
    ov.remoteBasis === "lifetime" && ov.level === "offloading", `${ov.remoteBasis}/${ov.level}`);
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
