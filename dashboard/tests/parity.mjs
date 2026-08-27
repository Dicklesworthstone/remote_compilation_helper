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
import { classifyWorker, classifyDev, expandBuilds, expandHints, seenByColumns } from "../tools/llm-view.mjs";

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

// ------------------------------------ the (dispatcher x worker) slot matrix
//
// The slot readings used to be on the wire THREE times — `worker_slots` per
// dispatcher, plus `seen_by` and `slots_by_dispatcher` per worker — three
// encodings of one d x w structure, the only thing in the snapshot whose size
// is the PRODUCT of both fleet counts. `tools/scaling.mjs` measured it at 91%
// of a 500-dispatcher payload. It is now emitted once, as `pool_slots`: one row
// per dispatcher, aligned to `Snapshot.workers`, `null` where that machine has
// no such worker. Everything below is a way that reconstruction could be wrong
// and produce a WRONG NUMBER rather than an error.
{
  // `null` means "this machine has no such worker"; `[0, 0]` means "derated to
  // zero", which is the alarm the drawer exists to raise. Conflating them is
  // the central failure mode of the row encoding.
  const row = [[0, 16], null, [4, 8], null, [2, 0]];
  const dv = derive.classifyDispatcher(d({ pool_slots: row }));
  chk("pool_slots drops the nulls rather than expanding them",
    dv.workers.length === 3, `${dv.workers.length} of 3`);
  chk("pool_slots keeps order and values across the gaps",
    JSON.stringify(dv.workers) ===
      JSON.stringify([{ used_slots: 0, total_slots: 16 }, { used_slots: 4, total_slots: 8 },
                      { used_slots: 2, total_slots: 0 }]),
    JSON.stringify(dv.workers));
  chk("a null is never counted as a zero-slot worker",
    dv.workers.filter((x) => (x.total_slots ?? 0) === 0).length === 1,
    `${dv.workers.filter((x) => (x.total_slots ?? 0) === 0).length} of 1`);
  chk("drawer aggregates match the surviving pairs",
    dv.workers.reduce((n, x) => n + (x.total_slots ?? 0), 0) === 24 &&
    dv.workers.reduce((n, x) => n + (x.used_slots ?? 0), 0) === 6);
  // Trailing nulls are trimmed by the collector, so a dispatcher that sees only
  // the first workers of a large fleet ships a SHORT row. Reading past its end
  // must yield "not seen", never a zero reading.
  chk("a short row is read as absence, not as zeroes",
    derive.classifyDispatcher(d({ pool_slots: [[1, 2]] })).workers.length === 1);
  // Both encodings can be in flight at once: a tab holding an older bundle, a
  // stale published file. `pool_slots` is authoritative when present.
  chk("pool_slots wins over a legacy worker_slots on the same record",
    derive.classifyDispatcher(d({ pool_slots: [[9, 9]], worker_slots: [[1, 1], [2, 2]] }))
      .workers.length === 1);
}

// `seen_by` is the same matrix read by COLUMN, and the browser and the LLM view
// derive it independently — the exact shape of drift this file exists to catch.
{
  const workers = [w({ id: "wa" }), w({ id: "wb" }), w({ id: "wc" })];
  const dispatchers = [
    d({ id: "dev-1", pool_slots: [[1, 8], null, [3, 8]] }),
    d({ id: "dev-2", pool_slots: [[2, 4], [5, 5]] }),
  ];
  const snapM = {
    schema: "x", label: "l", generated_at: new Date(SNAP_MS).toISOString(),
    totals: {}, dispatchers, workers, history: [],
  };
  const views = derive.classifyAll(snapM);
  const cols = seenByColumns(snapM);
  const expected = [["dev-1", "dev-2"], ["dev-2"], ["dev-1"]];
  for (let i = 0; i < workers.length; i++) {
    chk(`seen_by column ${i} is read from the rows`,
      JSON.stringify(views[i].seen_by) === JSON.stringify(expected[i]),
      JSON.stringify(views[i].seen_by));
    chk(`seen_by column ${i} agrees between derive and llm-view`,
      JSON.stringify(views[i].seen_by) === JSON.stringify(cols[i]),
      `derive=${JSON.stringify(views[i].seen_by)} llm=${JSON.stringify(cols[i])}`);
  }
  // Dispatcher order is the contract: the drawer lists machines in it, and the
  // collector built the old inline copy by iterating dispatchers outermost.
  chk("slots_by_dispatcher is keyed in dispatcher order",
    JSON.stringify(Object.keys(views[0].slots_by_dispatcher)) === JSON.stringify(["dev-1", "dev-2"]),
    JSON.stringify(Object.keys(views[0].slots_by_dispatcher)));
  chk("slots_by_dispatcher carries the per-observer readings",
    JSON.stringify(views[0].slots_by_dispatcher) ===
      JSON.stringify({ "dev-1": { used: 1, total: 8 }, "dev-2": { used: 2, total: 4 } }),
    JSON.stringify(views[0].slots_by_dispatcher));
  // Lazily materialised, so it must survive every way a consumer might read it.
  // Serialise ONCE and read the result back, rather than round-tripping as a
  // clone: what is under test is exactly what a consumer receives after the
  // view has been through JSON, so the serialized form is the subject, not an
  // incidental copy.
  const serializedView = JSON.stringify(views[0]);
  chk("the lazy slot record survives a spread and JSON round-trip",
    JSON.stringify({ ...views[0] }.slots_by_dispatcher) ===
      JSON.stringify(views[0].slots_by_dispatcher) &&
    JSON.parse(serializedView).slots_by_dispatcher["dev-2"].total === 4);
  chk("a worker no dispatcher reports keeps both fields absent",
    derive.classifyAll({ ...snapM, workers: [...workers, w({ id: "wd" })] })[3].seen_by === undefined);
  // A snapshot written before the matrix was de-duplicated carries the columns
  // inline; its `worker_slots` index a DIFFERENT space, so re-deriving them
  // would attribute readings to the wrong machines. It must be left alone.
  const legacySnap = {
    ...snapM,
    dispatchers: [d({ id: "dev-1", worker_slots: [[1, 8]] })],
    workers: [w({ id: "wa", seen_by: ["dev-9"], slots_by_dispatcher: { "dev-9": { used: 7, total: 7 } } })],
  };
  chk("a legacy snapshot keeps its own seen_by",
    JSON.stringify(derive.classifyAll(legacySnap)[0].seen_by) === JSON.stringify(["dev-9"]));
  chk("a legacy snapshot keeps its own slots_by_dispatcher",
    derive.classifyAll(legacySnap)[0].slots_by_dispatcher["dev-9"].total === 7);
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

// ------------------------------------------------------ snapshot string table
//
// Most of the strings left in those tuples repeat across dispatchers — every
// box reports the same remediation advice about the same shared worker, so 113
// hints carry 30 distinct messages and 20 distinct suggested actions. The
// collector folds them into ONE snapshot-level `strings[]` and writes an index
// in their place (-24,415B, -31.7% of the payload).
//
// The expansion now lives in two places that must agree exactly — `internedStr`
// in src/derive.ts and its mirror in tools/llm-view.mjs — and an index resolved
// against the wrong table, or a `null` mistaken for entry 0, is invisible to
// the type checker and shows up only as the wrong text on a live fleet.
{
  const strings = ["cargo build -p rch", "disk 96% full", "run sbh reclaim", "hz4", "rch"];
  //                     0                      1                 2            3     4

  // Interned form and literal form of the SAME data. The interned tuples put an
  // index in slots 0/1/3 of a build and 0/2/3/4 of a hint; `location` (2) and
  // `severity` (1) stay literal because they are never interned.
  const internedBuilds = [
    [4, 0, "Remote", 3, 12345, 0, "2026-08-26T11:58:00.000Z"],
    // The null/empty row. `null` must stay null and `""` must stay "": neither
    // may be read as `strings[0]`, which is what a `|| `-style fallback or a
    // truthiness test would do.
    [null, "", "Local", null, 0, 0, "2026-08-26T11:59:00.000Z"],
  ];
  const literalBuilds = [
    ["rch", "cargo build -p rch", "Remote", "hz4", 12345, 0, "2026-08-26T11:58:00.000Z"],
    [null, "", "Local", null, 0, 0, "2026-08-26T11:59:00.000Z"],
  ];
  const internedHints = [
    [3, "critical", 1, 2, 1],
    [null, "warn", 1, null, ""],
  ];
  const literalHints = [
    ["hz4", "critical", "disk 96% full", "run sbh reclaim", "disk 96% full"],
    [null, "warn", "disk 96% full", null, ""],
  ];

  const iv = derive.classifyDispatcher(d({ builds: internedBuilds, hints: internedHints }), strings);
  const lv = derive.classifyDispatcher(d({ builds: literalBuilds, hints: literalHints }));

  chk("interned builds expand to the literal records",
    JSON.stringify(iv.recent_builds) === JSON.stringify(lv.recent_builds),
    JSON.stringify(iv.recent_builds));
  chk("interned hints expand to the literal records",
    JSON.stringify(iv.remediation_hints) === JSON.stringify(lv.remediation_hints),
    JSON.stringify(iv.remediation_hints));
  chk("build interning agrees between derive and llm-view",
    JSON.stringify(iv.recent_builds) === JSON.stringify(expandBuilds(internedBuilds, strings)));
  chk("hint interning agrees between derive and llm-view",
    JSON.stringify(iv.remediation_hints) === JSON.stringify(expandHints(internedHints, strings)));

  // The trap this pass was warned about: a missing value must not collapse into
  // table entry 0. Entry 0 here is "cargo build -p rch", so a `null` project
  // read as an index would render every unnamed build as that command.
  chk("a null interned slot stays null, never entry 0",
    iv.recent_builds[1].project === null && iv.recent_builds[1].worker_id === null &&
    iv.remediation_hints[1].worker_id === null && iv.remediation_hints[1].suggested_action === null,
    JSON.stringify([iv.recent_builds[1].project, iv.remediation_hints[1].suggested_action]));
  chk("an empty interned slot stays the empty string",
    iv.recent_builds[1].command === "" && iv.remediation_hints[1].reason_code === "",
    JSON.stringify([iv.recent_builds[1].command, iv.remediation_hints[1].reason_code]));
  // One index may be referenced from several slots and several dispatchers —
  // that IS the saving — so resolution must be by value, not consumed.
  chk("one table entry serves several slots",
    iv.remediation_hints[0].message === "disk 96% full" &&
    iv.remediation_hints[0].reason_code === "disk 96% full" &&
    iv.remediation_hints[1].message === "disk 96% full");

  // Version skew, both directions.
  //
  // NEW code + OLD snapshot: no table at all, literal strings in every slot.
  // `internedStr` dispatches on the wire type, so these pass straight through —
  // unlike pass 3's key rename, this needs no fallback and loses nothing.
  const noTable = derive.classifyDispatcher(d({ builds: literalBuilds, hints: literalHints }), undefined);
  chk("a pre-table snapshot expands unchanged with no table",
    JSON.stringify(noTable.recent_builds) === JSON.stringify(lv.recent_builds) &&
    JSON.stringify(noTable.remediation_hints) === JSON.stringify(lv.remediation_hints));
  // ...and interned tuples with the table MISSING must degrade to empty values,
  // never to `undefined` rendered as the string "undefined".
  const lost = derive.classifyDispatcher(d({ builds: internedBuilds, hints: internedHints }));
  chk("interned tuples with no table degrade to null, not \"undefined\"",
    lost.recent_builds[0].project === null && lost.remediation_hints[0].message === null,
    JSON.stringify([lost.recent_builds[0].project, lost.remediation_hints[0].message]));
  // A truncated or corrupt table must not throw or leak `undefined` either.
  const short = derive.classifyDispatcher(d({ builds: internedBuilds, hints: internedHints }), ["only-one"]);
  chk("an out-of-range index yields null rather than undefined",
    short.recent_builds[0].project === null && short.recent_builds[0].command === "only-one",
    JSON.stringify([short.recent_builds[0].project, short.recent_builds[0].command]));
  chk("out-of-range agrees between derive and llm-view",
    JSON.stringify(short.recent_builds) === JSON.stringify(expandBuilds(internedBuilds, ["only-one"])));

  // `App.tsx` calls `snap.dispatchers.map(classifyDispatcher)`, so the second
  // argument it actually receives is the element INDEX. A number must never be
  // mistaken for a table, or every interned slot in the browser would resolve
  // to null.
  const mapped = [d({ builds: internedBuilds, hints: internedHints })].map(derive.classifyDispatcher);
  chk("a .map() index is not mistaken for a string table",
    JSON.stringify(mapped[0].recent_builds) === JSON.stringify(lost.recent_builds));

  // The browser never resolves indices in `classifyDispatcher` at all:
  // src/crypto.ts calls `rehydrateStrings()` on the decrypted snapshot, because
  // the table belongs to the snapshot and `.map(classifyDispatcher)` has no
  // argument to carry it. The two paths must produce identical records.
  const wire = {
    schema: "x", label: "l", generated_at: new Date(SNAP_MS).toISOString(),
    totals: {}, workers: [], history: [], strings,
    dispatchers: [d({ builds: structuredClone(internedBuilds), hints: structuredClone(internedHints) })],
  };
  const rehydrated = derive.rehydrateStrings(wire);
  const rv = derive.classifyDispatcher(rehydrated.dispatchers[0]);
  chk("rehydrateStrings matches per-call table resolution",
    JSON.stringify(rv.recent_builds) === JSON.stringify(iv.recent_builds) &&
    JSON.stringify(rv.remediation_hints) === JSON.stringify(iv.remediation_hints),
    JSON.stringify(rv.recent_builds));
  // Idempotent: the tuples now hold strings, and a second pass must leave them
  // alone rather than re-reading a string as an index.
  const twice = derive.classifyDispatcher(derive.rehydrateStrings(rehydrated).dispatchers[0]);
  chk("rehydrateStrings is idempotent",
    JSON.stringify(twice.recent_builds) === JSON.stringify(iv.recent_builds) &&
    JSON.stringify(twice.remediation_hints) === JSON.stringify(iv.remediation_hints));
  // And it must leave the never-interned slots exactly as they were: `location`
  // drives the offload verdict through `.toLowerCase()`, and `severity` picks
  // the alarm colour.
  chk("rehydrateStrings leaves location and severity untouched",
    rehydrated.dispatchers[0].builds[0][2] === "Remote" &&
    rehydrated.dispatchers[0].hints[0][1] === "critical");
  chk("a snapshot with no table survives rehydration",
    derive.rehydrateStrings({ dispatchers: [d()] }) != null &&
    derive.rehydrateStrings({}) != null);

  // The verdict itself must be unaffected: `location` is not interned, so the
  // offload share is computed from the same values either way.
  chk("the offload verdict is identical with and without interning",
    iv.level === lv.level && iv.levelReason === lv.levelReason && iv.remotePct === lv.remotePct,
    `${iv.level}/${iv.levelReason} vs ${lv.level}/${lv.levelReason}`);
  chk("classifyDev reads location off the raw tuple regardless of interning",
    classifyDev(d({ builds: internedBuilds })).remotePct ===
      classifyDev(d({ builds: literalBuilds })).remotePct);
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
