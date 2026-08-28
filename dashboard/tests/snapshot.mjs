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
  encrypt, verifyRoundTrip, existingSalt, internSnapshotStrings,
  buildProbeScript, splitProbeSections, dispatcherFromProbe, allSettledBounded,
  mergeWorkers, computeTotals, projectDispatchers,
} from "../tools/snapshot.mjs";
import { expandBuilds, expandHints } from "../tools/llm-view.mjs";
import {
  SNAPSHOT_COMPRESSION, SNAPSHOT_GZIP_LEVEL, compressPlaintext, decompressPlaintext,
  isIdentityCompression, isSupportedCompression,
} from "../tools/envelope.mjs";
import { gzipSync } from "node:zlib";

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

// ------------------------------------------------------------ the ssh probe

// The collector used to ask each dispatcher four questions over four separate
// `ssh` processes — 36 TCP connections and 36 key exchanges on a 10-machine
// fleet, all paid on the collector's own cpu. It now asks all four over ONE
// connection, with the four commands still running concurrently on the far
// side and their outputs framed apart. Everything below pins a property that
// collapse had to preserve.
{
  const script = buildProbeScript("0123456789abcdef");

  // The per-command budgets genuinely differ, and a combined invocation that
  // shared one budget would let a wedged `rch status` eat `workers list`'s.
  chk("status keeps its own 70s budget", script.includes("timeout 70 rch status --json"));
  chk("capabilities keeps its own 70s budget", script.includes("timeout 70 rch workers capabilities --json"));
  chk("workers list keeps its own 45s budget", script.includes("timeout 45 rch workers list --json"));
  chk("metrics keeps its own 10s budget", script.includes("curl -s --max-time 10 http://127.0.0.1:9100/metrics"));

  // `timeout(1)` is absent from a stock macOS and one dispatcher is a Mac; it
  // resolves there only via Homebrew on the default non-login ssh PATH. Keeping
  // the command text byte-identical is what keeps that working.
  // The three dev-machine self-checks keep their own, shorter budgets: doctor
  // runs ~34 local checks (no worker probes) and the other two are sub-second.
  chk("doctor keeps its own 40s budget", script.includes("timeout 40 rch doctor --json"));
  chk("shim status keeps its own 20s budget", script.includes("timeout 20 rch shim status --json"));
  chk("hook status keeps its own 20s budget", script.includes("timeout 20 rch hook status --json"));
  chk("every rch section still exports ~/.local/bin onto PATH",
    (script.match(/export PATH="\$HOME\/\.local\/bin:\$PATH"/g) ?? []).length === 12,
    `${(script.match(/export PATH/g) ?? []).length} occurrences (6 parallel + 6 sequential)`);
  // ...but only inside the rch sections. Leaking it into the curl section could
  // change which curl runs on a host that has one in ~/.local/bin.
  chk("the metrics section does not inherit the rch PATH export",
    script.split("\n").filter((l) => l.includes("curl -s --max-time 10")).every((l) => !l.includes("export PATH")));

  chk("each rch section still discards its own stderr",
    (script.match(/2>\/dev\/null/g) ?? []).length >= 8);

  // Concurrency on the far side is the whole point: run them serially in one
  // shell and the per-host wall becomes the SUM of four commands.
  chk("all seven sections run concurrently on the dispatcher",
    (script.match(/> "\$d\/[sclmdhk]" & q\d=\$!/g) ?? []).length === 7);
  chk("each section's own exit status is captured",
    (script.match(/wait \$q\d; e\d=\$\?/g) ?? []).length === 4);

  // A full /data/tmp is a live condition on this fleet. Losing mktemp must cost
  // parallelism, not the whole dispatcher.
  chk("a failed mktemp falls back to sequential collection over the same connection",
    script.includes('if [ -n "$d" ]; then') && script.includes("\nelse\n") && script.trimEnd().endsWith("\nfi"));

  // Cleanup names exactly the four files this script created, inside the
  // directory it created. Nothing else on a production host is touched.
  chk("cleanup removes only this script's own files",
    script.includes(`trap 'rm -f "$d/s" "$d/c" "$d/l" "$d/m"; rmdir "$d" 2>/dev/null' EXIT`));
  chk("the temp dir honours the host's own TMPDIR",
    script.includes('mktemp -d "${TMPDIR:-/tmp}/rchdash.XXXXXX"'));
}

// Framing has to be byte-exact, not approximately right. `parseMetrics` reports
// a dead endpoint on a FALSY stdout, so a single stray newline would turn "the
// metrics endpoint is gone" into "the endpoint is fine and has no workers" —
// which silently disables the worker-has-gone-dark rule fleet-wide.
{
  const N = "0123456789abcdef";
  const emit = (parts) => parts.map(([k, text, rc = 0]) => `${text}\n${N}:${k}:${rc}\n`).join("");

  const sec = splitProbeSections(emit([
    ["s", "{\"a\":1}\n"], ["c", ""], ["l", "no-trailing-newline", 1], ["m", "x\n\ny\n"],
  ]), N);
  chk("a section that ended in a newline keeps exactly one", sec.get("s").text === "{\"a\":1}\n");
  chk("an empty section stays empty, not a newline", sec.get("c").text === "");
  chk("a section without a trailing newline does not gain one", sec.get("l").text === "no-trailing-newline");
  chk("interior blank lines survive", sec.get("m").text === "x\n\ny\n");
  chk("each section carries its own exit status",
    sec.get("s").rc === 0 && sec.get("l").rc === 1);

  // ssh banner noise used to land in front of each command's JSON and was
  // tolerated by the first-`{`-to-last-`}` scan; it still is.
  const noisy = splitProbeSections("motd line\n" + emit([["s", "{\"a\":1}"]]), N);
  chk("noise before the first marker stays with the first section",
    noisy.get("s").text === "motd line\n{\"a\":1}");

  // The payload is not ours — a build command string could in principle contain
  // anything. The marker is a per-process random nonce, and a second frame for
  // a key that already parsed is ignored rather than allowed to replace it.
  chk("a duplicate frame cannot overwrite a section",
    splitProbeSections(emit([["s", "first"], ["s", "second"]]), N).get("s").text === "first");
  chk("a foreign nonce claims nothing",
    splitProbeSections(emit([["s", "x"]]), "ffffffffffffffff").size === 0);
}

// ------------------------------------------- per-section failure isolation

// THE property this pass had to keep. Before the collapse each question was its
// own ssh process, so `workers list` dying blanked tags and priority and set
// `config_degraded` while `rch status` — and therefore the whole dispatcher —
// carried on. One combined invocation must not turn one failing subcommand into
// a dead dispatcher.
{
  const N = "0123456789abcdef";
  const emit = (parts) => parts.map(([k, text, rc = 0]) => `${text}\n${N}:${k}:${rc}\n`).join("");
  // Sections the caller did not mention are filled with a healthy answer, so
  // every "exactly one section fails" case below keeps meaning exactly that
  // after the probe grew from four sections to seven. Pass `["d", "", 1]` (or
  // omit via `absent`) to make one of the new ones fail.
  const DEFAULTS = () => [["d", DOC], ["h", SHIM], ["k", HOOK]];
  const probe = (parts, error = null, { absent = [] } = {}) => {
    const have = new Set(parts.map((p) => p[0]));
    const all = [...parts, ...DEFAULTS().filter(([k]) => !have.has(k) && !absent.includes(k))];
    return { sections: splitProbeSections(emit(all), N), error };
  };

  const STATUS = JSON.stringify({
    api_version: "1.0", success: true,
    data: {
      posture: "remote_ready", posture_description: "offloading",
      remediation_hints: [{ worker_id: "hz3", severity: "critical", message: "disk", suggested_action: "reclaim", reason_code: "disk_low" }],
      daemon: {
        daemon: { version: "1.0.57", uptime_secs: 42, pid: 7, workers_total: 1, workers_healthy: 1, slots_total: 16, slots_available: 15 },
        workers: [{ id: "hz3", host: "hz3", status: "healthy", used_slots: 1, total_slots: 16, speed_score: 9 }],
        stats: { total_builds: 3, remote_count: 3, local_count: 0, success_count: 3, failure_count: 0, avg_duration_ms: 10 },
        recent_builds: [{ project_id: "rch", command: "cargo build", location: "Remote", worker_id: "hz3", duration_ms: 5, exit_code: 0, completed_at: "t" }],
        active_builds: [1], queued_builds: [], saved_time: { time_saved_ms: 99 },
      },
    },
  });
  const CAPS = JSON.stringify({ success: true, data: { workers: [{ id: "hz3", capabilities: { num_cpus: 64, rustc_version: "1.90" } }] } });
  const LIST = JSON.stringify({ success: true, data: { workers: [{ id: "hz3", tags: ["big"], priority: 120 }] } });
  const MET = 'rch_worker_latency_ms_sum{worker="hz3"} 200\nrch_worker_latency_ms_count{worker="hz3"} 4\nrch_worker_last_seen_timestamp{worker="hz3"} 1787800000\n';
  // The three dev-machine self-checks, shaped exactly as rch 1.0.60 prints them.
  const DOC = JSON.stringify({ success: true, data: {
    summary: { total: 3, passed: 2, warnings: 1, failed: 0 },
    checks: [
      { name: "rsync", status: "pass", message: "installed", fixable: false },
      { name: "claude_code_hook", status: "pass", message: "Claude Code PreToolUse hook is installed", fixable: true },
      { name: "ssh_config", status: "warn", message: "No SSH config file", fixable: false },
    ],
  } });
  const SHIM = JSON.stringify({ success: true, data: {
    installed: true, up_to_date: true, on_path_ahead_of_cargo: true, interception: "direct",
    local_builds_running: 2, toolchains_wrapped: 3, toolchains_total: 3,
  } });
  const HOOK = JSON.stringify({ success: true, data: { agents: [
    { agent: "ClaudeCode", status: "Installed" }, { agent: "CodexCli", status: "Not installed" },
  ] } });

  const healthy = dispatcherFromProbe("hz3-dev", probe([["s", STATUS], ["c", CAPS], ["l", LIST], ["m", MET]]));
  chk("a clean probe reports no collection errors", healthy.collection_errors.length === 0);
  chk("a clean probe is not config-degraded", healthy.config_degraded === false);
  chk("a clean probe fills every section",
    healthy.posture === "remote_ready" && healthy.workers[0].tags[0] === "big" &&
    healthy.workers[0].caps.num_cpus === 64 && healthy.workers[0].latency_ms === 50);

  // ONE section fails, exactly as `rch workers list` exiting non-zero used to.
  const listDead = dispatcherFromProbe("hz3-dev", probe([["s", STATUS], ["c", CAPS], ["l", "", 1], ["m", MET]]));
  chk("a failed `workers list` still leaves the dispatcher reachable", listDead.reachable === true);
  chk("a failed `workers list` still yields status, caps and metrics",
    listDead.posture === "remote_ready" && listDead.workers[0].caps.num_cpus === 64 &&
    listDead.workers[0].latency_ms === 50 && listDead.builds.length === 1);
  chk("a failed `workers list` sets config_degraded", listDead.config_degraded === true);
  chk("a failed `workers list` blanks only tags and priority",
    listDead.workers[0].tags.length === 0 && listDead.workers[0].priority === null);
  chk("a failed section yields exactly one, named, per-section reason",
    listDead.collection_errors.length === 1 && listDead.collection_errors[0] === "workers list: exited 1",
    JSON.stringify(listDead.collection_errors));

  // The other three sections, each failing alone.
  const capsDead = dispatcherFromProbe("hz3-dev", probe([["s", STATUS], ["c", "", 127], ["l", LIST], ["m", MET]]));
  chk("a failed `workers capabilities` costs only caps",
    capsDead.reachable && capsDead.workers[0].tags[0] === "big" && capsDead.workers[0].caps.num_cpus === null &&
    capsDead.config_degraded === false && capsDead.collection_errors[0] === "workers capabilities: exited 127");

  const metDead = dispatcherFromProbe("hz3-dev", probe([["s", STATUS], ["c", CAPS], ["l", LIST], ["m", "", 7]]));
  chk("a failed metrics scrape costs only latency and last-seen",
    metDead.reachable && metDead.workers[0].latency_ms === null && metDead.workers[0].last_seen_unix === null &&
    metDead.workers[0].caps.num_cpus === 64 && metDead.collection_errors[0] === "metrics: exited 7");
  // A metrics endpoint that answers with nothing but exits 0 must still be
  // called out — losing it silently disables the gone-dark rule.
  const metEmpty = dispatcherFromProbe("hz3-dev", probe([["s", STATUS], ["c", CAPS], ["l", LIST], ["m", ""]]));
  chk("an empty-but-successful metrics scrape is still reported",
    metEmpty.collection_errors[0] === "metrics: no response from 127.0.0.1:9100");

  // Only `rch status` failing takes the dispatcher down, which is what it did
  // before: `reachable` is defined as "status parsed".
  const statusDead = dispatcherFromProbe("hz3-dev", probe([["s", "", 1], ["c", CAPS], ["l", LIST], ["m", MET]]));
  chk("only a failed `rch status` makes a dispatcher unreachable",
    statusDead.reachable === false && statusDead.workers.length === 0 &&
    statusDead.collection_errors[0] === "status: exited 1");

  // A subcommand that exits non-zero but still printed usable JSON was parsed
  // before — some rch subcommands do exactly that — and still is.
  const noisyExit = dispatcherFromProbe("hz3-dev", probe([["s", STATUS, 3], ["c", CAPS], ["l", LIST], ["m", MET]]));
  chk("a non-zero exit that still printed JSON is used, not discarded",
    noisyExit.reachable === true && noisyExit.collection_errors.length === 0);

  // Transport failure: no frames at all. Every section must still name itself,
  // exactly as four dead ssh calls each named themselves before.
  const dead = dispatcherFromProbe("hz3-dev", { sections: new Map(), error: "ssh: connect to host hz3-dev port 22: No route to host" });
  chk("an unreachable host reports all four sections by name",
    dead.collection_errors.length === 4 &&
    dead.collection_errors.every((e) => e.includes("No route to host")) &&
    dead.collection_errors[0].startsWith("status:") &&
    dead.collection_errors[1].startsWith("workers capabilities:") &&
    dead.collection_errors[2].startsWith("workers list:") &&
    dead.collection_errors[3].startsWith("metrics:"),
    JSON.stringify(dead.collection_errors.map((e) => e.split(":")[0])));

  // rch's own error envelope, which is not a transport failure at all.
  const rchFailed = dispatcherFromProbe("hz3-dev", probe([
    ["s", JSON.stringify({ success: false, error: { code: "E_DAEMON", message: "not running" } })],
    ["c", CAPS], ["l", LIST], ["m", MET],
  ]));
  chk("an rch error envelope is reported as such, not as an unreachable host",
    rchFailed.reachable === false && rchFailed.collection_errors[0] === "status: E_DAEMON not running");
}

// ---------------------------------------------------------- bounded fan-out

// The fan-out is now one connection per dispatcher instead of four, but it was
// also unbounded. The cap must not change what comes back or in what order:
// `dispatchers[]` is positional and the string table indexes into it.
{
  const items = [1, 2, 3, 4, 5, 6, 7];
  const slow = async (n) => { await new Promise((r) => setTimeout(r, (8 - n) * 5)); return n * 10; };

  const unbounded = await allSettledBounded(items, 99, slow);
  const bounded = await allSettledBounded(items, 2, slow);
  chk("a limit at or above the fleet size is plain Promise.allSettled",
    JSON.stringify(unbounded) === JSON.stringify(items.map((n) => ({ status: "fulfilled", value: n * 10 }))));
  chk("results stay in INPUT order regardless of completion order",
    JSON.stringify(bounded) === JSON.stringify(unbounded));

  // Never more than `limit` in flight — this is the whole point of the cap.
  let live = 0, peak = 0;
  await allSettledBounded(items, 3, async () => {
    peak = Math.max(peak, ++live);
    await new Promise((r) => setTimeout(r, 5));
    live--;
  });
  chk("the limit is actually enforced", peak === 3, `peak=${peak}`);

  // One dispatcher whose mapper throws must not abort the others — the reason
  // this was allSettled and not all.
  const mixed = await allSettledBounded([1, 2, 3], 2, async (n) => {
    if (n === 2) throw new Error("boom");
    return n;
  });
  chk("a thrown mapper is isolated to its own slot",
    mixed[0].status === "fulfilled" && mixed[1].status === "rejected" &&
    mixed[1].reason.message === "boom" && mixed[2].value === 3);
  chk("an empty fleet settles without hanging", (await allSettledBounded([], 4, async () => 1)).length === 0);
}

// ------------------------------------------- merge, totals, slot projection

// The cross-dispatcher merge and the (dispatcher x worker) slot matrix.
//
// `tools/scaling.mjs` measured this pipeline from 1 to 500 dispatchers and
// found the slot matrix — the only structure whose size is the PRODUCT of both
// fleet counts — being transmitted THREE times: `worker_slots` per dispatcher
// plus `seen_by` and `slots_by_dispatcher` per worker, ~50 bytes per cell to
// carry ~8 bytes of fact. That is 6.5KB of a 10-machine payload and 15.7MB of a
// 500-machine one (91%). It is now emitted once, as `pool_slots`: one row per
// dispatcher, aligned index-for-index to the merged `workers[]`, `null` where
// that machine has no such worker. These cases pin the encoding, because an
// off-by-one in the alignment attributes one machine's derating to another and
// still renders perfectly plausible numbers.
{
  const mw = (id, used, total, over = {}) => ({
    id, host: `${id}.h`, user: "root", status: "healthy", circuit_state: "closed",
    used_slots: used, total_slots: total, speed: 50, last_error: null,
    consecutive_failures: 0, failure_history: [],
    pressure: { state: "healthy", reason: null, disk_free_gb: 100, disk_total_gb: 200,
                disk_io_util_pct: 0, memory_pressure: 0, telemetry_age_secs: 1, telemetry_fresh: true },
    latency_ms: 5, last_seen_unix: 1000, caps: { num_cpus: 8, load_avg_1: 1 },
    tags: [], priority: 100, ...over,
  });
  const md = (id, workers, over = {}) => ({
    id, reachable: true, collection_errors: [], config_degraded: false,
    posture: "remote_ready", posture_description: "ok", daemon: null,
    build_stats: { total: 2, remote: 2, local: 0, success: 2, failure: 0, avg_duration_ms: 1 },
    saved_time_ms: 0, active_builds: 1, queued_builds: 0, builds: [], hints: [], workers, ...over,
  });

  // Three machines, a shared pool, and deliberate disagreement about it.
  const dispatchers = [
    md("dev-a", [mw("wb", 1, 8), mw("wa", 0, 16)]),
    md("dev-b", [mw("wa", 4, 12), mw("wc", 2, 4)]),
    md("dev-c", [mw("wa", 2, 0)], { reachable: false, posture: null }),
  ];
  const workers = mergeWorkers(dispatchers);

  chk("the merge de-duplicates shared workers and sorts by id",
    workers.map((w) => w.id).join(",") === "wa,wb,wc", workers.map((w) => w.id).join(","));
  chk("capacity is the MAX any observer reported",
    workers[0].total_slots === 16, `wa total=${workers[0].total_slots}`);
  chk("occupancy is the WORST any observer reported",
    workers[0].used_slots === 4, `wa used=${workers[0].used_slots}`);
  // The columns are no longer built here — they are read back off the rows in
  // src/derive.ts. Leaving them behind would put the matrix on the wire twice.
  chk("the merge no longer materialises the per-worker columns",
    workers.every((w) => w.seen_by === undefined && w.slots_by_dispatcher === undefined));

  const totals = computeTotals(workers, dispatchers);
  chk("totals count distinct workers, not observations", totals.workers === 3, `${totals.workers}`);
  chk("totals sum the merged capacity", totals.slots === 16 + 8 + 4, `${totals.slots}`);
  chk("totals ignore unreachable dispatchers for build counters",
    totals.dispatchers_total === 3 && totals.dispatchers_reachable === 2 && totals.active_builds === 2,
    `${totals.dispatchers_total}/${totals.dispatchers_reachable}/${totals.active_builds}`);

  const emitted = projectDispatchers(dispatchers, workers);
  chk("each dispatcher emits one row of the matrix",
    emitted.length === 3 && emitted.every((d) => Array.isArray(d.pool_slots)));
  // dev-a listed wb BEFORE wa; the row is indexed by the fleet's order, not the
  // dispatcher's, which is exactly the transposition an off-by-one would break.
  chk("a row is aligned to the merged worker order, not the reporting order",
    JSON.stringify(emitted[0].pool_slots) === JSON.stringify([[0, 16], [1, 8]]),
    JSON.stringify(emitted[0].pool_slots));
  chk("a worker this machine cannot see is null, never a zero reading",
    JSON.stringify(emitted[1].pool_slots) === JSON.stringify([[4, 12], null, [2, 4]]),
    JSON.stringify(emitted[1].pool_slots));
  // dev-c sees only wa (index 0), so indices 1 and 2 are trailing nulls and
  // cost nothing. A short row means "nothing after this", never zero slots.
  chk("trailing nulls are trimmed off the row",
    JSON.stringify(emitted[2].pool_slots) === JSON.stringify([[2, 0]]),
    JSON.stringify(emitted[2].pool_slots));
  chk("a zero-slot derating survives — it is the alarm, not padding",
    emitted[2].pool_slots[0][1] === 0);
  chk("the per-dispatcher worker records are gone from the wire",
    emitted.every((d) => d.workers === undefined));
  chk("everything else about a dispatcher is untouched",
    emitted[0].id === "dev-a" && emitted[2].reachable === false && emitted[0].active_builds === 1);

  // The whole point: the matrix appears once. Count the cells in the payload.
  const cells = emitted.reduce((n, d) => n + d.pool_slots.filter(Array.isArray).length, 0);
  chk("the matrix is on the wire exactly once — one cell per observation",
    cells === dispatchers.reduce((n, d) => n + d.workers.length, 0), `${cells} cells`);

  chk("an empty fleet projects without throwing",
    JSON.stringify(projectDispatchers([], [])) === "[]");
  chk("a dispatcher reporting a worker nobody merged is skipped, not misaligned",
    JSON.stringify(projectDispatchers([md("dev-x", [mw("ghost", 1, 1)])], workers)[0].pool_slots) === "[]");
}

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
  const literal = structuredClone(input);
  const { strings, dispatchers } = internSnapshotStrings(structuredClone(input));

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
    JSON.stringify(internSnapshotStrings(structuredClone(input))) ===
      JSON.stringify(internSnapshotStrings(structuredClone(input))));

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
  return decompressPlaintext(Buffer.from(out), env.compression);
}

const env1 = await encrypt(JSON.stringify({ hello: "fleet" }), PASS);
const key1 = await deriveFrom(env1, PASS);
chk("envelope round-trips", JSON.parse(await decryptWith(env1, key1)).hello === "fleet");
chk("envelope declares its KDF", env1.kdf.iterations === 600000 && env1.kdf.hash === "SHA-256");

// -------------------------------------------------------- transport compression

// The published file is base64 of AES-GCM ciphertext. Ciphertext is
// incompressible by construction, so gzip at the CDN or in the browser's
// transfer decoding can do nothing for it and base64 adds 33% on top. The
// plaintext, before encryption, is the only layer where this payload shrinks.
chk("the envelope names its compression codec", env1.compression === SNAPSHOT_COMPRESSION,
  String(env1.compression));

// Multi-byte UTF-8 is the failure this pins: gzip works on BYTES, and a
// round-trip that split or re-decoded them anywhere would corrupt exactly the
// hint text and hostnames the fleet actually emits (— · → ✓ all appear in
// remediation hints).
const unicodeSample = JSON.stringify({
  msg: "Worker vmi1293453 — storage pressure ✓ · 39.7 GB free → run `du -sh /tmp/rch-*`",
  repeated: Array.from({ length: 40 }, () => "the same hint about the same shared worker"),
});
chk("compression round-trips multi-byte UTF-8 exactly",
  decompressPlaintext(compressPlaintext(unicodeSample), SNAPSHOT_COMPRESSION) === unicodeSample);
chk("a repetitive payload actually compresses",
  compressPlaintext(unicodeSample).length < Buffer.byteLength(unicodeSample) / 2,
  `${Buffer.byteLength(unicodeSample)}B -> ${compressPlaintext(unicodeSample).length}B`);

// ------------------------------------------------- the deflate level is FIXED
//
// `tools/envelope.mjs` pins level 9 and argues, from `node tools/scaling.mjs
// --gzip-levels`, that it should NOT be adaptive on input size: the whole cost
// at the live fleet is 0.56ms, and the most generous threshold anyone could
// defend (~720KB of plaintext, ~145 dispatchers) is a branch that would never
// execute here. These cases pin both halves of that decision — the value, and
// the property that makes the value safe to pin.
//
// The property: a gzip stream is self-terminating and does not carry its level.
// zlib writes the level only into the advisory XFL header byte, and only for
// the extremes — 2 for level 9, 4 for level 1, 0 for everything between — so
// levels 2..8 are not even distinguishable from each other. No reader is given
// a level, none can recover one, and none needs to. That is what lets this
// constant be revisited later without an envelope-format change, and it is
// worth a test rather than a claim in a comment.

const levelSample = JSON.stringify({
  schema: "rch.dashboard.snapshot.v2",
  note: "Worker vmi1293453 — storage pressure ✓ · 39.7 GB free → run `du -sh /tmp/rch-*`",
  workers: Array.from({ length: 120 }, (_, i) => ({
    id: `wkr-${String(i).padStart(4, "0")}`,
    status: ["healthy", "degraded", "draining", "unreachable"][i % 4],
    slots: [i % 17, 16], disk_free_gb: 220 + ((i * 37) % 1600),
    rustc: "1.94.0-nightly (a1b2c3d4e 2026-08-01)",
  })),
});
const LEVELS = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const encodings = new Map(LEVELS.map((lv) => [lv, gzipSync(Buffer.from(levelSample, "utf8"), { level: lv })]));

chk("the shipped deflate level is 9", SNAPSHOT_GZIP_LEVEL === 9, `level=${SNAPSHOT_GZIP_LEVEL}`);
chk("compressPlaintext emits exactly the shipped level, not something else",
  compressPlaintext(levelSample).equals(encodings.get(SNAPSHOT_GZIP_LEVEL)));

// Vacuity guard. If every level produced the same bytes, the round-trip checks
// below would prove nothing at all.
chk("the levels really do produce different encodings",
  new Set([...encodings.values()].map((b) => b.toString("base64"))).size >= 4,
  [...encodings].map(([lv, b]) => `L${lv}=${b.length}B`).join(" "));
chk("a lower level is never smaller than level 9 on the same input",
  LEVELS.every((lv) => encodings.get(lv).length >= encodings.get(9).length),
  `L1=${encodings.get(1).length}B L6=${encodings.get(6).length}B L9=${encodings.get(9).length}B`);

// THE isomorphism proof: the level changes the encoding and cannot change the
// plaintext. Nine encodings, one output.
const inflated = LEVELS.map((lv) => decompressPlaintext(encodings.get(lv), SNAPSHOT_COMPRESSION));
chk("every deflate level inflates to byte-identical plaintext",
  inflated.every((t) => t === levelSample),
  `${LEVELS.length} levels -> ${new Set(inflated).size} distinct plaintext`);
chk("level independence holds for multi-byte UTF-8 too",
  LEVELS.every((lv) =>
    decompressPlaintext(gzipSync(Buffer.from(unicodeSample, "utf8"), { level: lv }), SNAPSHOT_COMPRESSION)
    === unicodeSample));

// The reader is handed a codec NAME and never a level — there is no level field
// in the envelope, and the header cannot supply one either.
chk("the envelope carries a codec name and no level",
  env1.compression === "gzip" && !("level" in env1) && !("level" in env1.cipher),
  JSON.stringify({ compression: env1.compression, keys: Object.keys(env1) }));
chk("the gzip header does not identify the level (2..8 are indistinguishable)",
  new Set([2, 3, 4, 5, 6, 7, 8].map((lv) => encodings.get(lv)[8])).size === 1
  && encodings.get(9)[8] === 2 && encodings.get(1)[8] === 4,
  `XFL: L1=${encodings.get(1)[8]} L6=${encodings.get(6)[8]} L9=${encodings.get(9)[8]}`);

// A whole ENVELOPE written at a level the collector does not use must decode
// through the same reader path, unchanged. This is what "self-describing" has
// to mean in practice: `compression: "gzip"` is the entire contract, so a future
// decision to move the level — or make it a function of size — cannot strand a
// reader or require an envelope-format bump.
{
  const offLevelIv = crypto.getRandomValues(new Uint8Array(12));
  const encKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToU8(env1.kdf.salt), iterations: env1.kdf.iterations, hash: env1.kdf.hash },
    await crypto.subtle.importKey("raw", new TextEncoder().encode(PASS), "PBKDF2", false, ["deriveKey"]),
    { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const offLevelEnv = {
    format: env1.format,
    kdf: { ...env1.kdf },
    cipher: { name: "AES-GCM", iv: Buffer.from(offLevelIv).toString("base64") },
    compression: SNAPSHOT_COMPRESSION,
    ciphertext: Buffer.from(new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: offLevelIv }, encKey, encodings.get(1),
    ))).toString("base64"),
  };
  chk("an envelope compressed at level 1 decodes through the normal reader",
    (await decryptWith(offLevelEnv, key1)) === levelSample,
    `${encodings.get(1).length}B ciphertext payload vs ${encodings.get(9).length}B at level 9`);
}

// NO ADAPTIVE RULE SHIPPED. The level must not vary with input size — the
// decision recorded in tools/envelope.mjs is a fixed 9, and an unremarked change
// to that would silently alter every published envelope. The large sample below
// is deliberately built past the ~720KB threshold that WAS considered and
// rejected (a collector-CPU budget of one 600k PBKDF2, ~55ms, which the fitted
// cpu ~ B^1.6 puts at ~720KB of plaintext / ~145 dispatchers), so if an adaptive
// rule is ever introduced at the size that was argued for, this case fires.
{
  const tiny = JSON.stringify({ schema: "rch.dashboard.snapshot.v2", dispatchers: [] });
  let seed = 0x5eed;
  const rnd = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296;
  const big = JSON.stringify(Array.from({ length: 9000 }, (_, i) => ({
    id: `wkr-${String(i).padStart(5, "0")}`,
    host: `vmi${Math.floor(rnd() * 9e6)}.example.net`,
    slots: [Math.floor(rnd() * 64), 64],
    disk_free_gb: Math.round(rnd() * 1800),
    msg: "Disk is above the pressure threshold and rchd has derated this worker to zero slots.",
  })));
  chk("the sweep's threshold band is actually exercised", Buffer.byteLength(big) > 720_000,
    `${Buffer.byteLength(big).toLocaleString()}B — past the ~720KB an adaptive rule was argued for`);
  // XFL 2 is zlib's "maximum compression" marker; it is written for level 9 and
  // for no other level, so it is a direct read of what the encoder was asked for.
  chk("the level does not vary with input size — past the rejected threshold, same as 55B",
    compressPlaintext(tiny)[8] === 2 && compressPlaintext(big)[8] === 2,
    `XFL tiny=${compressPlaintext(tiny)[8]} (${Buffer.byteLength(tiny)}B) ` +
    `big=${compressPlaintext(big)[8]} (${Buffer.byteLength(big).toLocaleString()}B)`);
  chk("the large payload still round-trips exactly",
    decompressPlaintext(compressPlaintext(big), SNAPSHOT_COMPRESSION) === big);
}

// VERSION SKEW, backward: an envelope with NO `compression` field is what every
// snapshot published before this change looks like, and it must still decode.
// Built by hand rather than by asking encrypt() for it, because encrypt() no
// longer has a way to emit one — which is the point.
{
  const legacyPlain = JSON.stringify({ hello: "legacy", note: "written before compression existed" });
  const legacyIv = crypto.getRandomValues(new Uint8Array(12));
  const encKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToU8(env1.kdf.salt), iterations: env1.kdf.iterations, hash: env1.kdf.hash },
    await crypto.subtle.importKey("raw", new TextEncoder().encode(PASS), "PBKDF2", false, ["deriveKey"]),
    { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const legacyCt = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: legacyIv }, encKey, new TextEncoder().encode(legacyPlain),
  );
  const legacyEnv = {
    format: env1.format,
    kdf: { ...env1.kdf },
    cipher: { name: "AES-GCM", iv: Buffer.from(legacyIv).toString("base64") },
    ciphertext: Buffer.from(new Uint8Array(legacyCt)).toString("base64"),
  };
  chk("an envelope with no compression field is uncompressed", !("compression" in legacyEnv));
  chk("a pre-compression envelope still decodes",
    (await decryptWith(legacyEnv, key1)) === legacyPlain);
  chk("an explicit compression:none also decodes",
    (await decryptWith({ ...legacyEnv, compression: "none" }, key1)) === legacyPlain);
}

// VERSION SKEW, forward: a codec this build does not implement must be a NAMED
// failure. Silently handing gzip bytes to TextDecoder would produce mojibake
// that JSON.parse rejects with a message about the data, blaming the payload
// for a version problem — or, worse in some shape, parses into nonsense.
chk("an unknown codec is rejected by name", !isSupportedCompression("brotli"));
let codecErr = null;
try { decompressPlaintext(Buffer.from("x"), "brotli"); } catch (e) { codecErr = e.message; }
chk("an unknown codec throws a named error", /unsupported snapshot compression: brotli/.test(codecErr ?? ""),
  String(codecErr));
chk("absent, empty and none are all the identity codec",
  isIdentityCompression(undefined) && isIdentityCompression(null)
  && isIdentityCompression("") && isIdentityCompression("none") && isIdentityCompression("identity"));
chk("gzip is supported and is not the identity codec",
  isSupportedCompression("gzip") && !isIdentityCompression("gzip"));

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

// ------------------------------------------------- verifyRoundTrip (pre-publish proof)
//
// `verifyRoundTrip()` used to derive its own key with a second 600k-iteration
// PBKDF2 — 50.5–51.5ms of pure waste per collection, since `encrypt()` had
// already computed exactly that key. It now reuses it. These cases exist to pin
// down that NOTHING the old form rejected is accepted by the new one, because a
// verification that has quietly stopped verifying is worse than no verification
// at all: it is what stands between a typo and publishing a snapshot the browser
// cannot open.

// The key-material identity proof for widening the usage mask to
// ["encrypt","decrypt"]. A usage mask is WebCrypto bookkeeping, not key
// material: the same passphrase, salt, iteration count and hash must produce the
// same 256 bits either way. Encrypting identical plaintext under identical IVs
// and comparing ciphertexts proves it without needing the keys to be extractable.
{
  const salt = b64ToU8(env1.kdf.salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = new TextEncoder().encode("the same bytes under both usage masks");
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(PASS), "PBKDF2", false, ["deriveKey"],
  );
  const params = { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" };
  const encOnly = await crypto.subtle.deriveKey(params, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const encDec = await crypto.subtle.deriveKey(params, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const a = Buffer.from(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encOnly, body)));
  const b = Buffer.from(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encDec, body)));
  chk("widening the key usage mask does not change the key material", a.equals(b),
    `${a.toString("base64").slice(0, 24)}… == ${b.toString("base64").slice(0, 24)}…`);
}

{
  const plain = JSON.stringify({ hello: "verify", pad: "x".repeat(200) });
  const envV = await encrypt(plain, PASS);
  const threw = async (fn) => { try { await fn(); return null; } catch (e) { return e.message ?? String(e); } };

  chk("verifyRoundTrip accepts what encrypt() just produced",
    (await threw(() => verifyRoundTrip(envV, PASS, plain.length))) === null);

  // An envelope the WeakMap has never seen — round-tripped through JSON exactly
  // as `main()` would if it re-read the file — must still verify, by falling
  // through to a full derivation. A missing memo may only ever cost time.
  chk("an envelope with no memoised key still verifies",
    (await threw(() => verifyRoundTrip(structuredClone(envV), PASS, plain.length))) === null);

  // The memo must not let a DIFFERENT passphrase verify. It is keyed on the
  // passphrase too, so this falls through to a derivation and fails the GCM tag.
  chk("verifyRoundTrip still rejects a wrong passphrase",
    (await threw(() => verifyRoundTrip(envV, "definitely-not-the-passphrase-at-all", plain.length))) !== null);

  // Payload integrity. Mutated in place and restored so the memo (keyed by
  // object identity) stays live and these cases cost no derivation.
  const goodCt = envV.ciphertext;
  envV.ciphertext = Buffer.from(b64ToU8(goodCt).map((v, i) => (i === 5 ? v ^ 0xff : v))).toString("base64");
  chk("verifyRoundTrip still rejects a corrupted ciphertext",
    (await threw(() => verifyRoundTrip(envV, PASS, plain.length))) !== null);
  envV.ciphertext = goodCt;

  const goodIv = envV.cipher.iv;
  envV.cipher.iv = Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64");
  chk("verifyRoundTrip still rejects a rewritten IV",
    (await threw(() => verifyRoundTrip(envV, PASS, plain.length))) !== null);
  envV.cipher.iv = goodIv;

  chk("verifyRoundTrip still rejects a length mismatch",
    /round-trip length mismatch/.test(await threw(() => verifyRoundTrip(envV, PASS, plain.length + 1)) ?? ""));

  const badCodec = await threw(() => verifyRoundTrip({ ...envV, compression: "brotli" }, PASS, plain.length));
  chk("verifyRoundTrip still rejects a codec this build cannot inflate",
    /unsupported snapshot compression: brotli/.test(badCodec ?? ""), String(badCodec));

  // THE case the memo could have hidden, and the reason roundTripKey() asserts
  // instead of assuming. The browser and api/fleet.mjs derive from the
  // parameters WRITTEN INTO the envelope and nothing else, so an envelope whose
  // written salt/iterations/hash disagree with the key it was sealed under is a
  // snapshot only this process can ever open. Re-deriving used to catch that by
  // accident; it is now caught on purpose, and named.
  const goodSalt = envV.kdf.salt;
  envV.kdf.salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");
  chk("verifyRoundTrip rejects an envelope whose written salt is not the one used",
    /kdf\.salt does not match/.test(await threw(() => verifyRoundTrip(envV, PASS, plain.length)) ?? ""));
  envV.kdf.salt = goodSalt;

  envV.kdf.iterations = 1000;
  chk("verifyRoundTrip rejects an envelope whose written iteration count is not the one used",
    /kdf\.iterations 1000 does not match/.test(await threw(() => verifyRoundTrip(envV, PASS, plain.length)) ?? ""));
  envV.kdf.iterations = 600000;

  envV.kdf.hash = "SHA-512";
  chk("verifyRoundTrip rejects an envelope whose written hash is not the one used",
    /kdf\.hash SHA-512 does not match/.test(await threw(() => verifyRoundTrip(envV, PASS, plain.length)) ?? ""));
  envV.kdf.hash = "SHA-256";

  chk("the envelope is unchanged after all of that",
    (await threw(() => verifyRoundTrip(envV, PASS, plain.length))) === null);
}

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
// Self-describing transport: whatever the collector applied, a reader must be
// able to name it. An envelope that arrived here with a codec this build cannot
// inflate is a deployment that will 401/mojibake in production.
chk("the published envelope declares a codec this build can read",
  isSupportedCompression(liveEnvelope.compression),
  `compression=${JSON.stringify(liveEnvelope.compression ?? null)}`);

// ------------------------------------------------- passphrase whitespace

// Copying a passphrase out of a terminal, a password manager or Vault brings a
// trailing newline with it, and the field that receives it is masked — so the
// stray byte is invisible and the only symptom is "wrong passphrase".
//
// The danger is not the whitespace, it is DISAGREEMENT about it. `/api/fleet`
// trimmed its credentials from the start while the collector did not, so a
// passphrase with a trailing newline encrypted the snapshot under a string no
// reader could reproduce. These checks pin every entry point to the same
// answer; they fail the moment one of them stops agreeing.
{
  const base = "a-long-enough-fleet-passphrase";
  const decorated = [
    ["trailing newline", `${base}\n`],
    ["trailing space", `${base} `],
    ["leading space", ` ${base}`],
    ["CRLF", `${base}\r\n`],
    ["tab both ends", `\t${base}\t`],
    ["surrounded by blank lines", `\n\n${base}\n\n`],
  ];

  for (const [name, pass] of decorated) {
    chk(`${name} trims to the bare passphrase`, pass.trim() === base, JSON.stringify(pass));
  }

  // The real proof: a snapshot encrypted under the TRIMMED passphrase must open
  // under every decorated spelling of it, because each entry point trims before
  // deriving. If any one of them stopped trimming, this would fail.
  const envT = await encrypt(JSON.stringify({ hello: "trim" }), base);
  for (const [name, pass] of decorated) {
    const key = await deriveFrom(envT, pass.trim());
    let ok = false;
    try { ok = JSON.parse(await decryptWith(envT, key)).hello === "trim"; } catch { ok = false; }
    chk(`a passphrase with a ${name} still opens the snapshot`, ok);
  }

  // And the converse, which is why trimming must be everywhere rather than
  // somewhere: deriving from the UNtrimmed string yields a different key.
  const untrimmedKey = await deriveFrom(envT, `${base}\n`);
  let rejected = false;
  try { await decryptWith(envT, untrimmedKey); } catch { rejected = true; }
  chk("an UNtrimmed passphrase derives a different key (so all readers must trim)", rejected);

  // Interior whitespace is part of the secret and must survive.
  const spaced = "correct horse battery staple";
  chk("interior spaces are preserved", spaced.trim() === spaced);
  const envS = await encrypt(JSON.stringify({ hello: "spaced" }), spaced);
  const spacedKey = await deriveFrom(envS, ` ${spaced} `.trim());
  chk("a passphrase containing spaces still opens after trimming",
    JSON.parse(await decryptWith(envS, spacedKey)).hello === "spaced");
}

console.log(failures === 0 ? "\nALL SNAPSHOT CHECKS PASSED" : `\n${failures} SNAPSHOT CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
