/**
 * Distil a full fleet snapshot into a compact, action-first view for LLM/agent
 * consumption, and encode it as JSON or TOON.
 *
 * Why a separate view rather than serving the raw snapshot: the snapshot is
 * ~68KB of plaintext on a 10-machine fleet, most of it per-worker and per-build
 * detail an agent does not need to answer "is my fleet healthy and are my builds
 * offloading?". This view is roughly 4KB, leads with PROBLEMS, and uses TOON's
 * tabular arrays so the repeated per-worker keys are emitted once instead of N
 * times (~65% fewer characters than the equivalent JSON).
 *
 * Health thresholds below intentionally mirror `src/derive.ts`. They are
 * duplicated because that file is TypeScript compiled into the browser bundle
 * and this one runs in plain Node (CLI + serverless function). If you change a
 * threshold, change it in BOTH — `npm run test:llm` asserts they agree on a
 * fixture.
 */

import { encode as toonEncode } from "@toon-format/toon";
import { buildProblems, PROBLEM_KINDS, isHookDead, isStalledBuild } from "../src/problems.js";

export const STALE_CRIT_SECONDS = 60 * 60;

/** Every view the endpoint and the CLI accept. */
export const VIEWS = ["summary", "problems", "full", "diagnose", "help"];
export const FORMATS = ["toon", "json"];

/** Thrown by `buildLlmView` when `target` names nothing in the snapshot. */
export class UnknownTarget extends Error {
  constructor(target, known) {
    super(`unknown target "${target}"`);
    this.name = "UnknownTarget";
    this.target = target;
    this.known = known;
  }
}

const r1 = (n) => (typeof n === "number" && Number.isFinite(n) ? Math.round(n * 10) / 10 : null);

/**
 * Mirror of `fmtAge()` in src/derive.ts with the " ago" suffix dropped. The two
 * must agree exactly — tests/parity.mjs compares the reason strings verbatim.
 */
function fmtAgeBare(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

/** Mirror of `classify()` in src/derive.ts — keep in sync. */
export function classifyWorker(w, snapshotMs) {
  const p = w.pressure ?? {};
  const diskUsedPct =
    p.disk_total_gb && p.disk_free_gb != null && p.disk_total_gb > 0
      ? ((p.disk_total_gb - p.disk_free_gb) / p.disk_total_gb) * 100
      : null;
  const loadPerCore =
    w.caps?.load_avg_1 != null && w.caps?.num_cpus ? w.caps.load_avg_1 / w.caps.num_cpus : null;
  // Judged against SNAPSHOT time, not the reader's clock: otherwise an old
  // snapshot reports the whole fleet offline. Snapshot age is its own signal.
  const staleSeconds = w.last_seen_unix != null ? snapshotMs / 1000 - w.last_seen_unix : null;
  const st = (w.status ?? "").toLowerCase();

  let health = "healthy";
  let reason = "healthy";

  // A pressure event does not always carry a disk number; falling back to the
  // percentage unconditionally rendered the literal "disk undefined% full".
  const pressureReason = (fallback) =>
    p.reason
      ? `pressure: ${p.reason}`
      : diskUsedPct != null
        ? `disk ${diskUsedPct.toFixed(0)}% full`
        : fallback;

  if (st === "disabled") { health = "disabled"; reason = "manually disabled"; }
  else if (st === "down" || st === "unreachable" || w.circuit_state === "open") {
    health = "offline";
    reason = w.circuit_state === "open" ? "circuit breaker open" : `worker ${st || "unreachable"}`;
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline"; reason = `not seen for ${Math.round(staleSeconds / 60)}m`;
  } else if (p.state === "critical" || (diskUsedPct != null && diskUsedPct >= 95)) {
    health = "critical"; reason = pressureReason("critical pressure");
  } else if (st === "draining") { health = "warn"; reason = "draining (finishing current jobs)"; }
  else if (st === "drained") { health = "warn"; reason = "drained — accepting no new jobs"; }
  else if (p.state === "warning" || (diskUsedPct != null && diskUsedPct >= 88)) {
    health = "warn"; reason = pressureReason("pressure warning");
  } else if (p.state === "telemetry_gap") {
    health = "warn"; reason = p.reason ? `pressure: ${p.reason}` : "no pressure telemetry";
  } else if (st === "degraded") { health = "warn"; reason = "worker responding slowly"; }
  else if ((w.consecutive_failures ?? 0) > 0) {
    health = "warn";
    reason = `${w.consecutive_failures} consecutive failure${w.consecutive_failures === 1 ? "" : "s"}`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn"; reason = `load ${loadPerCore.toFixed(1)}x cores`;
  } else if (w.circuit_state === "half_open") { health = "warn"; reason = "circuit half-open (probing)"; }
  else if (w.caps?.projects_root_ok === false) { health = "warn"; reason = "projects root unhealthy"; }
  else if (p.telemetry_fresh === false) {
    health = "warn";
    reason = p.telemetry_age_secs != null
      ? `telemetry ${fmtAgeBare(p.telemetry_age_secs)} old`
      : "telemetry stale";
  } else if ((w.used_slots ?? 0) > 0) { health = "busy"; reason = `${w.used_slots}/${w.total_slots} slots in use`; }

  return { health, reason, diskUsedPct, loadPerCore };
}

/** Mirror of `classifyDispatcher()` in src/derive.ts — keep in sync. */
export function classifyDev(d) {
  // See src/derive.ts: `build_stats` is cumulative since daemon start, which is
  // the wrong basis for "is this box offloading now". Prefer the real recent
  // window and fall back to lifetime counters only when it is empty.
  const s = d.build_stats;
  // Counted straight off the wire tuples. `location` is the only field this
  // verdict needs, so expanding all seven into objects first would allocate a
  // record per build (121 on a 10-machine fleet) purely to read index 2.
  // Value-identical to `expandBuilds(d.builds).filter(b => b.location …)` — and
  // it stays value-identical only because `location` is never interned into the
  // string table, which is the main reason it is excluded. This function has no
  // access to `snap.strings`, so an interned `location` would read as a number
  // here and count every build as local.
  const recent = Array.isArray(d.builds) ? d.builds : [];
  const recentCounted = recent.length;
  const recentRemote = recent.filter(
    (b) => (Array.isArray(b) ? (b[B_LOCATION] ?? "") : "").toLowerCase() === "remote",
  ).length;

  const lifetimeCounted = s ? s.remote + s.local : 0;
  const basis = recentCounted > 0 ? "recent" : lifetimeCounted > 0 ? "lifetime" : null;

  const remotePct =
    basis === "recent"
      ? (recentRemote / recentCounted) * 100
      : basis === "lifetime"
        ? (s.remote / lifetimeCounted) * 100
        : null;

  const window = basis === "recent" ? `last ${recentCounted} builds` : "all builds since daemon start";

  let level, reason;
  if (!d.reachable) {
    level = "unreachable";
    const first = Array.isArray(d.collection_errors) ? d.collection_errors[0] : undefined;
    reason = first ? `no response from rch — ${first}` : "no response from rch";
  } else if (d.posture && d.posture !== "remote_ready") {
    level = d.posture.includes("local") ? "local-only" : "degraded";
    reason = d.posture_description ?? d.posture;
  } else if (remotePct != null && remotePct < 50) {
    level = "local-only"; reason = `only ${remotePct.toFixed(0)}% of the ${window} went remote`;
  } else if (basis === null) { level = "idle"; reason = "no builds recorded yet"; }
  else { level = "offloading"; reason = `${remotePct.toFixed(0)}% of the ${window} went to the pool`; }
  return { level, reason, remotePct, remoteBasis: basis, remoteCounted: recentCounted || lifetimeCounted };
}

/**
 * Wire tuple layouts, mirroring `BuildTuple` / `HintTuple` in src/types.ts.
 *
 * The collector ships recent builds and remediation hints positionally — every
 * value in them is consumed, but the repeated key names were 16.7KB of a 92.3KB
 * payload. Most of the surviving strings are then interned into
 * `snap.strings[]`, so a slot may hold an index instead of the value; see
 * `internedStr()` below. These indices ARE the schema; if you reorder a tuple
 * in `tools/snapshot.mjs`, change it here and in `expandBuilds()`/
 * `expandHints()` in src/derive.ts together.
 */
const B_PROJECT = 0, B_COMMAND = 1, B_LOCATION = 2, B_WORKER = 3,
      B_DURATION = 4, B_EXIT = 5, B_COMPLETED = 6;
const H_WORKER = 0, H_SEVERITY = 1, H_MESSAGE = 2, H_ACTION = 3, H_REASON = 4;

/**
 * Mirror of `internedStr()` in src/derive.ts — keep in sync.
 *
 * The collector folds the repeated build/hint strings into one snapshot-level
 * `strings[]` table and writes an index in their place: 137 builds carry 34
 * distinct projects, and 113 hints carry 30 distinct messages and 20 distinct
 * suggested actions, because every dispatcher reports the same advice about the
 * same shared worker.
 *
 * A `number` is an index; anything else is already the value. That dispatch is
 * what makes an old snapshot (no table, literal strings in these slots) expand
 * to exactly the same records, with no key rename and nothing lost.
 *
 * `B_LOCATION` and `H_SEVERITY` are NOT interned and must never be: `location`
 * is read straight off the raw tuple by `classifyDev()` below and
 * `.toLowerCase()`d by four consumers, and `severity` is compared against
 * "critical" to pick an alarm colour. See tools/snapshot.mjs.
 */
function internedStr(v, strings) {
  if (typeof v === "number") return (Array.isArray(strings) ? strings[v] : undefined) ?? null;
  return v ?? null;
}

/** Mirror of `expandBuilds()` in src/derive.ts — keep in sync. */
export function expandBuilds(rows, strings) {
  if (!Array.isArray(rows)) return [];
  return rows.map((b) => ({
    project: Array.isArray(b) ? internedStr(b[B_PROJECT], strings) : null,
    command: Array.isArray(b) ? internedStr(b[B_COMMAND], strings) : null,
    location: Array.isArray(b) ? (b[B_LOCATION] ?? null) : null,
    worker_id: Array.isArray(b) ? internedStr(b[B_WORKER], strings) : null,
    duration_ms: Array.isArray(b) ? (b[B_DURATION] ?? null) : null,
    exit_code: Array.isArray(b) ? (b[B_EXIT] ?? null) : null,
    completed_at: Array.isArray(b) ? (b[B_COMPLETED] ?? null) : null,
  }));
}

/** Mirror of `expandHints()` in src/derive.ts — keep in sync. */
export function expandHints(rows, strings) {
  if (!Array.isArray(rows)) return [];
  return rows.map((h) => ({
    worker_id: Array.isArray(h) ? internedStr(h[H_WORKER], strings) : null,
    severity: Array.isArray(h) ? (h[H_SEVERITY] ?? null) : null,
    message: Array.isArray(h) ? internedStr(h[H_MESSAGE], strings) : null,
    suggested_action: Array.isArray(h) ? internedStr(h[H_ACTION], strings) : null,
    reason_code: Array.isArray(h) ? internedStr(h[H_REASON], strings) : null,
  }));
}

/** Mirror of `expandAlerts()` in src/derive.ts — keep in sync. */
export function expandAlerts(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((a) => ({
    kind: Array.isArray(a) ? (a[0] ?? null) : null,
    severity: Array.isArray(a) ? (a[1] ?? null) : null,
    worker_id: Array.isArray(a) ? (a[2] ?? null) : null,
    message: Array.isArray(a) ? (a[3] ?? null) : null,
    first_seen: Array.isArray(a) ? (a[4] ?? null) : null,
    last_seen: Array.isArray(a) ? (a[5] ?? null) : null,
    state: Array.isArray(a) ? (a[6] ?? null) : null,
  }));
}

/** Mirror of `expandIssues()` in src/derive.ts — keep in sync. */
export function expandIssues(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((i) => ({
    severity: Array.isArray(i) ? (i[0] ?? null) : null,
    summary: Array.isArray(i) ? (i[1] ?? null) : null,
    remediation: Array.isArray(i) ? (i[2] ?? null) : null,
  }));
}

/** Mirror of `expandActive()` in src/derive.ts — keep in sync. */
export function expandActive(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((b) => ({
    id: Array.isArray(b) ? (b[0] ?? null) : null,
    project: Array.isArray(b) ? (b[1] ?? null) : null,
    worker_id: Array.isArray(b) ? (b[2] ?? null) : null,
    command: Array.isArray(b) ? (b[3] ?? null) : null,
    started_at: Array.isArray(b) ? (b[4] ?? null) : null,
    heartbeat_age_secs: Array.isArray(b) ? (b[5] ?? null) : null,
    progress_age_secs: Array.isArray(b) ? (b[6] ?? null) : null,
    phase: Array.isArray(b) ? (b[7] ?? null) : null,
    hook_alive: Array.isArray(b) ? (b[8] ?? null) : null,
    heartbeat_stale: Array.isArray(b) ? (b[9] ?? null) : null,
    progress_stale: Array.isArray(b) ? (b[10] ?? null) : null,
    confidence: Array.isArray(b) ? (b[11] ?? null) : null,
    slots: Array.isArray(b) ? (b[12] ?? null) : null,
    build_age_secs: Array.isArray(b) ? (b[13] ?? null) : null,
  }));
}

/** Mirror of `expandQueued()` in src/derive.ts — keep in sync. */
export function expandQueued(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map((q) => ({
    id: Array.isArray(q) ? (q[0] ?? null) : null,
    project: Array.isArray(q) ? (q[1] ?? null) : null,
    command: Array.isArray(q) ? (q[2] ?? null) : null,
    position: Array.isArray(q) ? (q[3] ?? null) : null,
    slots_needed: Array.isArray(q) ? (q[4] ?? null) : null,
    wait_time: Array.isArray(q) ? (q[5] ?? null) : null,
  }));
}

/**
 * Mirror of the `seen_by` half of `attachSlotColumns()` in src/derive.ts —
 * keep in sync.
 *
 * `dispatchers[].pool_slots` is one ROW of the (dispatcher x worker) derated
 * slot matrix, aligned to `snap.workers`. Each worker's `seen_by` is that same
 * matrix read the other way, by COLUMN. It used to be transmitted alongside the
 * rows — along with a third copy as `slots_by_dispatcher` — which put three
 * encodings of one d x w structure on a wire that is re-fetched every five
 * minutes. Deriving the column here costs one pass and removes the term that
 * dominates a large fleet's payload; see `projectDispatchers()` in
 * tools/snapshot.mjs for the measurements.
 *
 * Only `seen_by`, not `slots_by_dispatcher`: the browser drawer renders the
 * per-machine slot table and this view does not, so building a record per CELL
 * here would be 66ms of pure waste at 500 dispatchers. The browser builds that
 * one lazily for the same reason.
 *
 * Dispatcher-outermost, so the resulting order matches both the collector's
 * original construction order and `src/derive.ts`. A snapshot that already
 * carries `seen_by` is left alone: its `worker_slots` are positional against a
 * different index space and must not be reinterpreted as fleet-aligned rows.
 *
 * @returns array of dispatcher-id lists, indexed like `snap.workers`.
 */
export function seenByColumns(snap) {
  const dispatchers = snap?.dispatchers;
  const workers = snap?.workers;
  if (!Array.isArray(dispatchers) || !Array.isArray(workers)) return [];
  if (workers.some((w) => Array.isArray(w?.seen_by))) return [];

  const cols = new Array(workers.length);
  for (const d of dispatchers) {
    const row = d?.pool_slots;
    if (!Array.isArray(row)) continue;
    const end = Math.min(row.length, workers.length);
    for (let i = 0; i < end; i++) {
      // Only a real pair counts as "seen" — a null means this machine has no
      // such worker, which is not the same fact as "derated to zero".
      if (!Array.isArray(row[i])) continue;
      (cols[i] ??= []).push(d.id);
    }
  }
  return cols;
}

const SCHEMA = "rch.fleet.llm.v2";

/**
 * The self-describing help view. Served by `/api/fleet?view=help` and
 * `npm run llm -- --view help` so an agent that has only the URL can learn the
 * whole contract from the endpoint, with no README lookup.
 */
export function helpView() {
  return {
    schema: SCHEMA,
    what: "rch fleet state for agents: which dev machines are offloading, which workers are healthy, what is broken, and the command that fixes each thing.",
    start_here: "GET ?view=problems — every problem with severity, target, since, action and WHERE to run it (`on`). Empty problems[] with stale:false means the fleet is fine.",
    auth: "Authorization: Bearer <passphrase> (or X-Fleet-Key header, or ?key=). The passphrase is the AES key; a wrong one is a 401.",
    params: {
      view: "summary (default: overview + problems + per-machine/worker rows) | problems (just problems + next_actions, cheapest poll) | full (+ hints, recent builds, worker detail, history) | diagnose (requires target: everything about ONE machine or worker) | help",
      target: "a dev machine id or worker id. Filters summary/full/problems to that entity; required by diagnose. A box that is both (it dispatches AND takes builds) resolves to both halves; prefix `dev:` or `worker:` to pick one. Unknown id -> 404 listing the known ids.",
      format: "toon (default, ~65% fewer characters) | json",
    },
    freshness: "generated_at is when the snapshot was TAKEN; age_seconds is against the server clock; stale:true past 1h. The collector republishes on a schedule (see README); do not expect sub-minute data.",
    reading_problems: {
      severity: "critical = builds are (or will be) landing locally, or capacity is silently gone. warn = degraded but working.",
      kind: "dotted, stable — dev.* dev machine, worker.* worker, build.* hung build, fleet.* one root cause behind many symptoms, snapshot.* this feed",
      on: "where to run `action`: a dev machine id (ssh there, or you are there), `collector` (the box that publishes this dashboard), or empty when informational",
      since: "ISO time the daemon first raised the underlying alert, when known",
    },
    next_actions: "problems folded into distinct commands, grouped by machine, most severe first. `fixes` lists the targets each command addresses.",
    kinds: Object.entries(PROBLEM_KINDS).map(([kind, k]) => ({ kind, severity: k.severity, meaning: k.meaning, fix: k.fix })),
    exit_codes_cli: "npm run llm: 0 ok | 2 no passphrase | 3 unreadable snapshot | 4 wrong passphrase | 5 unknown target",
    http_status: "200 ok | 400 bad param (body says which) | 401 missing/wrong key | 404 unknown target (body lists known ids) | 405 not GET | 500 no snapshot",
  };
}

/**
 * Case-insensitive id match. A box can be BOTH a dev machine and a worker
 * (hz1 dispatches builds and takes them), so a bare id that matches both
 * resolves to `both` and the diagnose view carries both halves; `dev:hz1` /
 * `worker:hz1` pick one.
 */
function resolveTarget(snap, target) {
  let want = String(target).trim().toLowerCase();
  let only = null;
  const m = /^(dev|dev_machine|machine|worker):(.+)$/.exec(want);
  if (m) { only = m[1] === "worker" ? "worker" : "dev_machine"; want = m[2].trim(); }
  const dev = only === "worker" ? null : snap.dispatchers.find((d) => String(d.id).toLowerCase() === want);
  const w = only === "dev_machine" ? null : snap.workers.find((x) => String(x.id).toLowerCase() === want);
  if (dev && w) return { type: "both", id: dev.id, worker_id: w.id };
  if (dev) return { type: "dev_machine", id: dev.id };
  if (w) return { type: "worker", id: w.id };
  throw new UnknownTarget(target, {
    dev_machines: snap.dispatchers.map((d) => d.id),
    workers: snap.workers.map((x) => x.id),
  });
}

/** Does a problem row concern this entity? By target, by build owner, or by where its fix runs. */
function problemTouches(p, id) {
  const lc = id.toLowerCase();
  const t = p.target.toLowerCase();
  if (t === lc || t.startsWith(`${lc}:`) || p.on.toLowerCase() === lc) return true;
  // The fleet row names its root-cause workers in prose: "fix hz1, hz3". Match
  // the id as a whole token, so `hz1` does not claim `hz10`'s row.
  if (p.kind === "fleet.degraded") {
    const named = (p.detail.split("— fix ")[1] ?? "").split(",").map((x) => x.trim().toLowerCase());
    return named.includes(lc);
  }
  return false;
}

/**
 * Build the compact view.
 * @param snap  decrypted snapshot (schema rch.dashboard.snapshot.v2)
 * @param opts  { view, target, now: epoch ms }
 * @throws UnknownTarget when `target` names nothing in the snapshot
 */
export function buildLlmView(snap, opts = {}) {
  const view = VIEWS.includes(opts.view) ? opts.view : "summary";
  if (view === "help") return helpView();
  const now = opts.now ?? Date.now();
  const target = opts.target ? resolveTarget(snap, opts.target) : null;
  if (view === "diagnose" && !target) {
    throw new UnknownTarget("", {
      dev_machines: snap.dispatchers.map((d) => d.id),
      workers: snap.workers.map((x) => x.id),
    });
  }

  // An unparseable `generated_at` yields NaN, and every NaN comparison is
  // false — so a corrupt snapshot used to report itself as FRESH. Treat an
  // unreadable timestamp as infinitely stale instead, which is the safe
  // direction for a monitoring feed.
  const snapshotMs = new Date(snap.generated_at).getTime();
  const timestampValid = Number.isFinite(snapshotMs);
  const ageSeconds = timestampValid ? Math.round((now - snapshotMs) / 1000) : Number.POSITIVE_INFINITY;
  const workers = snap.workers.map((w) => ({ ...w, ...classifyWorker(w, snapshotMs) }));
  const devs = snap.dispatchers.map((d) => ({
    ...d,
    ...classifyDev(d),
    remediation_hints: expandHints(d.hints, snap.strings),
    alert_records: expandAlerts(d.alerts),
    issue_records: expandIssues(d.issues),
    active_records: expandActive(d.active),
    queued_records: expandQueued(d.queued),
  }));

  const counts = {};
  for (const w of workers) counts[w.health] = (counts[w.health] ?? 0) + 1;

  const t = snap.totals ?? {};
  const buildsCounted = (t.builds_remote ?? 0) + (t.builds_local ?? 0);

  // Problems first: this is what an agent should act on. Derived by the SAME
  // module the browser uses, so the two surfaces cannot disagree.
  const derived = buildProblems({
    workers, devs, snapshotValid: timestampValid, ageSeconds, staleAfter: STALE_CRIT_SECONDS,
  });
  let problems = derived.problems;
  let nextActions = derived.next_actions;
  if (target) {
    problems = problems.filter((p) => problemTouches(p, target.id) || p.kind.startsWith("snapshot."));
    const keep = new Set(problems.map((p) => `${p.on} ${p.action}`));
    nextActions = nextActions.filter((a) => keep.has(`${a.on} ${a.run}`));
  }

  // Bound the list so a large fleet cannot blow an agent's context, but NEVER
  // drop rows silently — a truncated problem list that looks complete is how a
  // monitoring tool lies. Severity-sorted, so the cut only ever loses the least
  // urgent rows, and the count of what was cut is reported.
  const PROBLEM_CAP = 40;
  const problemsOmitted = Math.max(0, problems.length - PROBLEM_CAP);
  const shownProblems = problemsOmitted > 0 ? problems.slice(0, PROBLEM_CAP) : problems;
  const critical = problems.filter((p) => p.severity === "critical").length;

  const out = {
    schema: SCHEMA,
    label: snap.label,
    generated_at: snap.generated_at,
    // null rather than Infinity: JSON has no Infinity and would emit null
    // anyway, so be explicit that the age is unknown, not zero.
    age_seconds: timestampValid ? ageSeconds : null,
    stale: !timestampValid || ageSeconds > STALE_CRIT_SECONDS,
    // One line an agent can act on without reading further.
    verdict:
      critical > 0
        ? `${critical} critical problem${critical === 1 ? "" : "s"} — read problems[]`
        : problems.length > 0
          ? `${problems.length} warning${problems.length === 1 ? "" : "s"}, nothing critical`
          : "fleet healthy",
    help: "?view=help",
  };
  if (target) out.target = target;

  out.summary = {
    workers: t.workers ?? workers.length,
    healthy: counts.healthy ?? 0,
    busy: counts.busy ?? 0,
    needs_attention: (counts.critical ?? 0) + (counts.warn ?? 0) + (counts.offline ?? 0),
    slots_used: t.slots_used ?? 0,
    slots_total: t.slots ?? 0,
    cores: t.cores ?? 0,
    disk_free_gb: Math.round(t.disk_free_gb ?? 0),
    disk_used_pct: t.disk_total_gb
      ? r1(((t.disk_total_gb - t.disk_free_gb) / t.disk_total_gb) * 100)
      : null,
    dev_machines: t.dispatchers_total ?? devs.length,
    dev_reachable: t.dispatchers_reachable ?? devs.filter((d) => d.reachable).length,
    dev_remote_ready: t.dispatchers_remote_ready ?? 0,
    // Known-missing hooks and live unmanaged compiles: the two fleet-wide
    // numbers whose correct value is zero.
    hooks_missing: t.dispatchers_hook_missing ?? devs.filter((d) => d.hook?.claude_code === false).length,
    local_builds_running: t.local_builds_running ?? devs.reduce((n, d) => n + (d.shim?.local_builds_running ?? 0), 0),
    builds_remote: t.builds_remote ?? 0,
    builds_local: t.builds_local ?? 0,
    offload_pct: buildsCounted > 0 ? r1(((t.builds_remote ?? 0) / buildsCounted) * 100) : null,
    active_builds: t.active_builds ?? 0,
    daemon_version: derived.fleet_version.version ?? "",
    version_skew: derived.fleet_version.off_version.length,
    problems_critical: critical,
    problems_warn: problems.length - critical,
  };
  out.problems = shownProblems;
  out.problems_total = problems.length;
  out.problems_omitted = problemsOmitted;
  out.next_actions = nextActions;

  if (view === "problems") return out;

  const devRow = (d) => ({
    id: d.id,
    level: d.level,
    posture: d.posture ?? "",
    // The measured offload share and its basis — the verdict's own numbers.
    offload_pct: d.remotePct == null ? null : r1(d.remotePct),
    basis: d.remoteBasis ? `${d.remoteBasis}:${d.remoteCounted}` : "",
    remote_builds: d.build_stats?.remote ?? 0,
    local_builds: d.build_stats?.local ?? 0,
    // Compiler processes running outside rch RIGHT NOW (null = unknown).
    local_now: d.shim?.local_builds_running ?? null,
    hook: d.hook ? (d.hook.claude_code === true ? "ok" : d.hook.claude_code === false ? "MISSING" : "?") : "",
    shim: d.shim
      ? d.shim.installed === false ? "MISSING"
        : d.shim.up_to_date === false ? "stale"
        : d.shim.on_path === false ? "shadowed"
        : d.shim.installed === true ? "ok" : "?"
      : "",
    doctor: d.doctor ? `${d.doctor.passed}/${d.doctor.total}` : "",
    workers_healthy: d.daemon?.workers_healthy ?? null,
    workers_total: d.daemon?.workers_total ?? null,
    slots_free: d.daemon?.slots_available ?? null,
    slots_total: d.daemon?.slots_total ?? null,
    active: d.active_builds ?? 0,
    queued: d.queued_builds ?? 0,
    version: d.daemon?.version ?? "",
    uptime_h: d.daemon?.uptime_secs != null ? Math.round(d.daemon.uptime_secs / 360) / 10 : null,
  });
  const workerRow = (w) => ({
    id: w.id,
    health: w.health,
    used: w.used_slots ?? 0,
    total: w.total_slots ?? 0,
    cores: w.caps?.num_cpus ?? null,
    load: r1(w.caps?.load_avg_1),
    disk_free_gb: Math.round(w.pressure?.disk_free_gb ?? 0),
    disk_pct: r1(w.diskUsedPct),
    speed: r1(w.speed),
    circuit: w.circuit_state ?? "",
    tags: (w.tags ?? []).join("|"),
    reason: w.health === "healthy" ? "" : w.reason,
  });

  const wantDev = target && target.type !== "worker";
  const wantWorker = target && target.type !== "dev_machine";
  const shownDevs = !target ? devs : wantDev ? devs.filter((d) => d.id === target.id) : [];
  const shownWorkers = !target ? workers : wantWorker ? workers.filter((w) => w.id === (target.worker_id ?? target.id)) : [];
  const cols = seenByColumns(snap);
  const colIndex = new Map(workers.map((w, i) => [w.id, i]));

  const devDetail = (d) => ({
    id: d.id,
    reason: d.reason,
    posture_description: d.posture_description ?? "",
    collection_errors: d.collection_errors ?? [],
    remediation_hints: (d.remediation_hints ?? []).map((h) => ({
      worker: h.worker_id ?? "",
      severity: h.severity ?? "",
      message: h.message ?? "",
      action: h.suggested_action ?? "",
    })),
    alerts: (d.alert_records ?? []).map((a) => ({
      kind: a.kind ?? "", severity: a.severity ?? "", worker: a.worker_id ?? "",
      since: a.first_seen ?? "", state: a.state ?? "", message: a.message ?? "",
    })),
    issues: (d.issue_records ?? []).map((i) => ({
      severity: i.severity ?? "", summary: i.summary ?? "", remediation: i.remediation ?? "",
    })),
    active_builds: (d.active_records ?? []).map((b) => ({
      id: b.id ?? "", project: b.project ?? "", worker: b.worker_id ?? "", phase: b.phase ?? "",
      age_s: b.build_age_secs ?? null, heartbeat_age_s: b.heartbeat_age_secs ?? null,
      progress_age_s: b.progress_age_secs ?? null, hook_alive: b.hook_alive ?? null,
      hook_dead: isHookDead(b), stalled: isStalledBuild(b), slots: b.slots ?? null,
      command: b.command ?? "",
    })),
    queued_builds: (d.queued_records ?? []).map((q) => ({
      id: q.id ?? "", project: q.project ?? "", position: q.position ?? null,
      slots_needed: q.slots_needed ?? null, waiting: q.wait_time ?? "", command: q.command ?? "",
    })),
    hook: d.hook ? { claude_code: d.hook.claude_code, agents: (d.hook.agents ?? []).map(([a, i]) => `${a}:${i ? "installed" : "missing"}`).join("|") } : null,
    shim: d.shim ?? null,
    doctor: d.doctor
      ? { ...d.doctor, failing: (d.doctor.failing ?? []).map((c) => ({ check: c[0] ?? "", status: c[1] ?? "", message: c[2] ?? "", fixable: c[3] === true })) }
      : null,
    convergence: d.convergence
      ? { ...d.convergence, workers: (d.convergence.workers ?? []).map((w) => ({ worker: w[0] ?? "", state: w[1] ?? "", missing_repos: w[2] ?? 0 })) }
      : null,
    tests: d.tests ?? null,
    // The browser drawer renders every build the collector sends; this view
    // is context-budgeted and shows only the newest 10. Note that `classifyDev`
    // above still counts ALL of them — the offload verdict must be measured
    // over the whole window, not the slice an agent happens to be shown.
    recent_builds: expandBuilds(d.builds, snap.strings).slice(-10).map((b) => ({
      project: b.project ?? "",
      location: b.location ?? "",
      worker: b.worker_id ?? "",
      ms: b.duration_ms ?? null,
      exit: b.exit_code ?? null,
    })),
  });
  const workerDetail = (w) => {
    const i = colIndex.get(w.id);
    const seenBy = w.seen_by ?? cols[i] ?? [];
    // This worker's derated slot reading on EVERY dev machine that has it —
    // rchd derates independently, so "0 slots on ts2, 8 on css" is a real
    // and diagnosable state.
    const slotsBy = {};
    for (const d of snap.dispatchers) {
      const pair = d?.pool_slots?.[i];
      if (Array.isArray(pair)) slotsBy[d.id] = `${pair[0] ?? "?"}/${pair[1] ?? "?"}`;
    }
    return {
      id: w.id,
      host: w.host ?? "",
      user: w.user ?? "",
      status: w.status ?? "",
      circuit: w.circuit_state ?? "",
      recovery_in_s: w.recovery_in_secs ?? null,
      bypass: w.bypass ?? "",
      pressure_state: w.pressure?.state ?? "",
      pressure_reason: w.pressure?.reason ?? "",
      pressure_confidence: w.pressure?.confidence ?? "",
      pressure_rule: w.pressure?.policy_rule ?? "",
      telemetry_age_s: w.pressure?.telemetry_age_secs ?? null,
      disk_total_gb: Math.round(w.pressure?.disk_total_gb ?? 0),
      disk_io_pct: r1(w.pressure?.disk_io_util_pct),
      mem_pressure: r1(w.pressure?.memory_pressure),
      latency_ms: r1(w.latency_ms),
      failures: w.consecutive_failures ?? 0,
      probe_history: (w.failure_history ?? []).map((ok) => (ok ? "." : "x")).join(""),
      last_error: w.last_error ?? "",
      rustc: w.caps?.rustc_version ?? "",
      load_5: r1(w.caps?.load_avg_5),
      load_15: r1(w.caps?.load_avg_15),
      priority: w.priority ?? null,
      seen_by: seenBy.join("|"),
      slots_by_dev: Object.entries(slotsBy).map(([k, v]) => `${k}=${v}`).join("|"),
    };
  };

  if (view === "diagnose") {
    // Everything about one entity, plus what the rest of the fleet says about
    // it. Nothing an agent would have to make a second call for. A box that
    // is both a dev machine and a worker gets both halves.
    if (wantDev) {
      const d = devs.find((x) => x.id === target.id);
      out.dev_machine = devRow(d);
      out.detail = devDetail(d);
      // This box's own derated view of the pool: the zero-slot workers are the
      // ones its builds cannot use, whatever the fleet-wide row says.
      const pool = [];
      const row = d.pool_slots;
      if (Array.isArray(row)) {
        for (let i = 0; i < row.length && i < workers.length; i++) {
          if (!Array.isArray(row[i])) continue;
          pool.push({ worker: workers[i].id, health: workers[i].health, used: row[i][0] ?? null, total: row[i][1] ?? null });
        }
      }
      out.pool_as_seen_here = pool;
    }
    if (wantWorker) {
      const w = workers.find((x) => x.id === (target.worker_id ?? target.id));
      out.worker = workerRow(w);
      // `detail` is the worker's when the target is only a worker; beside a
      // dev-machine half it is named so neither shadows the other.
      out[wantDev ? "worker_detail" : "detail"] = workerDetail(w);
      out.hints_about = devs.flatMap((d) => (d.remediation_hints ?? [])
        .filter((h) => h.worker_id === w.id)
        .map((h) => ({ from: d.id, severity: h.severity ?? "", message: h.message ?? "", action: h.suggested_action ?? "" })));
      out.alerts_about = devs.flatMap((d) => (d.alert_records ?? [])
        .filter((a) => a.worker_id === w.id)
        .map((a) => ({ from: d.id, kind: a.kind ?? "", since: a.first_seen ?? "", state: a.state ?? "", message: a.message ?? "" })));
      out.builds_running_here = devs.flatMap((d) => (d.active_records ?? [])
        .filter((b) => b.worker_id === w.id)
        .map((b) => ({ from: d.id, id: b.id ?? "", project: b.project ?? "", age_s: b.build_age_secs ?? null, phase: b.phase ?? "" })));
      out.recent_builds_here = devs.flatMap((d) => expandBuilds(d.builds, snap.strings)
        .filter((b) => b.worker_id === w.id).slice(-5)
        .map((b) => ({ from: d.id, project: b.project ?? "", ms: b.duration_ms ?? null, exit: b.exit_code ?? null, at: b.completed_at ?? "" })));
    }
    return out;
  }

  out.dev_machines = shownDevs.map(devRow);
  out.workers = shownWorkers.map(workerRow);

  if (view === "full") {
    out.dev_detail = shownDevs.map(devDetail);
    // Built HERE and not beside `workers` above: reading the matrix by column
    // is O(dispatchers x workers), and the summary view — the one an agent
    // polls — must not pay for a field it does not emit.
    out.worker_detail = shownWorkers.map(workerDetail);
    out.history = (snap.history ?? []).slice(-24);
  }

  return out;
}

/** Encode a view as `toon` (default) or `json`. */
export function encodeView(view, format = "toon") {
  if (format === "json") return JSON.stringify(view, null, 2);
  return toonEncode(view);
}

/** Content-Type for a format. */
export function contentType(format) {
  return format === "json" ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
}
