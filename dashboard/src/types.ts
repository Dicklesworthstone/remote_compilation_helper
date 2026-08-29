/** Shapes emitted by `tools/snapshot.mjs` (schema rch.dashboard.snapshot.v2). */

export interface WorkerCaps {
  num_cpus: number | null;
  load_avg_1: number | null;
  load_avg_5: number | null;
  load_avg_15: number | null;
  cpu_microarch_level: number | null;
  rustc_version: string | null;
  bun_version: string | null;
  node_version: string | null;
  go_version: string | null;
  zig_version: string | null;
  projects_root_ok: boolean | null;
}

export interface WorkerPressure {
  state: string | null;
  reason: string | null;
  /** rchd's confidence in `state` ("high" | "medium" | "low"), when reported. */
  confidence?: string | null;
  /** Which pressure policy rule fired, when reported. */
  policy_rule?: string | null;
  disk_free_gb: number | null;
  disk_total_gb: number | null;
  disk_io_util_pct: number | null;
  memory_pressure: number | null;
  telemetry_age_secs: number | null;
  telemetry_fresh: boolean | null;
}

export interface Worker {
  id: string;
  host: string | null;
  user: string | null;
  status: string | null;
  circuit_state: string | null;
  /** REAL derated slots from `rch status`, not the configured ceiling. */
  used_slots: number | null;
  total_slots: number | null;
  speed: number | null;
  last_error: string | null;
  consecutive_failures: number;
  /** Seconds until the circuit breaker retries this worker, when it is open. */
  recovery_in_secs?: number | null;
  /** rch's admission-bypass reason (`RCH-Innn ...`) when the daemon is skipping this worker. */
  bypass?: string | null;
  failure_history: boolean[];
  pressure: WorkerPressure;
  latency_ms: number | null;
  last_seen_unix: number | null;
  caps: WorkerCaps;
  tags: string[];
  /** From `rch workers list` — absent in `rch status`. */
  priority: number | null;
  /**
   * Which dev machines can see this worker, in snapshot dispatcher order.
   *
   * NOT ON THE WIRE. `classifyAll()` rebuilds it column-wise from
   * `Dispatcher.pool_slots` — see `projectDispatchers()` in tools/snapshot.mjs
   * for why the (dispatcher x worker) matrix is transmitted exactly once. It
   * stays optional because a snapshot written before that change carries it
   * inline, and `classifyAll()` leaves such a snapshot untouched.
   */
  seen_by?: string[];
  /**
   * Slot view per dev machine — rchd derates independently on each. Same
   * provenance as `seen_by`: rebuilt at classify time, keyed in dispatcher
   * order, absent from the wire.
   */
  slots_by_dispatcher?: Record<string, { used: number | null; total: number | null }>;
}

/** One recent build, as `classifyDispatcher()` hands it to the UI. */
export interface RecentBuild {
  project: string | null;
  command: string | null;
  /** "Remote" | "Local" */
  location: string | null;
  worker_id: string | null;
  duration_ms: number | null;
  exit_code: number | null;
  completed_at: string | null;
}

/**
 * One slot of a wire tuple whose string may have been INTERNED.
 *
 *   number  index into `Snapshot.strings`
 *   string  a literal the collector chose not to intern (`""` stays `""`)
 *   null    genuinely absent
 *
 * Only NON-EMPTY strings are ever interned, so neither `null` nor `""` can be
 * confused with table entry 0. Resolved by `internedStr()` in src/derive.ts and
 * its mirror in tools/llm-view.mjs; a snapshot written before the table existed
 * carries plain strings in these slots and passes through untouched.
 */
export type InternedString = string | number | null;

/**
 * The WIRE form of a `RecentBuild`.
 *
 * Positional, not named. All seven values are consumed — the dev-machine drawer
 * renders six and uses `command` as the row tooltip, and both classifiers count
 * `location` to decide whether the box is offloading — so none can be dropped.
 * The key names can: 121 builds on a 10-machine fleet repeated the same 84
 * characters of `"project":"command":…` 121 times, 10.2KB of a 92.3KB payload.
 * Expanded by `expandBuilds()` in src/derive.ts.
 *
 * `project`, `command` and `worker_id` are additionally INTERNED into
 * `Snapshot.strings` — 137 builds carry only 34 distinct projects and 9 distinct
 * workers. `location` deliberately is NOT: it is the one slot read positionally
 * off the raw tuple (`classifyDev()` in tools/llm-view.mjs) and four consumers
 * call `.toLowerCase()` on it, so an index there is a TypeError rather than a
 * wrong pixel. `completed_at` is not interned either — 137 distinct values in
 * 137 slots means a table that costs more than the strings it replaces.
 */
export type BuildTuple = [
  project: InternedString,
  command: InternedString,
  location: string | null,
  worker_id: InternedString,
  duration_ms: number | null,
  exit_code: number | null,
  completed_at: string | null,
];

/** One remediation hint, as `classifyDispatcher()` hands it to the UI. */
export interface RemediationHint {
  worker_id: string | null;
  severity: string | null;
  message: string | null;
  suggested_action: string | null;
  reason_code: string | null;
}

/**
 * The WIRE form of a `RemediationHint` — same reasoning as `BuildTuple`
 * (66 characters of key names × 99 hints = 6.5KB). Expanded by `expandHints()`.
 *
 * This is where interning pays best: 113 hints on a 10-machine fleet carry only
 * 30 distinct messages and 20 distinct suggested actions, because every box
 * reports the same advice about the same shared worker. The suggested actions
 * alone were 14.2KB inline and 2.5KB as a table.
 *
 * `severity` is deliberately NOT interned. It is the only candidate read as an
 * alarm LEVEL (`h.severity === "critical"` picks the pill colour), so an index
 * would silently downgrade a critical hint to a warn pill in any bundle that
 * predates the table. ~940B is worth paying not to under-report an alarm.
 */
export type HintTuple = [
  worker_id: InternedString,
  severity: string | null,
  message: InternedString,
  suggested_action: InternedString,
  reason_code: InternedString,
];

/** Wire form of an rchd alert. Not interned; ≤20 per dispatcher. */
export type AlertTuple = [
  kind: string | null,
  severity: string | null,
  worker_id: string | null,
  message: string | null,
  first_seen: string | null,
  last_seen: string | null,
  state: string | null,
];

export interface Alert {
  kind: string | null;
  severity: string | null;
  worker_id: string | null;
  message: string | null;
  first_seen: string | null;
  last_seen: string | null;
  state: string | null;
}

/** Wire form of an rchd issue: `[severity, summary, remediation]`. */
export type IssueTuple = [severity: string | null, summary: string | null, remediation: string | null];

export interface Issue {
  severity: string | null;
  summary: string | null;
  remediation: string | null;
}

/**
 * Wire form of an active build with rchd's stall detectors:
 * `[id, project, worker, command, started_at, heartbeat_age_secs,
 *   progress_age_secs, phase, hook_alive, heartbeat_stale, progress_stale,
 *   confidence, slots, build_age_secs]`.
 */
export type ActiveBuildTuple = [
  id: string | null,
  project: string | null,
  worker_id: string | null,
  command: string | null,
  started_at: string | null,
  heartbeat_age_secs: number | null,
  progress_age_secs: number | null,
  phase: string | null,
  hook_alive: boolean | null,
  heartbeat_stale: boolean | null,
  progress_stale: boolean | null,
  confidence: number | null,
  slots: number | null,
  build_age_secs: number | null,
];

export interface ActiveBuild {
  id: string | null;
  project: string | null;
  worker_id: string | null;
  command: string | null;
  started_at: string | null;
  heartbeat_age_secs: number | null;
  progress_age_secs: number | null;
  phase: string | null;
  hook_alive: boolean | null;
  heartbeat_stale: boolean | null;
  progress_stale: boolean | null;
  confidence: number | null;
  slots: number | null;
  build_age_secs: number | null;
}

/** Wire form of a queued build: `[id, project, command, position, slots_needed, wait_time]`. */
export type QueuedBuildTuple = [
  id: string | null,
  project: string | null,
  command: string | null,
  position: number | null,
  slots_needed: number | null,
  wait_time: string | null,
];

export interface QueuedBuild {
  id: string | null;
  project: string | null;
  command: string | null;
  position: number | null;
  slots_needed: number | null;
  wait_time: string | null;
}

/**
 * One dev machine's OWN derated reading of one worker's slots: `[used, total]`.
 *
 * Positional, not named. There is one of these per (dispatcher, worker) pair —
 * 142 of them on a 10-machine fleet — and at that repetition the key names cost
 * several times what the numbers do. This replaced a full duplicate `Worker`
 * record per dispatcher, which was 54.6% of the entire snapshot payload and
 * carried nothing the merged `workers[]` did not already hold.
 */
export type WorkerSlotPair = [used: number | null, total: number | null];

/** A `WorkerSlotPair` expanded by `classifyDispatcher()` for the dev-machine drawer. */
export interface DispatcherWorkerSlots {
  used_slots: number | null;
  total_slots: number | null;
}

export interface BuildStats {
  total: number;
  remote: number;
  local: number;
  success: number;
  failure: number;
  avg_duration_ms: number | null;
}

/** A dev machine — a box that RUNS rch and dispatches builds to the pool. */
export interface Dispatcher {
  id: string;
  reachable: boolean;
  /**
   * Why collection failed, when it did — one entry per failing rch subcommand.
   * Empty on a clean run. Kept rather than collapsed into `reachable: false` so
   * an ssh auth failure, a missing binary and a dead daemon stay distinguishable.
   */
  collection_errors: string[];
  /**
   * True when `rch workers list` failed, so `tags` and `priority` are MISSING
   * rather than genuinely unset. Without it an untagged fleet renders as though
   * that were the real config.
   */
  config_degraded: boolean;
  /**
   * How this machine was collected: `api` = rchd's tailnet status API,
   * `ssh` = the `rch … --json` probe (also the fallback when the API did not
   * answer — then `collection_errors` says why). Absent on older snapshots.
   */
  transport?: "api" | "ssh";
  /** When the ssh self-checks (doctor/shim/hook) behind an API-collected record were taken. */
  selfchecks_at?: string | null;
  posture: string | null;
  posture_description: string | null;
  daemon: {
    version: string | null;
    uptime_secs: number | null;
    pid: number | null;
    workers_total: number | null;
    workers_healthy: number | null;
    slots_total: number | null;
    slots_available: number | null;
  } | null;
  build_stats: BuildStats | null;
  saved_time_ms: number | null;
  active_builds: number;
  queued_builds: number;
  /**
   * Recent builds in wire form. Read them through `DispatcherView.recent_builds`,
   * which `classifyDispatcher()` expands from these tuples.
   */
  builds: BuildTuple[];
  /**
   * Remediation hints in wire form. Read them through
   * `DispatcherView.remediation_hints`.
   */
  hints: HintTuple[];
  /**
   * rchd's alert lifecycle, `[kind, severity, worker_id, message, first_seen,
   * last_seen, state]`. Consumed by `src/problems.js` (a worker problem's
   * `since`) and the dev-machine drawer. Optional: snapshots written before
   * these were re-added carry none.
   */
  alerts?: AlertTuple[];
  /** rchd's own diagnoses with the command it wants run: `[severity, summary, remediation]`. */
  issues?: IssueTuple[];
  /** Active builds with the daemon's stall detectors — see `ActiveBuildTuple`. */
  active?: ActiveBuildTuple[];
  /** Queued builds: `[id, project, command, position, slots_needed, wait_time]`. */
  queued?: QueuedBuildTuple[];
  /** Repo convergence as this box sees it; `workers` lists only the NOT-ready ones. */
  convergence?: {
    status: string | null;
    ready: number;
    drifting: number;
    converging: number;
    failed: number;
    stale: number;
    workers: [worker_id: string | null, drift_state: string | null, missing_repos: number][];
  } | null;
  /**
   * `rch doctor` on this box. `null` means the probe did not answer (old
   * `rch`, missing command) — UNKNOWN, never "fine". `failing` lists only the
   * checks that did not pass: `[name, status, message, fixable]`.
   */
  doctor?: {
    total: number;
    passed: number;
    warnings: number;
    failed: number;
    failing: [name: string | null, status: string | null, message: string | null, fixable: boolean][];
  } | null;
  /**
   * `rch shim status`: is the cargo shim installed, current and first on PATH,
   * and how many compiler processes are running OUTSIDE rch right now. The
   * latter is the "silently burning local cores" detector. `null` = unknown.
   */
  shim?: {
    installed: boolean | null;
    up_to_date: boolean | null;
    on_path: boolean | null;
    interception: string | null;
    local_builds_running: number | null;
    toolchains_wrapped: number | null;
    toolchains_total: number | null;
  } | null;
  /** `rch hook status`: is the PreToolUse hook installed, per agent. `null` = unknown. */
  hook?: {
    claude_code: boolean | null;
    agents: [agent: string | null, installed: boolean][];
  } | null;
  /** Lifetime test-run counters from the daemon, when reported. */
  tests?: { runs: number; passed: number; failed: number; build_errors: number } | null;
  /**
   * This machine's own derated slot reading for every worker in the fleet, as
   * ONE ROW of the (dispatcher x worker) matrix, aligned index-for-index to
   * `Snapshot.workers`.
   *
   *   pool_slots[i] = [used, total]   this machine's reading of workers[i]
   *   pool_slots[i] = null            this machine does not have workers[i]
   *
   * NOT a worker inventory — use the top-level `Snapshot.workers` for that, or
   * `Worker.slots_by_dispatcher` to go the other way. This exists only because
   * rchd derates each worker independently on every box, so "how much of the
   * pool can THIS machine actually reach" is a per-dispatcher fact.
   *
   * It is also the ONLY copy of that matrix on the wire, which is what keeps
   * the payload from growing as the product of both fleet counts three times
   * over; `projectDispatchers()` in tools/snapshot.mjs has the measurements.
   * Trailing nulls are trimmed, so the row may be shorter than `workers[]` —
   * index it defensively.
   *
   * Read it through `DispatcherView.workers`, which `classifyDispatcher()`
   * expands from this row, skipping the nulls.
   */
  pool_slots: (WorkerSlotPair | null)[];
  /**
   * The pre-matrix form of `pool_slots`: dense, and positional against THIS
   * dispatcher's own worker order rather than the fleet's.
   *
   * Only snapshots written before the matrix was de-duplicated carry it. It is
   * still read, so a browser tab holding an older payload keeps its pool panel;
   * the collector never writes it again. The two can never be confused because
   * they are different keys — which is the entire reason for the rename.
   */
  worker_slots?: WorkerSlotPair[];
}

export interface HistoryPoint {
  t: string;
  slots_total: number;
  slots_used: number;
  workers: number;
  disk_free_gb: number;
  builds_remote: number;
  builds_local: number;
  dispatchers_remote_ready: number;
}

export interface Snapshot {
  schema: string;
  label: string;
  generated_at: string;
  totals: {
    workers: number;
    slots: number;
    slots_used: number;
    cores: number;
    disk_free_gb: number;
    disk_total_gb: number;
    disk_reporting_workers?: number;
    dispatchers_total: number;
    dispatchers_reachable: number;
    dispatchers_remote_ready: number;
    builds_remote: number;
    builds_local: number;
    active_builds: number;
    /** Compiler processes running outside rch across the fleet right now (absent on old snapshots). */
    local_builds_running?: number;
    /** Dev machines whose Claude Code hook is known to be missing (absent on old snapshots). */
    dispatchers_hook_missing?: number;
  };
  dispatchers: Dispatcher[];
  workers: Worker[];
  /**
   * Snapshot-level string table for the interned build/hint tuple slots.
   *
   * ONE table for the whole snapshot, not one per array: the duplication is
   * almost entirely across dispatchers (the same hint text for the same shared
   * worker on every box), so per-dispatcher tables save only 1,810B against
   * 24,415B for a global one. Ordered hottest-first so the most repeated
   * strings get the shortest indices.
   *
   * Optional: a snapshot written before the table existed simply has no
   * `strings`, and every interned slot in it already holds its literal string,
   * so the expanders are value-identical either way.
   */
  strings?: string[];
  history: HistoryPoint[];
}

export type HealthLevel = "healthy" | "busy" | "warn" | "critical" | "offline" | "disabled";

export interface WorkerView extends Worker {
  health: HealthLevel;
  healthReason: string;
  diskUsedPct: number | null;
  loadPerCore: number | null;
  staleSeconds: number | null;
  slotPct: number | null;
}

/** Derived health for a dev machine. */
export type DevLevel = "offloading" | "idle" | "local-only" | "degraded" | "unreachable";

export interface DispatcherView extends Dispatcher {
  level: DevLevel;
  levelReason: string;
  remotePct: number | null;
  /**
   * Which window `remotePct` was measured over. "recent" is the last N actual
   * builds; "lifetime" is the cumulative daemon counters, used only when no
   * recent builds are recorded. null when there is nothing to measure.
   */
  remoteBasis: "recent" | "lifetime" | null;
  /** How many builds `remotePct` was computed from. */
  remoteCounted: number;
  /**
   * `worker_slots` expanded into records, one per worker this machine can see.
   * Slot readings only — every other worker fact lives on `Snapshot.workers`.
   */
  workers: DispatcherWorkerSlots[];
  /** `Dispatcher.builds` expanded back into records, oldest first. */
  recent_builds: RecentBuild[];
  /** `Dispatcher.hints` expanded back into records, in collector order. */
  remediation_hints: RemediationHint[];
  /** `Dispatcher.alerts` expanded; empty on snapshots that carry none. */
  alert_records: Alert[];
  /** `Dispatcher.issues` expanded; empty on snapshots that carry none. */
  issue_records: Issue[];
  /** `Dispatcher.active` expanded; empty on snapshots that carry none. */
  active_records: ActiveBuild[];
  /** `Dispatcher.queued` expanded; empty on snapshots that carry none. */
  queued_records: QueuedBuild[];
}
