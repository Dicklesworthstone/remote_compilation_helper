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
  failure_history: boolean[];
  pressure: WorkerPressure;
  latency_ms: number | null;
  last_seen_unix: number | null;
  caps: WorkerCaps;
  tags: string[];
  /** From `rch workers list` — absent in `rch status`. */
  priority: number | null;
  seen_by?: string[];
  /** Slot view per dev machine — rchd derates independently on each. */
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
 * The WIRE form of a `RecentBuild`.
 *
 * Positional, not named. All seven values are consumed — the dev-machine drawer
 * renders six and uses `command` as the row tooltip, and both classifiers count
 * `location` to decide whether the box is offloading — so none can be dropped.
 * The key names can: 121 builds on a 10-machine fleet repeated the same 84
 * characters of `"project":"command":…` 121 times, 10.2KB of a 92.3KB payload.
 * Expanded by `expandBuilds()` in src/derive.ts.
 */
export type BuildTuple = [
  project: string | null,
  command: string | null,
  location: string | null,
  worker_id: string | null,
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
 */
export type HintTuple = [
  worker_id: string | null,
  severity: string | null,
  message: string | null,
  suggested_action: string | null,
  reason_code: string | null,
];

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
  // `issues[]` and `alerts[]` are deliberately absent. The collector gathered
  // both and nothing ever read either one — no component, no derive path, no
  // LLM view, no test. They cost 8.0KB of a 92.3KB payload (8.7%) on every
  // 5-minute refresh. Re-add them only together with a consumer.
  /**
   * This machine's own derated slot reading for every worker it can see.
   *
   * NOT a worker inventory — use the top-level `Snapshot.workers` for that, or
   * `Worker.slots_by_dispatcher` to go the other way and ask which dev machines
   * can see a given worker. This exists only because rchd derates each worker
   * independently on every box, so "how much of the pool can THIS machine
   * actually reach" is a per-dispatcher fact.
   *
   * Read it through `DispatcherView.workers`, which `classifyDispatcher()`
   * expands from these pairs.
   */
  worker_slots: WorkerSlotPair[];
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
  };
  dispatchers: Dispatcher[];
  workers: Worker[];
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
}
