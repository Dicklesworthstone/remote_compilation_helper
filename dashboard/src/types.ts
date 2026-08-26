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
  enabled: boolean;
  seen_by?: string[];
  /** Slot view per dev machine — rchd derates independently on each. */
  slots_by_dispatcher?: Record<string, { used: number | null; total: number | null }>;
}

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

export interface RemediationHint {
  worker_id: string | null;
  severity: string | null;
  message: string | null;
  suggested_action: string | null;
  reason_code: string | null;
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
  recent_builds: RecentBuild[];
  issues: unknown[];
  alerts: unknown[];
  remediation_hints: RemediationHint[];
  workers: Worker[];
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
}
