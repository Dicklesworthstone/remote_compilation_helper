/** Shapes emitted by `tools/snapshot.mjs`. Keep in sync with SCHEMA there. */

export interface WorkerCaps {
  num_cpus: number | null;
  load_avg_1: number | null;
  load_avg_5: number | null;
  load_avg_15: number | null;
  disk_free_gb: number | null;
  disk_total_gb: number | null;
  memory_pressure: number | null;
  cpu_microarch_level: number | null;
  rustc_version: string | null;
  bun_version: string | null;
  node_version: string | null;
  go_version: string | null;
  zig_version: string | null;
  projects_root_ok: boolean | null;
}

export interface Worker {
  id: string;
  host: string | null;
  user: string | null;
  tags: string[];
  total_slots: number | null;
  priority: number | null;
  enabled: boolean;
  active_builds: number;
  circuit_state: string | null;
  last_seen_unix: number | null;
  latency_ms: number | null;
  speed: number | null;
  caps: WorkerCaps;
  seen_by?: string[];
}

export interface DispatcherQueue {
  queue_depth: number;
  workers_total: number | null;
  workers_available: number | null;
  workers_busy: number | null;
  workers_offline: number | null;
  workers_healthy: number | null;
  slots_total: number | null;
  slots_available: number | null;
  active_builds: unknown[];
  queued_builds: unknown[];
}

export interface Dispatcher {
  id: string;
  reachable: boolean;
  daemon_running: boolean | null;
  uptime_seconds: number | null;
  queue: DispatcherQueue | null;
  workers: Worker[];
}

export interface HistoryPoint {
  t: string;
  slots_total: number;
  slots_available: number;
  workers_healthy: number | null;
  disk_free_gb: number;
}

export interface Snapshot {
  schema: string;
  label: string;
  generated_at: string;
  totals: {
    workers: number;
    slots: number;
    cores: number;
    disk_free_gb: number;
    disk_total_gb: number;
    dispatchers_reachable: number;
    dispatchers_total: number;
  };
  dispatchers: Dispatcher[];
  workers: Worker[];
  history: HistoryPoint[];
}

/** Derived per-worker health, computed in the browser from the raw facts. */
export type HealthLevel = "healthy" | "busy" | "warn" | "critical" | "offline" | "disabled";

export interface WorkerView extends Worker {
  health: HealthLevel;
  healthReason: string;
  diskUsedPct: number | null;
  loadPerCore: number | null;
  staleSeconds: number | null;
}
