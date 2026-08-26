import type {
  Dispatcher, DispatcherView, DevLevel, HealthLevel, Snapshot, Worker, WorkerView,
} from "./types";

/** Snapshots older than this are called out — stale data is worse than none. */
export const STALE_WARN_SECONDS = 15 * 60;
export const STALE_CRIT_SECONDS = 60 * 60;

export function fmtGb(gb: number | null | undefined, digits = 0): string {
  if (gb == null || !Number.isFinite(gb)) return "—";
  if (gb >= 1024) return `${(gb / 1024).toFixed(digits === 0 ? 1 : digits)} TB`;
  return `${gb.toFixed(digits)} GB`;
}

export function fmtAge(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtUptime(seconds: number | null): string {
  if (seconds == null) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function fmtDuration(ms: number | null): string {
  if (ms == null || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60_000)}m`;
}

/**
 * Fold raw worker facts into one status.
 *
 * Order is deliberate. "We cannot reach it" outranks a stale disk reading,
 * because reachability is the more actionable fact. Disk outranks load: a full
 * disk takes a worker down hard, while high load is usually just work happening.
 */
/**
 * @param snapshotMs when the snapshot was TAKEN — not the reader's clock.
 *
 * Worker "last seen" must be judged against snapshot time. Using the browser's
 * clock made every worker in a two-hour-old snapshot report "offline", because
 * the snapshot's own age was being charged to each worker. Snapshot staleness
 * is surfaced separately by the header indicator and the stale banner.
 */
export function classify(w: Worker, snapshotMs: number): WorkerView {
  const p = w.pressure;
  const diskUsedPct =
    p.disk_total_gb && p.disk_free_gb != null && p.disk_total_gb > 0
      ? ((p.disk_total_gb - p.disk_free_gb) / p.disk_total_gb) * 100
      : null;
  const loadPerCore =
    w.caps.load_avg_1 != null && w.caps.num_cpus ? w.caps.load_avg_1 / w.caps.num_cpus : null;
  const staleSeconds = w.last_seen_unix != null ? snapshotMs / 1000 - w.last_seen_unix : null;
  const slotPct =
    w.total_slots && w.total_slots > 0 ? ((w.used_slots ?? 0) / w.total_slots) * 100 : null;

  const st = (w.status ?? "").toLowerCase();
  let health: HealthLevel = "healthy";
  let healthReason = "healthy";

  if (st === "disabled" || w.enabled === false) {
    health = "disabled";
    healthReason = "disabled in workers.toml";
  } else if (st === "down" || st === "unreachable" || w.circuit_state === "open") {
    health = "offline";
    healthReason = w.circuit_state === "open" ? "circuit breaker open" : `worker ${st || "unreachable"}`;
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline";
    healthReason = `not seen for ${Math.round(staleSeconds / 60)}m`;
  } else if (p.state === "critical" || (diskUsedPct != null && diskUsedPct >= 95)) {
    health = "critical";
    healthReason = p.reason ? `pressure: ${p.reason}` : `disk ${diskUsedPct?.toFixed(0)}% full`;
  } else if (st === "draining") {
    health = "warn";
    healthReason = "draining";
  } else if (p.state === "warning" || (diskUsedPct != null && diskUsedPct >= 88)) {
    health = "warn";
    healthReason = p.reason ? `pressure: ${p.reason}` : `disk ${diskUsedPct?.toFixed(0)}% full`;
  } else if (w.consecutive_failures > 0) {
    health = "warn";
    healthReason = `${w.consecutive_failures} consecutive failure${w.consecutive_failures === 1 ? "" : "s"}`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn";
    healthReason = `load ${loadPerCore.toFixed(1)}x cores`;
  } else if (w.circuit_state === "half_open") {
    health = "warn";
    healthReason = "circuit half-open (probing)";
  } else if ((w.used_slots ?? 0) > 0) {
    health = "busy";
    healthReason = `${w.used_slots}/${w.total_slots} slots in use`;
  } else if (w.caps.projects_root_ok === false) {
    health = "warn";
    healthReason = "projects root unhealthy";
  }

  return { ...w, health, healthReason, diskUsedPct, loadPerCore, staleSeconds, slotPct };
}

export function classifyAll(snap: Snapshot, _nowMs?: number): WorkerView[] {
  // Deliberately ignores the caller's clock — see classify().
  const snapshotMs = new Date(snap.generated_at).getTime();
  return snap.workers.map((w) => classify(w, snapshotMs));
}

/**
 * Classify a DEV MACHINE by the question that actually matters: are its builds
 * going to the worker pool, or is it quietly compiling locally?
 *
 * `local-only` is the loud one, and it is why this dashboard exists: a
 * dispatcher whose workers all fall below its `build_slots` estimate silently
 * compiles everything on itself while `rch queue`, worker probes and every
 * other surface still report a healthy fleet.
 */
export function classifyDispatcher(d: Dispatcher): DispatcherView {
  const s = d.build_stats;
  const counted = s ? s.remote + s.local : 0;
  const remotePct = counted > 0 ? (s!.remote / counted) * 100 : null;

  let level: DevLevel;
  let levelReason: string;

  if (!d.reachable) {
    level = "unreachable";
    levelReason = "no response from rch";
  } else if (d.posture && d.posture !== "remote_ready") {
    level = d.posture.includes("local") ? "local-only" : "degraded";
    levelReason = d.posture_description ?? d.posture;
  } else if (remotePct != null && remotePct < 50) {
    level = "local-only";
    levelReason = `only ${remotePct.toFixed(0)}% of recent builds went remote`;
  } else if (counted === 0) {
    level = "idle";
    levelReason = "no builds recorded yet";
  } else {
    level = "offloading";
    levelReason = `${remotePct?.toFixed(0)}% of recent builds went to the pool`;
  }

  return { ...d, level, levelReason, remotePct };
}

export const HEALTH_ORDER: HealthLevel[] = ["critical", "warn", "offline", "busy", "healthy", "disabled"];

export function healthRank(h: HealthLevel): number {
  const i = HEALTH_ORDER.indexOf(h);
  return i === -1 ? HEALTH_ORDER.length : i;
}

export const DEV_ORDER: DevLevel[] = ["unreachable", "local-only", "degraded", "offloading", "idle"];
export function devRank(l: DevLevel): number {
  const i = DEV_ORDER.indexOf(l);
  return i === -1 ? DEV_ORDER.length : i;
}

/** Bar colour class for a 0-100 utilisation value. */
export function utilClass(pct: number | null): string {
  if (pct == null) return "off";
  if (pct >= 95) return "crit";
  if (pct >= 88) return "warn";
  return "ok";
}
