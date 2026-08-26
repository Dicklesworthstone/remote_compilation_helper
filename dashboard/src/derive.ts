import type { HealthLevel, Snapshot, Worker, WorkerView } from "./types";

/** Snapshots older than this are called out loudly — stale data is worse than none. */
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

/**
 * Fold raw worker facts into one status.
 *
 * Ordering is deliberate: a disabled or unreachable worker is reported as such
 * even if its last known disk reading was alarming, because "we cannot see it"
 * is the more actionable fact. Disk is checked before load because a full disk
 * takes a worker down hard, whereas high load is usually just work happening.
 */
export function classify(w: Worker, nowMs: number): WorkerView {
  const caps = w.caps;
  const diskUsedPct =
    caps.disk_total_gb && caps.disk_free_gb != null && caps.disk_total_gb > 0
      ? ((caps.disk_total_gb - caps.disk_free_gb) / caps.disk_total_gb) * 100
      : null;
  const loadPerCore =
    caps.load_avg_1 != null && caps.num_cpus ? caps.load_avg_1 / caps.num_cpus : null;
  const staleSeconds = w.last_seen_unix != null ? nowMs / 1000 - w.last_seen_unix : null;

  let health: HealthLevel = "healthy";
  let healthReason = "healthy";

  if (!w.enabled) {
    health = "disabled";
    healthReason = "disabled in workers.toml";
  } else if (w.circuit_state === "open") {
    health = "offline";
    healthReason = "circuit breaker open";
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline";
    healthReason = `not seen for ${fmtAge(staleSeconds)}`;
  } else if (diskUsedPct != null && diskUsedPct >= 95) {
    health = "critical";
    healthReason = `disk ${diskUsedPct.toFixed(0)}% full`;
  } else if (diskUsedPct != null && diskUsedPct >= 88) {
    health = "warn";
    healthReason = `disk ${diskUsedPct.toFixed(0)}% full`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn";
    healthReason = `load ${loadPerCore.toFixed(1)}× cores`;
  } else if (w.circuit_state === "half_open") {
    health = "warn";
    healthReason = "circuit half-open (probing)";
  } else if (w.active_builds > 0) {
    health = "busy";
    healthReason = `${w.active_builds} active build${w.active_builds === 1 ? "" : "s"}`;
  } else if (caps.projects_root_ok === false) {
    health = "warn";
    healthReason = "projects root unhealthy";
  }

  return { ...w, health, healthReason, diskUsedPct, loadPerCore, staleSeconds };
}

export function classifyAll(snap: Snapshot, nowMs: number): WorkerView[] {
  return snap.workers.map((w) => classify(w, nowMs));
}

export const HEALTH_ORDER: HealthLevel[] = [
  "critical",
  "warn",
  "offline",
  "busy",
  "healthy",
  "disabled",
];

export function healthRank(h: HealthLevel): number {
  const i = HEALTH_ORDER.indexOf(h);
  return i === -1 ? HEALTH_ORDER.length : i;
}

/** Bar colour class for a 0-100 utilisation value. */
export function utilClass(pct: number | null): string {
  if (pct == null) return "off";
  if (pct >= 95) return "crit";
  if (pct >= 88) return "warn";
  return "ok";
}
