import type {
  BuildTuple, Dispatcher, DispatcherView, DispatcherWorkerSlots, DevLevel, HealthLevel,
  HintTuple, RecentBuild, RemediationHint, Snapshot, Worker, WorkerSlotPair, WorkerView,
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
  if (seconds == null || !Number.isFinite(seconds)) return "—";
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

  // A pressure event does not always carry a disk number (memory pressure, or a
  // telemetry gap). Falling back to the raw percentage unconditionally rendered
  // the literal string "disk undefined% full" on those workers.
  const pressureReason = (fallback: string) =>
    p.reason
      ? `pressure: ${p.reason}`
      : diskUsedPct != null
        ? `disk ${diskUsedPct.toFixed(0)}% full`
        : fallback;

  if (st === "disabled") {
    health = "disabled";
    healthReason = "manually disabled";
  } else if (st === "down" || st === "unreachable" || w.circuit_state === "open") {
    health = "offline";
    healthReason = w.circuit_state === "open" ? "circuit breaker open" : `worker ${st || "unreachable"}`;
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline";
    healthReason = `not seen for ${Math.round(staleSeconds / 60)}m`;
  } else if (p.state === "critical" || (diskUsedPct != null && diskUsedPct >= 95)) {
    health = "critical";
    healthReason = pressureReason("critical pressure");
  } else if (st === "draining") {
    health = "warn";
    healthReason = "draining (finishing current jobs)";
  } else if (st === "drained") {
    // Terminal state of a drain: idle and accepting nothing. It looks identical
    // to a healthy idle worker on every other surface, which is the trap.
    health = "warn";
    healthReason = "drained — accepting no new jobs";
  } else if (p.state === "warning" || (diskUsedPct != null && diskUsedPct >= 88)) {
    health = "warn";
    healthReason = pressureReason("pressure warning");
  } else if (p.state === "telemetry_gap") {
    // rch's own fourth pressure state. Treating it as healthy meant "I have no
    // idea how this worker is doing" rendered green.
    health = "warn";
    healthReason = p.reason ? `pressure: ${p.reason}` : "no pressure telemetry";
  } else if (st === "degraded") {
    health = "warn";
    healthReason = "worker responding slowly";
  } else if (w.consecutive_failures > 0) {
    health = "warn";
    healthReason = `${w.consecutive_failures} consecutive failure${w.consecutive_failures === 1 ? "" : "s"}`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn";
    healthReason = `load ${loadPerCore.toFixed(1)}x cores`;
  } else if (w.circuit_state === "half_open") {
    health = "warn";
    healthReason = "circuit half-open (probing)";
  } else if (w.caps.projects_root_ok === false) {
    // Must precede the `busy` branch: a busy worker with a broken projects root
    // is still broken, and this check used to be unreachable whenever a build
    // was running — exactly when it matters.
    health = "warn";
    healthReason = "projects root unhealthy";
  } else if (p.telemetry_fresh === false) {
    // Everything above says healthy, but the readings behind that verdict are
    // stale. Report the uncertainty rather than the conclusion.
    health = "warn";
    healthReason =
      p.telemetry_age_secs != null
        ? `telemetry ${fmtAge(p.telemetry_age_secs).replace(" ago", "")} old`
        : "telemetry stale";
  } else if ((w.used_slots ?? 0) > 0) {
    health = "busy";
    healthReason = `${w.used_slots}/${w.total_slots} slots in use`;
  }

  return { ...w, health, healthReason, diskUsedPct, loadPerCore, staleSeconds, slotPct };
}

export function classifyAll(snap: Snapshot, _nowMs?: number): WorkerView[] {
  // Deliberately ignores the caller's clock — see classify().
  const snapshotMs = new Date(snap.generated_at).getTime();
  return snap.workers.map((w) => classify(w, snapshotMs));
}

/**
 * Expand the wire form of a dev machine's derated slot view.
 *
 * The collector emits `[used, total]` pairs rather than a worker record per
 * dispatcher: at 142 pairs on a 10-machine fleet the duplicated records were
 * 54.6% of the whole snapshot and held nothing the merged `Snapshot.workers`
 * did not already carry. Only the slot readings are per-dispatcher, and the
 * dev-machine drawer only ever sums them and counts the zeroes.
 *
 * Tolerant of a missing or ragged array on purpose: a browser tab can be
 * holding a snapshot written by an older collector, and a dev machine with no
 * pool view must render as "0 workers seen", never crash the drawer.
 */
function expandWorkerSlots(pairs: WorkerSlotPair[] | undefined): DispatcherWorkerSlots[] {
  if (!Array.isArray(pairs)) return [];
  return pairs.map((p) => ({
    // `?? null` and not `|| null`: 0 used slots and 0 total slots are the two
    // most interesting readings here — a worker derated to 0 is invisible to
    // this machine, which is the whole reason the drawer shows this.
    used_slots: Array.isArray(p) ? (p[0] ?? null) : null,
    total_slots: Array.isArray(p) ? (p[1] ?? null) : null,
  }));
}

/**
 * Expand the wire form of a dev machine's recent builds.
 *
 * The collector ships `[project, command, location, worker_id, duration_ms,
 * exit_code, completed_at]` rather than an object per build: all seven values
 * are consumed, but at 121 records on a 10-machine fleet the repeated key names
 * alone were 10.2KB of a 92.3KB payload. Positions are the contract — keep this
 * in step with `tools/snapshot.mjs` and the mirror in `tools/llm-view.mjs`.
 *
 * Tolerant of a missing or ragged array on purpose: a browser tab can be holding
 * a snapshot written by an older collector, and a dev machine with no build
 * history must render "no builds recorded", never crash the drawer.
 */
export function expandBuilds(rows: BuildTuple[] | undefined): RecentBuild[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((b) => ({
    // `?? null` throughout, never `|| null`: `duration_ms: 0` and the
    // all-important `exit_code: 0` (the build SUCCEEDED) are real readings.
    project: Array.isArray(b) ? (b[0] ?? null) : null,
    command: Array.isArray(b) ? (b[1] ?? null) : null,
    location: Array.isArray(b) ? (b[2] ?? null) : null,
    worker_id: Array.isArray(b) ? (b[3] ?? null) : null,
    duration_ms: Array.isArray(b) ? (b[4] ?? null) : null,
    exit_code: Array.isArray(b) ? (b[5] ?? null) : null,
    completed_at: Array.isArray(b) ? (b[6] ?? null) : null,
  }));
}

/**
 * Expand the wire form of a dev machine's remediation hints:
 * `[worker_id, severity, message, suggested_action, reason_code]`.
 * Same reasoning and the same legacy tolerance as `expandBuilds()`.
 */
export function expandHints(rows: HintTuple[] | undefined): RemediationHint[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((h) => ({
    worker_id: Array.isArray(h) ? (h[0] ?? null) : null,
    severity: Array.isArray(h) ? (h[1] ?? null) : null,
    message: Array.isArray(h) ? (h[2] ?? null) : null,
    suggested_action: Array.isArray(h) ? (h[3] ?? null) : null,
    reason_code: Array.isArray(h) ? (h[4] ?? null) : null,
  }));
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
  // `build_stats` is CUMULATIVE since the daemon started, so it is the wrong
  // basis for a "is this box offloading right now" verdict: a machine that did
  // 200 local builds last month stays branded local-only through a week of
  // perfect offloading, and one that broke this morning takes weeks to cross
  // the threshold. `builds` is the actual recent window, so prefer it and fall
  // back to the lifetime counters only when it is empty. Every build in the
  // window counts, not a display slice: the verdict must be measured over what
  // the collector observed.
  const s = d.build_stats;
  const recent = expandBuilds(d.builds);
  const recentCounted = recent.length;
  const recentRemote = recent.filter((b) => (b.location ?? "").toLowerCase() === "remote").length;

  const lifetimeCounted = s ? s.remote + s.local : 0;
  const basis: "recent" | "lifetime" | null =
    recentCounted > 0 ? "recent" : lifetimeCounted > 0 ? "lifetime" : null;

  const remotePct =
    basis === "recent"
      ? (recentRemote / recentCounted) * 100
      : basis === "lifetime"
        ? (s!.remote / lifetimeCounted) * 100
        : null;

  const window = basis === "recent" ? `last ${recentCounted} builds` : "all builds since daemon start";

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
    levelReason = `only ${remotePct.toFixed(0)}% of the ${window} went remote`;
  } else if (basis === null) {
    level = "idle";
    levelReason = "no builds recorded yet";
  } else {
    level = "offloading";
    levelReason = `${remotePct!.toFixed(0)}% of the ${window} went to the pool`;
  }

  return {
    ...d,
    workers: expandWorkerSlots(d.worker_slots),
    // Expanded once here, not per component: the drawer renders these rows and
    // the card counts the hints, and both must see exactly the objects the
    // collector used to send.
    recent_builds: recent,
    remediation_hints: expandHints(d.hints),
    level, levelReason, remotePct, remoteBasis: basis,
    remoteCounted: recentCounted || lifetimeCounted,
  };
}

/**
 * Sort order, most urgent first. `offline` outranks `warn`: a worker we cannot
 * reach at all is a bigger problem than one with a single transient probe
 * failure. `disabled` sorts last — it is an intended state, not a fault.
 */
export const HEALTH_ORDER: HealthLevel[] = ["critical", "offline", "warn", "busy", "healthy", "disabled"];

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
