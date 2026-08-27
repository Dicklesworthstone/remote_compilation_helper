/**
 * Distil a full fleet snapshot into a compact, action-first view for LLM/agent
 * consumption, and encode it as JSON or TOON.
 *
 * Why a separate view rather than serving the raw snapshot: the snapshot is
 * ~196KB of plaintext, most of it per-worker detail an agent does not need to
 * answer "is my fleet healthy and are my builds offloading?". This view is
 * roughly 2-3KB, leads with PROBLEMS, and uses TOON's tabular arrays so the
 * repeated per-worker keys are emitted once instead of N times (~40% fewer
 * characters than the equivalent JSON).
 *
 * Health thresholds below intentionally mirror `src/derive.ts`. They are
 * duplicated because that file is TypeScript compiled into the browser bundle
 * and this one runs in plain Node (CLI + serverless function). If you change a
 * threshold, change it in BOTH — `npm run test:llm` asserts they agree on a
 * fixture.
 */

import { encode as toonEncode } from "@toon-format/toon";

export const STALE_CRIT_SECONDS = 60 * 60;

const r1 = (n) => (typeof n === "number" && Number.isFinite(n) ? Math.round(n * 10) / 10 : null);

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
  if (st === "disabled" || w.enabled === false) { health = "disabled"; reason = "disabled in workers.toml"; }
  else if (st === "down" || st === "unreachable" || w.circuit_state === "open") {
    health = "offline";
    reason = w.circuit_state === "open" ? "circuit breaker open" : `worker ${st || "unreachable"}`;
  } else if (staleSeconds != null && staleSeconds > STALE_CRIT_SECONDS) {
    health = "offline"; reason = `not seen for ${Math.round(staleSeconds / 60)}m`;
  } else if (p.state === "critical" || (diskUsedPct != null && diskUsedPct >= 95)) {
    health = "critical"; reason = p.reason ? `pressure: ${p.reason}` : `disk ${diskUsedPct?.toFixed(0)}% full`;
  } else if (st === "draining") { health = "warn"; reason = "draining"; }
  else if (p.state === "warning" || (diskUsedPct != null && diskUsedPct >= 88)) {
    health = "warn"; reason = p.reason ? `pressure: ${p.reason}` : `disk ${diskUsedPct?.toFixed(0)}% full`;
  } else if ((w.consecutive_failures ?? 0) > 0) {
    health = "warn";
    reason = `${w.consecutive_failures} consecutive failure${w.consecutive_failures === 1 ? "" : "s"}`;
  } else if (loadPerCore != null && loadPerCore >= 2) {
    health = "warn"; reason = `load ${loadPerCore.toFixed(1)}x cores`;
  } else if (w.circuit_state === "half_open") { health = "warn"; reason = "circuit half-open (probing)"; }
  else if ((w.used_slots ?? 0) > 0) { health = "busy"; reason = `${w.used_slots}/${w.total_slots} slots in use`; }
  else if (w.caps?.projects_root_ok === false) { health = "warn"; reason = "projects root unhealthy"; }

  return { health, reason, diskUsedPct, loadPerCore };
}

/** Mirror of `classifyDispatcher()` in src/derive.ts — keep in sync. */
export function classifyDev(d) {
  const s = d.build_stats;
  const counted = s ? s.remote + s.local : 0;
  const remotePct = counted > 0 ? (s.remote / counted) * 100 : null;
  let level, reason;
  if (!d.reachable) { level = "unreachable"; reason = "no response from rch"; }
  else if (d.posture && d.posture !== "remote_ready") {
    level = d.posture.includes("local") ? "local-only" : "degraded";
    reason = d.posture_description ?? d.posture;
  } else if (remotePct != null && remotePct < 50) {
    level = "local-only"; reason = `only ${remotePct.toFixed(0)}% of recent builds went remote`;
  } else if (counted === 0) { level = "idle"; reason = "no builds recorded yet"; }
  else { level = "offloading"; reason = `${remotePct.toFixed(0)}% of recent builds went to the pool`; }
  return { level, reason, remotePct };
}

const SEVERITY = { critical: 0, warn: 1, info: 2 };

/**
 * Build the compact view.
 * @param snap  decrypted snapshot (schema rch.dashboard.snapshot.v2)
 * @param opts  { view: "summary"|"full", now: epoch ms }
 */
export function buildLlmView(snap, opts = {}) {
  const view = opts.view === "full" ? "full" : "summary";
  const now = opts.now ?? Date.now();
  const ageSeconds = Math.round((now - new Date(snap.generated_at).getTime()) / 1000);

  const snapshotMs = new Date(snap.generated_at).getTime();
  const workers = snap.workers.map((w) => ({ ...w, ...classifyWorker(w, snapshotMs) }));
  const devs = snap.dispatchers.map((d) => ({ ...d, ...classifyDev(d) }));

  const counts = {};
  for (const w of workers) counts[w.health] = (counts[w.health] ?? 0) + 1;

  const t = snap.totals ?? {};
  const buildsCounted = (t.builds_remote ?? 0) + (t.builds_local ?? 0);

  // Problems first: this is what an agent should act on.
  const problems = [];
  for (const d of devs) {
    if (d.level === "unreachable" || d.level === "local-only" || d.level === "degraded") {
      problems.push({
        severity: d.level === "degraded" ? "warn" : "critical",
        kind: `dev.${d.level}`,
        target: d.id,
        detail: d.reason,
      });
    }
  }
  for (const w of workers) {
    if (w.health === "critical" || w.health === "offline") {
      problems.push({ severity: "critical", kind: `worker.${w.health}`, target: w.id, detail: w.reason });
    } else if (w.health === "warn") {
      problems.push({ severity: "warn", kind: "worker.warn", target: w.id, detail: w.reason });
    }
  }
  if (ageSeconds > STALE_CRIT_SECONDS) {
    problems.push({
      severity: "critical", kind: "snapshot.stale", target: "snapshot",
      detail: `snapshot is ${Math.round(ageSeconds / 60)}m old; re-run the collector`,
    });
  }
  problems.sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity] || a.target.localeCompare(b.target));

  // Bound the list so a large fleet cannot blow an agent's context, but NEVER
  // drop rows silently — a truncated problem list that looks complete is how a
  // monitoring tool lies. Severity-sorted, so the cut only ever loses the least
  // urgent rows, and the count of what was cut is reported.
  const PROBLEM_CAP = 40;
  const problemsOmitted = Math.max(0, problems.length - PROBLEM_CAP);
  const shownProblems = problemsOmitted > 0 ? problems.slice(0, PROBLEM_CAP) : problems;

  const out = {
    schema: "rch.fleet.llm.v1",
    label: snap.label,
    generated_at: snap.generated_at,
    age_seconds: ageSeconds,
    stale: ageSeconds > STALE_CRIT_SECONDS,
    summary: {
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
      builds_remote: t.builds_remote ?? 0,
      builds_local: t.builds_local ?? 0,
      offload_pct: buildsCounted > 0 ? r1(((t.builds_remote ?? 0) / buildsCounted) * 100) : null,
      active_builds: t.active_builds ?? 0,
    },
    problems: shownProblems,
    problems_total: problems.length,
    problems_omitted: problemsOmitted,
    dev_machines: devs.map((d) => ({
      id: d.id,
      level: d.level,
      posture: d.posture ?? "",
      remote: d.build_stats?.remote ?? 0,
      local: d.build_stats?.local ?? 0,
      workers_healthy: d.daemon?.workers_healthy ?? null,
      workers_total: d.daemon?.workers_total ?? null,
      slots_free: d.daemon?.slots_available ?? null,
      slots_total: d.daemon?.slots_total ?? null,
      active: d.active_builds ?? 0,
      version: d.daemon?.version ?? "",
      uptime_h: d.daemon?.uptime_secs != null ? Math.round(d.daemon.uptime_secs / 360) / 10 : null,
    })),
    workers: workers.map((w) => ({
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
    })),
  };

  if (view === "full") {
    out.dev_detail = devs.map((d) => ({
      id: d.id,
      reason: d.reason,
      posture_description: d.posture_description ?? "",
      remediation_hints: (d.remediation_hints ?? []).map((h) => ({
        worker: h.worker_id ?? "",
        severity: h.severity ?? "",
        message: h.message ?? "",
        action: h.suggested_action ?? "",
      })),
      recent_builds: (d.recent_builds ?? []).slice(-10).map((b) => ({
        project: b.project ?? "",
        location: b.location ?? "",
        worker: b.worker_id ?? "",
        ms: b.duration_ms ?? null,
        exit: b.exit_code ?? null,
      })),
    }));
    out.worker_detail = workers.map((w) => ({
      id: w.id,
      host: w.host ?? "",
      user: w.user ?? "",
      pressure_state: w.pressure?.state ?? "",
      pressure_reason: w.pressure?.reason ?? "",
      disk_io_pct: r1(w.pressure?.disk_io_util_pct),
      mem_pressure: r1(w.pressure?.memory_pressure),
      latency_ms: r1(w.latency_ms),
      failures: w.consecutive_failures ?? 0,
      rustc: w.caps?.rustc_version ?? "",
      seen_by: (w.seen_by ?? []).join("|"),
    }));
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
