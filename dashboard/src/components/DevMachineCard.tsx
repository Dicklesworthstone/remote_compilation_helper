import type { DispatcherView } from "../types";
import { fmtDuration, fmtUptime } from "../derive";

interface Props {
  d: DispatcherView;
  onOpen: (id: string) => void;
}

/**
 * A dev machine — a box that RUNS rch and dispatches builds. The headline is
 * the remote/local split, because a dev box that has quietly stopped offloading
 * looks perfectly healthy on every other surface.
 */
export function DevMachineCard({ d, onOpen }: Props) {
  const s = d.build_stats;
  const counted = s ? s.remote + s.local : 0;
  const remotePct = d.remotePct;
  // Bar colour encodes the remote share itself, not the posture: a box pushing
  // 100% of its builds to the pool is doing the right thing even when some
  // workers are pressure-blocked (posture "degraded") — the pill above carries
  // that alarm. Red here means builds are mostly landing locally.
  const cls =
    remotePct == null ? "off" : remotePct < 50 ? "crit" : remotePct < 80 ? "warn" : "ok";

  return (
    <button className="wcard" onClick={() => onOpen(d.id)} title={`View details for dev machine ${d.id}`}>
      <div className="wcard-top">
        <span className="wname">{d.id}</span>
        <span className={`pill dev-${d.level}`}>{d.level}</span>
        <span style={{ flex: 1 }} />
        {d.daemon?.version && <span className="metric-value">v{d.daemon.version}</span>}
      </div>
      <div className="whost">
        {d.reachable
          ? `${d.daemon?.workers_healthy ?? "—"}/${d.daemon?.workers_total ?? "—"} workers · up ${fmtUptime(d.daemon?.uptime_secs ?? null)}`
          : "unreachable"}
      </div>

      <div className="metrics">
        <div className="metric">
          <span className="metric-label">offload</span>
          <span
            className="bar"
            role="meter"
            aria-label="share of builds sent to the worker pool"
            aria-valuenow={remotePct != null ? Math.round(remotePct) : 0}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuetext={remotePct != null ? `${Math.round(remotePct)}%` : "no builds"}
          >
            <i className={cls} style={{ width: `${remotePct ?? 0}%` }} />
          </span>
          <span className="metric-value">
            {counted > 0 ? `${s!.remote}R / ${s!.local}L` : "no builds"}
          </span>
        </div>
        <div className="metric">
          <span className="metric-label">slots</span>
          <span className="bar" role="presentation">
            <i
              className={d.active_builds > 0 ? "busy" : "off"}
              style={{
                width: `${
                  d.daemon?.slots_total
                    ? ((d.daemon.slots_total - (d.daemon.slots_available ?? 0)) / d.daemon.slots_total) * 100
                    : 0
                }%`,
              }}
            />
          </span>
          <span className="metric-value">
            {d.daemon?.slots_available ?? "—"}/{d.daemon?.slots_total ?? "—"} free
          </span>
        </div>
      </div>

      <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>{d.levelReason}</div>

      {d.active_builds + d.queued_builds > 0 && (
        <div style={{ marginTop: 6, fontSize: 12, color: "var(--busy)" }}>
          {d.active_builds} active · {d.queued_builds} queued
        </div>
      )}

      {d.remediation_hints.length > 0 && (
        <div style={{ marginTop: 8, fontSize: 11.5, color: "var(--warn)" }}>
          {d.remediation_hints.length} remediation hint
          {d.remediation_hints.length === 1 ? "" : "s"}
        </div>
      )}

      {s && s.avg_duration_ms != null && counted > 0 && (
        <div className="tags">
          <span className="tag">avg {fmtDuration(s.avg_duration_ms)}</span>
          {s.failure > 0 && <span className="tag os">{s.failure} failed</span>}
        </div>
      )}
    </button>
  );
}
