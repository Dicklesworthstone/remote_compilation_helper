import { useEffect } from "react";
import type { DispatcherView } from "../types";
import { fmtDuration, fmtUptime } from "../derive";

interface Props {
  d: DispatcherView | null;
  onClose: () => void;
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="kv">
      <dt>{k}</dt>
      <dd>{v ?? "—"}</dd>
    </div>
  );
}

export function DevMachineDrawer({ d, onClose }: Props) {
  useEffect(() => {
    if (!d) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [d, onClose]);

  if (!d) return null;
  const s = d.build_stats;

  return (
    <>
      <button className="drawer-scrim" onClick={onClose} aria-label="Close details" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`${d.id} dev machine details`}>
        <div className="drawer-head">
          <h3>{d.id}</h3>
          <span className={`pill dev-${d.level}`}>{d.level}</span>
          <span style={{ flex: 1 }} />
          <button className="icon-btn" onClick={onClose}>Esc</button>
        </div>
        <div className="drawer-host">dev machine · dispatches builds to the pool</div>

        <div className="kv-group">
          <h4>Offload posture</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Assessment" v={d.levelReason} />
            <Row k="rch posture" v={d.posture ?? "—"} />
            <Row k="Description" v={d.posture_description ?? "—"} />
            <Row k="Builds remote" v={s ? s.remote : "—"} />
            <Row k="Builds local" v={s ? s.local : "—"} />
            <Row k="Remote share" v={d.remotePct != null ? `${d.remotePct.toFixed(0)}%` : "—"} />
            <Row k="Avg build" v={fmtDuration(s?.avg_duration_ms ?? null)} />
            <Row k="Failures" v={s ? s.failure : "—"} />
          </dl>
        </div>

        <div className="kv-group">
          <h4>Daemon</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Version" v={d.daemon?.version ?? "—"} />
            <Row k="Uptime" v={fmtUptime(d.daemon?.uptime_secs ?? null)} />
            <Row k="PID" v={d.daemon?.pid ?? "—"} />
            <Row k="Workers healthy" v={`${d.daemon?.workers_healthy ?? "—"} / ${d.daemon?.workers_total ?? "—"}`} />
            <Row k="Slots free" v={`${d.daemon?.slots_available ?? "—"} / ${d.daemon?.slots_total ?? "—"}`} />
            <Row k="Active / queued" v={`${d.active_builds} / ${d.queued_builds}`} />
          </dl>
        </div>

        {d.remediation_hints.length > 0 && (
          <div className="kv-group">
            <h4>Remediation hints ({d.remediation_hints.length})</h4>
            {d.remediation_hints.map((h, i) => (
              <div key={i} className="hint">
                <div className="hint-top">
                  <span className={`pill ${h.severity === "critical" ? "critical" : "warn"}`}>
                    {h.severity ?? "info"}
                  </span>
                  {h.worker_id && <span className="metric-value">{h.worker_id}</span>}
                </div>
                <div className="hint-msg">{h.message}</div>
                {h.suggested_action && <div className="hint-action">→ {h.suggested_action}</div>}
              </div>
            ))}
          </div>
        )}

        <div className="kv-group">
          <h4>Recent builds ({d.recent_builds.length})</h4>
          {d.recent_builds.length === 0 ? (
            <div className="empty" style={{ padding: 16 }}>no builds recorded</div>
          ) : (
            <div className="builds">
              {[...d.recent_builds].reverse().map((b, i) => {
                const remote = (b.location ?? "").toLowerCase() === "remote";
                return (
                  <div key={i} className="build-row">
                    <span className={`pill ${remote ? "healthy" : "warn"}`}>{remote ? "remote" : "local"}</span>
                    <span className="build-proj" title={b.command ?? undefined}>
                      {b.project ?? "—"}
                    </span>
                    <span className="metric-value">{b.worker_id ?? (remote ? "?" : "—")}</span>
                    <span className="metric-value">{fmtDuration(b.duration_ms)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
