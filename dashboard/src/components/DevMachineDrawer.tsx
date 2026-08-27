import { useMemo } from "react";
import type { DispatcherView } from "../types";
import { fmtDuration, fmtUptime } from "../derive";
import { useDialog } from "./useDialog";

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
  const panelRef = useDialog(d != null);

  // Deterministic, index-free list keys: an occurrence counter appended at
  // data-mapping time keeps identical hints/builds from colliding.
  const hintRows = useMemo(() => {
    const seen = new Map<string, number>();
    return (d?.remediation_hints ?? []).map((h) => {
      const base = `${h.worker_id ?? ""}|${h.reason_code ?? ""}|${h.message ?? ""}`;
      const n = (seen.get(base) ?? 0) + 1;
      seen.set(base, n);
      return { ...h, key: n === 1 ? base : `${base}|${n}` };
    });
  }, [d?.remediation_hints]);
  const buildRows = useMemo(() => {
    const seen = new Map<string, number>();
    return [...(d?.recent_builds ?? [])].reverse().map((b) => {
      const base = `${b.completed_at ?? ""}|${b.project ?? ""}|${b.worker_id ?? ""}|${b.duration_ms ?? ""}|${b.exit_code ?? ""}`;
      const n = (seen.get(base) ?? 0) + 1;
      seen.set(base, n);
      return {
        key: n === 1 ? base : `${base}|${n}`,
        remote: (b.location ?? "").toLowerCase() === "remote",
        project: b.project,
        command: b.command,
        worker_id: b.worker_id,
        duration_ms: b.duration_ms,
      };
    });
  }, [d?.recent_builds]);

  if (!d) return null;
  const s = d.build_stats;

  return (
    <dialog
      ref={panelRef}
      className="drawer"
      aria-label={`${d.id} dev machine details`}
      onCancel={() => onClose()}
      onClick={(e) => {
        if (e.target === panelRef.current) onClose(); // backdrop click
      }}
    >
        <div className="drawer-head">
          <h3>{d.id}</h3>
          <span className={`pill dev-${d.level}`}>{d.level}</span>
          <span style={{ flex: 1 }} />
          <button className="icon-btn" onClick={onClose}>Close</button>
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

        {hintRows.length > 0 && (
          <div className="kv-group">
            <h4>Remediation hints ({hintRows.length})</h4>
            {hintRows.map((h) => (
              <div key={h.key} className="hint">
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
              {buildRows.map((b) => (
                <div key={b.key} className="build-row">
                  <span className={`pill ${b.remote ? "healthy" : "warn"}`}>{b.remote ? "remote" : "local"}</span>
                  <span className="build-proj" title={b.command ?? undefined}>
                    {b.project ?? "—"}
                  </span>
                  <span className="metric-value">{b.worker_id ?? (b.remote ? "?" : "—")}</span>
                  <span className="metric-value">{fmtDuration(b.duration_ms)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
  </dialog>
  );
}
