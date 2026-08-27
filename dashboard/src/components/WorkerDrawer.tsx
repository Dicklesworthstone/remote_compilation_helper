import { useEffect } from "react";
import type { WorkerView } from "../types";
import { fmtAge, fmtGb } from "../derive";
import { useDialog } from "./useDialog";

interface Props {
  w: WorkerView | null;
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

export function WorkerDrawer({ w, onClose }: Props) {
  const panelRef = useDialog(w != null);
  useEffect(() => {
    if (!w) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [w, onClose]);

  if (!w) return null;
  const c = w.caps;
  const p = w.pressure;
  const fails = w.failure_history;

  return (
    <>
      <button className="drawer-scrim" onClick={onClose} aria-label="Close details" />
      <aside ref={panelRef} className="drawer" role="dialog" aria-modal="true" aria-label={`${w.id} details`}>
        <div className="drawer-head">
          <h3>{w.id}</h3>
          <span className={`pill ${w.health}`}>{w.health}</span>
          <span style={{ flex: 1 }} />
          <button className="icon-btn" onClick={onClose}>Close</button>
        </div>
        <div className="drawer-host">
          {w.user ? `${w.user}@` : ""}{w.host ?? "—"}
        </div>

        <div className="kv-group">
          <h4>Status</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Assessment" v={w.healthReason} />
            <Row k="rch status" v={w.status ?? "—"} />
            <Row k="Circuit" v={w.circuit_state ?? "—"} />
            <Row k="Slots in use" v={`${w.used_slots ?? 0} / ${w.total_slots ?? "—"}`} />
            <Row k="Consecutive failures" v={w.consecutive_failures} />
            <Row k="Last error" v={w.last_error ?? "none"} />
            <Row k="Last seen" v={fmtAge(w.staleSeconds)} />
            <Row k="Probe latency" v={w.latency_ms != null ? `${w.latency_ms.toFixed(0)} ms` : "—"} />
            <Row k="SpeedScore" v={w.speed != null ? w.speed.toFixed(1) : "—"} />
          </dl>
          {fails.length > 0 && (
            <div className="fail-strip" title="recent probe outcomes, oldest first">
              {fails.map((ok, i) => (
                <i key={i} className={ok ? "ok" : "bad"} />
              ))}
            </div>
          )}
        </div>

        <div className="kv-group">
          <h4>Pressure</h4>
          <dl style={{ margin: 0 }}>
            <Row k="State" v={p.state ?? "—"} />
            <Row k="Reason" v={p.reason ?? "—"} />
            <Row k="Disk free" v={fmtGb(p.disk_free_gb, 1)} />
            <Row k="Disk total" v={fmtGb(p.disk_total_gb, 1)} />
            <Row k="Disk used" v={w.diskUsedPct != null ? `${w.diskUsedPct.toFixed(1)}%` : "—"} />
            <Row k="Disk IO util" v={p.disk_io_util_pct != null ? `${p.disk_io_util_pct.toFixed(0)}%` : "—"} />
            <Row k="Memory pressure" v={p.memory_pressure != null ? `${p.memory_pressure.toFixed(1)}%` : "—"} />
            <Row
              k="Telemetry"
              v={
                p.telemetry_age_secs != null
                  ? `${p.telemetry_age_secs}s old${p.telemetry_fresh === false ? " (STALE)" : ""}`
                  : "—"
              }
            />
          </dl>
        </div>

        <div className="kv-group">
          <h4>Capacity</h4>
          <dl style={{ margin: 0 }}>
            <Row k="CPU cores" v={c.num_cpus ?? "—"} />
            <Row
              k="Load (1/5/15m)"
              v={
                c.load_avg_1 != null
                  ? `${c.load_avg_1.toFixed(2)} / ${c.load_avg_5?.toFixed(2) ?? "—"} / ${c.load_avg_15?.toFixed(2) ?? "—"}`
                  : "—"
              }
            />
            <Row k="Load per core" v={w.loadPerCore != null ? `${w.loadPerCore.toFixed(2)}×` : "—"} />
            <Row k="x86-64 level" v={c.cpu_microarch_level ? `v${c.cpu_microarch_level}` : "—"} />
            <Row k="Projects root" v={c.projects_root_ok == null ? "—" : c.projects_root_ok ? "ok" : "UNHEALTHY"} />
          </dl>
        </div>

        {w.slots_by_dispatcher && Object.keys(w.slots_by_dispatcher).length > 0 && (
          <div className="kv-group">
            <h4>Slots per dev machine</h4>
            <p className="note">
              rchd derates slots independently on each dispatcher, so the same worker can look
              different from each box. A worker derated below a dispatcher's <code>build_slots</code>
              {" "}is invisible to it.
            </p>
            <dl style={{ margin: 0 }}>
              {Object.entries(w.slots_by_dispatcher).map(([id, s]) => (
                <Row key={id} k={id} v={`${s.used ?? 0} / ${s.total ?? "—"}`} />
              ))}
            </dl>
          </div>
        )}

        <div className="kv-group">
          <h4>Toolchains</h4>
          <dl style={{ margin: 0 }}>
            <Row k="rustc" v={c.rustc_version ?? "—"} />
            <Row k="bun" v={c.bun_version ?? "—"} />
            <Row k="node" v={c.node_version ?? "—"} />
            <Row k="go" v={c.go_version?.replace(/^go version /, "") ?? "—"} />
            <Row k="zig" v={c.zig_version ?? "—"} />
          </dl>
        </div>
      </aside>
    </>
  );
}
