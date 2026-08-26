import { useEffect } from "react";
import type { WorkerView } from "../types";
import { fmtAge, fmtGb } from "../derive";

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

  return (
    <>
      <button className="drawer-scrim" onClick={onClose} aria-label="Close details" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`${w.id} details`}>
        <div className="drawer-head">
          <h3>{w.id}</h3>
          <span className={`pill ${w.health}`}>{w.health}</span>
          <span style={{ flex: 1 }} />
          <button className="icon-btn" onClick={onClose}>Esc</button>
        </div>
        <div className="drawer-host">
          {w.user ? `${w.user}@` : ""}{w.host ?? "—"}
        </div>

        <div className="kv-group">
          <h4>Status</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Assessment" v={w.healthReason} />
            <Row k="Enabled" v={w.enabled ? "yes" : "no"} />
            <Row k="Circuit" v={w.circuit_state ?? "—"} />
            <Row k="Active builds" v={w.active_builds} />
            <Row k="Last seen" v={fmtAge(w.staleSeconds)} />
            <Row k="Probe latency" v={w.latency_ms != null ? `${w.latency_ms.toFixed(0)} ms` : "—"} />
            <Row k="SpeedScore" v={w.speed != null ? w.speed.toFixed(1) : "—"} />
          </dl>
        </div>

        <div className="kv-group">
          <h4>Capacity</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Configured slots" v={w.total_slots ?? "—"} />
            <Row k="Priority" v={w.priority ?? "—"} />
            <Row k="CPU cores" v={c.num_cpus ?? "—"} />
            <Row
              k="Load (1/5/15m)"
              v={
                c.load_avg_1 != null
                  ? `${c.load_avg_1.toFixed(2)} / ${c.load_avg_5?.toFixed(2) ?? "—"} / ${c.load_avg_15?.toFixed(2) ?? "—"}`
                  : "—"
              }
            />
            <Row
              k="Load per core"
              v={w.loadPerCore != null ? `${w.loadPerCore.toFixed(2)}×` : "—"}
            />
            <Row k="x86-64 level" v={c.cpu_microarch_level ? `v${c.cpu_microarch_level}` : "—"} />
          </dl>
        </div>

        <div className="kv-group">
          <h4>Disk</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Free" v={fmtGb(c.disk_free_gb, 1)} />
            <Row k="Total" v={fmtGb(c.disk_total_gb, 1)} />
            <Row k="Used" v={w.diskUsedPct != null ? `${w.diskUsedPct.toFixed(1)}%` : "—"} />
            <Row k="Projects root" v={c.projects_root_ok == null ? "—" : c.projects_root_ok ? "ok" : "UNHEALTHY"} />
          </dl>
        </div>

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

        <div className="kv-group">
          <h4>Routing</h4>
          <dl style={{ margin: 0 }}>
            <Row k="Tags" v={w.tags.length ? w.tags.join(", ") : "—"} />
            <Row k="Known to" v={w.seen_by?.length ? w.seen_by.join(", ") : "—"} />
          </dl>
        </div>
      </aside>
    </>
  );
}
