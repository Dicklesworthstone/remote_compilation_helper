import type { WorkerView } from "../types";
import { fmtGb, utilClass } from "../derive";

interface Props {
  w: WorkerView;
  onOpen: (id: string) => void;
}

function Metric({
  label, pct, valueText, cls,
}: { label: string; pct: number | null; valueText: string; cls: string }) {
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span
        className="bar"
        role="meter"
        aria-label={label}
        aria-valuenow={pct ?? undefined}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <i className={cls} style={{ width: `${Math.min(100, Math.max(0, pct ?? 0))}%` }} />
      </span>
      <span className="metric-value">{valueText}</span>
    </div>
  );
}

export function WorkerCard({ w, onOpen }: Props) {
  const cores = w.caps.num_cpus;
  const loadPct = w.loadPerCore != null ? Math.min(100, w.loadPerCore * 100) : null;

  return (
    <button className="wcard" onClick={() => onOpen(w.id)} aria-label={`Details for worker ${w.id}`}>
      <div className="wcard-top">
        <span className="wname">{w.id}</span>
        <span className={`pill ${w.health}`}>{w.health}</span>
        <span style={{ flex: 1 }} />
        {w.speed != null && (
          <span className="metric-value" title="rch SpeedScore">{w.speed.toFixed(1)}</span>
        )}
      </div>
      <div className="whost">
        {w.user ? `${w.user}@` : ""}{w.host ?? "—"}
        {w.priority != null && <> · pri {w.priority}</>}
      </div>

      <div className="metrics">
        <Metric
          label="slots"
          pct={w.slotPct}
          cls={(w.used_slots ?? 0) > 0 ? "busy" : "off"}
          valueText={`${w.used_slots ?? 0}/${w.total_slots ?? "—"}`}
        />
        <Metric
          label="cpu"
          pct={loadPct}
          cls={utilClass(loadPct)}
          valueText={
            w.caps.load_avg_1 != null
              ? `${w.caps.load_avg_1.toFixed(1)}${cores ? ` / ${cores}c` : ""}`
              : "—"
          }
        />
        <Metric
          label="disk"
          pct={w.diskUsedPct}
          cls={utilClass(w.diskUsedPct)}
          valueText={
            w.diskUsedPct != null
              ? `${w.diskUsedPct.toFixed(0)}% · ${fmtGb(w.pressure.disk_free_gb)} free`
              : `${fmtGb(w.pressure.disk_free_gb)} free`
          }
        />
      </div>

      {w.health !== "healthy" && (
        <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>{w.healthReason}</div>
      )}

      {(w.tags.length > 0 || w.seen_by) && (
        <div className="tags">
          {w.tags.map((t) => (
            <span key={t} className={`tag${t.startsWith("os:") ? " os" : ""}`}>{t}</span>
          ))}
          {w.seen_by && <span className="tag">seen by {w.seen_by.length}</span>}
        </div>
      )}
    </button>
  );
}
