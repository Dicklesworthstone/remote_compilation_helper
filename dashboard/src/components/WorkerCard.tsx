import type { WorkerView } from "../types";
import { fmtGb, utilClass } from "../derive";

interface Props {
  w: WorkerView;
  onOpen: (id: string) => void;
  totalFleetSlots?: number;
  weightedSizing?: boolean;
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
        aria-valuenow={pct != null ? Math.round(pct) : 0}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={pct != null ? `${Math.round(pct)}%` : "unavailable"}
      >
        <i className={cls} style={{ width: `${Math.min(100, Math.max(0, pct ?? 0))}%` }} />
      </span>
      <span className="metric-value">{valueText}</span>
    </div>
  );
}

function SlotMatrix({ used, total, isWorkhorse }: { used: number; total: number; isWorkhorse: boolean }) {
  if (total <= 0) return null;
  const count = Math.min(total, 64);
  const activeCount = Math.min(used, count);
  const utilPct = Math.round((used / total) * 100);

  return (
    <div
      className={`slot-matrix ${isWorkhorse ? "workhorse" : ""} ${used > 0 ? "has-active" : ""}`}
      title={`${used} of ${total} slots active (${utilPct}% capacity utilized)`}
      aria-label={`${used} of ${total} build slots in use`}
    >
      <div className="slot-cells">
        {Array.from({ length: count }, (_, i) => {
          const isActive = i < activeCount;
          return (
            <span
              key={i}
              className={`slot-cell ${isActive ? "active" : "avail"}`}
              title={isActive ? `Slot #${i + 1}: Compiling build` : `Slot #${i + 1}: Available`}
            />
          );
        })}
      </div>
      <div className="slot-matrix-meta">
        <span className="slot-matrix-count">
          {used > 0 ? (
            <span className="slot-active-label">
              <span className="pulse-dot" />
              {used} active build{used === 1 ? "" : "s"}
            </span>
          ) : (
            <span className="slot-idle-label">{total} slots available</span>
          )}
        </span>
        <span className="slot-matrix-pct">{utilPct}% utilized</span>
      </div>
    </div>
  );
}

export function WorkerCard({ w, onOpen, totalFleetSlots, weightedSizing = true }: Props) {
  const cores = w.caps.num_cpus;
  const slots = w.total_slots ?? 0;
  const used = w.used_slots ?? 0;
  const isWorkhorse = slots >= 16;
  const isStandard = slots >= 6 && slots < 16;
  const tier = isWorkhorse ? "workhorse" : isStandard ? "standard" : "satellite";
  const fleetSharePct =
    totalFleetSlots && totalFleetSlots > 0 && slots > 0
      ? (slots / totalFleetSlots) * 100
      : null;
  const isActivelyCompiling = used > 0;
  const powerRating = w.speed != null && slots > 0 ? Math.round(w.speed * slots) : null;

  // Scale load against 2.0x threshold (warning boundary) so 0->100% represents 0->2.0x load/core
  const loadBarPct = w.loadPerCore != null ? Math.min(100, Math.max(0, (w.loadPerCore / 2.0) * 100)) : null;
  const loadCls =
    w.loadPerCore == null
      ? "off"
      : w.loadPerCore >= 2.0
        ? "warn"
        : w.loadPerCore >= 1.0
          ? "busy"
          : "ok";

  const cardClasses = [
    "wcard",
    tier,
    isActivelyCompiling ? "active-offloading" : "",
    weightedSizing && (isWorkhorse || (slots >= 12 && used >= 2)) ? "span-2" : "",
  ].filter(Boolean).join(" ");

  return (
    <button
      className={cardClasses}
      onClick={() => onOpen(w.id)}
      title={`View details for ${tier} worker ${w.id} (${slots} slots)`}
    >
      <div className="wcard-top">
        <span className="wname">{w.id}</span>
        <span className={`pill ${w.health}`}>{w.health}</span>
        <span className={`tier-badge ${tier}`} title={`Capacity tier: ${tier}`}>
          {tier === "workhorse" ? "⚡ Workhorse" : tier === "standard" ? "Standard" : "Satellite"}
        </span>
        <span style={{ flex: 1 }} />
        {fleetSharePct != null && (
          <span
            className="fleet-share"
            title={`${slots} slots represents ${fleetSharePct.toFixed(0)}% of total fleet build capacity`}
          >
            {fleetSharePct.toFixed(0)}% fleet
          </span>
        )}
        {w.speed != null && (
          <span
            className="metric-value speed-val"
            title={`rch SpeedScore: ${w.speed.toFixed(1)}${powerRating ? ` · Power Rating: ${powerRating}` : ""}`}
          >
            {w.speed.toFixed(1)}
          </span>
        )}
      </div>

      <div className="whost">
        {w.user ? `${w.user}@` : ""}{w.host ?? "—"}
        {w.priority != null && <> · pri {w.priority}</>}
        {cores ? <> · {cores} cores</> : null}
      </div>

      {slots > 0 && (
        <SlotMatrix used={used} total={slots} isWorkhorse={isWorkhorse} />
      )}

      <div className="metrics">
        <Metric
          label="slots"
          pct={w.slotPct}
          cls={used > 0 ? "busy" : "off"}
          valueText={`${used}/${w.total_slots ?? "—"}`}
        />
        <Metric
          label="cpu"
          pct={loadBarPct}
          cls={loadCls}
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

      {(w.tags.length > 0 || (w.seen_by && w.seen_by.length > 0)) && (
        <div className="tags">
          {w.tags.map((t) => (
            <span key={t} className={`tag${t.startsWith("os:") ? " os" : ""}`}>{t}</span>
          ))}
          {w.seen_by && w.seen_by.length > 0 && <span className="tag">seen by {w.seen_by.length}</span>}
        </div>
      )}
    </button>
  );
}
