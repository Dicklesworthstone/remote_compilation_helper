import type { Snapshot, HealthLevel } from "../types";
import { fmtGb } from "../derive";
import { Sparkline } from "./Sparkline";

interface Props {
  snap: Snapshot;
  counts: Partial<Record<HealthLevel, number>>;
  hardProblems: number;
}

/**
 * Headline KPIs and the trend sparklines — pure presentation, no state. Kept
 * out of App so the orchestrator stays readable; values are recomputed from
 * the snapshot on each snapshot change, which is nanoseconds against a
 * 96-point history.
 */
export function Overview({ snap, counts, hardProblems }: Props) {
  const t = snap.totals;
  const attention = (counts.critical ?? 0) + (counts.warn ?? 0) + (counts.offline ?? 0);
  const buildsCounted = t.builds_remote + t.builds_local;
  const remotePct = buildsCounted > 0 ? (t.builds_remote / buildsCounted) * 100 : null;
  const diskUsedPct =
    t.disk_total_gb > 0 ? ((t.disk_total_gb - t.disk_free_gb) / t.disk_total_gb) * 100 : null;
  const last = snap.history[snap.history.length - 1];
  const times = snap.history.map((h) => h.t);

  return (
    <>
      <section className="kpis">
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
          <div className="kpi-label">Workers</div>
          <div className="kpi-value">{t.workers}</div>
          <div className="kpi-sub">{counts.healthy ?? 0} healthy · {counts.busy ?? 0} busy</div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: attention > 0 ? "var(--warn)" : "var(--ok)" }}>
          <div className="kpi-label">Needs attention</div>
          <div className="kpi-value">{attention}</div>
          <div className="kpi-sub">
            {counts.critical ?? 0} critical · {counts.warn ?? 0} warn · {counts.offline ?? 0} offline
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
          <div className="kpi-label">Build slots</div>
          <div className="kpi-value">{t.slots_used}<span className="unit">/ {t.slots}</span></div>
          <div className="kpi-sub">{t.active_builds} active build{t.active_builds === 1 ? "" : "s"}</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: hardProblems > 0 ? "var(--crit)" : "var(--ok)" }}
        >
          <div className="kpi-label">Dev machines</div>
          <div className="kpi-value">
            {t.dispatchers_remote_ready}<span className="unit">/ {t.dispatchers_reachable}</span>
          </div>
          <div className="kpi-sub">remote-ready of {t.dispatchers_total} configured</div>
        </div>
        <div
          className="kpi"
          style={{ ["--kpi-accent" as string]: remotePct != null && remotePct < 80 ? "var(--warn)" : "var(--ok)" }}
        >
          <div className="kpi-label">Builds offloaded</div>
          <div className="kpi-value">
            {remotePct != null ? `${remotePct.toFixed(0)}%` : "—"}
          </div>
          <div className="kpi-sub">{t.builds_remote} remote · {t.builds_local} local</div>
        </div>
        <div
          className="kpi"
          style={{
            ["--kpi-accent" as string]:
              diskUsedPct == null
                ? "var(--border)"
                : diskUsedPct >= 88
                  ? "var(--warn)"
                  : "var(--ok)",
          }}
        >
          <div className="kpi-label">Disk free</div>
          <div className="kpi-value">{t.disk_total_gb > 0 ? fmtGb(t.disk_free_gb) : "—"}</div>
          <div className="kpi-sub">
            {diskUsedPct != null
              ? `${diskUsedPct.toFixed(0)}% of ${fmtGb(t.disk_total_gb)} used${
                  t.disk_reporting_workers != null && t.disk_reporting_workers < t.workers
                    ? ` (${t.disk_reporting_workers}/${t.workers} reporting)`
                    : ""
                }`
              : "no disk telemetry"}
          </div>
        </div>
      </section>

      {snap.history.length > 1 && (
        <section className="section">
          <div className="section-head">
            <h2>Trend</h2>
            <span className="count-pill">{snap.history.length} snapshots</span>
          </div>
          <div className="trend-grid">
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--busy)" }}>
              <div className="kpi-label">Slots in use</div>
              <div className="kpi-value">{last.slots_used}</div>
              <Sparkline
                values={snap.history.map((h) => h.slots_used)}
                times={times}
                stroke="var(--busy)"
                label="slots in use over time"
              />
            </div>
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--ok)" }}>
              <div className="kpi-label">Disk free</div>
              <div className="kpi-value">{fmtGb(last.disk_free_gb)}</div>
              <Sparkline
                values={snap.history.map((h) => h.disk_free_gb)}
                times={times}
                format={(n) => fmtGb(n)}
                stroke="var(--ok)"
                label="fleet disk free over time"
              />
            </div>
            <div className="kpi" style={{ ["--kpi-accent" as string]: "var(--accent)" }}>
              <div className="kpi-label">Remote builds</div>
              <div className="kpi-value">{last.builds_remote}</div>
              <Sparkline
                values={snap.history.map((h) => h.builds_remote)}
                times={times}
                stroke="var(--accent)"
                label="remote builds over time"
              />
            </div>
          </div>
        </section>
      )}
    </>
  );
}
