import type { HealthLevel, WorkerView } from "../types";
import { fmtAge, STALE_CRIT_SECONDS, STALE_WARN_SECONDS } from "../derive";
import { WorkerCard } from "./WorkerCard";

interface TopbarProps {
  label: string;
  ageSec: number;
  refreshing: boolean;
  onRefresh: () => void;
  auto: boolean;
  /** Minutes until the next auto-refresh; null when auto is off or no snapshot yet. */
  autoInMin: number | null;
  onToggleAuto: () => void;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onLock: () => void;
}

/** Sticky header: brand, snapshot age with the live/stale/old dot, actions. */
export function Topbar(p: TopbarProps) {
  const dotClass =
    p.ageSec > STALE_CRIT_SECONDS ? "old" : p.ageSec > STALE_WARN_SECONDS ? "stale" : "live";
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark">rch</span>
        <span className="brand-label">{p.label}</span>
      </div>
      <span className="spacer" />
      <div className="stamp">
        <span className={`dot ${dotClass}`} />
        snapshot {fmtAge(p.ageSec)}
        {p.autoInMin != null && (
          <span className="auto-in" title="Auto-refresh countdown">· auto ~{p.autoInMin}m</span>
        )}
      </div>
      <button className="icon-btn" onClick={p.onRefresh} disabled={p.refreshing} aria-busy={p.refreshing}>
        {p.refreshing ? "Refreshing…" : "Refresh"}
      </button>
      <button
        className="icon-btn"
        onClick={p.onToggleAuto}
        aria-pressed={p.auto}
        title="Reload the snapshot automatically every 5 minutes"
      >
        Auto
      </button>
      <button className="icon-btn" onClick={p.onToggleTheme}>
        {p.theme === "dark" ? "Light" : "Dark"}
      </button>
      <button className="icon-btn" onClick={p.onLock}>Lock</button>
    </header>
  );
}

export type Sort = "health" | "name" | "speed" | "disk" | "load" | "slots";

interface WorkersProps {
  visible: WorkerView[];
  total: number;
  counts: Partial<Record<HealthLevel, number>>;
  query: string;
  onQuery: (q: string) => void;
  statusFilter: HealthLevel | "all";
  onStatusFilter: (s: HealthLevel | "all") => void;
  sort: Sort;
  onSort: (s: Sort) => void;
  onOpen: (id: string) => void;
}

const FILTERS = ["all", "critical", "warn", "offline", "busy", "healthy"] as const;

/** Filterable, sortable worker grid and its toolbar. */
export function WorkersSection(p: WorkersProps) {
  return (
    <section className="section">
      <div className="section-head">
        <h2>Workers</h2>
        <span className="count-pill">{p.visible.length} of {p.total}</span>
        <span className="spacer" />
        <div className="filters">
          <input
            id="worker-search-input"
            className="search"
            placeholder="Filter by name, host or tag… (/)"
            value={p.query}
            onChange={(e) => p.onQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                p.onQuery("");
                (e.target as HTMLInputElement).blur();
              }
            }}
            aria-label="Filter workers"
          />
          {FILTERS.map((s) => (
            <button
              key={s}
              className="chip"
              aria-pressed={p.statusFilter === s}
              onClick={() => p.onStatusFilter(s as HealthLevel | "all")}
            >
              {s}{s !== "all" && p.counts[s] ? ` ${p.counts[s]}` : ""}
            </button>
          ))}
          <select
            className="search"
            value={p.sort}
            onChange={(e) => p.onSort(e.target.value as Sort)}
            aria-label="Sort workers"
            style={{ minWidth: 0 }}
          >
            <option value="health">sort: health</option>
            <option value="name">sort: name</option>
            <option value="speed">sort: speed</option>
            <option value="slots">sort: slots</option>
            <option value="disk">sort: disk used</option>
            <option value="load">sort: load</option>
          </select>
        </div>
      </div>

      {p.visible.length === 0 ? (
        <div className="empty">No workers match this filter.</div>
      ) : (
        <div className="grid">
          {p.visible.map((w) => (
            <WorkerCard key={w.id} w={w} onOpen={p.onOpen} />
          ))}
        </div>
      )}
    </section>
  );
}
