import { useEffect, useMemo, useRef, useState } from "react";
import type { DispatcherView, WorkerView } from "../types";

interface Props {
  devs: DispatcherView[];
  workers: WorkerView[];
  onOpenDev: (id: string) => void;
  onOpenWorker: (id: string) => void;
}

interface Edge {
  dev: string;
  worker: string;
  used: number | null;
  total: number | null;
}

const NODE_GAP = 10;
const COL_W = 230;
const MIN_H = 26;
const MAX_H = 60;

/**
 * Node height encodes DERATED CAPACITY: a 16-slot workhorse renders visibly
 * larger than a 2-slot minnow, so the fleet's shape reads before its labels
 * do. Square-root scaling keeps the spread legible without letting one big
 * box monopolize the column.
 */
function hFor(slots: number | null | undefined): number {
  const n = Math.max(0, slots ?? 0);
  if (n === 0) return MIN_H - 4;
  return Math.min(MAX_H, MIN_H + 8 * Math.sqrt(n));
}

function workerDot(w: WorkerView): string {
  return w.health === "healthy" ? "ok"
    : w.health === "busy" ? "busy"
    : w.health === "warn" ? "warn"
    : w.health === "critical" ? "crit"
    : "off";
}

function devDot(d: DispatcherView): string {
  return d.level === "offloading" ? "ok"
    : d.level === "idle" ? "off"
    : d.level === "degraded" ? "warn"
    : "crit";
}

/** True when the viewport is wide enough for the bipartite map. */
function useWideMap() {
  const [wide, setWide] = useState(() =>
    typeof window === "undefined" ? true : window.matchMedia("(min-width: 900px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 900px)");
    const onChange = (e: MediaQueryListEvent) => setWide(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return wide;
}

/**
 * The fleet as one connected picture: dev machines on the left, workers on the
 * right, an edge for every (machine, worker) relationship the snapshot
 * reports — and now, weight: node SIZE is derated capacity, the fill strip is
 * live utilization, and both columns sort big-to-small so the fleet's shape
 * cascades down the page.
 *
 * Edge grammar, busiest meaning loudest:
 *   solid blue   — this machine has builds running on that worker right now
 *   faint gray   — the machine sees the worker with derated capacity free
 *   dashed red   — the machine's derated view of that worker is ZERO slots:
 *                  the worker is invisible to it, the silent-local root cause
 *
 * Hover focuses: connected edges stay lit, everything else fades. Click opens
 * the same drawers as the cards below.
 */
export function FleetMap({ devs: rawDevs, workers: rawWorkers, onOpenDev, onOpenWorker }: Props) {
  const wide = useWideMap();
  const [focus, setFocus] = useState<string | null>(null);

  // Capacity order, most important first: workers by derated slots, machines
  // by the size of the pool they can reach. Health breaks ties (problems float
  // within a size band), then id for determinism.
  const workers = useMemo(
    () => [...rawWorkers].sort((a, b) =>
      (b.total_slots ?? 0) - (a.total_slots ?? 0) ||
      a.health.localeCompare(b.health) ||
      a.id.localeCompare(b.id)),
    [rawWorkers],
  );
  const devs = useMemo(
    () => [...rawDevs].sort((a, b) =>
      devCap(b) - devCap(a) || a.level.localeCompare(b.level) || a.id.localeCompare(b.id)),
    [rawDevs],
  );

  const edges = useMemo<Edge[]>(() => {
    const out: Edge[] = [];
    for (const w of workers) {
      for (const dev of w.seen_by ?? []) {
        const s = w.slots_by_dispatcher?.[dev];
        out.push({ dev, worker: w.id, used: s?.used ?? null, total: s?.total ?? null });
      }
    }
    return out;
  }, [workers]);

  // Workers no machine reports: real orphans get their own lane at the bottom
  // (zero capacity → smallest nodes) rather than silently looking connected.
  const orphans = useMemo(
    () => workers.filter((w) => (w.seen_by?.length ?? 0) === 0),
    [workers],
  );

  if (workers.length === 0 && devs.length === 0) return null;
  return wide ? (
    <BipartiteMap
      devs={devs}
      workers={workers}
      orphans={orphans}
      edges={edges}
      focus={focus}
      setFocus={setFocus}
      onOpenDev={onOpenDev}
      onOpenWorker={onOpenWorker}
    />
  ) : (
    <GroupedMap
      devs={devs}
      workers={workers}
      orphans={orphans}
      onOpenDev={onOpenDev}
      onOpenWorker={onOpenWorker}
    />
  );
}

/** A dev machine's reachable pool: the totals across its own derated row. */
function devCap(d: DispatcherView): number {
  return (d.pool_slots ?? []).reduce((n, p) => n + (Array.isArray(p) ? (p[1] ?? 0) : 0), 0);
}

function devUsed(d: DispatcherView): number {
  return (d.pool_slots ?? []).reduce((n, p) => n + (Array.isArray(p) ? (p[0] ?? 0) : 0), 0);
}

/** Center-y of row `i` given the column's cumulative heights. */
function rowY(offs: number[], i: number): number {
  return offs[i] + (offs[i + 1] - offs[i]) / 2;
}

/** Cumulative top offsets for a column of nodes with per-node heights. */
function columnOffsets(heights: number[]): number[] {
  const offs = [NODE_GAP];
  for (let i = 0; i < heights.length; i++) offs.push(offs[i] + heights[i] + NODE_GAP);
  return offs;
}

function edgeClass(e: Edge): string {
  if (e.total === 0) return "fm-edge inv";
  if ((e.used ?? 0) > 0) return "fm-edge active";
  return "fm-edge avail";
}

function edgeDimmed(e: Edge, focus: string | null): boolean {
  return focus != null && e.dev !== focus && e.worker !== focus;
}

function edgeStyle(e: Edge): React.CSSProperties | undefined {
  if ((e.used ?? 0) > 0) {
    const sw = Math.min(5.5, 2.0 + (e.used ?? 1) * 0.7);
    return { strokeWidth: sw };
  }
  return undefined;
}

/* ------------------------------------------------------------------ wide */

interface WideProps extends Props {
  orphans: WorkerView[];
  edges: Edge[];
  focus: string | null;
  setFocus: (id: string | null) => void;
}

function BipartiteMap({ devs, workers, orphans, edges, focus, setFocus, onOpenDev, onOpenWorker }: WideProps) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(900);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w && w > 0) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const allWorkers = [...workers, ...orphans];
  const devHeights = devs.map((d) => hFor(devCap(d)));
  const workerHeights = allWorkers.map((w) => hFor(w.total_slots));
  const devOffs = columnOffsets(devHeights);
  const workerOffs = columnOffsets(workerHeights);
  const height = Math.max(
    devOffs[devOffs.length - 1] ?? NODE_GAP,
    workerOffs[workerOffs.length - 1] ?? NODE_GAP,
  );
  const leftX = COL_W - 10;
  // Memoized: `allWorkers` feeds the workerRow map's dependency array, and a
  // fresh array per render would defeat the memo below.
  const allWorkers = useMemo(() => [...workers, ...orphans], [workers, orphans]);
  // Row lookup by id — O(1) per edge instead of a findIndex per edge.
  const devRow = useMemo(() => new Map(devs.map((d, i) => [d.id, i])), [devs]);
  const workerRow = useMemo(() => new Map(allWorkers.map((w, i) => [w.id, i])), [allWorkers]);

  return (
    <div className="fm-scroll">
      <div className="fm-wrap" ref={wrapRef} style={{ height }} onMouseLeave={() => setFocus(null)}>
        <svg className="fm-edges" width={width} height={height} aria-hidden="true">
          {edges.map((e) => {
            const di = devRow.get(e.dev);
            const wi = workerRow.get(e.worker);
            if (di == null || wi == null) return null;
            const x1 = leftX;
            const y1 = rowY(devOffs, di);
            const x2 = rightX;
            const y2 = rowY(workerOffs, wi);
            const mx = (x1 + x2) / 2;
            const dimmed = edgeDimmed(e, focus);
            return (
              <path
                key={`${e.dev}|${e.worker}`}
                className={`${edgeClass(e)}${dimmed ? " dim" : ""}`}
                style={edgeStyle(e)}
                d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              />
            );
          })}
        </svg>

        {devs.map((d, i) => {
          const cap = devCap(d);
          const used = devUsed(d);
          const pct = cap > 0 ? Math.min(100, (used / cap) * 100) : 0;
          return (
            <button
              key={d.id}
              className="fm-node dev"
              style={{ left: 0, top: devOffs[i], height: devHeights[i], width: COL_W - 18 }}
              onMouseEnter={() => setFocus(d.id)}
              onFocus={() => setFocus(d.id)}
              onClick={() => onOpenDev(d.id)}
              title={`${d.id} — ${d.level} · pool ${used}/${cap} slots — open details`}
            >
              <span className="fm-fill dev" style={{ width: `${pct}%` }} aria-hidden="true" />
              <span className={`fm-dot ${devDot(d)}`} />
              <span className="fm-name">{d.id}</span>
              <span className="fm-sub">{used}/{cap}</span>
            </button>
          );
        })}

        {allWorkers.map((w, i) => {
          const pct = w.slotPct ?? 0;
          const isWorkhorse = (w.total_slots ?? 0) >= 16;
          return (
            <button
              key={w.id}
              className={`fm-node worker ${isWorkhorse ? "workhorse" : ""} ${(w.used_slots ?? 0) > 0 ? "active" : ""}`}
              style={{ left: width - COL_W + 18, top: workerOffs[i], height: workerHeights[i], width: COL_W - 18 }}
              onMouseEnter={() => setFocus(w.id)}
              onFocus={() => setFocus(w.id)}
              onClick={() => onOpenWorker(w.id)}
              title={`${w.id} — ${w.health} · ${w.used_slots ?? 0}/${w.total_slots ?? "—"} slots${isWorkhorse ? " (Workhorse)" : ""} — open details`}
            >
              <span className={`fm-fill ${pct >= 88 ? "hot" : "use"}`} style={{ width: `${Math.min(100, pct)}%` }} aria-hidden="true" />
              <span className={`fm-dot ${workerDot(w)}`} />
              <span className="fm-name">
                {w.id}
                {isWorkhorse && <span className="fm-workhorse-tag" title="Workhorse capacity (16+ slots)">⚡</span>}
              </span>
              <span className="fm-sub">
                {w.used_slots ?? 0}/{w.total_slots ?? "—"}
                {(w.seen_by?.length ?? 0) === 0 ? " · unseen" : ""}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- narrow */

interface NarrowProps extends Props {
  orphans: WorkerView[];
}

function GroupedMap({ devs, workers, orphans, onOpenDev, onOpenWorker }: NarrowProps) {
  const byDev = useMemo(() => {
    const m = new Map<string, WorkerView[]>();
    for (const w of workers) {
      for (const dev of w.seen_by ?? []) {
        const list = m.get(dev);
        if (list) list.push(w);
        else m.set(dev, [w]);
      }
    }
    return m;
  }, [workers]);

  const workerChip = (w: WorkerView, dev?: string) => {
    const pair = dev ? w.slots_by_dispatcher?.[dev] : undefined;
    const invisible = pair != null && pair.total === 0;
    const big = (pair?.total ?? w.total_slots ?? 0) >= 8;
    return (
      <button
        key={`${dev ?? "fleet"}|${w.id}`}
        className={`fm-chip${invisible ? " inv" : ""}${big ? " big" : ""}`}
        onClick={() => onOpenWorker(w.id)}
        title={invisible ? `${w.id} is derated to 0 slots on ${dev} — invisible to it` : `${w.id} — ${w.health}`}
      >
        <span className={`fm-dot ${workerDot(w)}`} />
        {w.id}
        <span className="fm-sub">
          {pair ? `${pair.used ?? 0}/${pair.total ?? "—"}` : `${w.used_slots ?? 0}/${w.total_slots ?? "—"}`}
        </span>
      </button>
    );
  };

  return (
    <div className="fm-groups">
      {devs.map((d) => {
        const list = byDev.get(d.id) ?? [];
        return (
          <div key={d.id} className="fm-group">
            <button className={`fm-node dev static ${devDot(d)}`} onClick={() => onOpenDev(d.id)}>
              <span className="fm-name">{d.id}</span>
              <span className="fm-sub">
                {d.level} · {list.length} worker{list.length === 1 ? "" : "s"} · pool {devUsed(d)}/{devCap(d)}
              </span>
            </button>
            <div className="fm-chips">
              {list.length > 0 ? list.map((w) => workerChip(w, d.id)) : <span className="fm-sub">sees no workers</span>}
            </div>
          </div>
        );
      })}
      {orphans.length > 0 && (
        <div className="fm-group">
          <div className="fm-node dev static off">
            <span className="fm-name">unclaimed</span>
            <span className="fm-sub">no dev machine reports these</span>
          </div>
          <div className="fm-chips">{orphans.map((w) => workerChip(w))}</div>
        </div>
      )}
      {workers.length > 0 && devs.length === 0 && (
        <div className="fm-chips">{workers.map((w) => workerChip(w))}</div>
      )}
    </div>
  );
}
