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

const NODE_H = 38;
const NODE_GAP = 8;
const COL_W = 230;

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
 * right, and an edge for every (machine, worker) relationship the snapshot
 * actually reports — the thing no list layout can show.
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
export function FleetMap({ devs, workers, onOpenDev, onOpenWorker }: Props) {
  const wide = useWideMap();
  const [focus, setFocus] = useState<string | null>(null);

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

  // Workers no machine reports: real orphans get their own lane rather than
  // silently looking connected.
  const orphans = useMemo(() => workers.filter((w) => (w.seen_by?.length ?? 0) === 0), [workers]);

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

/** Center-y of row `i` — pure layout math, shared by edges and nodes. */
function rowY(i: number): number {
  return NODE_GAP + i * (NODE_H + NODE_GAP) + NODE_H / 2;
}

function edgeClass(e: Edge): string {
  if (e.total === 0) return "fm-edge inv";
  if ((e.used ?? 0) > 0) return "fm-edge active";
  return "fm-edge avail";
}

function edgeDimmed(e: Edge, focus: string | null): boolean {
  if (!focus) return false;
  return e.dev !== focus && e.worker !== focus;
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
  const rows = Math.max(devs.length, allWorkers.length, 1);
  const height = rows * (NODE_H + NODE_GAP) + NODE_GAP;
  const leftX = COL_W - 10;
  const rightX = width - COL_W + 10;


  return (
    <div className="fm-scroll">
      <div className="fm-wrap" ref={wrapRef} style={{ height }} onMouseLeave={() => setFocus(null)}>
        <svg className="fm-edges" width={width} height={height} aria-hidden="true">
          {edges.map((e) => {
            const di = devs.findIndex((d) => d.id === e.dev);
            const wi = allWorkers.findIndex((w) => w.id === e.worker);
            if (di < 0 || wi < 0) return null;
            const x1 = leftX;
            const y1 = rowY(di);
            const x2 = rightX;
            const y2 = rowY(wi);
            const mx = (x1 + x2) / 2;
            const dimmed = edgeDimmed(e, focus);
            return (
              <path
                key={`${e.dev}|${e.worker}`}
                className={`${edgeClass(e)}${dimmed ? " dim" : ""}`}
                d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              />
            );
          })}
        </svg>

        {devs.map((d, i) => (
          <button
            key={d.id}
            className="fm-node dev"
            style={{ left: 0, top: rowY(i) - NODE_H / 2, width: COL_W - 18 }}
            onMouseEnter={() => setFocus(d.id)}
            onFocus={() => setFocus(d.id)}
            onClick={() => onOpenDev(d.id)}
            title={`${d.id} — ${d.level}: open details`}
          >
            <span className={`fm-dot ${d.level === "offloading" ? "ok" : d.level === "idle" ? "off" : d.level === "degraded" ? "warn" : "crit"}`} />
            <span className="fm-name">{d.id}</span>
            <span className="fm-sub">{d.level}</span>
          </button>
        ))}

        {allWorkers.map((w, i) => (
          <button
            key={w.id}
            className="fm-node worker"
            style={{ left: width - COL_W + 18, top: rowY(i) - NODE_H / 2, width: COL_W - 18 }}
            onMouseEnter={() => setFocus(w.id)}
            onFocus={() => setFocus(w.id)}
            onClick={() => onOpenWorker(w.id)}
            title={`${w.id} — ${w.health}: open details`}
          >
            <span className={`fm-dot ${w.health === "healthy" ? "ok" : w.health === "busy" ? "busy" : w.health === "warn" ? "warn" : w.health === "critical" ? "crit" : "off"}`} />
            <span className="fm-name">{w.id}</span>
            <span className="fm-sub">
              {w.used_slots ?? 0}/{w.total_slots ?? "—"}
              {(w.seen_by?.length ?? 0) === 0 ? " · unseen" : ""}
            </span>
          </button>
        ))}
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
    return (
      <button
        key={`${dev ?? "fleet"}|${w.id}`}
        className={`fm-chip ${invisible ? "inv" : ""}`}
        onClick={() => onOpenWorker(w.id)}
        title={invisible ? `${w.id} is derated to 0 slots on ${dev} — invisible to it` : `${w.id} — ${w.health}`}
      >
        <span className={`fm-dot ${w.health === "healthy" ? "ok" : w.health === "busy" ? "busy" : w.health === "warn" ? "warn" : w.health === "critical" ? "crit" : "off"}`} />
        {w.id}
        <span className="fm-sub">{pair ? `${pair.used ?? 0}/${pair.total ?? "—"}` : w.health === "busy" ? `${w.used_slots ?? 0}/${w.total_slots ?? "—"}` : ""}</span>
      </button>
    );
  };

  return (
    <div className="fm-groups">
      {devs.map((d) => {
        const list = byDev.get(d.id) ?? [];
        return (
          <div key={d.id} className="fm-group">
            <button className={`fm-node dev static ${d.level === "offloading" ? "ok" : d.level === "idle" ? "off" : d.level === "degraded" ? "warn" : "crit"}`} onClick={() => onOpenDev(d.id)}>
              <span className="fm-name">{d.id}</span>
              <span className="fm-sub">
                {d.level} · {list.length} worker{list.length === 1 ? "" : "s"}
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
