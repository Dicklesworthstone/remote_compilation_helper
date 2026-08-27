import { useId, useState } from "react";

interface Props {
  values: number[];
  /** Snapshot timestamps (ISO) matching `values` — enables the "when" in the hover tip. */
  times?: string[];
  /** Format the hovered value (e.g. fmtGb for disk-free series). */
  format?: (n: number) => string;
  /** Draw the area under the line as well as the stroke. */
  filled?: boolean;
  stroke?: string;
  label?: string;
}

/**
 * Dependency-free sparkline. A charting library would be ~40x the bytes for one
 * polyline, and this way the colours are the same CSS tokens as everything else.
 * Hovering shows the value (and age, when `times` is given) at the nearest point.
 */
export function Sparkline({ values, times, format, filled = true, stroke = "var(--accent)", label }: Props) {
  // useId, not a hash of the data: two sparklines whose first value and length
  // happen to match would otherwise share one gradient element. Hooks must run
  // unconditionally, so these sit above the early return.
  const id = useId();
  const [hover, setHover] = useState<number | null>(null);
  if (values.length < 2) {
    return <div className="empty" style={{ padding: 16 }}>not enough history yet</div>;
  }
  const w = 100;
  const h = 30;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / span) * (h - 4) - 2;
    return [x, y] as const;
  });
  const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  const area = `${line} L${w},${h} L0,${h} Z`;

  const hoverTip = (() => {
    if (hover == null) return null;
    const v = values[hover];
    if (v == null) return null;
    const when = times?.[hover] ? Date.parse(times[hover]) : NaN;
    const ago = Number.isFinite(when) ? ` · ${fmtAgo(Date.now() - when)}` : "";
    return `${format ? format(v) : String(v)}${ago}`;
  })();

  return (
    <div
      className="spark-wrap"
      onPointerMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        const frac = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width));
        setHover(Math.round(frac * (values.length - 1)));
      }}
      onPointerLeave={() => setHover(null)}
    >
      <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img"
           aria-label={label ?? "trend"}>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={stroke} stopOpacity="0.30" />
            <stop offset="100%" stopColor={stroke} stopOpacity="0" />
          </linearGradient>
        </defs>
        {filled && <path d={area} fill={`url(#${id})`} />}
        <path d={line} fill="none" stroke={stroke} strokeWidth="1.5"
              vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
        {hover != null && pts[hover] && (
          <circle cx={pts[hover][0]} cy={pts[hover][1]} r="2" fill={stroke} vectorEffect="non-scaling-stroke" />
        )}
      </svg>
      {hoverTip && <div className="spark-tip">{hoverTip}</div>}
    </div>
  );
}

function fmtAgo(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
