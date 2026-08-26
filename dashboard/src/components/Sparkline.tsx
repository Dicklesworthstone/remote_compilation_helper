import { useId } from "react";

interface Props {
  values: number[];
  /** Draw the area under the line as well as the stroke. */
  filled?: boolean;
  stroke?: string;
  label?: string;
}

/**
 * Dependency-free sparkline. A charting library would be ~40x the bytes for one
 * polyline, and this way the colours are the same CSS tokens as everything else.
 */
export function Sparkline({ values, filled = true, stroke = "var(--accent)", label }: Props) {
  // useId, not a hash of the data: two sparklines whose first value and length
  // happen to match would otherwise share one gradient element. Hooks must run
  // unconditionally, so this sits above the early return.
  const id = useId();
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

  return (
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
    </svg>
  );
}
