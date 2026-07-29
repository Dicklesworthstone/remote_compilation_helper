'use client';

import { useMemo } from 'react';
import { Trophy, Server } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { WorkerStatusInfo } from '@/lib/types';

interface ComparisonTableProps {
  /** Workers to compare */
  workers: WorkerStatusInfo[];
  /** Callback when clicking view details for a worker */
  onViewDetails?: (workerId: string) => void;
}

const metadataRows: { label: string; getValue: (w: WorkerStatusInfo) => string }[] = [
  { label: 'Slots', getValue: (w) => `${w.used_slots}/${w.total_slots}` },
  { label: 'Status', getValue: (w) => w.status },
  { label: 'Circuit', getValue: (w) => w.circuit_state.replace('_', ' ') },
];

function getScoreColor(score: number, best: number): string {
  if (score === best) return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300';
  const ratio = score / best;
  if (ratio >= 0.95) return 'bg-sky-500/10 text-sky-700 dark:text-sky-300';
  if (ratio >= 0.85) return 'bg-amber-500/10 text-amber-700 dark:text-amber-300';
  return 'bg-muted/50 text-muted-foreground';
}

function ScoreCell({
  value,
  isBest,
  format = (v: number) => v.toFixed(1),
  bestValue,
}: {
  value: number;
  isBest: boolean;
  format?: (v: number) => string;
  bestValue: number;
}) {
  return (
    <td className={`px-4 py-2 text-center font-mono ${getScoreColor(value, bestValue)}`}>
      <div className="flex items-center justify-center gap-1">
        {format(value)}
        {isBest && <Trophy className="w-3.5 h-3.5 text-amber-500" aria-label="Best in category" />}
      </div>
    </td>
  );
}

export function ComparisonTable({ workers, onViewDetails }: ComparisonTableProps) {
  const bestScores = useMemo(() => {
    if (workers.length === 0) return {};
    return {
      speed_score: Math.max(...workers.map((w) => w.speed_score)),
      total_slots: Math.max(...workers.map((w) => w.total_slots)),
    };
  }, [workers]);

  if (workers.length === 0) {
    return (
      <Card className="bg-surface border-border">
        <CardContent className="py-12 text-center">
          <Server className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
          <p className="text-muted-foreground">Select workers to compare</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-surface border-border overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Server className="w-4 h-4" />
          Side-by-Side Comparison
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm" role="grid">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground w-32">
                  Metric
                </th>
                {workers.map((worker) => (
                  <th
                    key={worker.id}
                    className="px-4 py-3 text-center font-medium min-w-[120px]"
                  >
                    <div className="font-semibold text-foreground">{worker.id}</div>
                    <div className="text-xs text-muted-foreground font-normal truncate">
                      {worker.host}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {/* Total Score Row */}
              <tr className="border-b border-border bg-primary/5">
                <td className="px-4 py-3 font-semibold text-foreground">Total Score</td>
                {workers.map((worker) => (
                  <ScoreCell
                    key={worker.id}
                    value={worker.speed_score}
                    isBest={worker.speed_score === bestScores.speed_score}
                    bestValue={bestScores.speed_score ?? 100}
                  />
                ))}
              </tr>

              {/* Divider */}
              <tr>
                <td
                  colSpan={workers.length + 1}
                  className="px-4 py-1 text-xs text-muted-foreground bg-muted/20"
                >
                  Hardware
                </td>
              </tr>

              {/* Metadata Rows */}
              {metadataRows.map((row, idx) => (
                <tr
                  key={row.label}
                  className={idx < metadataRows.length - 1 ? 'border-b border-border/50' : ''}
                >
                  <td className="px-4 py-2 text-muted-foreground">{row.label}</td>
                  {workers.map((worker) => (
                    <td
                      key={worker.id}
                      className="px-4 py-2 text-center font-mono text-sm"
                    >
                      {row.getValue(worker)}
                    </td>
                  ))}
                </tr>
              ))}

              {/* View Details Row */}
              {onViewDetails && (
                <tr className="border-t border-border">
                  <td className="px-4 py-2"></td>
                  {workers.map((worker) => (
                    <td key={worker.id} className="px-4 py-2 text-center">
                      <button
                        type="button"
                        onClick={() => onViewDetails(worker.id)}
                        className="text-xs text-primary hover:underline"
                      >
                        View Details
                      </button>
                    </td>
                  ))}
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

export type { ComparisonTableProps };
