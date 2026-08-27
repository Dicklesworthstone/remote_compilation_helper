'use client';

import * as React from 'react';
import { Info } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip } from '@/components/ui/tooltip';

export interface ComponentRowProps {
  name: string;
  score: number | null;
  weight: number;
  rawValue: string;
  description: string;
  isPartial?: boolean;
  'data-testid'?: string;
}

/**
 * Get the color for a score bar based on the score value.
 * Uses semantic colors matching the SpeedScoreBadge levels.
 */
function getScoreColor(score: number): string {
  if (score >= 90) return 'rgb(16 185 129)'; // emerald-500
  if (score >= 70) return 'rgb(14 165 233)'; // sky-500
  if (score >= 50) return 'rgb(245 158 11)'; // amber-500
  if (score >= 30) return 'rgb(249 115 22)'; // orange-500
  return 'rgb(239 68 68)'; // red-500
}

/**
 * ComponentRow displays a single benchmark component with animated progress bar.
 * Shows the component name, score bar, weight, contribution, and raw value.
 */
export function ComponentRow({
  name,
  score,
  weight,
  rawValue,
  description,
  isPartial = false,
  'data-testid': testId,
}: ComponentRowProps) {
  const contribution = score != null ? score * weight : null;
  const [animatedScore, setAnimatedScore] = React.useState(0);

  // Animate bar fill on mount
  React.useEffect(() => {
    if (score != null) {
      const timer = setTimeout(() => setAnimatedScore(score), 100);
      return () => clearTimeout(timer);
    }
  }, [score]);

  return (
    <div
      className={cn(
        'grid grid-cols-[80px_1fr_48px_56px_56px_24px] sm:grid-cols-[100px_1fr_48px_56px_56px_24px_120px] gap-2 items-center py-2 border-b border-border/50 last:border-0',
        { 'opacity-50': isPartial }
      )}
      data-testid={testId}
    >
      {/* Component Name */}
      <div className="font-medium text-sm text-foreground">{name}</div>

      {/* Score Bar */}
      <div className="h-4 bg-muted/50 rounded-full overflow-hidden relative">
        {score != null ? (
          <div
            className="h-full w-full rounded-full origin-left transition-transform duration-500 ease-out"
            style={{
              transform: `scaleX(${animatedScore / 100})`,
              backgroundColor: getScoreColor(score),
            }}
            data-testid={testId ? `${testId}-bar` : undefined}
          />
        ) : (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
            Not measured
          </div>
        )}
      </div>

      {/* Score Value */}
      <div className="text-sm tabular-nums text-right font-medium">
        {score != null ? score.toFixed(0) : '—'}
      </div>

      {/* Weight */}
      <div className="text-xs text-muted-foreground text-right tabular-nums">
        ×{weight.toFixed(2)}
      </div>

      {/* Contribution */}
      <div className="text-xs text-muted-foreground text-right tabular-nums">
        ={contribution != null ? contribution.toFixed(1) : '—'}
      </div>

      {/* Info Tooltip */}
      <Tooltip content={description} side="left">
        <button
          type="button"
          className="p-0.5 rounded hover:bg-muted/50 transition-colors focus:outline-none focus:ring-2 focus:ring-ring"
          aria-label={`Info about ${name}`}
        >
          <Info className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
        </button>
      </Tooltip>

      {/* Raw Value (hidden on small screens) */}
      <div className="hidden sm:block text-xs text-muted-foreground truncate" title={rawValue}>
        {rawValue}
      </div>
    </div>
  );
}
