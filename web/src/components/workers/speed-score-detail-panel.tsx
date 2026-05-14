'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { AlertCircle, Beaker, ChevronDown, ChevronUp } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import type { SpeedScoreView, BenchmarkResults, PartialSpeedScore } from '@/lib/types';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { ComponentBreakdown } from './component-breakdown';

// ============================================================================
// Type Definitions
// ============================================================================

export interface SpeedScoreDetailPanelProps {
  workerId: string;
  speedscore: SpeedScoreView | PartialSpeedScore | null;
  rawResults?: BenchmarkResults | null;
  isLoading?: boolean;
  error?: Error | null;
  onRetry?: () => void;
  onTriggerBenchmark?: () => void;
  isAdmin?: boolean;
  isExpanded?: boolean;
  onToggle?: () => void;
}

// ============================================================================
// Helper Components
// ============================================================================

/**
 * Total score badge displayed in the panel header.
 */
function TotalScoreBadge({ score }: { score: number }) {
  const getScoreStyle = (s: number) => {
    if (s >= 90) return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300';
    if (s >= 70) return 'border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300';
    if (s >= 50) return 'border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300';
    if (s >= 30) return 'border-orange-500/40 bg-orange-500/15 text-orange-700 dark:text-orange-300';
    return 'border-red-500/40 bg-red-500/15 text-red-700 dark:text-red-300';
  };

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center px-3 py-1.5 rounded-full border text-lg font-bold tabular-nums',
        getScoreStyle(score)
      )}
      role="status"
      aria-label={`Total SpeedScore: ${Math.round(score)}`}
    >
      {Math.round(score)}
    </span>
  );
}

/**
 * Format a date string to relative time (e.g., "2 hours ago").
 */
function formatRelativeTime(dateStr: string): string {
  try {
    return formatDistanceToNow(new Date(dateStr), { addSuffix: true });
  } catch {
    return dateStr;
  }
}

// ============================================================================
// State Components
// ============================================================================

/**
 * Loading skeleton for the detail panel.
 */
function SpeedScoreDetailPanelSkeleton() {
  return (
    <Card className="speedscore-detail-panel" aria-busy="true" data-testid="speedscore-detail-panel-loading">
      <CardHeader className="flex flex-row items-center justify-between pb-4">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-10 w-16 rounded-full" />
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="flex items-center gap-2">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-8" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Error state with retry button.
 */
function SpeedScoreDetailPanelError({
  workerId,
  error,
  onRetry,
}: {
  workerId: string;
  error: Error;
  onRetry?: () => void;
}) {
  return (
    <Card className="speedscore-detail-panel" data-testid="speedscore-detail-panel-error">
      <CardHeader>
        <CardTitle>SpeedScore Details: {workerId}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center justify-center py-8 text-center">
        <AlertCircle className="w-12 h-12 text-destructive mb-4" aria-hidden="true" />
        <p className="text-lg font-medium text-foreground mb-2">Failed to load SpeedScore details</p>
        <p className="text-sm text-muted-foreground mb-4">{error.message}</p>
        {onRetry && (
          <Button onClick={onRetry} variant="outline">
            Try Again
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Empty state for workers that haven't been benchmarked.
 */
function SpeedScoreDetailPanelEmpty({
  workerId,
  onTriggerBenchmark,
  isAdmin,
}: {
  workerId: string;
  onTriggerBenchmark?: () => void;
  isAdmin?: boolean;
}) {
  return (
    <Card className="speedscore-detail-panel" data-testid="speedscore-detail-panel-empty">
      <CardHeader>
        <CardTitle>SpeedScore Details: {workerId}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center justify-center py-8 text-center">
        <Beaker className="w-12 h-12 text-muted-foreground mb-4" aria-hidden="true" />
        <p className="text-lg font-medium text-foreground mb-2">Not Yet Benchmarked</p>
        <p className="text-sm text-muted-foreground mb-4 max-w-sm">
          This worker has not completed a benchmark. SpeedScore will be available after the first benchmark run.
        </p>
        {isAdmin && onTriggerBenchmark && (
          <Button onClick={onTriggerBenchmark}>Run Benchmark Now</Button>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Partial results state when benchmark failed mid-way.
 */
function SpeedScoreDetailPanelPartial({
  workerId,
  speedscore,
  failedPhase,
  onRetry,
}: {
  workerId: string;
  speedscore: PartialSpeedScore;
  failedPhase: string;
  onRetry?: () => void;
}) {
  return (
    <Card className="speedscore-detail-panel" data-testid="speedscore-detail-panel-partial">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>SpeedScore Details: {workerId}</CardTitle>
        <Badge variant="secondary" className="bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/40">
          Partial Results
        </Badge>
      </CardHeader>
      <CardContent>
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-md p-3 mb-4">
          <p className="text-sm text-amber-700 dark:text-amber-300">
            Benchmark failed during <strong>{failedPhase}</strong> phase. Showing partial results.
          </p>
        </div>
        <ComponentBreakdown
          speedscore={speedscore}
          partialUpTo={failedPhase as PartialSpeedScore['failed_phase']}
        />
        {onRetry && (
          <div className="mt-4 flex justify-end">
            <Button onClick={onRetry} variant="outline" size="sm">
              Retry Benchmark
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * SpeedScoreDetailPanel shows detailed SpeedScore breakdown with component
 * scores, weights, contributions, and raw benchmark values.
 *
 * Supports loading, error, empty, partial, and full states with proper
 * accessibility and keyboard navigation.
 */
export function SpeedScoreDetailPanel({
  workerId,
  speedscore,
  rawResults,
  isLoading = false,
  error = null,
  onRetry,
  onTriggerBenchmark,
  isAdmin = false,
  isExpanded = true,
  onToggle,
}: SpeedScoreDetailPanelProps) {
  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle?.();
    }
    if (e.key === 'Escape' && isExpanded) {
      onToggle?.();
    }
  };

  // Loading state
  if (isLoading) {
    return <SpeedScoreDetailPanelSkeleton />;
  }

  // Error state
  if (error) {
    return <SpeedScoreDetailPanelError workerId={workerId} error={error} onRetry={onRetry} />;
  }

  // Empty state (not benchmarked)
  if (!speedscore) {
    return (
      <SpeedScoreDetailPanelEmpty
        workerId={workerId}
        onTriggerBenchmark={onTriggerBenchmark}
        isAdmin={isAdmin}
      />
    );
  }

  // Partial results state
  if ('is_partial' in speedscore && speedscore.is_partial) {
    return (
      <SpeedScoreDetailPanelPartial
        workerId={workerId}
        speedscore={speedscore}
        failedPhase={speedscore.failed_phase}
        onRetry={onTriggerBenchmark}
      />
    );
  }

  // Full panel with expand/collapse
  const fullScore = speedscore as SpeedScoreView;
  const ChevronIcon = isExpanded ? ChevronUp : ChevronDown;

  return (
    <Card
      className="speedscore-detail-panel"
      role="region"
      aria-labelledby={`panel-title-${workerId}`}
      data-testid="speedscore-detail-panel"
    >
      <CardHeader
        className={cn(
          'flex flex-row items-center justify-between pb-4',
          onToggle && 'cursor-pointer hover:bg-muted/30 transition-colors rounded-t-xl'
        )}
        onClick={onToggle}
        onKeyDown={handleKeyDown}
        tabIndex={onToggle ? 0 : undefined}
        role={onToggle ? 'button' : undefined}
        aria-expanded={onToggle ? isExpanded : undefined}
        aria-controls={`panel-content-${workerId}`}
        aria-label={onToggle ? `Toggle SpeedScore details for ${workerId}` : undefined}
      >
        <CardTitle id={`panel-title-${workerId}`} className="text-base">
          SpeedScore Details: {workerId}
        </CardTitle>
        <div className="flex items-center gap-2">
          <TotalScoreBadge score={fullScore.total} />
          {onToggle && (
            <ChevronIcon
              className="w-5 h-5 text-muted-foreground"
              aria-hidden="true"
            />
          )}
        </div>
      </CardHeader>

      <AnimatePresence initial={false}>
        {isExpanded && (
          <motion.div
            id={`panel-content-${workerId}`}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            style={{ overflow: 'hidden' }}
          >
            <CardContent>
              <ComponentBreakdown speedscore={fullScore} rawResults={rawResults} />
            </CardContent>

            <CardFooter className="flex flex-wrap items-center justify-between gap-2 pt-4 border-t">
              <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                <span>
                  Benchmarked: {formatRelativeTime(fullScore.measured_at)}
                </span>
                <span>Version: {fullScore.version}</span>
              </div>
              {isAdmin && onTriggerBenchmark && (
                <Button onClick={onTriggerBenchmark} variant="outline" size="sm">
                  Re-benchmark
                </Button>
              )}
            </CardFooter>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}

// Export sub-components for testing
export {
  SpeedScoreDetailPanelSkeleton,
  SpeedScoreDetailPanelError,
  SpeedScoreDetailPanelEmpty,
  SpeedScoreDetailPanelPartial,
  TotalScoreBadge,
};
