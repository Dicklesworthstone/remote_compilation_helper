'use client';

import { useState } from 'react';
import { Play, Loader2, CheckCircle, XCircle, Clock } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useBenchmarkProgress, type BenchmarkPhase } from '@/lib/hooks/use-benchmark-progress';
import { cn } from '@/lib/utils';

interface BenchmarkTriggerButtonProps {
  workerId: string;
  disabled?: boolean;
  onCompleted?: () => void;
}

const phaseLabels: Record<BenchmarkPhase, string> = {
  cpu: 'CPU',
  memory: 'Memory',
  disk: 'Disk I/O',
  network: 'Network',
  compilation: 'Compilation',
};

const phaseOrder: BenchmarkPhase[] = ['cpu', 'memory', 'disk', 'network', 'compilation'];

/**
 * Button to trigger a benchmark with inline progress display.
 */
export function BenchmarkTriggerButton({
  workerId,
  disabled = false,
  onCompleted,
}: BenchmarkTriggerButtonProps) {
  const [showProgress, setShowProgress] = useState(false);

  const benchmark = useBenchmarkProgress({
    workerId,
    onCompleted: () => {
      onCompleted?.();
      // Keep showing for a moment, then hide
      setTimeout(() => {
        setShowProgress(false);
        benchmark.reset();
      }, 3000);
    },
    onFailed: () => {
      // Keep showing error for a moment, then allow retry
      setTimeout(() => {
        setShowProgress(false);
      }, 5000);
    },
  });

  const handleTrigger = async () => {
    setShowProgress(true);
    await benchmark.trigger();
  };

  const handleDismiss = () => {
    setShowProgress(false);
    if (benchmark.isFailed || benchmark.isCompleted) {
      benchmark.reset();
    }
  };

  const handleRetry = async () => {
    benchmark.reset();
    await benchmark.trigger();
  };

  // Button only mode (not active)
  if (!showProgress && benchmark.isIdle) {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={handleTrigger}
        disabled={disabled}
        className="gap-1.5"
        title="Trigger benchmark"
        data-testid="benchmark-trigger-button"
      >
        <Play className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Benchmark</span>
      </Button>
    );
  }

  // Progress panel mode
  return (
    <AnimatePresence mode="wait">
      <motion.div
        initial={{ opacity: 0, scale: 0.98, y: -4 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.98, y: -4 }}
        transition={{ duration: 0.2 }}
        className="w-full"
        data-testid="benchmark-progress-panel"
      >
        <div className="rounded-lg border border-border bg-surface-elevated p-3 space-y-3">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <StatusIcon status={benchmark.status} />
              <span className="text-sm font-medium">
                <StatusLabel status={benchmark.status} />
              </span>
            </div>
            {(benchmark.isCompleted || benchmark.isFailed) && (
              <button
                onClick={handleDismiss}
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                Dismiss
              </button>
            )}
          </div>

          {/* Progress indicator (queued/running) */}
          {(benchmark.isQueued || benchmark.isTriggering) && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Clock className="h-3.5 w-3.5 animate-pulse" />
              <span>Waiting in queue...</span>
            </div>
          )}

          {benchmark.isRunning && (
            <div className="space-y-2">
              {/* Phase pills */}
              <div className="flex flex-wrap gap-1.5">
                {phaseOrder.map((phase) => (
                  <PhasePill
                    key={phase}
                    phase={phase}
                    currentPhase={benchmark.currentPhase}
                    overallProgress={benchmark.overallProgress}
                  />
                ))}
              </div>

              {/* Progress bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>
                    {benchmark.currentPhase
                      ? `${phaseLabels[benchmark.currentPhase]}: ${Math.round(benchmark.phaseProgress)}%`
                      : 'Starting...'}
                  </span>
                  <span>{benchmark.elapsedSecs.toFixed(0)}s</span>
                </div>
                <Progress value={benchmark.overallProgress} />
              </div>
            </div>
          )}

          {/* Completed result */}
          {benchmark.isCompleted && benchmark.result && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">New SpeedScore:</span>
                <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                  {Math.round(benchmark.result.total)}
                </span>
              </div>
              {benchmark.durationSecs !== null && (
                <div className="text-xs text-muted-foreground">
                  Completed in {benchmark.durationSecs.toFixed(1)}s
                </div>
              )}
            </div>
          )}

          {/* Error state */}
          {benchmark.isFailed && (
            <div className="space-y-2">
              <div className="text-xs text-error">{benchmark.error}</div>
              <Button variant="outline" size="sm" onClick={handleRetry} className="gap-1.5">
                <Play className="h-3.5 w-3.5" />
                Retry
              </Button>
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'triggering':
    case 'queued':
    case 'running':
      return <Loader2 className="h-4 w-4 animate-spin text-primary" />;
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />;
    case 'failed':
      return <XCircle className="h-4 w-4 text-error" />;
    default:
      return <Play className="h-4 w-4 text-muted-foreground" />;
  }
}

function StatusLabel({ status }: { status: string }) {
  switch (status) {
    case 'triggering':
      return 'Triggering...';
    case 'queued':
      return 'Queued';
    case 'running':
      return 'Running Benchmark';
    case 'completed':
      return 'Benchmark Complete';
    case 'failed':
      return 'Benchmark Failed';
    default:
      return 'Ready';
  }
}

function PhasePill({
  phase,
  currentPhase,
  overallProgress,
}: {
  phase: BenchmarkPhase;
  currentPhase: BenchmarkPhase | null;
  overallProgress: number;
}) {
  const phaseIndex = phaseOrder.indexOf(phase);
  const currentIndex = currentPhase ? phaseOrder.indexOf(currentPhase) : -1;

  const isComplete = currentIndex > phaseIndex || (currentIndex === phaseIndex && overallProgress >= ((phaseIndex + 1) / phaseOrder.length) * 100);
  const isCurrent = phase === currentPhase;
  const isPending = currentIndex < phaseIndex;

  return (
    <span
      className={cn(
        'px-2 py-0.5 rounded-full text-[10px] font-medium transition-colors',
        isComplete && 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300',
        isCurrent && 'bg-primary/20 text-primary animate-pulse',
        isPending && 'bg-muted text-muted-foreground'
      )}
    >
      {phaseLabels[phase]}
    </span>
  );
}
