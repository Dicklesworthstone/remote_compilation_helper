'use client';

import { Play, Loader2, CheckCircle, XCircle, Clock, Cpu, HardDrive, Wifi, Wrench, MemoryStick } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useBenchmarkProgress, type BenchmarkPhase } from '@/lib/hooks/use-benchmark-progress';
import type { SpeedScoreView } from '@/lib/types';
import { cn } from '@/lib/utils';

interface BenchmarkProgressModalProps {
  workerId: string;
  workerName?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCompleted?: (result: SpeedScoreView) => void;
}

const phaseConfig: Record<BenchmarkPhase, { label: string; icon: typeof Cpu; description: string }> = {
  cpu: {
    label: 'CPU',
    icon: Cpu,
    description: 'Testing floating-point performance',
  },
  memory: {
    label: 'Memory',
    icon: MemoryStick,
    description: 'Measuring memory bandwidth',
  },
  disk: {
    label: 'Disk I/O',
    icon: HardDrive,
    description: 'Testing read/write speeds',
  },
  network: {
    label: 'Network',
    icon: Wifi,
    description: 'Measuring network throughput',
  },
  compilation: {
    label: 'Compilation',
    icon: Wrench,
    description: 'Running compilation benchmark',
  },
};

const phaseOrder: BenchmarkPhase[] = ['cpu', 'memory', 'disk', 'network', 'compilation'];

/**
 * Modal dialog showing detailed benchmark progress and results.
 */
export function BenchmarkProgressModal({
  workerId,
  workerName,
  open,
  onOpenChange,
  onCompleted,
}: BenchmarkProgressModalProps) {
  const benchmark = useBenchmarkProgress({
    workerId,
    onCompleted: (result) => {
      onCompleted?.(result);
    },
  });

  const handleTrigger = async () => {
    await benchmark.trigger();
  };

  const handleClose = () => {
    if (!benchmark.isActive) {
      benchmark.reset();
      onOpenChange(false);
    }
  };

  const displayName = workerName || workerId;

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md" data-testid="benchmark-progress-modal">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <StatusIcon status={benchmark.status} />
            Benchmark: {displayName}
          </DialogTitle>
          <DialogDescription>
            {benchmark.isIdle && 'Run a performance benchmark on this worker to update its SpeedScore.'}
            {benchmark.isTriggering && 'Submitting benchmark request...'}
            {benchmark.isQueued && 'Waiting for benchmark to start...'}
            {benchmark.isRunning && 'Benchmark in progress. This may take a few minutes.'}
            {benchmark.isCompleted && 'Benchmark completed successfully.'}
            {benchmark.isFailed && 'Benchmark failed. You can retry or dismiss this dialog.'}
          </DialogDescription>
        </DialogHeader>

        <div className="py-4">
          <AnimatePresence mode="wait">
            {/* Idle state */}
            {benchmark.isIdle && (
              <motion.div
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-center py-6"
              >
                <p className="text-sm text-muted-foreground mb-4">
                  The benchmark will test CPU, memory, disk, network, and compilation performance.
                </p>
                <Button onClick={handleTrigger} className="gap-2">
                  <Play className="h-4 w-4" />
                  Start Benchmark
                </Button>
              </motion.div>
            )}

            {/* Triggering/Queued state */}
            {(benchmark.isTriggering || benchmark.isQueued) && (
              <motion.div
                key="queued"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center py-6 gap-3"
              >
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>{benchmark.isTriggering ? 'Submitting request...' : 'Queued, waiting to start...'}</span>
                </div>
              </motion.div>
            )}

            {/* Running state */}
            {benchmark.isRunning && (
              <motion.div
                key="running"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                {/* Phase list */}
                <div className="space-y-2">
                  {phaseOrder.map((phase, idx) => (
                    <PhaseRow
                      key={phase}
                      phase={phase}
                      currentPhase={benchmark.currentPhase}
                      phaseProgress={benchmark.phaseProgress}
                      phaseIndex={idx}
                    />
                  ))}
                </div>

                {/* Overall progress */}
                <div className="space-y-2 pt-2 border-t">
                  <div className="flex justify-between text-sm">
                    <span className="font-medium">Overall Progress</span>
                    <span className="text-muted-foreground tabular-nums">
                      {Math.round(benchmark.overallProgress)}%
                    </span>
                  </div>
                  <Progress value={benchmark.overallProgress} className="h-3" />
                  <div className="text-xs text-muted-foreground text-right">
                    Elapsed: {formatElapsed(benchmark.elapsedSecs)}
                  </div>
                </div>
              </motion.div>
            )}

            {/* Completed state */}
            {benchmark.isCompleted && benchmark.result && (
              <motion.div
                key="completed"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div className="text-center py-4">
                  <CheckCircle className="h-12 w-12 text-emerald-600 dark:text-emerald-400 mx-auto mb-3" />
                  <div className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">
                    {benchmark.result.total != null && Number.isFinite(benchmark.result.total)
                      ? Math.round(benchmark.result.total)
                      : '—'}
                  </div>
                  <div className="text-sm text-muted-foreground">New SpeedScore</div>
                </div>

                {/* Score breakdown */}
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <ScoreItem label="CPU" value={benchmark.result.cpu_score} />
                  <ScoreItem label="Memory" value={benchmark.result.memory_score} />
                  <ScoreItem label="Disk I/O" value={benchmark.result.disk_score} />
                  <ScoreItem label="Network" value={benchmark.result.network_score} />
                  <ScoreItem label="Compilation" value={benchmark.result.compilation_score} className="col-span-2" />
                </div>

                {benchmark.durationSecs !== null && (
                  <div className="text-xs text-muted-foreground text-center pt-2">
                    Completed in {benchmark.durationSecs.toFixed(1)} seconds
                  </div>
                )}
              </motion.div>
            )}

            {/* Failed state */}
            {benchmark.isFailed && (
              <motion.div
                key="failed"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="text-center py-6"
              >
                <XCircle className="h-12 w-12 text-error mx-auto mb-3" />
                <div className="text-sm text-error mb-4">{benchmark.error}</div>
                <Button onClick={handleTrigger} variant="outline" className="gap-2">
                  <Play className="h-4 w-4" />
                  Retry Benchmark
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={handleClose}
            disabled={benchmark.isActive}
          >
            {benchmark.isActive ? 'Running...' : 'Close'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'triggering':
    case 'queued':
    case 'running':
      return <Loader2 className="h-5 w-5 animate-spin text-primary" />;
    case 'completed':
      return <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />;
    case 'failed':
      return <XCircle className="h-5 w-5 text-error" />;
    default:
      return <Play className="h-5 w-5 text-muted-foreground" />;
  }
}

function PhaseRow({
  phase,
  currentPhase,
  phaseProgress,
  phaseIndex,
}: {
  phase: BenchmarkPhase;
  currentPhase: BenchmarkPhase | null;
  phaseProgress: number;
  phaseIndex: number;
}) {
  const config = phaseConfig[phase];
  const Icon = config.icon;
  const currentIndex = currentPhase ? phaseOrder.indexOf(currentPhase) : -1;

  const isComplete = currentIndex > phaseIndex;
  const isCurrent = phase === currentPhase;
  const isPending = currentIndex < phaseIndex;

  return (
    <div
      className={cn(
        'flex items-center gap-3 p-2 rounded-lg transition-colors',
        isCurrent && 'bg-primary/10',
        isComplete && 'opacity-60'
      )}
    >
      <div
        className={cn(
          'flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center',
          isComplete && 'bg-emerald-500/20',
          isCurrent && 'bg-primary/20',
          isPending && 'bg-muted'
        )}
      >
        {isComplete ? (
          <CheckCircle className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
        ) : isCurrent ? (
          <Icon className="h-4 w-4 text-primary animate-pulse" />
        ) : (
          <Icon className="h-4 w-4 text-muted-foreground" />
        )}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className={cn('text-sm font-medium', isPending && 'text-muted-foreground')}>
            {config.label}
          </span>
          {isCurrent && (
            <span className="text-xs text-muted-foreground tabular-nums">
              {Math.round(phaseProgress)}%
            </span>
          )}
          {isComplete && (
            <CheckCircle className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
          )}
        </div>
        {isCurrent && (
          <div className="mt-1">
            <Progress value={phaseProgress} className="h-1.5" />
            <div className="text-xs text-muted-foreground mt-0.5">{config.description}</div>
          </div>
        )}
      </div>
    </div>
  );
}

function ScoreItem({
  label,
  value,
  className,
}: {
  label: string;
  value: number;
  className?: string;
}) {
  return (
    <div className={cn('flex justify-between p-2 bg-muted/50 rounded', className)}>
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium tabular-nums">
        {value != null && Number.isFinite(value) ? Math.round(value) : '—'}
      </span>
    </div>
  );
}

function formatElapsed(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}
