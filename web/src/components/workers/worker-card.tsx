'use client';

import { useState } from 'react';
import { Server, AlertCircle, CheckCircle, Clock, Zap, Play } from 'lucide-react';
import type { WorkerStatusInfo, CircuitState, WorkerStatus, SpeedScoreView } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { BenchmarkProgressModal } from './benchmark-progress-modal';
import { SpeedScoreBadge } from './speed-score-badge';

interface WorkerCardProps {
  worker: WorkerStatusInfo;
  speedScoreView?: SpeedScoreView | null;
  /** Callback when a benchmark completes successfully */
  onBenchmarkCompleted?: () => void;
  /** Whether to show the benchmark trigger button */
  showBenchmarkTrigger?: boolean;
}

const statusConfig: Record<WorkerStatus, { label: string; color: string; icon: typeof CheckCircle }> = {
  healthy: { label: 'Healthy', color: 'text-healthy bg-healthy/10', icon: CheckCircle },
  degraded: { label: 'Degraded', color: 'text-warning bg-warning/10', icon: Clock },
  unreachable: { label: 'Unreachable', color: 'text-error bg-error/10', icon: AlertCircle },
  draining: { label: 'Draining', color: 'text-draining bg-draining/10', icon: Clock },
  disabled: { label: 'Disabled', color: 'text-muted-foreground bg-muted/10', icon: AlertCircle },
};

const circuitConfig: Record<CircuitState, { label: string; color: string }> = {
  closed: { label: 'Closed', color: 'text-circuit-closed' },
  half_open: { label: 'Half-Open', color: 'text-circuit-half-open' },
  open: { label: 'Open', color: 'text-circuit-open' },
};

export function WorkerCard({
  worker,
  speedScoreView = null,
  onBenchmarkCompleted,
  showBenchmarkTrigger = true,
}: WorkerCardProps) {
  const [benchmarkModalOpen, setBenchmarkModalOpen] = useState(false);
  const status = statusConfig[worker.status];
  const circuit = circuitConfig[worker.circuit_state];
  const slotsUsedPercent =
    Number.isFinite(worker.total_slots) && worker.total_slots > 0
      ? Math.min(100, Math.max(0, (worker.used_slots / worker.total_slots) * 100))
      : 0;
  const StatusIcon = status.icon;
  const speedScore = Number.isFinite(worker.speed_score) ? worker.speed_score : null;
  const previousScore = typeof worker.speed_score_prev === 'number' ? worker.speed_score_prev : null;
  const breakdown = speedScoreView
    ? {
        cpu_score: speedScoreView.cpu_score,
        memory_score: speedScoreView.memory_score,
        disk_score: speedScoreView.disk_score,
        network_score: speedScoreView.network_score,
        compilation_score: speedScoreView.compilation_score,
        measured_at: speedScoreView.measured_at,
      }
    : null;

  // Benchmark can only be triggered on healthy or degraded workers
  const canBenchmark = worker.status === 'healthy' || worker.status === 'degraded';
  const isWorkhorse = worker.total_slots >= 16;
  const isStandard = worker.total_slots >= 6 && worker.total_slots < 16;
  const tier = isWorkhorse ? 'Workhorse' : isStandard ? 'Standard' : 'Satellite';
  const isActivelyCompiling = worker.used_slots > 0;
  const powerRating = Number.isFinite(worker.speed_score) && worker.total_slots > 0
    ? Math.round(worker.speed_score * worker.total_slots)
    : null;

  return (
    <div
      className={`bg-card border rounded-lg p-4 transition-all duration-200 ${
        isWorkhorse ? 'border-primary/40 bg-card/95 shadow-sm' : 'border-border'
      } ${
        isActivelyCompiling ? 'border-l-4 border-l-primary ring-1 ring-primary/20' : ''
      } hover:border-primary/60`}
      data-testid="worker-card"
      data-worker-id={worker.id}
    >
      <div className="flex items-start justify-between mb-3 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-surface-elevated flex items-center justify-center relative">
            <Server className={`w-5 h-5 ${isWorkhorse ? 'text-primary' : 'text-muted-foreground'}`} />
            {isWorkhorse && (
              <span className="absolute -top-1 -right-1 text-xs" title="Workhorse (16+ slots)">⚡</span>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-foreground">{worker.id}</h3>
              <span
                className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-full ${
                  isWorkhorse
                    ? 'bg-primary/15 text-primary border border-primary/30'
                    : 'bg-muted text-muted-foreground'
                }`}
              >
                {tier}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{worker.user}@{worker.host}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <SpeedScoreBadge score={speedScore} previousScore={previousScore} breakdown={breakdown} size="sm" />
          <div
            className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${status.color}`}
            data-testid="worker-status"
            data-status={worker.status}
          >
            <StatusIcon className="w-3.5 h-3.5" />
            {status.label}
          </div>
        </div>
      </div>

      {/* Discrete Slot Matrix */}
      {worker.total_slots > 0 && (
        <div className="mb-3 p-2 bg-surface-elevated/50 border border-border/50 rounded-md">
          <div className="flex items-center justify-between text-xs text-muted-foreground mb-1.5">
            <span className="font-mono text-[11px]">
              {worker.used_slots > 0 ? (
                <span className="text-primary font-medium flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  {worker.used_slots} active build{worker.used_slots === 1 ? '' : 's'}
                </span>
              ) : (
                `${worker.total_slots} slots available`
              )}
            </span>
            <span className="font-mono text-[11px]">
              {worker.used_slots} / {worker.total_slots} ({Math.round(slotsUsedPercent)}%)
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {Array.from({ length: Math.min(worker.total_slots, 48) }, (_, i) => {
              const isActive = i < worker.used_slots;
              return (
                <div
                  key={i}
                  className={`h-2.5 w-2.5 rounded-sm transition-colors ${
                    isActive
                      ? 'bg-primary shadow-[0_0_4px_rgba(var(--primary),0.6)]'
                      : 'bg-muted-foreground/20'
                  }`}
                  title={isActive ? `Slot #${i + 1}: Compiling` : `Slot #${i + 1}: Available`}
                />
              );
            })}
          </div>
        </div>
      )}

      {/* Slots Progress Bar */}
      <div className="mb-3" data-testid="worker-slots">
        <div className="h-1.5 bg-surface-elevated rounded-full overflow-hidden"
          role="progressbar"
          data-testid="worker-slots-bar"
          aria-label="Slots used"
          aria-valuemin={0}
          aria-valuemax={worker.total_slots}
          aria-valuenow={worker.used_slots}
          aria-valuetext={`${worker.used_slots} of ${worker.total_slots} slots used`}
        >
          <div
            className="h-full w-full bg-primary rounded-full origin-left transition-transform duration-500 ease-out"
            style={{ transform: `scaleX(${slotsUsedPercent / 100})` }}
            data-testid="worker-slots-fill"
          />
        </div>
      </div>

      {/* Stats Row */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1" title={powerRating ? `Power Rating: ${powerRating}` : undefined}>
            <Zap className="w-3.5 h-3.5" />
            <span>Speed: {speedScore != null ? speedScore.toFixed(1) : '—'}</span>
            {powerRating != null && <span className="text-[10px] text-muted-foreground/75 font-mono">({powerRating}p)</span>}
          </div>
          <div
            className={`flex items-center gap-1 ${circuit.color}`}
            data-testid="worker-circuit"
            data-circuit={worker.circuit_state}
          >
            <span>Circuit: {circuit.label}</span>
          </div>
        </div>

        {/* Benchmark Trigger Button */}
        {showBenchmarkTrigger && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setBenchmarkModalOpen(true)}
            disabled={!canBenchmark}
            className="gap-1 h-7 px-2 text-xs"
            title={canBenchmark ? 'Run benchmark' : 'Worker must be healthy or degraded to benchmark'}
            data-testid="benchmark-trigger-button"
          >
            <Play className="h-3 w-3" />
            <span className="hidden sm:inline">Benchmark</span>
          </Button>
        )}
      </div>

      {/* Error Message */}
      {worker.last_error && (
        <div className="mt-3 p-2 bg-error/10 rounded text-xs text-error" data-testid="worker-error">
          {worker.last_error}
        </div>
      )}

      {/* Benchmark Progress Modal */}
      {showBenchmarkTrigger && (
        <BenchmarkProgressModal
          workerId={worker.id}
          workerName={worker.id}
          open={benchmarkModalOpen}
          onOpenChange={setBenchmarkModalOpen}
          onCompleted={onBenchmarkCompleted}
        />
      )}
    </div>
  );
}
