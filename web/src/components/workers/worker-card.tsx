'use client';

import { Server, AlertCircle, CheckCircle, Clock, Zap, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { motion } from 'motion/react';
import type { WorkerStatusInfo, CircuitState, WorkerStatus } from '@/lib/types';
import { cn } from '@/lib/utils';

interface WorkerCardProps {
  worker: WorkerStatusInfo;
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

type ScoreLevel = 'excellent' | 'good' | 'average' | 'below_average' | 'poor';

const scoreLevelConfig: Record<ScoreLevel, { label: string; className: string }> = {
  excellent: {
    label: 'Excellent',
    className: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 dark:bg-emerald-500/20',
  },
  good: {
    label: 'Good',
    className: 'border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300 dark:bg-sky-500/20',
  },
  average: {
    label: 'Average',
    className: 'border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300 dark:bg-amber-500/20',
  },
  below_average: {
    label: 'Below Average',
    className: 'border-orange-500/40 bg-orange-500/15 text-orange-700 dark:text-orange-300 dark:bg-orange-500/20',
  },
  poor: {
    label: 'Poor',
    className: 'border-red-500/40 bg-red-500/15 text-red-700 dark:text-red-300 dark:bg-red-500/20',
  },
};

const badgeSizeClasses = {
  sm: 'px-2 py-0.5 text-[11px]',
  md: 'px-2.5 py-1 text-xs',
};

type TrendDirection = 'up' | 'down' | 'stable';
type TrendMagnitude = 'small' | 'medium' | 'large';

interface Trend {
  direction: TrendDirection;
  magnitude: TrendMagnitude;
  delta: number;
}

interface SpeedScoreBadgeProps {
  score: number | null | undefined;
  previousScore?: number | null;
  size?: keyof typeof badgeSizeClasses;
  showTrend?: boolean;
  isLoading?: boolean;
  error?: Error | null;
  onRetry?: () => void;
}

function clampScore(score: number): number {
  return Math.min(100, Math.max(0, score));
}

function getScoreLevel(score: number): ScoreLevel {
  if (score >= 90) return 'excellent';
  if (score >= 70) return 'good';
  if (score >= 50) return 'average';
  if (score >= 30) return 'below_average';
  return 'poor';
}

function calculateTrend(current: number, previous: number): Trend {
  const delta = current - previous;
  const absDelta = Math.abs(delta);
  const baseline = Math.max(Math.abs(previous), 1);
  const percentChange = (absDelta / baseline) * 100;

  let direction: TrendDirection = 'stable';
  if (absDelta >= 1) {
    direction = delta > 0 ? 'up' : 'down';
  }

  let magnitude: TrendMagnitude = 'small';
  if (percentChange >= 15) {
    magnitude = 'large';
  } else if (percentChange >= 5) {
    magnitude = 'medium';
  }

  return { direction, magnitude, delta };
}

function TrendIndicator({ trend }: { trend: Trend }) {
  const Icon = trend.direction === 'up' ? TrendingUp : trend.direction === 'down' ? TrendingDown : Minus;
  const tone =
    trend.direction === 'up'
      ? 'text-emerald-600 dark:text-emerald-300'
      : trend.direction === 'down'
        ? 'text-red-600 dark:text-red-300'
        : 'text-muted-foreground';

  return (
    <span
      className={cn('hidden sm:inline-flex items-center', tone)}
      data-testid="speedscore-trend"
      data-direction={trend.direction}
      data-magnitude={trend.magnitude}
      aria-label={`Trend: ${trend.direction}, ${Math.abs(trend.delta).toFixed(1)} points`}
      title={`${trend.delta >= 0 ? '+' : ''}${trend.delta.toFixed(1)} since last benchmark`}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
    </span>
  );
}

function SpeedScoreBadge({
  score,
  previousScore,
  size = 'sm',
  showTrend = true,
  isLoading = false,
  error = null,
  onRetry,
}: SpeedScoreBadgeProps) {
  const baseClass = cn(
    'inline-flex items-center gap-1 rounded-full border font-semibold leading-none',
    badgeSizeClasses[size]
  );

  if (isLoading) {
    return (
      <span
        className={cn(baseClass, 'bg-muted/40 text-muted-foreground animate-pulse')}
        aria-busy="true"
        data-testid="speedscore-badge"
      >
        <span className="inline-block h-3 w-6 rounded bg-muted" />
      </span>
    );
  }

  if (error) {
    return (
      <button
        type="button"
        onClick={onRetry}
        className={cn(baseClass, 'bg-error/10 text-error border-error/30')}
        aria-label="SpeedScore failed to load. Click to retry."
        data-testid="speedscore-badge"
      >
        <AlertCircle className="h-3.5 w-3.5" aria-hidden="true" />
        <span>Error</span>
      </button>
    );
  }

  const numericScore = typeof score === 'number' && Number.isFinite(score) ? score : null;

  if (numericScore === null) {
    return (
      <span
        className={cn(baseClass, 'bg-muted/50 text-muted-foreground border-border')}
        aria-label="Not benchmarked"
        data-testid="speedscore-badge"
      >
        N/A
      </span>
    );
  }

  const clamped = clampScore(numericScore);
  const level = getScoreLevel(clamped);
  const levelConfig = scoreLevelConfig[level];
  const trend =
    showTrend && typeof previousScore === 'number' && Number.isFinite(previousScore)
      ? calculateTrend(clamped, previousScore)
      : null;

  return (
    <span
      className={cn(baseClass, levelConfig.className)}
      role="status"
      aria-label={`SpeedScore: ${Math.round(clamped)} out of 100, ${levelConfig.label}`}
      title={`SpeedScore ${Math.round(clamped)} (${levelConfig.label})`}
      data-testid="speedscore-badge"
    >
      <span className="tabular-nums">{Math.round(clamped)}</span>
      {trend ? <TrendIndicator trend={trend} /> : null}
    </span>
  );
}

export function WorkerCard({ worker }: WorkerCardProps) {
  const status = statusConfig[worker.status];
  const circuit = circuitConfig[worker.circuit_state];
  const slotsUsedPercent = (worker.used_slots / worker.total_slots) * 100;
  const StatusIcon = status.icon;
  const speedScore = Number.isFinite(worker.speed_score) ? worker.speed_score : null;
  const previousScore = typeof worker.speed_score_prev === 'number' ? worker.speed_score_prev : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
      data-testid="worker-card"
      data-worker-id={worker.id}
    >
      <div className="flex items-start justify-between mb-3 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-surface-elevated flex items-center justify-center">
            <Server className="w-5 h-5 text-muted-foreground" />
          </div>
          <div>
            <h3 className="font-medium text-foreground">{worker.id}</h3>
            <p className="text-sm text-muted-foreground">{worker.user}@{worker.host}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <SpeedScoreBadge score={speedScore} previousScore={previousScore} size="sm" />
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

      {/* Slots Progress */}
      <div className="mb-3" data-testid="worker-slots">
        <div className="flex justify-between text-xs text-muted-foreground mb-1">
          <span>Slots Used</span>
          <span>{worker.used_slots} / {worker.total_slots}</span>
        </div>
        <div
          className="h-2 bg-surface-elevated rounded-full overflow-hidden"
          role="progressbar"
          aria-label="Slots used"
          aria-valuemin={0}
          aria-valuemax={worker.total_slots}
          aria-valuenow={worker.used_slots}
          aria-valuetext={`${worker.used_slots} of ${worker.total_slots} slots used`}
        >
          <motion.div
            className="h-full bg-primary rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${slotsUsedPercent}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            data-testid="worker-slots-bar"
          />
        </div>
      </div>

      {/* Stats Row */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-1">
          <Zap className="w-3.5 h-3.5" />
          <span>Speed: {worker.speed_score.toFixed(1)}</span>
        </div>
        <div
          className={`flex items-center gap-1 ${circuit.color}`}
          data-testid="worker-circuit"
          data-circuit={worker.circuit_state}
        >
          <span>Circuit: {circuit.label}</span>
        </div>
      </div>

      {/* Error Message */}
      {worker.last_error && (
        <div className="mt-3 p-2 bg-error/10 rounded text-xs text-error" data-testid="worker-error">
          {worker.last_error}
        </div>
      )}
    </motion.div>
  );
}
