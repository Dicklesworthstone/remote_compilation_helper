'use client';

import { Server, AlertCircle, CheckCircle, Clock, Zap } from 'lucide-react';
import { motion } from 'motion/react';
import type { WorkerStatusInfo, CircuitState, WorkerStatus } from '@/lib/types';

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

export function WorkerCard({ worker }: WorkerCardProps) {
  const status = statusConfig[worker.status];
  const circuit = circuitConfig[worker.circuit_state];
  const slotsUsedPercent = (worker.used_slots / worker.total_slots) * 100;
  const StatusIcon = status.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
      data-testid="worker-card"
      data-worker-id={worker.id}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-surface-elevated flex items-center justify-center">
            <Server className="w-5 h-5 text-muted-foreground" />
          </div>
          <div>
            <h3 className="font-medium text-foreground">{worker.id}</h3>
            <p className="text-sm text-muted-foreground">{worker.user}@{worker.host}</p>
          </div>
        </div>
        <div
          className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${status.color}`}
          data-testid="worker-status"
          data-status={worker.status}
        >
          <StatusIcon className="w-3.5 h-3.5" />
          {status.label}
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
