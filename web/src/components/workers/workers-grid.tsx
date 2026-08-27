'use client';

import { useMemo, useState } from 'react';
import type { SpeedScoreView, WorkerStatusInfo } from '@/lib/types';
import { WorkerCard } from './worker-card';

interface WorkersGridProps {
  workers: WorkerStatusInfo[];
  speedScores?: Map<string, SpeedScoreView>;
}

type WorkerSort = 'status' | 'slots-avail' | 'slots-total' | 'speed' | 'utilization';

const statusOrder: Record<WorkerStatusInfo['status'], number> = {
  healthy: 0,
  degraded: 1,
  draining: 2,
  unreachable: 3,
  disabled: 4,
};

export function WorkersGrid({ workers, speedScores }: WorkersGridProps) {
  const [sortBy, setSortBy] = useState<WorkerSort>('status');

  const totalSlots = useMemo(() => workers.reduce((acc, w) => acc + (w.total_slots || 0), 0), [workers]);
  const totalUsed = useMemo(() => workers.reduce((acc, w) => acc + (w.used_slots || 0), 0), [workers]);

  const sortedWorkers = useMemo(() => {
    const list = [...workers];
    list.sort((a, b) => {
      switch (sortBy) {
        case 'slots-total': {
          const diff = (b.total_slots || 0) - (a.total_slots || 0);
          if (diff !== 0) return diff;
          return (b.used_slots || 0) - (a.used_slots || 0);
        }
        case 'utilization': {
          const aUtil = (a.used_slots || 0) / Math.max(1, a.total_slots || 1);
          const bUtil = (b.used_slots || 0) / Math.max(1, b.total_slots || 1);
          if (aUtil !== bUtil) return bUtil - aUtil;
          return (b.used_slots || 0) - (a.used_slots || 0);
        }
        case 'slots-avail': {
          const aSlots = a.total_slots - a.used_slots;
          const bSlots = b.total_slots - b.used_slots;
          if (aSlots !== bSlots) {
            return bSlots - aSlots;
          }
          break;
        }
        case 'speed':
          if (a.speed_score !== b.speed_score) {
            return b.speed_score - a.speed_score;
          }
          break;
        case 'status':
        default:
          if (statusOrder[a.status] !== statusOrder[b.status]) {
            return statusOrder[a.status] - statusOrder[b.status];
          }
          break;
      }
      return a.id.localeCompare(b.id);
    });
    return list;
  }, [workers, sortBy]);

  if (workers.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p>No workers configured</p>
        <p className="text-sm mt-1">Add workers with: rch add user@host</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
        <div className="flex items-center gap-2">
          <span>{workers.length} worker{workers.length === 1 ? '' : 's'}</span>
          <span>·</span>
          <span className="font-mono text-foreground font-medium">
            {totalUsed}/{totalSlots} slots active
          </span>
          {totalSlots > 0 && (
            <span className="text-[11px]">({Math.round((totalUsed / totalSlots) * 100)}% fleet load)</span>
          )}
        </div>
        <label className="flex items-center gap-2">
          <span>Sort by</span>
          <select
            value={sortBy}
            onChange={(event) => setSortBy(event.target.value as WorkerSort)}
            className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            <option value="status">Status</option>
            <option value="slots-total">Capacity (slots)</option>
            <option value="utilization">Utilization</option>
            <option value="slots-avail">Slots available</option>
            <option value="speed">Speed score</option>
          </select>
        </label>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {sortedWorkers.map((worker) => (
          <div
            key={worker.id}
            className={worker.total_slots >= 16 ? 'col-span-1 md:col-span-2' : 'col-span-1'}
          >
            <WorkerCard
              worker={worker}
              speedScoreView={speedScores?.get(worker.id) ?? null}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
