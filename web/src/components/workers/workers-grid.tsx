'use client';

import { useMemo, useState } from 'react';
import { AnimatePresence } from 'motion/react';
import type { SpeedScoreView, WorkerStatusInfo } from '@/lib/types';
import { WorkerCard } from './worker-card';

interface WorkersGridProps {
  workers: WorkerStatusInfo[];
  speedScores?: Map<string, SpeedScoreView>;
}

type WorkerSort = 'status' | 'slots' | 'speed';

const statusOrder: Record<WorkerStatusInfo['status'], number> = {
  healthy: 0,
  degraded: 1,
  draining: 2,
  unreachable: 3,
  disabled: 4,
};

export function WorkersGrid({ workers, speedScores }: WorkersGridProps) {
  const [sortBy, setSortBy] = useState<WorkerSort>('status');

  const sortedWorkers = useMemo(() => {
    const list = [...workers];
    list.sort((a, b) => {
      switch (sortBy) {
        case 'slots': {
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
        <span>{workers.length} worker{workers.length === 1 ? '' : 's'}</span>
        <label className="flex items-center gap-2">
          <span>Sort by</span>
          <select
            value={sortBy}
            onChange={(event) => setSortBy(event.target.value as WorkerSort)}
            className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            <option value="status">Status</option>
            <option value="slots">Slots available</option>
            <option value="speed">Speed score</option>
          </select>
        </label>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <AnimatePresence mode="popLayout">
          {sortedWorkers.map((worker) => (
            <WorkerCard
              key={worker.id}
              worker={worker}
              speedScoreView={speedScores?.get(worker.id) ?? null}
            />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
