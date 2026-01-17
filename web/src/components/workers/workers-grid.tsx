'use client';

import { AnimatePresence } from 'motion/react';
import type { WorkerStatusInfo } from '@/lib/types';
import { WorkerCard } from './worker-card';

interface WorkersGridProps {
  workers: WorkerStatusInfo[];
}

export function WorkersGrid({ workers }: WorkersGridProps) {
  if (workers.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p>No workers configured</p>
        <p className="text-sm mt-1">Add workers with: rch add user@host</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <AnimatePresence mode="popLayout">
        {workers.map((worker) => (
          <WorkerCard key={worker.id} worker={worker} />
        ))}
      </AnimatePresence>
    </div>
  );
}
