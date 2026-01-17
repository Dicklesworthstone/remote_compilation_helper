'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Server } from 'lucide-react';
import type { WorkerStatusInfo, WorkerStatus } from '@/lib/types';

interface WorkerSummaryProps {
  workers: WorkerStatusInfo[];
}

function groupByStatus(workers: WorkerStatusInfo[]): Record<WorkerStatus, number> {
  const counts: Record<WorkerStatus, number> = {
    healthy: 0,
    degraded: 0,
    unreachable: 0,
    draining: 0,
    disabled: 0,
  };

  for (const worker of workers) {
    counts[worker.status]++;
  }

  return counts;
}

const statusColors: Record<WorkerStatus, string> = {
  healthy: 'text-healthy',
  degraded: 'text-degraded',
  unreachable: 'text-unreachable',
  draining: 'text-draining',
  disabled: 'text-muted-foreground',
};

export function WorkerSummary({ workers }: WorkerSummaryProps) {
  const counts = groupByStatus(workers);
  const totalSlots = workers.reduce((sum, w) => sum + w.total_slots, 0);
  const usedSlots = workers.reduce((sum, w) => sum + w.used_slots, 0);
  const availableSlots = totalSlots - usedSlots;

  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Server className="w-4 h-4" />
          Worker Fleet
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex justify-between items-center mb-4">
          <div className="text-3xl font-bold">{workers.length}</div>
          <div className="text-sm text-muted-foreground">Total Workers</div>
        </div>

        <div className="space-y-2">
          {Object.entries(counts).map(([status, count]) =>
            count > 0 && (
              <div key={status} className="flex justify-between text-sm">
                <span className={statusColors[status as WorkerStatus]}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </span>
                <span className="font-mono">{count}</span>
              </div>
            )
          )}
        </div>

        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Available Slots</span>
            <span className="font-mono text-healthy">{availableSlots}/{totalSlots}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
