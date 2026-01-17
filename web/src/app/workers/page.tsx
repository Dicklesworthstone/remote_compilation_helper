'use client';

import useSWR from 'swr';
import { Server, AlertTriangle, RefreshCw } from 'lucide-react';
import { motion } from 'motion/react';
import { api } from '@/lib/api';
import { WorkersGrid } from '@/components/workers';
import type { StatusResponse } from '@/lib/types';

export default function WorkersPage() {
  const { data, error, isLoading, mutate, isValidating } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000,
      revalidateOnFocus: true,
    }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-muted-foreground">Loading workers...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-error" />
        <div className="text-error font-medium">Failed to connect to daemon</div>
        <div className="text-sm text-muted-foreground">
          Make sure rchd is running
        </div>
      </div>
    );
  }

  const { workers } = data;
  const healthyCount = workers.filter(w => w.status === 'healthy').length;
  const totalSlots = workers.reduce((sum, w) => sum + w.total_slots, 0);
  const usedSlots = workers.reduce((sum, w) => sum + w.used_slots, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Server className="w-6 h-6" />
            Workers
          </h1>
          <p className="text-muted-foreground text-sm">
            {healthyCount}/{workers.length} healthy &middot; {totalSlots - usedSlots}/{totalSlots} slots available
          </p>
        </div>
        <button
          onClick={() => mutate()}
          disabled={isValidating}
          className="p-2 rounded-lg hover:bg-surface-elevated transition-colors disabled:opacity-50"
          title="Refresh"
        >
          <motion.div
            animate={isValidating ? { rotate: 360 } : { rotate: 0 }}
            transition={isValidating ? { duration: 1, repeat: Infinity, ease: 'linear' } : {}}
          >
            <RefreshCw className="w-5 h-5 text-muted-foreground" />
          </motion.div>
        </button>
      </div>

      {workers.length === 0 ? (
        <div className="text-center py-12">
          <Server className="h-12 w-12 text-muted mx-auto mb-4" />
          <h3 className="font-medium mb-2">No workers configured</h3>
          <p className="text-muted-foreground text-sm">
            Add workers to your config to get started.
          </p>
        </div>
      ) : (
        <WorkersGrid workers={workers} />
      )}
    </div>
  );
}
