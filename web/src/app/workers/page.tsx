'use client';

import { useEffect, useRef, useState } from 'react';
import useSWR from 'swr';
import { Server, RefreshCw } from 'lucide-react';
import { motion } from 'motion/react';
import { toast } from 'sonner';
import { api } from '@/lib/api';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import { WorkersGrid, WorkersGridSkeleton } from '@/components/workers';
import type { StatusResponse } from '@/lib/types';

function WorkersPageSkeleton() {
  return (
    <div className="space-y-6" data-testid="workers-skeleton">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Skeleton className="h-6 w-6 rounded-full" />
            <Skeleton className="h-6 w-28" />
          </div>
          <Skeleton className="h-4 w-64 mt-2" />
        </div>
        <Skeleton className="h-9 w-9 rounded-lg" />
      </div>

      <WorkersGridSkeleton />
    </div>
  );
}

export default function WorkersPage() {
  const [isRetrying, setIsRetrying] = useState(false);
  const hadErrorRef = useRef(false);
  const { data, error, isLoading, mutate, isValidating } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000,
      revalidateOnFocus: true,
    }
  );

  useEffect(() => {
    if (hadErrorRef.current && !error) {
      toast.success('Connection restored');
    }
    hadErrorRef.current = Boolean(error);
  }, [error]);

  const handleRetry = async () => {
    setIsRetrying(true);
    toast('Retrying connection...');
    try {
      await mutate();
    } catch (err) {
      toast.error('Retry failed');
    } finally {
      setIsRetrying(false);
    }
  };

  const handleRefresh = async () => {
    try {
      await mutate();
      toast.success('Workers refreshed');
    } catch (err) {
      toast.error('Failed to refresh workers');
    }
  };

  if (isLoading) {
    return <WorkersPageSkeleton />;
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-full">
        <ErrorState
          error={error || 'Failed to load workers'}
          title="Failed to connect to daemon"
          hint={errorHints.daemonConnection}
          onRetry={handleRetry}
          isRetrying={isRetrying}
        />
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
          type="button"
          onClick={handleRefresh}
          disabled={isValidating}
          className="p-2 rounded-lg hover:bg-surface-elevated transition-colors disabled:opacity-50"
          title="Refresh"
          aria-label="Refresh workers"
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
