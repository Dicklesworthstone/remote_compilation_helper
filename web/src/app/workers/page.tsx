'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';
import { Server, RefreshCw } from 'lucide-react';
import { motion } from 'motion/react';
import { toast } from 'sonner';
import { api } from '@/lib/api';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import { BenchmarkHistoryChart } from '@/components/charts';
import { WorkerComparisonView } from '@/components/compare';
import { BenchmarkTriggerButton, SpeedScoreDetailPanel, WorkersGrid, WorkersGridSkeleton } from '@/components/workers';
import { useSpeedScoreHistoryPage } from '@/lib/hooks/use-speedscore-history';
import type { SpeedScoreListResponse, StatusResponse } from '@/lib/types';

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
  const detailsRef = useRef<HTMLDivElement | null>(null);
  const { data, error, isLoading, mutate, isValidating } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000,
      revalidateOnFocus: true,
    }
  );
  const { data: speedScores, error: speedScoresError, isLoading: speedScoresLoading, mutate: mutateSpeedScores } = useSWR<SpeedScoreListResponse>(
    data ? 'speedscores' : null,
    () => api.getSpeedScores(),
    {
      refreshInterval: 15000,
    }
  );
  const workers = useMemo(() => data?.workers ?? [], [data?.workers]);
  const [selectedWorkerId, setSelectedWorkerId] = useState<string | null>(null);
  const selectedWorker = useMemo(
    () => workers.find((worker) => worker.id === selectedWorkerId) ?? null,
    [workers, selectedWorkerId]
  );
  const speedScoresMap = useMemo(() => {
    if (!speedScores?.workers) {
      return new Map<string, NonNullable<SpeedScoreListResponse['workers'][number]['speedscore']>>();
    }
    return new Map(
      speedScores.workers
        .filter((entry) => entry.speedscore)
        .map((entry) => [entry.worker_id, entry.speedscore!])
    );
  }, [speedScores]);
  const historyQuery = useSpeedScoreHistoryPage(selectedWorkerId, {
    limit: 200,
    enabled: Boolean(selectedWorkerId),
    refetchInterval: 15000,
  });

  useEffect(() => {
    if (hadErrorRef.current && !error) {
      toast.success('Connection restored');
    }
    hadErrorRef.current = Boolean(error);
  }, [error]);

  useEffect(() => {
    if (workers.length === 0) {
      if (selectedWorkerId !== null) {
        setSelectedWorkerId(null);
      }
      return;
    }
    if (!selectedWorkerId || !workers.some((worker) => worker.id === selectedWorkerId)) {
      setSelectedWorkerId(workers[0].id);
    }
  }, [workers, selectedWorkerId]);

  const handleRetry = async () => {
    setIsRetrying(true);
    toast('Retrying connection...');
    try {
      await mutate();
    } catch {
      toast.error('Retry failed');
    } finally {
      setIsRetrying(false);
    }
  };

  const handleRefresh = async () => {
    try {
      await mutate();
      toast.success('Workers refreshed');
    } catch {
      toast.error('Failed to refresh workers');
    }
  };

  const handleBenchmarkCompleted = async () => {
    await Promise.allSettled([
      mutate(),
      mutateSpeedScores(),
      historyQuery.refetch(),
    ]);
  };

  const handleSelectWorker = (workerId: string) => {
    setSelectedWorkerId(workerId);
    requestAnimationFrame(() => {
      detailsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
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

  const healthyCount = workers.filter(w => w.status === 'healthy').length;
  const totalSlots = workers.reduce((sum, w) => sum + w.total_slots, 0);
  const usedSlots = workers.reduce((sum, w) => sum + w.used_slots, 0);
  const selectedSpeedScore = selectedWorkerId ? speedScoresMap.get(selectedWorkerId) ?? null : null;
  const canBenchmark = selectedWorker?.status === 'healthy' || selectedWorker?.status === 'degraded';

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
        <WorkersGrid workers={workers} speedScores={speedScoresMap} />
      )}

      {workers.length > 0 && (
        <>
          <section ref={detailsRef} className="space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-foreground">SpeedScore Details</h2>
                <p className="text-sm text-muted-foreground">
                  Component breakdown and benchmark history for a selected worker.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <label className="text-xs text-muted-foreground" htmlFor="speedscore-worker-select">
                  Worker
                </label>
                <select
                  id="speedscore-worker-select"
                  value={selectedWorkerId ?? ''}
                  onChange={(event) => setSelectedWorkerId(event.target.value)}
                  className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
                >
                  {selectedWorkerId === null && (
                    <option value="" disabled>
                      Select worker
                    </option>
                  )}
                  {workers.map((worker) => (
                    <option key={worker.id} value={worker.id}>
                      {worker.id}
                    </option>
                  ))}
                </select>
                {selectedWorker && (
                  <BenchmarkTriggerButton
                    workerId={selectedWorker.id}
                    disabled={!canBenchmark}
                    onCompleted={handleBenchmarkCompleted}
                  />
                )}
              </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <SpeedScoreDetailPanel
                workerId={selectedWorkerId ?? 'unknown'}
                speedscore={selectedSpeedScore}
                isLoading={speedScoresLoading}
                error={speedScoresError instanceof Error ? speedScoresError : null}
                onRetry={() => mutateSpeedScores()}
              />
              {historyQuery.isError ? (
                <div className="bg-card border border-border rounded-lg p-4 text-sm text-error">
                  Failed to load SpeedScore history.{' '}
                  <button
                    type="button"
                    onClick={() => historyQuery.refetch()}
                    className="text-primary underline"
                  >
                    Retry
                  </button>
                </div>
              ) : (
                <BenchmarkHistoryChart
                  workerId={selectedWorkerId ?? 'unknown'}
                  history={historyQuery.data?.history ?? []}
                  isLoading={historyQuery.isLoading}
                />
              )}
            </div>
          </section>

          <section className="space-y-4">
            <WorkerComparisonView
              workers={workers}
              speedScores={speedScoresMap}
              onViewDetails={handleSelectWorker}
            />
          </section>
        </>
      )}
    </div>
  );
}
