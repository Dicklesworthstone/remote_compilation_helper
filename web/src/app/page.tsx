'use client';

import { useEffect, useRef, useState } from 'react';
import useSWR from 'swr';
import { Server, Hammer, Clock, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { api } from '@/lib/api';
import { Header } from '@/components/layout';
import { BuildHistoryTable, TableSkeleton } from '@/components/builds';
import { StatCard, StatCardSkeleton } from '@/components/stats';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import { WorkersGrid, WorkersGridSkeleton } from '@/components/workers';
import type { StatusResponse } from '@/lib/types';

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function DashboardSkeleton() {
  return (
    <div className="flex flex-col h-full" data-testid="dashboard-skeleton">
      <div className="h-14 bg-surface border-b border-border flex items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-3 w-28" />
          <Skeleton className="h-3 w-40" />
        </div>
        <Skeleton className="h-8 w-8 rounded-lg" />
      </div>

      <div className="flex-1 overflow-auto p-6 space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <StatCardSkeleton key={`stat-skeleton-${index}`} />
          ))}
        </div>

        <section>
          <div className="flex items-center justify-between mb-4">
            <Skeleton className="h-5 w-24" />
            <Skeleton className="h-4 w-16" />
          </div>
          <WorkersGridSkeleton />
        </section>

        <section>
          <div className="flex items-center justify-between mb-4">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-4 w-20" />
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <TableSkeleton
              rows={4}
              columns={6}
              className="border-0 rounded-none bg-transparent"
              testId="build-history-skeleton"
            />
          </div>
        </section>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [isRetrying, setIsRetrying] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const hadErrorRef = useRef(false);
  const { data, error, isLoading, mutate } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000, // Poll every 2 seconds
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
    setIsRefreshing(true);
    try {
      await mutate();
      toast.success('Dashboard refreshed');
    } catch {
      toast.error('Failed to refresh dashboard');
    } finally {
      setIsRefreshing(false);
    }
  };

  if (isLoading) {
    return <DashboardSkeleton />;
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <ErrorState
          error={error}
          title="Failed to connect to daemon"
          hint={errorHints.daemonConnection}
          onRetry={handleRetry}
          isRetrying={isRetrying}
        />
      </div>
    );
  }

  const status = data!;
  const successRate = status.stats.total_builds > 0
    ? Math.round((status.stats.success_count / status.stats.total_builds) * 100)
    : 100;

  return (
    <div className="flex flex-col h-full">
      <Header
        daemon={status.daemon}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
      />

      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Workers"
            value={`${status.daemon.workers_healthy}/${status.daemon.workers_total}`}
            icon={Server}
          />
          <StatCard
            label="Available Slots"
            value={`${status.daemon.slots_available}/${status.daemon.slots_total}`}
            icon={Hammer}
          />
          <StatCard
            label="Total Builds"
            value={status.stats.total_builds}
            icon={Clock}
          />
          <StatCard
            label="Success Rate"
            value={`${successRate}%`}
            icon={AlertTriangle}
          />
        </div>

        {/* Issues Alert */}
        {status.issues.length > 0 && (
          <div className="bg-warning/10 border border-warning/30 rounded-lg p-4">
            <h3 className="font-medium text-warning mb-2">Active Issues</h3>
            <ul className="space-y-2">
              {status.issues.map((issue, idx) => (
                <li key={idx} className="text-sm">
                  <span className={`font-medium ${
                    issue.severity === 'error' ? 'text-error' :
                    issue.severity === 'warning' ? 'text-warning' :
                    'text-muted-foreground'
                  }`}>
                    [{issue.severity}]
                  </span>{' '}
                  <span className="text-foreground">{issue.summary}</span>
                  {issue.remediation && (
                    <span className="text-muted-foreground ml-2">— {issue.remediation}</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Workers Section */}
        <section>
          <h2 className="text-lg font-semibold text-foreground mb-4">Workers</h2>
          <WorkersGrid workers={status.workers} />
        </section>

        {/* Build History Section */}
        <section>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-foreground">Build History</h2>
            {status.stats.total_builds > 0 && (
              <span className="text-sm text-muted-foreground">
                Avg: {formatDuration(status.stats.avg_duration_ms)}
              </span>
            )}
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <BuildHistoryTable
              activeBuilds={status.active_builds}
              recentBuilds={status.recent_builds}
            />
          </div>
        </section>
      </div>
    </div>
  );
}
