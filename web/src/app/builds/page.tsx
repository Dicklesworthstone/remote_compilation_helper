'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { History, RefreshCw, CheckCircle, XCircle, Clock } from 'lucide-react';
import { motion } from 'motion/react';
import { formatDistanceToNow } from 'date-fns';
import { api } from '@/lib/api';
import { TableSkeleton } from '@/components/builds';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import type { StatusResponse } from '@/lib/types';

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function BuildsPageSkeleton() {
  return (
    <div className="space-y-6" data-testid="builds-skeleton">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Skeleton className="h-6 w-6 rounded-full" />
            <Skeleton className="h-6 w-36" />
          </div>
          <Skeleton className="h-4 w-56 mt-2" />
        </div>
        <Skeleton className="h-9 w-9 rounded-lg" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div
            key={`build-stat-skeleton-${index}`}
            className="bg-surface border border-border rounded-lg p-4"
          >
            <Skeleton className="h-3 w-24 mb-2" />
            <Skeleton className="h-7 w-16" />
          </div>
        ))}
      </div>

      <div>
        <div className="flex items-center justify-between mb-3">
          <Skeleton className="h-5 w-28" />
        </div>
        <div className="bg-surface border border-border rounded-lg divide-y divide-border">
          {Array.from({ length: 2 }).map((_, index) => (
            <div key={`active-skeleton-${index}`} className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Skeleton className="h-2 w-2 rounded-full" />
                <div className="space-y-2">
                  <Skeleton className="h-3 w-28" />
                  <Skeleton className="h-3 w-40" />
                </div>
              </div>
              <Skeleton className="h-3 w-16" />
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-3">
          <Skeleton className="h-5 w-32" />
        </div>
        <TableSkeleton rows={6} columns={5} testId="builds-table-skeleton" />
      </div>
    </div>
  );
}

export default function BuildsPage() {
  const [isRetrying, setIsRetrying] = useState(false);
  const { data, error, isLoading, mutate, isValidating } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000,
      revalidateOnFocus: true,
    }
  );

  const handleRetry = async () => {
    setIsRetrying(true);
    try {
      await mutate();
    } finally {
      setIsRetrying(false);
    }
  };

  if (isLoading) {
    return <BuildsPageSkeleton />;
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-full">
        <ErrorState
          error={error || 'Failed to load build history'}
          title="Failed to connect to daemon"
          hint={errorHints.daemonConnection}
          onRetry={handleRetry}
          isRetrying={isRetrying}
        />
      </div>
    );
  }

  const { active_builds, recent_builds, stats } = data;
  const successRate = stats.total_builds > 0
    ? Math.round((stats.successful_builds / stats.total_builds) * 100)
    : 100;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <History className="w-6 h-6" />
            Build History
          </h1>
          <p className="text-muted-foreground text-sm">
            {stats.total_builds} total builds &middot; {successRate}% success rate
          </p>
        </div>
        <button
          type="button"
          onClick={() => mutate()}
          disabled={isValidating}
          className="p-2 rounded-lg hover:bg-surface-elevated transition-colors disabled:opacity-50"
          title="Refresh"
          aria-label="Refresh build history"
        >
          <motion.div
            animate={isValidating ? { rotate: 360 } : { rotate: 0 }}
            transition={isValidating ? { duration: 1, repeat: Infinity, ease: 'linear' } : {}}
          >
            <RefreshCw className="w-5 h-5 text-muted-foreground" />
          </motion.div>
        </button>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Total Builds</div>
          <div className="text-2xl font-bold">{stats.total_builds}</div>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="text-sm text-muted-foreground flex items-center gap-1">
            <CheckCircle className="w-3 h-3 text-healthy" /> Successful
          </div>
          <div className="text-2xl font-bold text-healthy">{stats.successful_builds}</div>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="text-sm text-muted-foreground flex items-center gap-1">
            <XCircle className="w-3 h-3 text-error" /> Failed
          </div>
          <div className="text-2xl font-bold text-error">{stats.failed_builds}</div>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="text-sm text-muted-foreground flex items-center gap-1">
            <Clock className="w-3 h-3" /> Avg Duration
          </div>
          <div className="text-2xl font-bold font-mono">{formatDuration(stats.avg_duration_ms)}</div>
        </div>
      </div>

      {/* Active Builds */}
      {active_builds.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Active Builds</h2>
          <div className="bg-surface border border-border rounded-lg divide-y divide-border">
            {active_builds.map((build) => (
              <motion.div
                key={build.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="p-4 flex items-center justify-between"
                data-testid="active-build"
                data-build-id={build.id}
              >
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-warning animate-pulse" />
                  <div>
                    <div className="font-mono text-sm">{build.project_id}</div>
                    <div className="text-xs text-muted-foreground">{build.command}</div>
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">
                  on {build.worker_id}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Builds */}
      <div>
        <h2 className="text-lg font-semibold mb-3">Recent Builds</h2>
        {recent_builds.length === 0 ? (
          <div className="bg-surface border border-border rounded-lg p-8 text-center">
            <History className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
            <p className="text-muted-foreground">No builds recorded yet</p>
          </div>
        ) : (
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <table className="w-full text-sm" data-testid="builds-table">
              <thead className="bg-surface-elevated">
                <tr>
                  <th scope="col" className="text-left p-3 font-medium text-muted-foreground">Project</th>
                  <th scope="col" className="text-left p-3 font-medium text-muted-foreground">Worker</th>
                  <th scope="col" className="text-left p-3 font-medium text-muted-foreground">Duration</th>
                  <th scope="col" className="text-left p-3 font-medium text-muted-foreground">Status</th>
                  <th scope="col" className="text-left p-3 font-medium text-muted-foreground">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {recent_builds.map((build) => (
                  <tr
                    key={build.id}
                    className="hover:bg-surface-elevated/50"
                    data-testid="build-row"
                    data-build-id={build.id}
                  >
                    <td className="p-3 font-mono">{build.project_id}</td>
                    <td className="p-3 text-muted-foreground">{build.worker_id}</td>
                    <td className="p-3 font-mono">{formatDuration(build.duration_ms)}</td>
                    <td className="p-3">
                      {build.exit_code === 0 ? (
                        <span className="inline-flex items-center gap-1 text-healthy">
                          <CheckCircle className="w-4 h-4" /> Success
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-error">
                          <XCircle className="w-4 h-4" /> Exit {build.exit_code}
                        </span>
                      )}
                    </td>
                    <td className="p-3 text-muted-foreground">
                      {formatDistanceToNow(new Date(build.started_at), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
