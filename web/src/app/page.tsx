'use client';

import useSWR from 'swr';
import { Server, Hammer, Clock, AlertTriangle } from 'lucide-react';
import { api } from '@/lib/api';
import { Header } from '@/components/layout';
import { WorkersGrid } from '@/components/workers';
import { BuildHistoryTable } from '@/components/builds';
import { StatCard } from '@/components/stats';
import type { StatusResponse } from '@/lib/types';

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

export default function DashboardPage() {
  const { data, error, isLoading } = useSWR<StatusResponse>(
    'status',
    () => api.getStatus(),
    {
      refreshInterval: 2000, // Poll every 2 seconds
      revalidateOnFocus: true,
    }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-muted-foreground">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-error" />
        <div className="text-error font-medium">Failed to connect to daemon</div>
        <div className="text-sm text-muted-foreground">
          Make sure rchd is running: rchd start
        </div>
      </div>
    );
  }

  const status = data!;
  const successRate = status.stats.total_builds > 0
    ? Math.round((status.stats.successful_builds / status.stats.total_builds) * 100)
    : 100;

  return (
    <div className="flex flex-col h-full">
      <Header daemon={status.daemon} />

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
