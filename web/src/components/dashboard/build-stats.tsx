'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart3, CheckCircle, XCircle, Clock } from 'lucide-react';
import type { BuildStats } from '@/lib/types';

interface BuildStatsProps {
  stats: BuildStats;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m`;
}

export function BuildStatsCard({ stats }: BuildStatsProps) {
  const successRate = stats.total_builds > 0
    ? Math.round((stats.successful_builds / stats.total_builds) * 100)
    : 0;

  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <BarChart3 className="w-4 h-4" />
          Build Statistics
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="text-sm text-muted-foreground">Total Builds</div>
            <div className="text-2xl font-bold">{stats.total_builds}</div>
          </div>
          <div>
            <div className="text-sm text-muted-foreground">Success Rate</div>
            <div className="text-2xl font-bold text-healthy">{successRate}%</div>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-healthy" />
            <div>
              <div className="text-sm text-muted-foreground">Successful</div>
              <div className="font-mono">{stats.successful_builds}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-error" />
            <div>
              <div className="text-sm text-muted-foreground">Failed</div>
              <div className="font-mono">{stats.failed_builds}</div>
            </div>
          </div>
        </div>
        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Avg Duration:</span>
            <span className="font-mono text-sm">{formatDuration(stats.avg_duration_ms)}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
