'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { History, CheckCircle, XCircle } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import type { BuildRecord } from '@/lib/types';

interface RecentBuildsProps {
  builds: BuildRecord[];
  limit?: number;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

export function RecentBuilds({ builds, limit = 5 }: RecentBuildsProps) {
  const displayBuilds = builds.slice(0, limit);

  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <History className="w-4 h-4" />
          Recent Builds
        </CardTitle>
      </CardHeader>
      <CardContent>
        {displayBuilds.length === 0 ? (
          <div className="text-sm text-muted-foreground text-center py-4">
            No builds yet
          </div>
        ) : (
          <div className="space-y-3">
            {displayBuilds.map((build) => (
              <div
                key={build.id}
                className="flex items-center justify-between text-sm"
              >
                <div className="flex items-center gap-2 min-w-0">
                  {build.exit_code === 0 ? (
                    <CheckCircle className="w-4 h-4 text-healthy flex-shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-error flex-shrink-0" />
                  )}
                  <span className="font-mono truncate">{build.project_id}</span>
                </div>
                <div className="flex items-center gap-3 text-muted-foreground">
                  <span className="font-mono">{formatDuration(build.duration_ms)}</span>
                  <span className="text-xs">
                    {formatDistanceToNow(new Date(build.started_at), { addSuffix: true })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
