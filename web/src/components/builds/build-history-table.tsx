'use client';

import { CheckCircle, XCircle, Clock } from 'lucide-react';
import { motion } from 'motion/react';
import type { BuildRecord, ActiveBuild } from '@/lib/types';

interface BuildHistoryTableProps {
  activeBuilds: ActiveBuild[];
  recentBuilds: BuildRecord[];
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

function formatTime(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function truncateCommand(cmd: string, maxLen = 40): string {
  if (cmd.length <= maxLen) return cmd;
  return cmd.slice(0, maxLen - 3) + '...';
}

export function BuildHistoryTable({ activeBuilds, recentBuilds }: BuildHistoryTableProps) {
  const hasBuilds = activeBuilds.length > 0 || recentBuilds.length > 0;

  if (!hasBuilds) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p>No builds yet</p>
        <p className="text-sm mt-1">Run a build command to see history</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground">
            <th className="pb-3 font-medium">Status</th>
            <th className="pb-3 font-medium">Project</th>
            <th className="pb-3 font-medium">Worker</th>
            <th className="pb-3 font-medium">Command</th>
            <th className="pb-3 font-medium">Duration</th>
            <th className="pb-3 font-medium">Time</th>
          </tr>
        </thead>
        <tbody>
          {/* Active builds first */}
          {activeBuilds.map((build) => (
            <motion.tr
              key={`active-${build.id}`}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="border-b border-border/50"
            >
              <td className="py-3">
                <span className="flex items-center gap-1.5 text-warning">
                  <Clock className="w-4 h-4 animate-pulse" />
                  Running
                </span>
              </td>
              <td className="py-3 font-mono text-xs">{build.project_id}</td>
              <td className="py-3">{build.worker_id}</td>
              <td className="py-3 font-mono text-xs text-muted-foreground" title={build.command}>
                {truncateCommand(build.command)}
              </td>
              <td className="py-3 text-muted-foreground">-</td>
              <td className="py-3 text-muted-foreground">{formatTime(build.started_at)}</td>
            </motion.tr>
          ))}

          {/* Completed builds */}
          {recentBuilds.map((build) => (
            <motion.tr
              key={`completed-${build.id}`}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="border-b border-border/50"
            >
              <td className="py-3">
                {build.exit_code === 0 ? (
                  <span className="flex items-center gap-1.5 text-healthy">
                    <CheckCircle className="w-4 h-4" />
                    Success
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-error">
                    <XCircle className="w-4 h-4" />
                    Failed ({build.exit_code})
                  </span>
                )}
              </td>
              <td className="py-3 font-mono text-xs">{build.project_id}</td>
              <td className="py-3">{build.worker_id}</td>
              <td className="py-3 font-mono text-xs text-muted-foreground" title={build.command}>
                {truncateCommand(build.command)}
              </td>
              <td className="py-3 font-mono text-xs">{formatDuration(build.duration_ms)}</td>
              <td className="py-3 text-muted-foreground">{formatTime(build.completed_at)}</td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
