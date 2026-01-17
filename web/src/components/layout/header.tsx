'use client';

import { RefreshCw, Circle } from 'lucide-react';
import { motion } from 'motion/react';
import type { DaemonStatusInfo } from '@/lib/types';

interface HeaderProps {
  daemon: DaemonStatusInfo;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function Header({ daemon, onRefresh, isRefreshing }: HeaderProps) {
  return (
    <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Circle className="w-3 h-3 fill-current text-healthy" />
          <span className="text-sm text-muted-foreground">
            Daemon Connected
          </span>
        </div>
        <span className="text-xs text-muted-foreground">
          v{daemon.version} • Uptime: {formatUptime(daemon.uptime_secs)}
        </span>
      </div>

      <div className="flex items-center gap-4">
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg hover:bg-surface-elevated transition-colors disabled:opacity-50"
          title="Refresh data"
        >
          <motion.div
            animate={isRefreshing ? { rotate: 360 } : { rotate: 0 }}
            transition={isRefreshing ? { duration: 1, repeat: Infinity, ease: 'linear' } : {}}
          >
            <RefreshCw className="w-5 h-5 text-muted-foreground" />
          </motion.div>
        </button>
      </div>
    </header>
  );
}
