'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Activity, Clock, Server, Layers } from 'lucide-react';
import type { DaemonStatusInfo } from '@/lib/types';

interface DaemonStatusProps {
  daemon: DaemonStatusInfo;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function DaemonStatus({ daemon }: DaemonStatusProps) {
  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="w-4 h-4 text-healthy" />
          Daemon Status
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="text-sm text-muted-foreground">Version</div>
            <div className="font-mono text-sm">{daemon.version}</div>
          </div>
          <div>
            <div className="text-sm text-muted-foreground">Uptime</div>
            <div className="font-mono text-sm flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatUptime(daemon.uptime_secs)}
            </div>
          </div>
          <div>
            <div className="text-sm text-muted-foreground">Workers</div>
            <div className="font-mono text-sm flex items-center gap-1">
              <Server className="w-3 h-3" />
              {daemon.workers_healthy}/{daemon.workers_total}
            </div>
          </div>
          <div>
            <div className="text-sm text-muted-foreground">Slots</div>
            <div className="font-mono text-sm flex items-center gap-1">
              <Layers className="w-3 h-3" />
              {daemon.slots_available}/{daemon.slots_total}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
