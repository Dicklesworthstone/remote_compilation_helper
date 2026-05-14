'use client';

import { useMemo } from 'react';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Legend,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Activity } from 'lucide-react';
import type { WorkerStatusInfo, SpeedScoreView } from '@/lib/types';

interface ComparisonRadarProps {
  /** Workers to compare */
  workers: WorkerStatusInfo[];
  /** Optional SpeedScore views for detailed component scores */
  speedScores?: Map<string, SpeedScoreView>;
  /** Chart height in pixels */
  height?: number;
}

// Colors for up to 4 workers
const RADAR_COLORS = [
  { stroke: '#3b82f6', fill: '#3b82f6' }, // Blue
  { stroke: '#22c55e', fill: '#22c55e' }, // Green
  { stroke: '#f97316', fill: '#f97316' }, // Orange
  { stroke: '#8b5cf6', fill: '#8b5cf6' }, // Purple
];

interface RadarDataPoint {
  metric: string;
  fullMark: number;
  [workerId: string]: string | number;
}

interface TooltipPayloadItem {
  name: string;
  value: number;
  color: string;
  dataKey: string;
}

function RadarTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  label?: string;
}) {
  if (!active || !payload) return null;

  return (
    <div className="bg-popover border border-border rounded-lg shadow-lg p-3 text-sm">
      <p className="font-medium text-foreground mb-2">{label}</p>
      <div className="space-y-1">
        {payload.map((entry) => (
          <p key={entry.dataKey} className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-muted-foreground">{entry.name}:</span>
            <span className="font-mono font-medium" style={{ color: entry.color }}>
              {entry.value.toFixed(1)}
            </span>
          </p>
        ))}
      </div>
    </div>
  );
}

export function ComparisonRadar({
  workers,
  speedScores,
  height = 350,
}: ComparisonRadarProps) {
  const radarData = useMemo((): RadarDataPoint[] => {
    if (workers.length === 0) return [];

    // Define metrics - if we have SpeedScoreView data, use component scores
    // Otherwise, we'll just show total speed_score across all dimensions
    const metrics = ['CPU', 'Memory', 'Disk', 'Network', 'Compilation'];

    return metrics.map((metric) => {
      const dataPoint: RadarDataPoint = {
        metric,
        fullMark: 100,
      };

      workers.forEach((worker) => {
        const scoreView = speedScores?.get(worker.id);
        if (scoreView) {
          // Use actual component scores if available
          switch (metric) {
            case 'CPU':
              dataPoint[worker.id] = scoreView.cpu_score;
              break;
            case 'Memory':
              dataPoint[worker.id] = scoreView.memory_score;
              break;
            case 'Disk':
              dataPoint[worker.id] = scoreView.disk_score;
              break;
            case 'Network':
              dataPoint[worker.id] = scoreView.network_score;
              break;
            case 'Compilation':
              dataPoint[worker.id] = scoreView.compilation_score;
              break;
          }
        } else {
          // Fallback: use total speed_score for all metrics
          // This creates a uniform pentagon based on overall score
          dataPoint[worker.id] = worker.speed_score;
        }
      });

      return dataPoint;
    });
  }, [workers, speedScores]);

  if (workers.length === 0) {
    return (
      <Card className="bg-surface border-border">
        <CardContent className="py-12 text-center">
          <Activity className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
          <p className="text-muted-foreground">Select workers to see radar comparison</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="w-4 h-4" />
          Performance Profile
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div style={{ height }} className="w-full">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="80%">
              <PolarGrid stroke="hsl(var(--border))" />
              <PolarAngleAxis
                dataKey="metric"
                tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 100]}
                tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                tickCount={5}
              />
              <Tooltip content={<RadarTooltip />} />
              <Legend
                wrapperStyle={{ paddingTop: '20px' }}
                formatter={(value) => (
                  <span className="text-xs text-muted-foreground">{value}</span>
                )}
              />
              {workers.map((worker, index) => (
                <Radar
                  key={worker.id}
                  name={worker.id}
                  dataKey={worker.id}
                  stroke={RADAR_COLORS[index % RADAR_COLORS.length].stroke}
                  fill={RADAR_COLORS[index % RADAR_COLORS.length].fill}
                  fillOpacity={0.25}
                  strokeWidth={2}
                />
              ))}
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

export type { ComparisonRadarProps };
