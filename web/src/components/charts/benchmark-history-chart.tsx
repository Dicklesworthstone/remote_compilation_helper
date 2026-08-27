'use client';

import { useMemo, useState, useCallback } from 'react';
import { format } from 'date-fns';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Brush,
  CartesianGrid,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { TrendingUp, Eye, EyeOff } from 'lucide-react';
import {
  transformToChartData,
  filterByDateRange,
  downsampleData,
  getDateRangeFromPreset,
  DATE_RANGE_PRESETS,
  SCORE_COMPONENTS,
  TOTAL_LINE_COLOR,
  type DateRangePreset,
} from '@/lib/chart-utils';
import type { SpeedScoreView } from '@/lib/types';

interface BenchmarkHistoryChartProps {
  /** Worker ID for display */
  workerId: string;
  /** SpeedScore history data */
  history: SpeedScoreView[];
  /** Show component score lines */
  showComponents?: boolean;
  /** Enable component toggle controls */
  allowComponentToggle?: boolean;
  /** Maximum data points before downsampling */
  maxDataPoints?: number;
  /** Chart height in pixels */
  height?: number;
  /** Initial date range preset */
  initialPreset?: DateRangePreset;
  /** Callback when date range changes */
  onDateRangeChange?: (range: [Date | null, Date | null]) => void;
  /** Show loading skeleton */
  isLoading?: boolean;
}

interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{
    name: string;
    value: number;
    color: string;
    dataKey: string;
  }>;
  label?: number;
}

function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload || !label) return null;

  let formattedDate = '';
  try {
    const date = new Date(label);
    if (!isNaN(date.getTime())) {
      formattedDate = format(date, 'PPpp');
    }
  } catch {
    formattedDate = String(label);
  }

  return (
    <div className="bg-popover border border-border rounded-lg shadow-lg p-3 text-sm">
      <p className="font-medium text-foreground mb-2">{formattedDate}</p>
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

function DateRangeSelector({
  activePreset,
  onPresetChange,
}: {
  activePreset: DateRangePreset;
  onPresetChange: (preset: DateRangePreset) => void;
}) {
  return (
    <div className="flex gap-1" role="group" aria-label="Date range presets">
      {DATE_RANGE_PRESETS.map((preset) => (
        <Button
          key={preset.label}
          variant={activePreset.label === preset.label ? 'default' : 'ghost'}
          size="sm"
          onClick={() => onPresetChange(preset)}
          className="px-2 py-1 text-xs h-7"
        >
          {preset.label}
        </Button>
      ))}
    </div>
  );
}

function ComponentToggle({
  showComponents,
  onToggle,
}: {
  showComponents: boolean;
  onToggle: () => void;
}) {
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onToggle}
      className="gap-1.5 text-xs h-7"
      title={showComponents ? 'Hide component breakdown' : 'Show component breakdown'}
    >
      {showComponents ? (
        <>
          <EyeOff className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Hide Components</span>
        </>
      ) : (
        <>
          <Eye className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Show Components</span>
        </>
      )}
    </Button>
  );
}

function ChartSkeleton({ height }: { height: number }) {
  return (
    <div
      className="animate-pulse bg-muted/50 rounded-lg"
      style={{ height }}
      role="img"
      aria-label="Loading chart..."
    />
  );
}

export function BenchmarkHistoryChart({
  workerId,
  history,
  showComponents: initialShowComponents = false,
  allowComponentToggle = true,
  maxDataPoints = 500,
  height = 400,
  initialPreset = DATE_RANGE_PRESETS[2], // 30d default
  onDateRangeChange,
  isLoading = false,
}: BenchmarkHistoryChartProps) {
  const [showComponents, setShowComponents] = useState(initialShowComponents);
  const [activePreset, setActivePreset] = useState(initialPreset);
  const [dateRange, setDateRange] = useState<[Date | null, Date | null]>(() =>
    getDateRangeFromPreset(initialPreset)
  );

  const handlePresetChange = useCallback(
    (preset: DateRangePreset) => {
      setActivePreset(preset);
      const newRange = getDateRangeFromPreset(preset);
      setDateRange(newRange);
      onDateRangeChange?.(newRange);
    },
    [onDateRangeChange]
  );

  const handleToggleComponents = useCallback(() => {
    setShowComponents((prev) => !prev);
  }, []);

  const chartData = useMemo(() => {
    if (!history || history.length === 0) return [];

    const transformed = transformToChartData(history);
    const filtered = filterByDateRange(transformed, dateRange[0], dateRange[1]);
    return downsampleData(filtered, maxDataPoints);
  }, [history, dateRange, maxDataPoints]);

  const formatXAxis = useCallback((timestamp: number) => {
    try {
      const date = new Date(timestamp);
      if (isNaN(date.getTime())) return '';
      // Shorter format for small screens
      return format(date, 'MMM d');
    } catch {
      return '';
    }
  }, []);

  if (isLoading) {
    return (
      <Card className="bg-surface border-border">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-4">
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              SpeedScore History
            </CardTitle>
            <div className="flex items-center gap-2">
              <div className="h-7 w-40 bg-muted/50 rounded animate-pulse" />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ChartSkeleton height={height} />
        </CardContent>
      </Card>
    );
  }

  if (chartData.length === 0) {
    return (
      <Card className="bg-surface border-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="w-4 h-4" />
            SpeedScore History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div
            className="flex items-center justify-center text-muted-foreground"
            style={{ height }}
          >
            <p>No benchmark history available for {workerId}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-surface border-border">
      <CardHeader className="pb-2">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="w-4 h-4" />
            SpeedScore History
            <span className="text-xs font-normal text-muted-foreground">
              ({chartData.length} data points)
            </span>
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            <DateRangeSelector
              activePreset={activePreset}
              onPresetChange={handlePresetChange}
            />
            {allowComponentToggle && (
              <ComponentToggle
                showComponents={showComponents}
                onToggle={handleToggleComponents}
              />
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="w-full" style={{ height }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={chartData}
              margin={{ top: 5, right: 30, left: 0, bottom: 5 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
                opacity={0.5}
              />
              <XAxis
                dataKey="timestamp"
                tickFormatter={formatXAxis}
                stroke="hsl(var(--muted-foreground))"
                fontSize={12}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                domain={[0, 100]}
                stroke="hsl(var(--muted-foreground))"
                fontSize={12}
                tickLine={false}
                axisLine={false}
                tickFormatter={(value) => `${value}`}
              />
              <Tooltip content={<ChartTooltip />} />
              <Legend
                wrapperStyle={{ paddingTop: '20px' }}
                formatter={(value) => (
                  <span className="text-xs text-muted-foreground">{value}</span>
                )}
              />

              <Line
                type="monotone"
                dataKey="total"
                stroke={TOTAL_LINE_COLOR}
                strokeWidth={2}
                dot={chartData.length <= 50 ? { r: 3 } : false}
                activeDot={{ r: 5 }}
                name="Total SpeedScore"
              />

              {showComponents &&
                SCORE_COMPONENTS.map((component) => (
                  <Line
                    key={component.key}
                    type="monotone"
                    dataKey={component.key}
                    stroke={component.color}
                    strokeWidth={1.5}
                    dot={false}
                    activeDot={{ r: 4 }}
                    name={component.label}
                    strokeOpacity={0.8}
                  />
                ))}

              {chartData.length > 20 && (
                <Brush
                  dataKey="timestamp"
                  height={30}
                  stroke="hsl(var(--primary))"
                  tickFormatter={formatXAxis}
                  fill="hsl(var(--muted))"
                />
              )}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

export type { BenchmarkHistoryChartProps };
