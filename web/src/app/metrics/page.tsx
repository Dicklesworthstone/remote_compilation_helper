'use client';

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import {
  Activity,
  AlertCircle,
  ArrowDownUp,
  CheckCircle,
  Database,
  Gauge,
  Info,
  RefreshCw,
  Server,
  ShieldAlert,
  Timer,
  XCircle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { motion } from 'motion/react';
import { api } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import type { BudgetStatusResponse } from '@/lib/types';

type MetricSample = {
  value: number;
  labels: Record<string, string>;
};

type MetricTone = 'neutral' | 'positive' | 'warning' | 'danger';

type MetricCardProps = {
  label: string;
  value: string;
  icon: LucideIcon;
  hint: string;
  sublabel?: string;
  tone?: MetricTone;
};

const toneClasses: Record<MetricTone, string> = {
  neutral: 'border-border bg-card',
  positive: 'border-healthy/30 bg-healthy/5',
  warning: 'border-warning/30 bg-warning/5',
  danger: 'border-error/30 bg-error/5',
};

function MetricCard({ label, value, icon: Icon, hint, sublabel, tone = 'neutral' }: MetricCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-lg border p-4 shadow-sm ${toneClasses[tone]}`}
      data-testid="metric-card"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">{label}</span>
            <span title={hint}>
              <Info
                className="w-3.5 h-3.5 text-muted-foreground"
                aria-label={hint}
              />
            </span>
          </div>
          <div className="text-2xl font-semibold text-foreground">{value}</div>
        </div>
        <Icon className="w-4 h-4 text-muted-foreground" />
      </div>
      {sublabel && <p className="mt-2 text-xs text-muted-foreground">{sublabel}</p>}
    </motion.div>
  );
}

function parsePrometheusText(text: string): Record<string, MetricSample[]> {
  const metrics: Record<string, MetricSample[]> = {};
  if (!text) {
    return metrics;
  }

  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) {
      continue;
    }

    const metricPart = parts[0];
    const value = Number.parseFloat(parts[1]);
    if (Number.isNaN(value)) {
      continue;
    }

    let name = metricPart;
    const labels: Record<string, string> = {};
    const labelStart = metricPart.indexOf('{');
    if (labelStart >= 0) {
      name = metricPart.slice(0, labelStart);
      const labelBody = metricPart.slice(labelStart + 1, metricPart.lastIndexOf('}'));
      if (labelBody) {
        const labelRegex = /(\w+)="([^"]*)"/g;
        let match: RegExpExecArray | null;
        while ((match = labelRegex.exec(labelBody)) !== null) {
          labels[match[1]] = match[2];
        }
      }
    }

    if (!metrics[name]) {
      metrics[name] = [];
    }
    metrics[name].push({ value, labels });
  }

  return metrics;
}

function sumMetric(
  metrics: Record<string, MetricSample[]>,
  name: string,
  predicate?: (labels: Record<string, string>) => boolean
): number | null {
  const samples = metrics[name];
  if (!samples || samples.length === 0) {
    return null;
  }

  let total = 0;
  for (const sample of samples) {
    if (!predicate || predicate(sample.labels)) {
      total += sample.value;
    }
  }

  return total;
}

function averageHistogram(metrics: Record<string, MetricSample[]>, baseName: string): number | null {
  const sum = sumMetric(metrics, `${baseName}_sum`);
  const count = sumMetric(metrics, `${baseName}_count`);
  if (sum === null || count === null || count === 0) {
    return null;
  }
  return sum / count;
}

function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—';
  }
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(value);
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—';
  }
  return `${Math.round(value)}%`;
}

function formatDurationSeconds(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—';
  }
  if (value < 1) {
    return `${Math.round(value * 1000)}ms`;
  }
  if (value < 60) {
    return `${value.toFixed(1)}s`;
  }
  return `${(value / 60).toFixed(1)}m`;
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '—';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  const precision = size < 10 && unitIndex > 0 ? 1 : 0;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function formatBudgetName(name: string): string {
  if (!name) {
    return 'Budget';
  }
  if (name.toLowerCase() !== name) {
    return name;
  }
  return name
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

interface WorkerStatusCounts {
  total: number;
  healthy: number;
  degraded: number;
  unreachable: number;
  draining: number;
  disabled: number;
}

function getWorkerStatusCounts(metrics: Record<string, MetricSample[]>): WorkerStatusCounts {
  const samples = metrics['rch_worker_status'] ?? [];
  const workers = new Set<string>();
  const counts = {
    healthy: 0,
    degraded: 0,
    unreachable: 0,
    draining: 0,
    disabled: 0,
  };

  type StatusKey = keyof typeof counts;
  const validStatuses = new Set<string>(Object.keys(counts));

  for (const sample of samples) {
    if (sample.labels.worker) {
      workers.add(sample.labels.worker);
    }
    const status = sample.labels.status;
    if (!status) {
      continue;
    }
    if (sample.value >= 0.5 && validStatuses.has(status)) {
      counts[status as StatusKey] += 1;
    }
  }

  return { total: workers.size, ...counts };
}

function getCircuitCounts(metrics: Record<string, MetricSample[]>) {
  const samples = metrics['rch_circuit_state'] ?? [];
  let open = 0;
  let halfOpen = 0;

  for (const sample of samples) {
    if (sample.value >= 1.5) {
      open += 1;
    } else if (sample.value >= 0.5) {
      halfOpen += 1;
    }
  }

  return { open, halfOpen };
}

function MetricsPageSkeleton() {
  return (
    <div className="space-y-6" data-testid="metrics-skeleton">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Skeleton className="h-6 w-6 rounded-full" />
            <Skeleton className="h-6 w-28" />
          </div>
          <Skeleton className="h-4 w-72 mt-2" />
        </div>
        <Skeleton className="h-9 w-24 rounded-full" />
      </div>

      <div>
        <Skeleton className="h-5 w-44 mb-3" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <div
              key={`metric-skeleton-${index}`}
              className="bg-surface border border-border rounded-lg p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <Skeleton className="h-4 w-28" />
                <Skeleton className="h-4 w-4 rounded-full" />
              </div>
              <Skeleton className="h-6 w-20" />
              <Skeleton className="h-3 w-32 mt-3" />
            </div>
          ))}
        </div>
      </div>

      <div>
        <Skeleton className="h-5 w-40 mb-3" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div
              key={`budget-skeleton-${index}`}
              className="bg-surface border border-border rounded-lg p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <Skeleton className="h-4 w-28" />
                <Skeleton className="h-4 w-4 rounded-full" />
              </div>
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, rowIndex) => (
                  <div key={`budget-row-${rowIndex}`} className="flex justify-between">
                    <Skeleton className="h-3 w-14" />
                    <Skeleton className="h-3 w-16" />
                  </div>
                ))}
              </div>
              <div className="mt-3">
                <Skeleton className="h-1 w-full rounded-full" />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <Skeleton className="h-5 w-40 mb-3" />
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={`metric-line-${index}`} className="h-3 w-full" />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function MetricsPage() {
  const [isRetrying, setIsRetrying] = useState(false);
  const {
    data: budgetData,
    error: budgetError,
    isLoading: budgetLoading,
    mutate: mutateBudget,
    isValidating: budgetValidating,
  } = useSWR<BudgetStatusResponse>('budget', () => api.getBudget(), {
    refreshInterval: 5000,
    revalidateOnFocus: true,
  });

  const {
    data: metricsText,
    error: metricsError,
    isLoading: metricsLoading,
    mutate: mutateMetrics,
    isValidating: metricsValidating,
  } = useSWR<string>('metrics', () => api.getMetrics(), {
    refreshInterval: 5000,
    revalidateOnFocus: true,
  });

  const isRefreshing = budgetValidating || metricsValidating;

  const parsedMetrics = useMemo(
    () => parsePrometheusText(metricsText ?? ''),
    [metricsText]
  );

  const totalBuilds = sumMetric(parsedMetrics, 'rch_builds_total');
  const successBuilds = sumMetric(parsedMetrics, 'rch_builds_total', (labels) => labels.result === 'success');
  const successRate = totalBuilds && totalBuilds > 0
    ? ((successBuilds ?? 0) / totalBuilds) * 100
    : null;
  const averageBuildSeconds = averageHistogram(parsedMetrics, 'rch_build_duration_seconds');
  const activeBuilds = sumMetric(parsedMetrics, 'rch_builds_active');
  const queueDepth = sumMetric(parsedMetrics, 'rch_build_queue_depth');
  const transferBytes = sumMetric(parsedMetrics, 'rch_transfer_bytes_total');
  const workerCounts = getWorkerStatusCounts(parsedMetrics);
  const circuitCounts = getCircuitCounts(parsedMetrics);

  const workersOnline = workerCounts.healthy + workerCounts.degraded;
  const workerDisplay = workerCounts.total > 0
    ? `${workersOnline}/${workerCounts.total}`
    : '—';

  const circuitTone: MetricTone = circuitCounts.open > 0
    ? 'danger'
    : circuitCounts.halfOpen > 0
      ? 'warning'
      : 'positive';

  const handleRetry = async () => {
    setIsRetrying(true);
    try {
      await Promise.all([mutateBudget(), mutateMetrics()]);
    } finally {
      setIsRetrying(false);
    }
  };

  if (budgetLoading || metricsLoading) {
    return <MetricsPageSkeleton />;
  }

  if (budgetError || metricsError) {
    return (
      <div className="flex items-center justify-center h-full">
        <ErrorState
          error={budgetError || metricsError || 'Failed to load metrics'}
          title="Failed to load metrics"
          hint={errorHints.daemonConnection}
          onRetry={handleRetry}
          isRetrying={isRetrying}
        />
      </div>
    );
  }

  const statusIcon = budgetData?.status === 'passing' ? (
    <CheckCircle className="w-5 h-5 text-healthy" />
  ) : budgetData?.status === 'warning' ? (
    <AlertCircle className="w-5 h-5 text-warning" />
  ) : (
    <XCircle className="w-5 h-5 text-error" />
  );

  const statusBadgeVariant = budgetData?.status === 'passing'
    ? 'default'
    : budgetData?.status === 'warning'
      ? 'secondary'
      : 'destructive';

  const statusBadgeLabel = budgetData?.status ?? 'unknown';

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="w-6 h-6" />
            Metrics
          </h1>
          <p className="text-muted-foreground text-sm">
            A plain-language snapshot of system health with the raw data tucked away.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant={statusBadgeVariant}
            className="capitalize"
            data-testid="metrics-status-badge"
          >
            {statusBadgeLabel}
          </Badge>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={handleRetry}
            disabled={isRefreshing}
            aria-label="Refresh metrics"
          >
            <motion.div
              animate={isRefreshing ? { rotate: 360 } : { rotate: 0 }}
              transition={isRefreshing ? { duration: 1, repeat: Infinity, ease: 'linear' } : {}}
            >
              <RefreshCw className="w-5 h-5 text-muted-foreground" />
            </motion.div>
          </Button>
        </div>
      </div>

      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">System Snapshot</h2>
            <p className="text-sm text-muted-foreground">
              Quick answers to the questions most teams ask: is it healthy, is it fast, and is it busy?
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            Auto-refreshing every 5s
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <MetricCard
            label="Total Builds"
            value={formatNumber(totalBuilds)}
            icon={Database}
            hint="All build commands recorded since the daemon started."
            sublabel="Includes local fallbacks and remote builds."
          />
          <MetricCard
            label="Success Rate"
            value={formatPercent(successRate)}
            icon={Gauge}
            hint="Percentage of builds that completed successfully."
            tone={successRate !== null && successRate < 95 ? 'warning' : 'neutral'}
          />
          <MetricCard
            label="Average Build Time"
            value={formatDurationSeconds(averageBuildSeconds)}
            icon={Timer}
            hint="Average duration across all recorded builds."
            sublabel="Lower is better."
          />
          <MetricCard
            label="Active Builds"
            value={formatNumber(activeBuilds)}
            icon={Activity}
            hint="Builds currently running on workers or locally."
            sublabel={queueDepth !== null ? `Queue depth: ${formatNumber(queueDepth)}` : 'Queue depth: —'}
          />
          <MetricCard
            label="Workers Online"
            value={workerDisplay}
            icon={Server}
            hint="Healthy and degraded workers currently reachable by the daemon."
            tone={workerCounts.total > 0 && workersOnline === 0 ? 'danger' : 'neutral'}
          />
          <MetricCard
            label="Data Moved"
            value={formatBytes(transferBytes)}
            icon={ArrowDownUp}
            hint="Total bytes transferred between the daemon and workers."
            sublabel="Helps explain bandwidth usage."
          />
        </div>
      </section>

      {budgetData && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold flex items-center gap-2">
                {statusIcon}
                Performance Budgets
              </h2>
              <p className="text-sm text-muted-foreground">
                Budgets keep RCH snappy. If a budget fails, it means the hook or daemon is getting slow.
              </p>
            </div>
            <Badge
              variant={statusBadgeVariant}
              className="capitalize"
              data-testid="budget-status-badge"
            >
              {statusBadgeLabel}
            </Badge>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {budgetData.budgets.map((budget) => (
              <div
                key={budget.name}
                data-testid="budget-card"
                className={`bg-surface border rounded-lg p-4 ${
                  budget.is_passing ? 'border-border' : 'border-error/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{formatBudgetName(budget.name)}</span>
                  {budget.is_passing ? (
                    <CheckCircle className="w-4 h-4 text-healthy" />
                  ) : (
                    <XCircle className="w-4 h-4 text-error" />
                  )}
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between text-muted-foreground">
                    <span>Budget</span>
                    <span className="font-mono">{budget.budget_ms}ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Typical (p50)</span>
                    <span className="font-mono">{budget.p50_ms.toFixed(2)}ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Slow (p95)</span>
                    <span className={`font-mono ${budget.p95_ms > budget.budget_ms ? 'text-error' : ''}`}>
                      {budget.p95_ms.toFixed(2)}ms
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Worst (p99)</span>
                    <span className={`font-mono ${budget.p99_ms > budget.budget_ms ? 'text-error' : ''}`}>
                      {budget.p99_ms.toFixed(2)}ms
                    </span>
                  </div>
                  {budget.violation_count > 0 && (
                    <div className="flex justify-between text-error">
                      <span>Violations</span>
                      <span className="font-mono">{budget.violation_count}</span>
                    </div>
                  )}
                </div>
                <div className="mt-3">
                  <Progress
                    value={Math.min((budget.p95_ms / budget.budget_ms) * 100, 100)}
                    className="h-1"
                    aria-label={`${budget.name} budget utilization`}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className={`rounded-lg border p-4 ${toneClasses[circuitTone]}`}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-medium flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Safety Rails
                </h3>
                <p className="text-sm text-muted-foreground">
                  Circuit breakers protect you from flaky workers. If any are open, RCH will avoid them.
                </p>
              </div>
              <div className="text-right">
                <div className="text-sm font-medium text-foreground">
                  {circuitCounts.open} open
                </div>
                <div className="text-xs text-muted-foreground">
                  {circuitCounts.halfOpen} half-open
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Raw Prometheus Metrics</h2>
        <details className="group bg-surface border border-border rounded-lg">
          <summary className="cursor-pointer list-none px-4 py-3 flex items-center justify-between">
            <span className="text-sm font-medium text-foreground">Show raw metrics</span>
            <span className="text-xs text-muted-foreground group-open:hidden">Hidden by default</span>
            <span className="text-xs text-muted-foreground hidden group-open:block">Collapse</span>
          </summary>
          <div className="border-t border-border px-4 py-3">
            <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
              {metricsText || 'No metrics available'}
            </pre>
          </div>
        </details>
      </section>
    </div>
  );
}
