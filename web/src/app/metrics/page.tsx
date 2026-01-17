'use client';

import useSWR from 'swr';
import { Activity, AlertTriangle, RefreshCw, CheckCircle, XCircle, AlertCircle } from 'lucide-react';
import { motion } from 'motion/react';
import { api } from '@/lib/api';
import { Progress } from '@/components/ui/progress';
import type { BudgetStatusResponse } from '@/lib/types';

export default function MetricsPage() {
  const { data: budgetData, error: budgetError, isLoading: budgetLoading, mutate, isValidating } = useSWR<BudgetStatusResponse>(
    'budget',
    () => api.getBudget(),
    {
      refreshInterval: 5000, // Poll every 5 seconds
      revalidateOnFocus: true,
    }
  );

  const { data: metricsText, error: metricsError, isLoading: metricsLoading } = useSWR<string>(
    'metrics',
    () => api.getMetrics(),
    {
      refreshInterval: 5000,
      revalidateOnFocus: true,
    }
  );

  if (budgetLoading || metricsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-muted-foreground">Loading metrics...</div>
      </div>
    );
  }

  if (budgetError || metricsError) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-error" />
        <div className="text-error font-medium">Failed to load metrics</div>
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="w-6 h-6" />
            Metrics
          </h1>
          <p className="text-muted-foreground text-sm">
            Performance budgets and Prometheus metrics
          </p>
        </div>
        <button
          onClick={() => mutate()}
          disabled={isValidating}
          className="p-2 rounded-lg hover:bg-surface-elevated transition-colors disabled:opacity-50"
          title="Refresh"
        >
          <motion.div
            animate={isValidating ? { rotate: 360 } : { rotate: 0 }}
            transition={isValidating ? { duration: 1, repeat: Infinity, ease: 'linear' } : {}}
          >
            <RefreshCw className="w-5 h-5 text-muted-foreground" />
          </motion.div>
        </button>
      </div>

      {/* Budget Status */}
      {budgetData && (
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            {statusIcon}
            Performance Budgets
            <span className={`text-sm font-normal px-2 py-0.5 rounded ${
              budgetData.status === 'passing' ? 'bg-healthy/20 text-healthy' :
              budgetData.status === 'warning' ? 'bg-warning/20 text-warning' :
              'bg-error/20 text-error'
            }`}>
              {budgetData.status}
            </span>
          </h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {budgetData.budgets.map((budget) => (
              <div
                key={budget.name}
                className={`bg-surface border rounded-lg p-4 ${
                  budget.is_passing ? 'border-border' : 'border-error/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{budget.name}</span>
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
                    <span className="text-muted-foreground">p50</span>
                    <span className="font-mono">{budget.p50_ms.toFixed(2)}ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">p95</span>
                    <span className={`font-mono ${budget.p95_ms > budget.budget_ms ? 'text-error' : ''}`}>
                      {budget.p95_ms.toFixed(2)}ms
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">p99</span>
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
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw Prometheus Metrics */}
      <div>
        <h2 className="text-lg font-semibold mb-3">Prometheus Metrics</h2>
        <div className="bg-surface border border-border rounded-lg p-4 overflow-auto max-h-96">
          <pre className="text-xs font-mono text-muted-foreground whitespace-pre">
            {metricsText || 'No metrics available'}
          </pre>
        </div>
      </div>
    </div>
  );
}
