'use client';

import useSWR from 'swr';
import { ShieldCheck, AlertTriangle, RefreshCw, Activity } from 'lucide-react';
import { api } from '@/lib/api';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, errorHints } from '@/components/ui/error-state';
import type {
  RemediationActionClass,
  BandSeverity,
  RemediationBand,
  RemediationView,
} from '@/lib/types';

// Human-facing remediation views (bd-session-history-remediation-ocv9i.14.4).
// Renders the same redacted RemediationView the TUI and CLI show, distinguishing
// operator-action / self-healing / normal-fail-open postures.

const ACTION_LABEL: Record<RemediationActionClass, string> = {
  healthy: 'Healthy',
  normal_fail_open: 'Normal (fail-open local)',
  self_healing_in_progress: 'Self-healing in progress',
  operator_action_required: 'Operator action required',
};

function actionClasses(klass: RemediationActionClass): string {
  switch (klass) {
    case 'operator_action_required':
      return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'self_healing_in_progress':
      return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    case 'normal_fail_open':
      return 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';
    case 'healthy':
    default:
      return 'bg-green-500/15 text-green-400 border-green-500/30';
  }
}

function severityDot(sev: BandSeverity): string {
  switch (sev) {
    case 'critical':
      return 'bg-red-500';
    case 'warn':
      return 'bg-yellow-500';
    case 'info':
      return 'bg-blue-500';
    case 'ok':
    default:
      return 'bg-green-500';
  }
}

function ActionBadge({ klass }: { klass: RemediationActionClass }) {
  return (
    <span
      data-testid={`action-${klass}`}
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${actionClasses(klass)}`}
    >
      {ACTION_LABEL[klass]}
    </span>
  );
}

function BandCard({ band }: { band: RemediationBand }) {
  return (
    <div
      data-testid={`band-${band.id}`}
      data-action-class={band.action_class}
      data-severity={band.severity}
      className="rounded-lg border border-border bg-surface p-4"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${severityDot(band.severity)}`} />
          <h3 className="font-medium text-sm">{band.title}</h3>
        </div>
        <ActionBadge klass={band.action_class} />
      </div>
      <p className="mt-2 text-sm text-muted-foreground">{band.headline}</p>
      {band.detail_lines.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
          {band.detail_lines.map((line, i) => (
            <li key={`${band.id}-detail-${i}`}>{line}</li>
          ))}
        </ul>
      )}
      {band.reason_code && (
        <p className="mt-2 text-xs text-muted-foreground/70">reason: {band.reason_code}</p>
      )}
    </div>
  );
}

function RemediationSkeleton() {
  return (
    <div className="flex-1 overflow-auto p-6 space-y-4" data-testid="remediation-skeleton">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={`rem-skeleton-${i}`} className="h-24 w-full rounded-lg" />
      ))}
    </div>
  );
}

function OverallBanner({ view }: { view: RemediationView }) {
  const needsAction = view.overall === 'operator_action_required';
  const Icon = needsAction ? AlertTriangle : view.overall === 'healthy' ? ShieldCheck : Activity;
  return (
    <div
      data-testid="remediation-overall"
      data-overall={view.overall}
      className={`flex items-center gap-3 rounded-lg border p-4 ${actionClasses(view.overall)}`}
    >
      <Icon className="h-5 w-5" />
      <div>
        <p className="text-sm font-semibold">Overall posture: {ACTION_LABEL[view.overall]}</p>
        <p className="text-xs opacity-80">
          operator-action vs self-healing vs normal fail-open
        </p>
      </div>
    </div>
  );
}

export default function RemediationPage() {
  const { data, error, isLoading, mutate } = useSWR<RemediationView>(
    'remediation',
    () => api.getRemediation(),
    { refreshInterval: 5000 }
  );

  return (
    <div className="flex flex-col h-full">
      <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6">
        <h1 className="text-sm font-semibold">Remediation</h1>
        <button
          type="button"
          onClick={() => mutate()}
          data-testid="remediation-refresh"
          className="rounded-lg p-2 hover:bg-surface-hover"
          aria-label="Refresh remediation view"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </header>

      {isLoading && <RemediationSkeleton />}

      {error && !isLoading && (
        <div className="flex-1 p-6">
          <ErrorState
            title="Remediation view unavailable"
            error={error instanceof Error ? error : 'Failed to load remediation view'}
            hint={errorHints.daemonConnection}
            onRetry={() => mutate()}
          />
        </div>
      )}

      {data && !isLoading && (
        <div className="flex-1 overflow-auto p-6 space-y-6" data-testid="remediation-content">
          <OverallBanner view={data} />

          <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data.bands.map((band) => (
              <BandCard key={band.id} band={band} />
            ))}
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold">Recent incidents</h2>
            {data.incidents.length === 0 ? (
              <p data-testid="incidents-none" className="text-sm text-muted-foreground">
                No recent incidents.
              </p>
            ) : (
              <ul data-testid="incidents-list" className="space-y-1 text-sm">
                {data.incidents.map((inc, i) => (
                  <li key={`incident-${i}`} className="text-muted-foreground">
                    <span className="font-mono text-xs">{inc.reason_code}</span> {inc.event_type}
                    {inc.worker_id ? ` [${inc.worker_id}]` : ''} — {inc.summary} ({inc.age_secs}s
                    ago)
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
