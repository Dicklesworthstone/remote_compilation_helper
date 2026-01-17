import type {
  StatusResponse,
  HealthResponse,
  ReadyResponse,
  BudgetStatusResponse,
  DaemonStatusInfo,
  WorkerStatusInfo,
  ActiveBuild,
  BuildRecord,
  Issue,
  BuildStats,
} from '../../src/lib/types';

export const mockDaemonStatus: DaemonStatusInfo = {
  pid: 12345,
  uptime_secs: 3600,
  version: '0.5.0',
  socket_path: '/tmp/rch.sock',
  started_at: '2026-01-01T11:00:00.000Z',
  workers_total: 3,
  workers_healthy: 2,
  slots_total: 32,
  slots_available: 12,
};

export const mockWorkers: WorkerStatusInfo[] = [
  {
    id: 'worker-1',
    host: '10.0.0.11',
    user: 'ubuntu',
    status: 'healthy',
    circuit_state: 'closed',
    used_slots: 4,
    total_slots: 16,
    speed_score: 92.4,
    last_error: null,
  },
  {
    id: 'worker-2',
    host: '10.0.0.12',
    user: 'builder',
    status: 'degraded',
    circuit_state: 'half_open',
    used_slots: 8,
    total_slots: 8,
    speed_score: 61.2,
    last_error: 'High load detected, probing connection.',
  },
  {
    id: 'worker-3',
    host: '10.0.0.13',
    user: 'builder',
    status: 'unreachable',
    circuit_state: 'open',
    used_slots: 0,
    total_slots: 8,
    speed_score: 0,
    last_error: 'No heartbeat for 120s.',
  },
];

export const mockActiveBuilds: ActiveBuild[] = [
  {
    id: 101,
    project_id: 'remote_compilation_helper',
    worker_id: 'worker-1',
    command: 'cargo build --release',
    started_at: '2026-01-01T12:00:05.000Z',
  },
];

export const mockRecentBuilds: BuildRecord[] = [
  {
    id: 99,
    project_id: 'remote_compilation_helper',
    worker_id: 'worker-2',
    command: 'cargo test --workspace',
    exit_code: 0,
    duration_ms: 4821,
    started_at: '2026-01-01T11:50:00.000Z',
    completed_at: '2026-01-01T11:50:04.821Z',
  },
  {
    id: 98,
    project_id: 'web-dashboard',
    worker_id: 'worker-1',
    command: 'bun test --coverage',
    exit_code: 1,
    duration_ms: 3120,
    started_at: '2026-01-01T11:40:00.000Z',
    completed_at: '2026-01-01T11:40:03.120Z',
  },
];

export const mockIssues: Issue[] = [
  {
    severity: 'warning',
    summary: 'Worker worker-2 circuit half-open',
    remediation: 'Retry probe or restart worker service.',
  },
];

export const mockStats: BuildStats = {
  total_builds: 128,
  successful_builds: 120,
  failed_builds: 8,
  total_duration_ms: 502_000,
  avg_duration_ms: 3922,
};

export const mockStatusResponse: StatusResponse = {
  daemon: mockDaemonStatus,
  workers: mockWorkers,
  active_builds: mockActiveBuilds,
  recent_builds: mockRecentBuilds,
  issues: mockIssues,
  stats: mockStats,
};

export const mockHealthResponse: HealthResponse = {
  status: 'healthy',
  version: '0.5.0',
  uptime_seconds: 3600,
};

export const mockReadyResponse: ReadyResponse = {
  status: 'ready',
  workers_available: true,
};

export const mockBudgetResponse: BudgetStatusResponse = {
  status: 'passing',
  budgets: [
    {
      name: 'classification',
      budget_ms: 5,
      p50_ms: 0.4,
      p95_ms: 1.2,
      p99_ms: 2.3,
      is_passing: true,
      violation_count: 0,
    },
    {
      name: 'worker_selection',
      budget_ms: 10,
      p50_ms: 1.6,
      p95_ms: 4.8,
      p99_ms: 7.9,
      is_passing: true,
      violation_count: 0,
    },
  ],
};

export const mockMetricsText = [
  '# HELP rch_builds_total Total builds executed',
  '# TYPE rch_builds_total counter',
  'rch_builds_total 128',
  '# HELP rch_workers_total Total workers configured',
  '# TYPE rch_workers_total gauge',
  'rch_workers_total 3',
].join('\n');
