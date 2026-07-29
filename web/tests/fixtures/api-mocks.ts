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
  SpeedScoreView,
  SpeedScoreResponse,
  SpeedScoreHistoryResponse,
  SpeedScoreListResponse,
  BenchmarkResults,
  RemediationView,
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
    location: 'remote',
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
    location: 'remote',
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
  success_count: 120,
  failure_count: 8,
  remote_count: 96,
  local_count: 32,
  avg_duration_ms: 3922,
};

// A degraded-but-self-healing remediation view: one worker temporarily
// bypassed (auto-rejoin), others healthy. Mirrors the daemon-assembled,
// redacted RemediationView (bd-session-history-remediation-ocv9i.14.4).
export const mockRemediationView: RemediationView = {
  schema_version: '1.0.0',
  generated_at_unix_ms: 1_700_000_000_000,
  overall: 'self_healing_in_progress',
  bands: [
    {
      id: 'desired_fleet',
      title: 'Desired Fleet',
      severity: 'ok',
      action_class: 'healthy',
      headline: '2/3 worker(s) ready',
      detail_lines: ['desired 3 · eligible 2 · bypassed 1 · disabled 0 · unreachable 0 · missing 0'],
      reason_code: 'healthy',
    },
    {
      id: 'live_eligibility',
      title: 'Live Eligibility',
      severity: 'warn',
      action_class: 'self_healing_in_progress',
      headline: '2 of 3 desired worker(s) eligible',
      detail_lines: ['1 temporarily bypassed (auto-rejoin)'],
    },
    {
      id: 'admissible_workers',
      title: 'Admissible Workers',
      severity: 'ok',
      action_class: 'healthy',
      headline: '2 of 2 live worker(s) can run a command now',
      detail_lines: [],
    },
    {
      id: 'proof_queue',
      title: 'Proof Queue',
      severity: 'ok',
      action_class: 'healthy',
      headline: 'no proofs pending',
      detail_lines: [],
    },
    {
      id: 'active_jobs',
      title: 'Active Jobs',
      severity: 'info',
      action_class: 'healthy',
      headline: '1 active · 0 queued',
      detail_lines: [],
    },
    {
      id: 'disk_pressure',
      title: 'Disk Pressure',
      severity: 'ok',
      action_class: 'healthy',
      headline: 'no disk pressure',
      detail_lines: [],
    },
    {
      id: 'telemetry_freshness',
      title: 'Telemetry Freshness',
      severity: 'ok',
      action_class: 'healthy',
      headline: '2 worker(s) reporting fresh telemetry',
      detail_lines: [],
    },
    {
      id: 'incidents',
      title: 'Recent Incidents',
      severity: 'ok',
      action_class: 'healthy',
      headline: 'no recent incidents',
      detail_lines: [],
    },
  ],
  incidents: [],
};

export const mockStatusResponse: StatusResponse = {
  daemon: mockDaemonStatus,
  workers: mockWorkers,
  active_builds: mockActiveBuilds,
  queued_builds: [],
  recent_builds: mockRecentBuilds,
  issues: mockIssues,
  stats: mockStats,
  remediation: mockRemediationView,
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

// SpeedScore mock data
export const mockSpeedScores: Record<string, SpeedScoreView> = {
  'worker-1': {
    total: 92.4,
    cpu_score: 95,
    memory_score: 88,
    disk_score: 91,
    network_score: 93,
    compilation_score: 94,
    measured_at: '2026-01-18T10:00:00Z',
    version: 1,
  },
  'worker-2': {
    total: 61.2,
    cpu_score: 65,
    memory_score: 58,
    disk_score: 55,
    network_score: 62,
    compilation_score: 66,
    measured_at: '2026-01-17T15:30:00Z',
    version: 1,
  },
  'worker-3': {
    total: 0,
    cpu_score: 0,
    memory_score: 0,
    disk_score: 0,
    network_score: 0,
    compilation_score: 0,
    measured_at: '2026-01-15T08:00:00Z',
    version: 1,
  },
};

export const mockBenchmarkResults: Record<string, BenchmarkResults> = {
  'worker-1': {
    cpu: { gflops: 450.5 },
    memory: { bandwidth_gbps: 48.2 },
    disk: { sequential_read_mbps: 3200, random_read_iops: 180000 },
    network: { download_mbps: 920, upload_mbps: 480 },
    compilation: { units_per_sec: 52.3 },
  },
  'worker-2': {
    cpu: { gflops: 280.1 },
    memory: { bandwidth_gbps: 32.5 },
    disk: { sequential_read_mbps: 1800, random_read_iops: 85000 },
    network: { download_mbps: 650, upload_mbps: 320 },
    compilation: { units_per_sec: 28.7 },
  },
};

export const mockSpeedScoreHistory: Record<string, SpeedScoreView[]> = {
  'worker-1': [
    mockSpeedScores['worker-1'],
    {
      total: 90.1,
      cpu_score: 92,
      memory_score: 86,
      disk_score: 89,
      network_score: 91,
      compilation_score: 92,
      measured_at: '2026-01-17T10:00:00Z',
      version: 1,
    },
    {
      total: 88.5,
      cpu_score: 90,
      memory_score: 85,
      disk_score: 87,
      network_score: 89,
      compilation_score: 91,
      measured_at: '2026-01-16T10:00:00Z',
      version: 1,
    },
  ],
  'worker-2': [
    mockSpeedScores['worker-2'],
    {
      total: 59.8,
      cpu_score: 63,
      memory_score: 56,
      disk_score: 54,
      network_score: 60,
      compilation_score: 64,
      measured_at: '2026-01-16T15:30:00Z',
      version: 1,
    },
  ],
};

export function mockSpeedScoreResponse(workerId: string): SpeedScoreResponse {
  return {
    worker_id: workerId,
    speedscore: mockSpeedScores[workerId] ?? null,
  };
}

export function mockSpeedScoreHistoryResponse(
  workerId: string,
  limit = 10
): SpeedScoreHistoryResponse {
  const history = mockSpeedScoreHistory[workerId] ?? [];
  return {
    worker_id: workerId,
    history: history.slice(0, limit),
    pagination: {
      total: history.length,
      offset: 0,
      limit,
      has_more: history.length > limit,
    },
  };
}

export const mockSpeedScoreListResponse: SpeedScoreListResponse = {
  workers: mockWorkers.map((w) => ({
    worker_id: w.id,
    speedscore: mockSpeedScores[w.id] ?? null,
    status: w.status,
  })),
};
