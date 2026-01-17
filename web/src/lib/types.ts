// Types matching rchd API responses

export type WorkerStatus = 'healthy' | 'degraded' | 'unreachable' | 'draining' | 'disabled';
export type CircuitState = 'closed' | 'half_open' | 'open';

export interface DaemonStatusInfo {
  pid: number;
  uptime_secs: number;
  version: string;
  socket_path: string;
  started_at: string;
  workers_total: number;
  workers_healthy: number;
  slots_total: number;
  slots_available: number;
}

export interface WorkerStatusInfo {
  id: string;
  host: string;
  user: string;
  status: WorkerStatus;
  circuit_state: CircuitState;
  used_slots: number;
  total_slots: number;
  speed_score: number;
  last_error: string | null;
}

export interface ActiveBuild {
  id: number;
  project_id: string;
  worker_id: string;
  command: string;
  started_at: string;
}

export interface BuildRecord {
  id: number;
  project_id: string;
  worker_id: string;
  command: string;
  exit_code: number;
  duration_ms: number;
  started_at: string;
  completed_at: string;
}

export interface Issue {
  severity: 'info' | 'warning' | 'error';
  summary: string;
  remediation: string | null;
}

export interface BuildStats {
  total_builds: number;
  successful_builds: number;
  failed_builds: number;
  total_duration_ms: number;
  avg_duration_ms: number;
}

export interface StatusResponse {
  daemon: DaemonStatusInfo;
  workers: WorkerStatusInfo[];
  active_builds: ActiveBuild[];
  recent_builds: BuildRecord[];
  issues: Issue[];
  stats: BuildStats;
}

export interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  version: string;
  uptime_seconds: number;
}

export interface ReadyResponse {
  status: 'ready' | 'not_ready';
  workers_available: boolean;
  reason?: string;
}

export interface BudgetStatusResponse {
  status: 'passing' | 'warning' | 'failing';
  budgets: BudgetInfo[];
}

export interface BudgetInfo {
  name: string;
  budget_ms: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  is_passing: boolean;
  violation_count: number;
}
