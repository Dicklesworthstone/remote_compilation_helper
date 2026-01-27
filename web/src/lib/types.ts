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
  speed_score_prev?: number | null;
  last_error: string | null;
}

export interface ActiveBuild {
  id: number;
  project_id: string;
  worker_id: string;
  command: string;
  started_at: string;
}

export interface QueuedBuild {
  id: number;
  project_id: string;
  command: string;
  queued_at: string;
  position: number;
  slots_needed: number;
  estimated_start: string | null;
  wait_time: string;
}

export type BuildLocation = 'local' | 'remote';

export interface BuildRecord {
  id: number;
  project_id: string;
  worker_id: string | null;
  command: string;
  exit_code: number;
  duration_ms: number;
  started_at: string;
  completed_at: string;
  location: BuildLocation;
  bytes_transferred?: number | null;
}

export interface Issue {
  severity: 'info' | 'warning' | 'error';
  summary: string;
  remediation: string | null;
}

export interface BuildStats {
  total_builds: number;
  success_count: number;
  failure_count: number;
  remote_count: number;
  local_count: number;
  avg_duration_ms: number;
}

export interface StatusResponse {
  daemon: DaemonStatusInfo;
  workers: WorkerStatusInfo[];
  active_builds: ActiveBuild[];
  queued_builds: QueuedBuild[];
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

// ============================================================================
// SSE/WebSocket Event Types (per bead remote_compilation_helper-y8n)
// ============================================================================

/**
 * Base SSE event structure from rchd
 */
export interface RchdBaseEvent {
  event: string;
  timestamp: string;
}

/**
 * Connection established event (sent by Next.js proxy)
 */
export interface ConnectedEvent extends RchdBaseEvent {
  event: 'connected';
  data: {
    request_id: string;
    subscribed_workers: string[] | null;
    timestamp: string;
  };
}

/**
 * Heartbeat event (sent by Next.js proxy every 30s)
 */
export interface HeartbeatEvent extends RchdBaseEvent {
  event: 'heartbeat';
  data: {
    timestamp: string;
    request_id: string;
  };
}

/**
 * Error event (sent by Next.js proxy on connection issues)
 */
export interface ErrorEvent extends RchdBaseEvent {
  event: 'error';
  data: {
    message: string;
    code?: string;
    timestamp: string;
  };
}

/**
 * SpeedScore updated event (from rchd)
 */
export interface SpeedScoreUpdatedEvent extends RchdBaseEvent {
  event: 'speedscore_updated';
  data: {
    worker_id: string;
    speedscore: SpeedScoreView;
    previous_total?: number;
    change_pct?: number;
  };
}

/**
 * Benchmark lifecycle events (from rchd)
 */
export interface BenchmarkStartedEvent extends RchdBaseEvent {
  event: 'benchmark_started';
  data: {
    worker_id: string;
    job_id: string;
  };
}

export interface BenchmarkProgressEvent extends RchdBaseEvent {
  event: 'benchmark_progress';
  data: {
    worker_id: string;
    job_id: string;
    phase: 'cpu' | 'memory' | 'disk' | 'network' | 'compilation';
    phase_progress_pct: number;
    overall_progress_pct: number;
    elapsed_secs: number;
  };
}

export interface BenchmarkCompletedEvent extends RchdBaseEvent {
  event: 'benchmark_completed';
  data: {
    worker_id: string;
    job_id: string;
    speedscore: SpeedScoreView;
    duration_secs: number;
    success: boolean;
  };
}

export interface BenchmarkFailedEvent extends RchdBaseEvent {
  event: 'benchmark_failed';
  data: {
    worker_id: string;
    job_id: string;
    error: string;
    phase?: string;
    partial_results?: Partial<SpeedScoreView>;
  };
}

export interface BenchmarkQueuedEvent extends RchdBaseEvent {
  event: 'benchmark_queued';
  data: {
    worker_id: string;
    request_id: string;
    queued_at: string;
  };
}

/**
 * SpeedScore API view (matches rchd SpeedScoreView)
 */
export interface SpeedScoreView {
  total: number;
  cpu_score: number;
  memory_score: number;
  disk_score: number;
  network_score: number;
  compilation_score: number;
  measured_at: string;
  version: number;
}

/**
 * Partial SpeedScore for benchmarks that failed mid-way
 */
export interface PartialSpeedScore extends Partial<SpeedScoreView> {
  is_partial: true;
  failed_phase: 'cpu' | 'memory' | 'disk' | 'network' | 'compilation';
}

/**
 * Raw benchmark results with detailed metrics per component
 */
export interface BenchmarkResults {
  cpu?: {
    gflops: number;
  };
  memory?: {
    bandwidth_gbps: number;
  };
  disk?: {
    sequential_read_mbps: number;
    random_read_iops: number;
  };
  network?: {
    download_mbps: number;
    upload_mbps: number;
  };
  compilation?: {
    units_per_sec: number;
  };
}

/**
 * SpeedScore response for a single worker
 */
export interface SpeedScoreResponse {
  worker_id: string;
  speedscore: SpeedScoreView | null;
  message?: string;
}

/**
 * SpeedScore history response with pagination
 */
export interface SpeedScoreHistoryResponse {
  worker_id: string;
  history: SpeedScoreView[];
  pagination: {
    total: number;
    offset: number;
    limit: number;
    has_more: boolean;
  };
}

/**
 * SpeedScore list response (all workers)
 */
export interface SpeedScoreListResponse {
  workers: Array<{
    worker_id: string;
    speedscore: SpeedScoreView | null;
    status: WorkerStatus;
  }>;
}

/**
 * Benchmark trigger response
 */
export interface BenchmarkTriggerResponse {
  status: 'queued';
  worker_id: string;
  request_id: string;
}

/**
 * Union type for all SSE events
 */
export type RchdEvent =
  | ConnectedEvent
  | HeartbeatEvent
  | ErrorEvent
  | SpeedScoreUpdatedEvent
  | BenchmarkStartedEvent
  | BenchmarkProgressEvent
  | BenchmarkCompletedEvent
  | BenchmarkFailedEvent
  | BenchmarkQueuedEvent;
