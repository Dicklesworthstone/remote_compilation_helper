import type { WorkerStatusInfo, SpeedScoreView } from './types';

/**
 * Find the best (highest) value for each metric among workers
 */
export function findBestScores(workers: WorkerStatusInfo[]): {
  speedScore: number;
  totalSlots: number;
} {
  if (workers.length === 0) {
    return { speedScore: 0, totalSlots: 0 };
  }

  return {
    speedScore: Math.max(...workers.map((w) => w.speed_score)),
    totalSlots: Math.max(...workers.map((w) => w.total_slots)),
  };
}

/**
 * Find the best component scores from SpeedScoreView data
 */
export function findBestComponentScores(
  speedScores: SpeedScoreView[]
): Record<keyof Omit<SpeedScoreView, 'measured_at' | 'version'>, number> {
  if (speedScores.length === 0) {
    return {
      total: 0,
      cpu_score: 0,
      memory_score: 0,
      disk_score: 0,
      network_score: 0,
      compilation_score: 0,
    };
  }

  return {
    total: Math.max(...speedScores.map((s) => s.total)),
    cpu_score: Math.max(...speedScores.map((s) => s.cpu_score)),
    memory_score: Math.max(...speedScores.map((s) => s.memory_score)),
    disk_score: Math.max(...speedScores.map((s) => s.disk_score)),
    network_score: Math.max(...speedScores.map((s) => s.network_score)),
    compilation_score: Math.max(...speedScores.map((s) => s.compilation_score)),
  };
}

/**
 * Calculate the relative performance ratio compared to the best
 */
export function calculatePerformanceRatio(value: number, best: number): number {
  if (best === 0) return 0;
  return value / best;
}

/**
 * Get a tier based on performance ratio
 */
export type PerformanceTier = 'best' | 'excellent' | 'good' | 'average' | 'below_average';

export function getPerformanceTier(ratio: number): PerformanceTier {
  if (ratio >= 1) return 'best';
  if (ratio >= 0.95) return 'excellent';
  if (ratio >= 0.85) return 'good';
  if (ratio >= 0.70) return 'average';
  return 'below_average';
}

/**
 * Sort workers by speed score (descending)
 */
export function sortWorkersByScore(workers: WorkerStatusInfo[]): WorkerStatusInfo[] {
  return [...workers].sort((a, b) => b.speed_score - a.speed_score);
}

/**
 * Get top N workers by speed score
 */
export function getTopWorkers(workers: WorkerStatusInfo[], n: number): WorkerStatusInfo[] {
  return sortWorkersByScore(workers).slice(0, n);
}

/**
 * Filter workers by status
 */
export function filterWorkersByStatus(
  workers: WorkerStatusInfo[],
  statuses: WorkerStatusInfo['status'][]
): WorkerStatusInfo[] {
  const statusSet = new Set(statuses);
  return workers.filter((w) => statusSet.has(w.status));
}

/**
 * Get healthy workers only
 */
export function getHealthyWorkers(workers: WorkerStatusInfo[]): WorkerStatusInfo[] {
  return filterWorkersByStatus(workers, ['healthy']);
}

/**
 * Generate shareable URL params for selected workers
 */
export function generateShareableParams(workerIds: string[]): string {
  if (workerIds.length === 0) return '';
  return `workers=${workerIds.join(',')}`;
}

/**
 * Parse worker IDs from URL params
 */
export function parseWorkerIdsFromParams(param: string | null): string[] {
  if (!param) return [];
  return param.split(',').filter(Boolean);
}
