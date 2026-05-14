'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import type {
  BenchmarkStartedEvent,
  BenchmarkProgressEvent,
  BenchmarkCompletedEvent,
  BenchmarkFailedEvent,
  BenchmarkQueuedEvent,
  BenchmarkTriggerResponse,
  SpeedScoreView,
} from '../types';

export type BenchmarkPhase = 'cpu' | 'memory' | 'disk' | 'network' | 'compilation';

export interface BenchmarkState {
  status: 'idle' | 'triggering' | 'queued' | 'running' | 'completed' | 'failed';
  requestId: string | null;
  jobId: string | null;
  currentPhase: BenchmarkPhase | null;
  phaseProgress: number;
  overallProgress: number;
  elapsedSecs: number;
  error: string | null;
  result: SpeedScoreView | null;
  durationSecs: number | null;
}

const initialState: BenchmarkState = {
  status: 'idle',
  requestId: null,
  jobId: null,
  currentPhase: null,
  phaseProgress: 0,
  overallProgress: 0,
  elapsedSecs: 0,
  error: null,
  result: null,
  durationSecs: null,
};

interface UseBenchmarkProgressOptions {
  workerId: string;
  onCompleted?: (result: SpeedScoreView) => void;
  onFailed?: (error: string) => void;
}

/**
 * Hook for triggering benchmarks and tracking their progress via SSE.
 *
 * Connects to the SSE endpoint filtered by worker ID and listens for
 * benchmark lifecycle events.
 */
export function useBenchmarkProgress({
  workerId,
  onCompleted,
  onFailed,
}: UseBenchmarkProgressOptions) {
  const [state, setState] = useState<BenchmarkState>(initialState);
  const eventSourceRef = useRef<EventSource | null>(null);
  const isActiveRef = useRef(false);
  const statusRef = useRef(state.status);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const connectRef = useRef<(() => void) | null>(null);
  statusRef.current = state.status;

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isActiveRef.current = false;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, []);

  const handleBenchmarkQueued = useCallback((data: BenchmarkQueuedEvent['data']) => {
    if (data.worker_id !== workerId) return;
    setState((prev) => ({
      ...prev,
      status: 'queued',
      requestId: data.request_id,
    }));
  }, [workerId]);

  const handleBenchmarkStarted = useCallback((data: BenchmarkStartedEvent['data']) => {
    if (data.worker_id !== workerId) return;
    setState((prev) => ({
      ...prev,
      status: 'running',
      jobId: data.job_id,
      currentPhase: 'cpu',
      phaseProgress: 0,
      overallProgress: 0,
    }));
  }, [workerId]);

  const handleBenchmarkProgress = useCallback((data: BenchmarkProgressEvent['data']) => {
    if (data.worker_id !== workerId) return;
    setState((prev) => ({
      ...prev,
      currentPhase: data.phase,
      phaseProgress: data.phase_progress_pct,
      overallProgress: data.overall_progress_pct,
      elapsedSecs: data.elapsed_secs,
    }));
  }, [workerId]);

  const handleBenchmarkCompleted = useCallback((data: BenchmarkCompletedEvent['data']) => {
    if (data.worker_id !== workerId) return;
    setState((prev) => ({
      ...prev,
      status: 'completed',
      result: data.speedscore,
      durationSecs: data.duration_secs,
      overallProgress: 100,
    }));
    onCompleted?.(data.speedscore);

    // Disconnect after completion
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, [workerId, onCompleted]);

  const handleBenchmarkFailed = useCallback((data: BenchmarkFailedEvent['data']) => {
    if (data.worker_id !== workerId) return;
    setState((prev) => ({
      ...prev,
      status: 'failed',
      error: data.error,
    }));
    onFailed?.(data.error);

    // Disconnect after failure
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, [workerId, onFailed]);

  const handleEvent = useCallback((data: unknown) => {
    const event = data as { event?: string; data?: Record<string, unknown> };
    if (!event.event) return;

    switch (event.event) {
      case 'benchmark_queued':
        handleBenchmarkQueued(event.data as BenchmarkQueuedEvent['data']);
        break;
      case 'benchmark_started':
        handleBenchmarkStarted(event.data as BenchmarkStartedEvent['data']);
        break;
      case 'benchmark_progress':
        handleBenchmarkProgress(event.data as BenchmarkProgressEvent['data']);
        break;
      case 'benchmark_completed':
        handleBenchmarkCompleted(event.data as BenchmarkCompletedEvent['data']);
        break;
      case 'benchmark_failed':
        handleBenchmarkFailed(event.data as BenchmarkFailedEvent['data']);
        break;
    }
  }, [
    handleBenchmarkQueued,
    handleBenchmarkStarted,
    handleBenchmarkProgress,
    handleBenchmarkCompleted,
    handleBenchmarkFailed,
  ]);

  // Connect to SSE for the worker
  const connect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const url = `/api/ws?subscribe=${encodeURIComponent(workerId)}`;
    const eventSource = new EventSource(url);
    eventSourceRef.current = eventSource;
    isActiveRef.current = true;

    eventSource.addEventListener('message', (event) => {
      if (!isActiveRef.current) return;

      try {
        const data = JSON.parse(event.data);
        handleEvent(data);
      } catch {
        // Ignore parse errors
      }
    });

    // Also listen for specific event types
    eventSource.addEventListener('benchmark_queued', (event) => {
      if (!isActiveRef.current) return;
      try {
        const data = JSON.parse((event as MessageEvent).data);
        handleBenchmarkQueued(data);
      } catch {
        // Ignore
      }
    });

    eventSource.onerror = () => {
      // Reconnect after a delay if still active
      if (isActiveRef.current && statusRef.current === 'running') {
        reconnectTimerRef.current = setTimeout(() => {
          reconnectTimerRef.current = null;
          if (isActiveRef.current) connectRef.current?.();
        }, 3000);
      }
    };
  }, [workerId, handleEvent, handleBenchmarkQueued]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  /**
   * Trigger a benchmark for the worker.
   */
  const trigger = useCallback(async () => {
    setState((prev) => ({ ...prev, status: 'triggering', error: null }));

    // Connect to SSE before triggering
    connect();

    try {
      const response = await fetch(`/api/workers/${encodeURIComponent(workerId)}/benchmark/trigger`, {
        method: 'POST',
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const errorMsg = data.message || data.error || `Request failed with status ${response.status}`;

        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          throw new Error(
            retryAfter
              ? `Rate limited. Try again in ${retryAfter} seconds.`
              : 'Rate limited. Please try again later.'
          );
        }

        throw new Error(errorMsg);
      }

      const data: BenchmarkTriggerResponse = await response.json();
      setState((prev) => ({
        ...prev,
        status: 'queued',
        requestId: data.request_id,
      }));
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to trigger benchmark';
      setState((prev) => ({
        ...prev,
        status: 'failed',
        error: errorMsg,
      }));

      // Disconnect on trigger failure
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    }
  }, [workerId, connect]);

  /**
   * Reset to idle state.
   */
  const reset = useCallback(() => {
    isActiveRef.current = false;
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setState(initialState);
  }, []);

  return {
    ...state,
    trigger,
    reset,
    isIdle: state.status === 'idle',
    isTriggering: state.status === 'triggering',
    isQueued: state.status === 'queued',
    isRunning: state.status === 'running',
    isCompleted: state.status === 'completed',
    isFailed: state.status === 'failed',
    isActive: state.status === 'triggering' || state.status === 'queued' || state.status === 'running',
  };
}
