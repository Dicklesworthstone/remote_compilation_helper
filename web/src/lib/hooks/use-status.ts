'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '../api';
import type { StatusResponse, HealthResponse, ReadyResponse, BudgetStatusResponse } from '../types';

/**
 * Hook for fetching full daemon status including workers and builds
 */
export function useStatus() {
  return useQuery<StatusResponse>({
    queryKey: ['status'],
    queryFn: () => api.getStatus(),
  });
}

/**
 * Hook for basic health check
 */
export function useHealth() {
  return useQuery<HealthResponse>({
    queryKey: ['health'],
    queryFn: () => api.getHealth(),
  });
}

/**
 * Hook for readiness status
 */
export function useReady() {
  return useQuery<ReadyResponse>({
    queryKey: ['ready'],
    queryFn: () => api.getReady(),
  });
}

/**
 * Hook for budget compliance status
 */
export function useBudget() {
  return useQuery<BudgetStatusResponse>({
    queryKey: ['budget'],
    queryFn: () => api.getBudget(),
  });
}
