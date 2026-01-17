import type { Page } from '@playwright/test';
import type {
  StatusResponse,
  HealthResponse,
  ReadyResponse,
  BudgetStatusResponse,
} from '../../src/lib/types';
import {
  mockStatusResponse,
  mockHealthResponse,
  mockReadyResponse,
  mockBudgetResponse,
  mockMetricsText,
} from './api-mocks';

type ApiMockOverrides = {
  status?: StatusResponse;
  health?: HealthResponse;
  ready?: ReadyResponse;
  budget?: BudgetStatusResponse;
  metrics?: string;
};

export async function mockApiResponses(
  page: Page,
  overrides: ApiMockOverrides = {}
) {
  const status = overrides.status ?? mockStatusResponse;
  const health = overrides.health ?? mockHealthResponse;
  const ready = overrides.ready ?? mockReadyResponse;
  const budget = overrides.budget ?? mockBudgetResponse;
  const metrics = overrides.metrics ?? mockMetricsText;

  await page.route('**/status', async (route) => {
    console.log('[mock] Intercepting /status');
    await route.fulfill({ json: status });
  });

  await page.route('**/health', async (route) => {
    console.log('[mock] Intercepting /health');
    await route.fulfill({ json: health });
  });

  await page.route('**/ready', async (route) => {
    console.log('[mock] Intercepting /ready');
    await route.fulfill({ json: ready });
  });

  await page.route('**/budget', async (route) => {
    console.log('[mock] Intercepting /budget');
    await route.fulfill({ json: budget });
  });

  await page.route('**/metrics', async (route) => {
    console.log('[mock] Intercepting /metrics');
    await route.fulfill({ body: metrics, contentType: 'text/plain' });
  });
}
