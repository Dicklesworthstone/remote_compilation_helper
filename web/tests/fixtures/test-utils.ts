import type { Page } from '@playwright/test';
import type {
  StatusResponse,
  HealthResponse,
  ReadyResponse,
  BudgetStatusResponse,
  SpeedScoreResponse,
  SpeedScoreHistoryResponse,
  SpeedScoreListResponse,
} from '../../src/lib/types';
import {
  mockStatusResponse,
  mockHealthResponse,
  mockReadyResponse,
  mockBudgetResponse,
  mockMetricsText,
  mockSpeedScoreResponse,
  mockSpeedScoreHistoryResponse,
  mockSpeedScoreListResponse,
} from './api-mocks';

type ApiMockOverrides = {
  status?: StatusResponse;
  health?: HealthResponse;
  ready?: ReadyResponse;
  budget?: BudgetStatusResponse;
  metrics?: string;
  speedscores?: SpeedScoreListResponse;
  speedscoreForWorker?: (workerId: string) => SpeedScoreResponse;
  speedscoreHistoryForWorker?: (workerId: string, days?: number, limit?: number) => SpeedScoreHistoryResponse;
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
    if (route.request().resourceType() === 'document') {
      await route.fallback();
      return;
    }
    console.log('[mock] Intercepting /metrics');
    await route.fulfill({ body: metrics, contentType: 'text/plain' });
  });

  // SpeedScore API routes
  const speedscores = overrides.speedscores ?? mockSpeedScoreListResponse;
  const getSpeedScore = overrides.speedscoreForWorker ?? mockSpeedScoreResponse;
  const getSpeedScoreHistory = overrides.speedscoreHistoryForWorker ?? mockSpeedScoreHistoryResponse;

  await page.route('**/api/workers/speedscores', async (route) => {
    console.log('[mock] Intercepting /api/workers/speedscores');
    await route.fulfill({ json: speedscores });
  });

  await page.route(/\/api\/workers\/([^/]+)\/speedscore\/history/, async (route) => {
    const url = new URL(route.request().url());
    const workerId = url.pathname.split('/')[3];
    const days = parseInt(url.searchParams.get('days') ?? '7', 10);
    const limit = parseInt(url.searchParams.get('limit') ?? '10', 10);
    console.log(`[mock] Intercepting /api/workers/${workerId}/speedscore/history`);
    await route.fulfill({ json: getSpeedScoreHistory(workerId, days, limit) });
  });

  await page.route(/\/api\/workers\/([^/]+)\/speedscore$/, async (route) => {
    const url = new URL(route.request().url());
    const workerId = url.pathname.split('/')[3];
    console.log(`[mock] Intercepting /api/workers/${workerId}/speedscore`);
    const response = getSpeedScore(workerId);
    if (!response.speedscore) {
      await route.fulfill({ status: 404, json: { error: 'Worker not found or no benchmark data' } });
    } else {
      await route.fulfill({ json: response });
    }
  });
}
