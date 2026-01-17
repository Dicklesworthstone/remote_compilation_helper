import { test, expect, type Page } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import { mockStatusResponse } from '../fixtures/api-mocks';

async function settleAnimations(page: Page) {
  await page.waitForTimeout(500);
}

test('visual: dashboard full page snapshot', async ({ page }) => {
  console.log('[visual] TEST START: dashboard full page snapshot');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.goto('/');
  console.log('[visual] NAVIGATE: Loaded /');

  await page.waitForSelector('[data-testid="stat-card"]');
  console.log('[visual] WAIT: stat cards rendered');

  await settleAnimations(page);
  console.log('[visual] CAPTURE: dashboard full page');

  await expect(page).toHaveScreenshot('dashboard.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] PASS: dashboard snapshot captured');
});

test('visual: workers page snapshot', async ({ page }) => {
  console.log('[visual] TEST START: workers page snapshot');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.goto('/workers');
  console.log('[visual] NAVIGATE: Loaded /workers');

  await page.waitForSelector('[data-testid="worker-card"]');
  console.log('[visual] WAIT: worker cards rendered');

  await settleAnimations(page);
  console.log('[visual] CAPTURE: workers page');

  await expect(page).toHaveScreenshot('workers.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] PASS: workers snapshot captured');
});

test('visual: builds page snapshot', async ({ page }) => {
  console.log('[visual] TEST START: builds page snapshot');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.goto('/builds');
  console.log('[visual] NAVIGATE: Loaded /builds');

  await page.waitForSelector('[data-testid="builds-table"]');
  console.log('[visual] WAIT: builds table rendered');

  await settleAnimations(page);
  console.log('[visual] CAPTURE: builds page');

  await expect(page).toHaveScreenshot('builds.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] PASS: builds snapshot captured');
});

test('visual: metrics page snapshot', async ({ page }) => {
  console.log('[visual] TEST START: metrics page snapshot');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.goto('/metrics');
  console.log('[visual] NAVIGATE: Loaded /metrics');

  await page.waitForSelector('text=Performance Budgets');
  console.log('[visual] WAIT: metrics content rendered');

  await settleAnimations(page);
  console.log('[visual] CAPTURE: metrics page');

  await expect(page).toHaveScreenshot('metrics.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] PASS: metrics snapshot captured');
});

test('visual: component snapshots (stat card, worker cards)', async ({ page }) => {
  console.log('[visual] TEST START: component snapshots');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.goto('/');
  console.log('[visual] NAVIGATE: Loaded /');

  const statCard = page.locator('[data-testid="stat-card"]').first();
  await expect(statCard).toBeVisible();
  await expect(statCard).toHaveScreenshot('stat-card.png', { threshold: 0.2 });
  console.log('[visual] CAPTURE: stat card');

  await page.goto('/workers');
  console.log('[visual] NAVIGATE: Loaded /workers');

  const healthyCard = page.locator('[data-worker-id="worker-1"]');
  const unhealthyCard = page.locator('[data-worker-id="worker-3"]');
  await expect(healthyCard).toBeVisible();
  await expect(unhealthyCard).toBeVisible();

  await expect(healthyCard).toHaveScreenshot('worker-card-healthy.png', { threshold: 0.2 });
  console.log('[visual] CAPTURE: worker card (healthy)');

  await expect(unhealthyCard).toHaveScreenshot('worker-card-unreachable.png', { threshold: 0.2 });
  console.log('[visual] CAPTURE: worker card (unreachable)');

  console.log('[visual] PASS: component snapshots captured');
});

test('visual: error and empty states', async ({ page }) => {
  console.log('[visual] TEST START: error and empty state snapshots');

  await page.route('**/status', async (route) => {
    console.log('[mock] Intercepting /status (500)');
    await route.fulfill({ status: 500, body: 'boom', contentType: 'text/plain' });
  });

  await page.goto('/workers');
  console.log('[visual] NAVIGATE: Loaded /workers (error state)');

  const errorState = page.locator('[data-testid="error-state"]');
  await expect(errorState).toBeVisible();
  await expect(errorState).toHaveScreenshot('error-state.png', { threshold: 0.2 });
  console.log('[visual] CAPTURE: error state');

  await page.unroute('**/status');
  const emptyStatus = { ...mockStatusResponse, workers: [] };
  await mockApiResponses(page, { status: emptyStatus });

  await page.goto('/workers');
  console.log('[visual] NAVIGATE: Loaded /workers (empty state)');

  await expect(page.getByText('No workers configured')).toBeVisible();
  await expect(page.locator('text=No workers configured')).toHaveScreenshot('empty-state.png', { threshold: 0.2 });
  console.log('[visual] CAPTURE: empty state');

  console.log('[visual] PASS: error and empty state snapshots captured');
});

test('visual: mobile dashboard and navigation drawer', async ({ page }) => {
  console.log('[visual] TEST START: mobile dashboard and navigation drawer');

  await mockApiResponses(page);
  console.log('[visual] MOCK: status/health/ready/budget/metrics');

  await page.setViewportSize({ width: 375, height: 667 });
  console.log('[visual] VIEWPORT: 375x667');

  await page.goto('/');
  console.log('[visual] NAVIGATE: Loaded /');

  await page.waitForSelector('[data-testid="stat-card"]');
  await settleAnimations(page);
  await expect(page).toHaveScreenshot('dashboard-mobile.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] CAPTURE: mobile dashboard');

  await page.click('[data-testid="hamburger-menu"]');
  await expect(page.locator('[data-testid="sidebar"]')).toBeVisible();
  await settleAnimations(page);

  await expect(page).toHaveScreenshot('navigation-drawer-mobile.png', { fullPage: true, threshold: 0.2 });
  console.log('[visual] CAPTURE: navigation drawer mobile');

  console.log('[visual] PASS: mobile snapshots captured');
});

// TODO: Add light mode snapshots after ngl.8 (theme toggle) is implemented.
