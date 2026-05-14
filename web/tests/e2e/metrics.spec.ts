import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import { mockBudgetResponse, mockMetricsText } from '../fixtures/api-mocks';

const daemonMetricsUrl = (url: URL) =>
  url.origin === 'http://localhost:9100' && url.pathname === '/metrics';

test.describe('Metrics Page', () => {
  test('metrics page loads and displays metric cards', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: metrics page loads and displays metric cards');
    await mockApiResponses(page);

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] WAIT: Metric cards visible');
    const metricCards = page.locator('[data-testid="metric-card"]');
    await expect(metricCards).toHaveCount(6);

    console.log('[e2e:metrics] VERIFY: System Snapshot section visible');
    await expect(page.getByText('System Snapshot')).toBeVisible();

    console.log('[e2e:metrics] VERIFY: Metric card labels present');
    await expect(metricCards.filter({ hasText: 'Total Builds' })).toBeVisible();
    await expect(metricCards.filter({ hasText: 'Success Rate' })).toBeVisible();
    await expect(metricCards.filter({ hasText: 'Average Build Time' })).toBeVisible();
    await expect(metricCards.filter({ hasText: 'Active Builds' })).toBeVisible();
    await expect(metricCards.filter({ hasText: 'Workers Online' })).toBeVisible();
    await expect(metricCards.filter({ hasText: 'Data Moved' })).toBeVisible();

    console.log('[e2e:metrics] TEST PASS: metrics page loads and displays metric cards');
  });

  test('performance budgets section displays correctly', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: performance budgets section displays correctly');
    await mockApiResponses(page);

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] WAIT: Performance Budgets section visible');
    await expect(page.getByText('Performance Budgets')).toBeVisible();

    console.log('[e2e:metrics] VERIFY: Budget cards displayed');
    for (const budget of mockBudgetResponse.budgets) {
      const budgetName = budget.name
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (char) => char.toUpperCase());
      await expect(page.getByText(budgetName)).toBeVisible();
      console.log(`[e2e:metrics] VERIFY: Budget ${budgetName} visible`);
    }

    console.log('[e2e:metrics] VERIFY: Budget metrics visible');
    await expect(page.getByText('Budget', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('Typical (p50)').first()).toBeVisible();
    await expect(page.getByText('Slow (p95)').first()).toBeVisible();
    await expect(page.getByText('Worst (p99)').first()).toBeVisible();

    console.log('[e2e:metrics] TEST PASS: performance budgets section displays correctly');
  });

  test('safety rails section shows circuit breaker status', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: safety rails section shows circuit breaker status');
    await mockApiResponses(page);

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] VERIFY: Safety Rails section visible');
    await expect(page.getByText('Safety Rails')).toBeVisible();
    await expect(page.getByText('Circuit breakers protect you from flaky workers')).toBeVisible();

    console.log('[e2e:metrics] VERIFY: Circuit breaker counts visible');
    await expect(page.getByText(/\d+ open/)).toBeVisible();
    await expect(page.getByText(/\d+ half-open/)).toBeVisible();

    console.log('[e2e:metrics] TEST PASS: safety rails section shows circuit breaker status');
  });

  test('raw metrics expandable section works', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: raw metrics expandable section works');
    await mockApiResponses(page);

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] VERIFY: Raw Prometheus Metrics section visible');
    await expect(page.getByText('Raw Prometheus Metrics')).toBeVisible();

    console.log('[e2e:metrics] VERIFY: Raw metrics initially collapsed');
    const detailsElement = page.locator('details');
    await expect(detailsElement).toBeVisible();
    await expect(page.getByText('Hidden by default')).toBeVisible();

    console.log('[e2e:metrics] ACTION: Click to expand raw metrics');
    await page.getByText('Show raw metrics').click();

    console.log('[e2e:metrics] VERIFY: Raw metrics content visible');
    await expect(page.getByText('rch_builds_total')).toBeVisible();

    console.log('[e2e:metrics] TEST PASS: raw metrics expandable section works');
  });

  test('metrics page shows error state with retry', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: metrics page shows error state with retry');

    let requestCount = 0;
    await page.route('**/budget', async (route) => {
      requestCount += 1;
      if (requestCount === 1) {
        console.log('[e2e:metrics] MOCK: /budget returns 500');
        await route.fulfill({ status: 500, body: 'daemon offline' });
        return;
      }
      console.log('[e2e:metrics] MOCK: /budget returns success');
      await route.fulfill({ json: mockBudgetResponse });
    });

    await page.route(daemonMetricsUrl, async (route) => {
      await route.fulfill({ body: mockMetricsText, contentType: 'text/plain' });
    });

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] WAIT: Error state visible');
    await expect(page.getByTestId('error-state')).toBeVisible();
    await expect(page.getByText('Failed to load metrics')).toBeVisible();

    console.log('[e2e:metrics] ACTION: Click retry');
    await page.getByRole('button', { name: 'Try Again' }).click();

    console.log('[e2e:metrics] VERIFY: Metrics page recovers');
    await expect(page.locator('[data-testid="metric-card"]')).toHaveCount(6);

    console.log('[e2e:metrics] TEST PASS: metrics page shows error state with retry');
  });

  test('metrics page shows loading skeleton', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: metrics page shows loading skeleton');

    await page.route('**/budget', async (route) => {
      console.log('[e2e:metrics] MOCK: delaying /budget response');
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await route.fulfill({ json: mockBudgetResponse });
    });

    await page.route(daemonMetricsUrl, async (route) => {
      console.log('[e2e:metrics] MOCK: delaying /metrics response');
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await route.fulfill({ body: mockMetricsText, contentType: 'text/plain' });
    });

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] VERIFY: Skeleton visible');
    await expect(page.getByTestId('metrics-skeleton')).toBeVisible();

    console.log('[e2e:metrics] WAIT: Skeleton disappears');
    await expect(page.getByTestId('metrics-skeleton')).toBeHidden({ timeout: 5000 });

    console.log('[e2e:metrics] TEST PASS: metrics page shows loading skeleton');
  });

  test('metrics refresh button triggers data reload', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: metrics refresh button triggers data reload');

    await mockApiResponses(page);
    await page.unroute('**/budget');

    let requestCount = 0;
    await page.route('**/budget', async (route) => {
      requestCount += 1;
      if (requestCount === 1) {
        console.log('[e2e:metrics] MOCK: initial /budget');
        await route.fulfill({ json: mockBudgetResponse });
        return;
      }

      console.log('[e2e:metrics] MOCK: refresh /budget with updated values');
      await new Promise((resolve) => setTimeout(resolve, 500));
      await route.fulfill({
        json: {
          ...mockBudgetResponse,
          status: 'warning',
        },
      });
    });

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] VERIFY: Initial status badge');
    await expect(page.getByText('passing', { exact: true }).first()).toBeVisible();

    console.log('[e2e:metrics] ACTION: Click refresh button');
    const refreshButton = page.getByRole('button', { name: 'Refresh metrics' });
    await refreshButton.click();

    console.log('[e2e:metrics] VERIFY: Updated status badge');
    await expect(page.getByText('warning', { exact: true }).first()).toBeVisible({ timeout: 5000 });

    console.log('[e2e:metrics] TEST PASS: metrics refresh button triggers data reload');
  });

  test('metrics page status badge reflects budget status', async ({ page }) => {
    console.log('[e2e:metrics] TEST START: metrics page status badge reflects budget status');
    await mockApiResponses(page);

    console.log('[e2e:metrics] NAVIGATE: Loading /metrics');
    await page.goto('/metrics');

    console.log('[e2e:metrics] VERIFY: Status badge visible');
    const statusBadge = page.locator('.capitalize').filter({ hasText: /passing|warning|failing/ });
    await expect(statusBadge.first()).toBeVisible();

    console.log('[e2e:metrics] VERIFY: Auto-refresh indicator visible');
    await expect(page.getByText('Auto-refreshing every 5s')).toBeVisible();

    console.log('[e2e:metrics] TEST PASS: metrics page status badge reflects budget status');
  });
});
