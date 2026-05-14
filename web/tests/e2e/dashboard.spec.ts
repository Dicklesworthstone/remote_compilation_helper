import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import { mockStatusResponse } from '../fixtures/api-mocks';

test.describe('Dashboard', () => {
  test('dashboard loads stat cards', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard loads stat cards');
    await mockApiResponses(page);

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] WAIT: Stat cards visible');
    await expect(page.getByTestId('stat-card')).toHaveCount(4);

    console.log('[e2e:dashboard] VERIFY: Stat card labels present');
    await expect(page.getByTestId('stat-card').filter({ hasText: 'Workers' })).toHaveCount(1);
    await expect(page.getByTestId('stat-card').filter({ hasText: 'Available Slots' })).toHaveCount(1);
    await expect(page.getByTestId('stat-card').filter({ hasText: 'Total Builds' })).toHaveCount(1);
    await expect(page.getByTestId('stat-card').filter({ hasText: 'Success Rate' })).toHaveCount(1);

    console.log('[e2e:dashboard] TEST PASS: dashboard loads stat cards');
  });

  test('dashboard workers summary', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard workers summary');
    await mockApiResponses(page);

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] WAIT: Workers section visible');
    await expect(page.getByRole('heading', { name: 'Workers' })).toBeVisible();

    console.log('[e2e:dashboard] VERIFY: Worker cards rendered');
    await expect(page.getByTestId('worker-card')).toHaveCount(3);

    console.log('[e2e:dashboard] VERIFY: Worker statuses visible');
    await expect(page.getByText('Healthy')).toBeVisible();
    await expect(page.getByText('Degraded')).toBeVisible();
    await expect(page.getByText('Unreachable')).toBeVisible();

    console.log('[e2e:dashboard] TEST PASS: dashboard workers summary');
  });

  test('dashboard recent builds table', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard recent builds');
    await mockApiResponses(page);

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] WAIT: Build History table visible');
    await expect(page.getByRole('heading', { name: 'Build History' })).toBeVisible();
    await expect(page.getByRole('table')).toBeVisible();

    console.log('[e2e:dashboard] VERIFY: Build rows and statuses');
    const table = page.getByRole('table');
    await expect(table.getByText('Running', { exact: true })).toBeVisible();
    await expect(table.getByText('Success', { exact: true })).toBeVisible();
    await expect(table.getByText('Failed (1)', { exact: true })).toBeVisible();

    console.log('[e2e:dashboard] TEST PASS: dashboard recent builds');
  });

  test('dashboard error state with retry', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard error state with retry');

    await mockApiResponses(page);
    await page.unroute('**/status');

    let requestCount = 0;
    await page.route('**/status', async (route) => {
      requestCount += 1;
      if (requestCount === 1) {
        console.log('[e2e:dashboard] MOCK: /status returns 500');
        await route.fulfill({ status: 500, body: 'daemon offline' });
        return;
      }

      console.log('[e2e:dashboard] MOCK: /status returns success');
      await route.fulfill({ json: mockStatusResponse });
    });

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] WAIT: Error state visible');
    await expect(page.getByTestId('error-state')).toBeVisible();
    await expect(page.getByText('Failed to connect to daemon')).toBeVisible();

    console.log('[e2e:dashboard] ACTION: Click retry');
    await page.getByRole('button', { name: 'Try Again' }).click();

    console.log('[e2e:dashboard] VERIFY: Dashboard recovers');
    await expect(page.getByTestId('stat-card')).toHaveCount(4);

    console.log('[e2e:dashboard] TEST PASS: dashboard error state with retry');
  });

  test('dashboard loading skeleton', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard loading skeleton');

    await mockApiResponses(page);
    await page.unroute('**/status');

    await page.route('**/status', async (route) => {
      console.log('[e2e:dashboard] MOCK: delaying /status response');
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await route.fulfill({ json: mockStatusResponse });
    });

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] VERIFY: Skeleton visible');
    await expect(page.getByTestId('dashboard-skeleton')).toBeVisible();

    console.log('[e2e:dashboard] WAIT: Skeleton disappears');
    await expect(page.getByTestId('dashboard-skeleton')).toBeHidden({ timeout: 5000 });

    console.log('[e2e:dashboard] TEST PASS: dashboard loading skeleton');
  });

  test('dashboard refresh button triggers reload', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard refresh button');

    await mockApiResponses(page);
    await page.unroute('**/status');

    let requestCount = 0;
    await page.route('**/status', async (route) => {
      requestCount += 1;
      if (requestCount === 1) {
        console.log('[e2e:dashboard] MOCK: initial /status');
        await route.fulfill({ json: mockStatusResponse });
        return;
      }

      console.log('[e2e:dashboard] MOCK: refresh /status');
      await new Promise((resolve) => setTimeout(resolve, 800));
      await route.fulfill({
        json: {
          ...mockStatusResponse,
          stats: {
            ...mockStatusResponse.stats,
            total_builds: mockStatusResponse.stats.total_builds + 1,
          },
        },
      });
    });

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] WAIT: Refresh button visible');
    const refreshButton = page.locator('button[title="Refresh data"]');
    await expect(refreshButton).toBeVisible();

    console.log('[e2e:dashboard] ACTION: Click refresh');
    await refreshButton.click();

    console.log('[e2e:dashboard] VERIFY: Refresh in progress');
    await expect(refreshButton).toBeDisabled();

    const updatedTotal = String(mockStatusResponse.stats.total_builds + 1);
    console.log(`[e2e:dashboard] VERIFY: Total builds updated to ${updatedTotal}`);
    await expect(page.getByText(updatedTotal)).toBeVisible();

    console.log('[e2e:dashboard] TEST PASS: dashboard refresh button');
  });

  test('dashboard responsive mobile', async ({ page }) => {
    console.log('[e2e:dashboard] TEST START: dashboard responsive mobile');
    await mockApiResponses(page);

    console.log('[e2e:dashboard] ACTION: Set mobile viewport');
    await page.setViewportSize({ width: 375, height: 667 });

    console.log('[e2e:dashboard] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:dashboard] VERIFY: Hamburger menu visible');
    await expect(page.getByTestId('hamburger-menu')).toBeVisible();

    console.log('[e2e:dashboard] TEST PASS: dashboard responsive mobile');
  });
});
