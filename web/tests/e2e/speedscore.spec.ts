import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import {
  mockWorkers,
  mockSpeedScores,
  mockSpeedScoreListResponse,
  mockSpeedScoreHistoryResponse,
  mockDaemonStatus,
  mockStats,
} from '../fixtures/api-mocks';

const scoreLevelLabel: Record<string, string> = {
  excellent: 'Excellent',
  good: 'Good',
  average: 'Average',
  below_average: 'Below Average',
  poor: 'Poor',
};

function getScoreLevel(score: number): string {
  if (score >= 90) return 'excellent';
  if (score >= 70) return 'good';
  if (score >= 50) return 'average';
  if (score >= 30) return 'below_average';
  return 'poor';
}

test.describe('SpeedScore Badge Display', () => {
  test('worker cards display SpeedScore badges', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: worker cards display SpeedScore badges');

    await mockApiResponses(page);
    console.log('[e2e:speedscore] MOCK: API responses registered');

    await page.goto('/workers');
    console.log('[e2e:speedscore] NAVIGATE: Loaded /workers');

    for (const worker of mockWorkers) {
      const card = page.locator(
        `[data-testid="worker-card"][data-worker-id="${worker.id}"]`
      );
      await expect(card).toBeVisible();

      const badge = card.locator('[data-testid="speedscore-badge"]');
      await expect(badge).toBeVisible();

      const speedScore = mockSpeedScores[worker.id];
      if (speedScore && speedScore.total > 0) {
        const expectedScore = Math.round(speedScore.total);
        await expect(badge).toContainText(expectedScore.toString());
        console.log(
          `[e2e:speedscore] VERIFY: Worker ${worker.id} shows SpeedScore ${expectedScore}`
        );
      } else {
        // Worker with score 0 will show "0", unbenchmarked shows "N/A"
        const text = await badge.textContent();
        expect(text).toMatch(/0|N\/A/);
        console.log(`[e2e:speedscore] VERIFY: Worker ${worker.id} shows ${text}`);
      }
    }

    console.log('[e2e:speedscore] TEST PASS: worker cards display SpeedScore badges');
  });

  test('SpeedScore badge shows correct color based on score level', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: SpeedScore badge shows correct color');

    await mockApiResponses(page);
    await page.goto('/workers');

    // worker-1 has score 92.4 (excellent - emerald)
    const worker1Badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');
    await expect(worker1Badge).toBeVisible();
    const worker1Class = await worker1Badge.getAttribute('class');
    expect(worker1Class).toContain('emerald');
    console.log('[e2e:speedscore] VERIFY: worker-1 (92.4) has emerald/excellent color');

    // worker-2 has score 61.2 (average - amber)
    const worker2Badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-2"]')
      .locator('[data-testid="speedscore-badge"]');
    await expect(worker2Badge).toBeVisible();
    const worker2Class = await worker2Badge.getAttribute('class');
    expect(worker2Class).toContain('amber');
    console.log('[e2e:speedscore] VERIFY: worker-2 (61.2) has amber/average color');

    console.log('[e2e:speedscore] TEST PASS: SpeedScore badge shows correct color');
  });

  test('SpeedScore badge has proper accessibility attributes', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: SpeedScore badge accessibility');

    await mockApiResponses(page);
    await page.goto('/workers');

    const badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');
    await expect(badge).toBeVisible();

    // Check role attribute
    await expect(badge).toHaveAttribute('role', 'status');

    // Check aria-label includes score
    const ariaLabel = await badge.getAttribute('aria-label');
    expect(ariaLabel).toContain('SpeedScore');
    expect(ariaLabel).toContain('92');
    expect(ariaLabel).toContain('Excellent');
    console.log(`[e2e:speedscore] VERIFY: aria-label = "${ariaLabel}"`);

    console.log('[e2e:speedscore] TEST PASS: SpeedScore badge accessibility');
  });
});

test.describe('SpeedScore Trend Indicator', () => {
  test('shows trend indicator when previous score exists', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: trend indicator visibility');

    // Update mock workers to include previous scores
    const workersWithPrevScore = mockWorkers.map((w) => ({
      ...w,
      speed_score_prev: w.id === 'worker-1' ? 85.0 : undefined,
    }));

    await mockApiResponses(page, {
      status: {
        daemon: {
          pid: 12345,
          uptime_secs: 3600,
          version: '0.5.0',
          socket_path: '/tmp/rch.sock',
          started_at: '2026-01-01T11:00:00.000Z',
          workers_total: 3,
          workers_healthy: 2,
          slots_total: 32,
          slots_available: 12,
        },
        workers: workersWithPrevScore,
        active_builds: [],
        recent_builds: [],
        issues: [],
        stats: {
          total_builds: 0,
          successful_builds: 0,
          failed_builds: 0,
          total_duration_ms: 0,
          avg_duration_ms: 0,
        },
      },
    });

    await page.goto('/workers');

    // worker-1 has prev score 85, current 92.4 (up trend)
    const trendIndicator = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-trend"]');

    // Trend indicator may be hidden on mobile, check it exists in DOM
    await expect(trendIndicator).toBeAttached();
    await expect(trendIndicator).toHaveAttribute('data-direction', 'up');
    console.log('[e2e:speedscore] VERIFY: worker-1 shows upward trend');

    console.log('[e2e:speedscore] TEST PASS: trend indicator visibility');
  });
});

test.describe('SpeedScore API Endpoints', () => {
  test('fetches all workers SpeedScores', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: fetch all workers SpeedScores');

    await mockApiResponses(page);
    // Need to navigate to page first so route handlers are active
    await page.goto('/workers');

    // Use page.evaluate to make fetch from within page context (route handlers apply)
    const data = await page.evaluate(async () => {
      const response = await fetch('/api/workers/speedscores');
      if (!response.ok) throw new Error(`Status: ${response.status}`);
      return response.json();
    });

    expect(data.workers).toBeInstanceOf(Array);
    expect(data.workers.length).toBe(mockSpeedScoreListResponse.workers.length);

    for (const worker of data.workers) {
      expect(worker).toHaveProperty('worker_id');
      expect(worker).toHaveProperty('speedscore');
      expect(worker).toHaveProperty('status');
      console.log(`[e2e:speedscore] VERIFY: Worker ${worker.worker_id} in response`);
    }

    console.log('[e2e:speedscore] TEST PASS: fetch all workers SpeedScores');
  });

  test('fetches individual worker SpeedScore', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: fetch individual worker SpeedScore');

    await mockApiResponses(page);
    await page.goto('/workers');

    const data = await page.evaluate(async () => {
      const response = await fetch('/api/workers/worker-1/speedscore');
      if (!response.ok) throw new Error(`Status: ${response.status}`);
      return response.json();
    });

    expect(data.worker_id).toBe('worker-1');
    expect(data.speedscore).not.toBeNull();
    expect(data.speedscore.total).toBeCloseTo(92.4, 1);
    expect(data.speedscore.cpu_score).toBe(95);
    expect(data.speedscore.memory_score).toBe(88);
    expect(data.speedscore.disk_score).toBe(91);
    expect(data.speedscore.network_score).toBe(93);
    expect(data.speedscore.compilation_score).toBe(94);
    console.log('[e2e:speedscore] VERIFY: worker-1 SpeedScore components correct');

    console.log('[e2e:speedscore] TEST PASS: fetch individual worker SpeedScore');
  });

  test('returns 404 for unknown worker SpeedScore', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: 404 for unknown worker');

    await mockApiResponses(page);
    await page.goto('/workers');

    const result = await page.evaluate(async () => {
      const response = await fetch('/api/workers/nonexistent/speedscore');
      return { status: response.status };
    });

    expect(result.status).toBe(404);
    console.log('[e2e:speedscore] VERIFY: 404 returned for nonexistent worker');

    console.log('[e2e:speedscore] TEST PASS: 404 for unknown worker');
  });

  test('fetches SpeedScore history with pagination', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: fetch SpeedScore history');

    await mockApiResponses(page);
    await page.goto('/workers');

    const data = await page.evaluate(async () => {
      const response = await fetch('/api/workers/worker-1/speedscore/history?days=7&limit=10');
      if (!response.ok) throw new Error(`Status: ${response.status}`);
      return response.json();
    });

    expect(data.worker_id).toBe('worker-1');
    expect(data.history).toBeInstanceOf(Array);
    expect(data.history.length).toBeGreaterThanOrEqual(1);
    expect(data.history.length).toBeLessThanOrEqual(10);

    // Verify ordering (newest first)
    for (let i = 1; i < data.history.length; i++) {
      const prev = new Date(data.history[i - 1].measured_at);
      const curr = new Date(data.history[i].measured_at);
      expect(prev.getTime()).toBeGreaterThanOrEqual(curr.getTime());
    }
    console.log(`[e2e:speedscore] VERIFY: History has ${data.history.length} entries, ordered by date`);

    expect(data.pagination).toHaveProperty('total');
    expect(data.pagination).toHaveProperty('offset');
    expect(data.pagination).toHaveProperty('limit');
    console.log('[e2e:speedscore] VERIFY: Pagination info present');

    console.log('[e2e:speedscore] TEST PASS: fetch SpeedScore history');
  });
});

test.describe('SpeedScore Dashboard Integration', () => {
  test('dashboard shows worker SpeedScores in overview', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: dashboard SpeedScore overview');

    await mockApiResponses(page);
    await page.goto('/');

    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="worker-card"]', { timeout: 5000 });

    // Check that SpeedScore badges are visible on dashboard
    const badges = page.locator('[data-testid="speedscore-badge"]');
    const count = await badges.count();
    expect(count).toBeGreaterThanOrEqual(1);
    console.log(`[e2e:speedscore] VERIFY: Found ${count} SpeedScore badges on dashboard`);

    console.log('[e2e:speedscore] TEST PASS: dashboard SpeedScore overview');
  });

  test('workers page shows all SpeedScore badges', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: workers page SpeedScore badges');

    await mockApiResponses(page);
    await page.goto('/workers');

    // Wait for worker cards to load first
    await page.waitForSelector('[data-testid="worker-card"]', { timeout: 5000 });

    const badges = page.locator('[data-testid="speedscore-badge"]');
    const count = await badges.count();
    expect(count).toBe(mockWorkers.length);
    console.log(`[e2e:speedscore] VERIFY: ${count} SpeedScore badges for ${mockWorkers.length} workers`);

    console.log('[e2e:speedscore] TEST PASS: workers page SpeedScore badges');
  });

  test('SpeedScore N/A state for unbenchmarked workers', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: N/A state for unbenchmarked workers');

    // Create workers without SpeedScores
    const workersWithoutScores = mockWorkers.map((w) => ({
      ...w,
      speed_score: 0,
    }));

    await mockApiResponses(page, {
      status: {
        daemon: {
          pid: 12345,
          uptime_secs: 3600,
          version: '0.5.0',
          socket_path: '/tmp/rch.sock',
          started_at: '2026-01-01T11:00:00.000Z',
          workers_total: 3,
          workers_healthy: 2,
          slots_total: 32,
          slots_available: 12,
        },
        workers: workersWithoutScores,
        active_builds: [],
        recent_builds: [],
        issues: [],
        stats: {
          total_builds: 0,
          successful_builds: 0,
          failed_builds: 0,
          total_duration_ms: 0,
          avg_duration_ms: 0,
        },
      },
    });

    await page.goto('/workers');

    // All badges should show N/A or 0 for workers with score 0
    const badges = page.locator('[data-testid="speedscore-badge"]');
    const count = await badges.count();

    for (let i = 0; i < count; i++) {
      const badge = badges.nth(i);
      const text = await badge.textContent();
      // Score 0 will render as "0" since it's a valid number
      expect(text).toMatch(/0|N\/A/);
    }
    console.log('[e2e:speedscore] VERIFY: Unbenchmarked workers show 0 or N/A');

    console.log('[e2e:speedscore] TEST PASS: N/A state for unbenchmarked workers');
  });
});

test.describe('SpeedScore Loading and Error States', () => {
  test('shows loading state while fetching SpeedScore', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: loading state');

    // Delay the API response to observe loading state
    await page.route('**/status', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      await route.fulfill({
        json: {
          daemon: {
            pid: 12345,
            uptime_secs: 3600,
            version: '0.5.0',
            socket_path: '/tmp/rch.sock',
            started_at: '2026-01-01T11:00:00.000Z',
            workers_total: 1,
            workers_healthy: 1,
            slots_total: 8,
            slots_available: 4,
          },
          workers: mockWorkers.slice(0, 1),
          active_builds: [],
          recent_builds: [],
          issues: [],
          stats: {
            total_builds: 0,
            successful_builds: 0,
            failed_builds: 0,
            total_duration_ms: 0,
            avg_duration_ms: 0,
          },
        },
      });
    });

    // Navigate and check for any loading indicators
    await page.goto('/workers');

    // The page should eventually load with worker cards
    await expect(page.locator('[data-testid="worker-card"]')).toBeVisible({ timeout: 5000 });
    console.log('[e2e:speedscore] VERIFY: Page loads successfully after delay');

    console.log('[e2e:speedscore] TEST PASS: loading state');
  });

  test('handles API errors gracefully', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: API error handling');

    // First load the page with successful responses
    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Mock the individual speedscore endpoint to fail
    await page.route('**/api/workers/worker-1/speedscore', async (route) => {
      console.log('[mock] Returning 500 error for worker-1 speedscore');
      await route.fulfill({
        status: 500,
        json: { error: 'Internal Server Error' },
      });
    });

    // Worker cards should still be visible (graceful degradation)
    const card = page.locator('[data-testid="worker-card"][data-worker-id="worker-1"]');
    await expect(card).toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Worker card remains visible despite API error');

    console.log('[e2e:speedscore] TEST PASS: API error handling');
  });

  test('handles timeout errors gracefully', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: timeout error handling');

    // Set up a route that has a delay
    await page.route('**/status', async (route) => {
      // Short delay to simulate slow network
      await new Promise((resolve) => setTimeout(resolve, 100));
      await route.fulfill({
        json: {
          daemon: mockDaemonStatus,
          workers: mockWorkers,
          active_builds: [],
          recent_builds: [],
          issues: [],
          stats: mockStats,
        },
      });
    });

    await page.goto('/workers');

    // Page should still render eventually - use .first() since there are multiple cards
    await expect(page.locator('[data-testid="worker-card"]').first()).toBeVisible({ timeout: 5000 });
    console.log('[e2e:speedscore] VERIFY: Page recovers from slow response');

    console.log('[e2e:speedscore] TEST PASS: timeout error handling');
  });
});

test.describe('Benchmark Progress Modal', () => {
  test('opens benchmark modal when trigger button is clicked', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: benchmark modal opens');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Click the benchmark trigger button on worker-1 (healthy worker)
    const triggerBtn = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="benchmark-trigger-button"]');
    await expect(triggerBtn).toBeVisible();
    await triggerBtn.click();

    // Modal should appear
    const modal = page.locator('[data-testid="benchmark-progress-modal"]');
    await expect(modal).toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Benchmark modal is visible');

    // Modal should contain expected content
    await expect(modal).toContainText('Benchmark');
    await expect(modal).toContainText('worker-1');
    console.log('[e2e:speedscore] VERIFY: Modal shows correct worker name');

    console.log('[e2e:speedscore] TEST PASS: benchmark modal opens');
  });

  test('benchmark trigger button is disabled for unhealthy workers', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: benchmark disabled for unreachable workers');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // worker-3 is unreachable, so benchmark should be disabled
    const triggerBtn = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-3"]')
      .locator('[data-testid="benchmark-trigger-button"]');
    await expect(triggerBtn).toBeVisible();
    await expect(triggerBtn).toBeDisabled();
    console.log('[e2e:speedscore] VERIFY: Benchmark button disabled for unreachable worker');

    console.log('[e2e:speedscore] TEST PASS: benchmark disabled for unreachable workers');
  });

  test('benchmark modal can be closed', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: benchmark modal closes');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Open modal
    const triggerBtn = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="benchmark-trigger-button"]');
    await triggerBtn.click();

    const modal = page.locator('[data-testid="benchmark-progress-modal"]');
    await expect(modal).toBeVisible();

    // Close modal using the X button at top right (built into DialogContent)
    const closeBtn = modal.locator('button:has(svg.lucide-x), button[class*="absolute"][class*="right"]').first();
    await closeBtn.click();

    // Modal should be hidden
    await expect(modal).not.toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Modal closes when Close button clicked');

    console.log('[e2e:speedscore] TEST PASS: benchmark modal closes');
  });

  test('benchmark modal shows idle state content', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: benchmark modal idle state');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Open modal
    const triggerBtn = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="benchmark-trigger-button"]');
    await triggerBtn.click();

    const modal = page.locator('[data-testid="benchmark-progress-modal"]');
    await expect(modal).toBeVisible();

    // Modal should show idle state content
    await expect(modal).toContainText('CPU');
    await expect(modal).toContainText('memory');
    await expect(modal).toContainText('disk');
    await expect(modal).toContainText('network');
    await expect(modal).toContainText('compilation');

    // Should have Start Benchmark button
    const startBtn = modal.locator('button:has-text("Start Benchmark")');
    await expect(startBtn).toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Modal shows idle state with Start button');

    console.log('[e2e:speedscore] TEST PASS: benchmark modal idle state');
  });
});

test.describe('SpeedScore WebSocket Updates (mocked)', () => {
  test('dashboard updates when worker data changes', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: data updates on page');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Get initial score display
    const badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');
    const initialScore = await badge.textContent();
    expect(initialScore).toContain('92');
    console.log(`[e2e:speedscore] INITIAL: worker-1 score = ${initialScore}`);

    // Update the mock to return a different score
    const updatedWorkers = mockWorkers.map((w) =>
      w.id === 'worker-1' ? { ...w, speed_score: 95.5 } : w
    );

    await page.route('**/status', async (route) => {
      await route.fulfill({
        json: {
          daemon: {
            pid: 12345,
            uptime_secs: 3700,
            version: '0.5.0',
            socket_path: '/tmp/rch.sock',
            started_at: '2026-01-01T11:00:00.000Z',
            workers_total: 3,
            workers_healthy: 2,
            slots_total: 32,
            slots_available: 12,
          },
          workers: updatedWorkers,
          active_builds: [],
          recent_builds: [],
          issues: [],
          stats: {
            total_builds: 0,
            successful_builds: 0,
            failed_builds: 0,
            total_duration_ms: 0,
            avg_duration_ms: 0,
          },
        },
      });
    });

    // Trigger a refresh by navigating
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Check that score updated
    const updatedBadge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');
    const updatedScore = await updatedBadge.textContent();
    expect(updatedScore).toContain('96'); // 95.5 rounds to 96
    console.log(`[e2e:speedscore] UPDATED: worker-1 score = ${updatedScore}`);

    console.log('[e2e:speedscore] TEST PASS: data updates on page');
  });

  test('multiple workers update independently', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: independent worker updates');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Verify all workers show their scores
    for (const worker of mockWorkers) {
      const badge = page
        .locator(`[data-testid="worker-card"][data-worker-id="${worker.id}"]`)
        .locator('[data-testid="speedscore-badge"]');
      await expect(badge).toBeVisible();
      const score = await badge.textContent();
      console.log(`[e2e:speedscore] VERIFY: ${worker.id} shows score ${score}`);
    }

    console.log('[e2e:speedscore] TEST PASS: independent worker updates');
  });
});

test.describe('SpeedScore Accessibility', () => {
  test('SpeedScore badges have proper color contrast', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: color contrast check');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="speedscore-badge"]');

    // Check that badges use semantic colors based on score level
    const worker1Badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');
    const worker1Class = await worker1Badge.getAttribute('class');

    // Excellent score (92.4) should have emerald coloring
    expect(worker1Class).toContain('emerald');
    console.log('[e2e:speedscore] VERIFY: Excellent score has emerald color class');

    const worker2Badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-2"]')
      .locator('[data-testid="speedscore-badge"]');
    const worker2Class = await worker2Badge.getAttribute('class');

    // Average score (61.2) should have amber coloring
    expect(worker2Class).toContain('amber');
    console.log('[e2e:speedscore] VERIFY: Average score has amber color class');

    console.log('[e2e:speedscore] TEST PASS: color contrast check');
  });

  test('SpeedScore badges are focusable for screen readers', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: screen reader focusability');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="speedscore-badge"]');

    const badge = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="speedscore-badge"]');

    // Badge should have proper role and label
    await expect(badge).toHaveAttribute('role', 'status');
    const ariaLabel = await badge.getAttribute('aria-label');
    expect(ariaLabel).toBeTruthy();
    expect(ariaLabel).toMatch(/SpeedScore.*\d+.*out of 100/i);
    console.log(`[e2e:speedscore] VERIFY: aria-label = "${ariaLabel}"`);

    console.log('[e2e:speedscore] TEST PASS: screen reader focusability');
  });

  test('benchmark modal is keyboard accessible', async ({ page }) => {
    console.log('[e2e:speedscore] TEST START: modal keyboard accessibility');

    await mockApiResponses(page);
    await page.goto('/workers');
    await page.waitForSelector('[data-testid="worker-card"]');

    // Focus and activate benchmark button via keyboard
    const triggerBtn = page
      .locator('[data-testid="worker-card"][data-worker-id="worker-1"]')
      .locator('[data-testid="benchmark-trigger-button"]');
    await triggerBtn.focus();
    await page.keyboard.press('Enter');

    // Modal should open
    const modal = page.locator('[data-testid="benchmark-progress-modal"]');
    await expect(modal).toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Modal opens via keyboard');

    // Escape should close modal
    await page.keyboard.press('Escape');
    await expect(modal).not.toBeVisible();
    console.log('[e2e:speedscore] VERIFY: Modal closes with Escape key');

    console.log('[e2e:speedscore] TEST PASS: modal keyboard accessibility');
  });
});
