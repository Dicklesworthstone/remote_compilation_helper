import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import { mockWorkers, mockStatusResponse } from '../fixtures/api-mocks';

const statusLabel: Record<string, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  unreachable: 'Unreachable',
  draining: 'Draining',
  disabled: 'Disabled',
};

const circuitLabel: Record<string, string> = {
  closed: 'Closed',
  half_open: 'Half-Open',
  open: 'Open',
};

test('workers grid displays all workers', async ({ page }) => {
  console.log('[e2e:workers] TEST START: workers grid displays all workers');

  await mockApiResponses(page);
  console.log('[e2e:workers] MOCK: API responses registered');

  await page.goto('/workers');
  console.log('[e2e:workers] NAVIGATE: Loaded /workers');

  const workerCards = page.locator('[data-testid="worker-card"]');
  const count = await workerCards.count();
  console.log(`[e2e:workers] FOUND: ${count} worker cards`);

  expect(count).toBe(mockWorkers.length);
  console.log('[e2e:workers] TEST PASS: workers grid displays all workers');
});

test('worker health badges and circuit states are visible', async ({ page }) => {
  console.log('[e2e:workers] TEST START: worker health badges and circuit states are visible');

  await mockApiResponses(page);
  console.log('[e2e:workers] MOCK: API responses registered');

  await page.goto('/workers');
  console.log('[e2e:workers] NAVIGATE: Loaded /workers');

  for (const worker of mockWorkers) {
    const card = page.locator(
      `[data-testid="worker-card"][data-worker-id="${worker.id}"]`
    );
    await expect(card).toBeVisible();

    const badge = card.locator('[data-testid="worker-status"]');
    await expect(badge).toHaveAttribute('data-status', worker.status);
    await expect(badge).toContainText(statusLabel[worker.status]);
    console.log(
      `[e2e:workers] VERIFY: Worker ${worker.id} has badge ${statusLabel[worker.status]}`
    );

    const circuit = card.locator('[data-testid="worker-circuit"]');
    await expect(circuit).toHaveAttribute('data-circuit', worker.circuit_state);
    await expect(circuit).toContainText(`Circuit: ${circuitLabel[worker.circuit_state]}`);
    console.log(
      `[e2e:workers] VERIFY: Worker ${worker.id} circuit ${circuitLabel[worker.circuit_state]}`
    );
  }

  console.log('[e2e:workers] TEST PASS: worker health badges and circuit states visible');
});

test('worker slot usage and errors render correctly', async ({ page }) => {
  console.log('[e2e:workers] TEST START: worker slot usage and errors render correctly');

  await mockApiResponses(page);
  console.log('[e2e:workers] MOCK: API responses registered');

  await page.goto('/workers');
  console.log('[e2e:workers] NAVIGATE: Loaded /workers');

  for (const worker of mockWorkers) {
    const card = page.locator(
      `[data-testid="worker-card"][data-worker-id="${worker.id}"]`
    );
    await expect(card).toBeVisible();

    const slots = card.locator('[data-testid="worker-slots"]');
    await expect(slots).toContainText(`Slots Used`);
    await expect(slots).toContainText(`${worker.used_slots} / ${worker.total_slots}`);
    console.log(
      `[e2e:workers] VERIFY: Worker ${worker.id} slots ${worker.used_slots}/${worker.total_slots}`
    );

    const slotsBar = card.locator('[data-testid="worker-slots-bar"]');
    await expect(slotsBar).toBeVisible();

    if (worker.last_error) {
      const error = card.locator('[data-testid="worker-error"]');
      await expect(error).toContainText(worker.last_error);
      console.log(
        `[e2e:workers] VERIFY: Worker ${worker.id} error message displayed`
      );
    }
  }

  console.log('[e2e:workers] TEST PASS: worker slot usage and errors render correctly');
});

test('workers page shows empty state when no workers configured', async ({ page }) => {
  console.log('[e2e:workers] TEST START: workers page shows empty state');

  const emptyStatus = {
    ...mockStatusResponse,
    workers: [],
  };

  await mockApiResponses(page, { status: emptyStatus });
  console.log('[e2e:workers] MOCK: API responses registered with empty workers');

  await page.goto('/workers');
  console.log('[e2e:workers] NAVIGATE: Loaded /workers');

  await expect(page.getByText('No workers configured')).toBeVisible();
  await expect(page.getByText('Add workers to your config to get started.')).toBeVisible();
  console.log('[e2e:workers] TEST PASS: empty state visible');
});

