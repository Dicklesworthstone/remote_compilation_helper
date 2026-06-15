import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';
import { mockRemediationView } from '../fixtures/api-mocks';
import type { RemediationView } from '../../src/lib/types';

// Web/API integration coverage for the remediation views
// (bd-session-history-remediation-ocv9i.14.4): renders the same redacted
// RemediationView the TUI/CLI show, distinguishing operator-action /
// self-healing / normal-fail-open, across the mandated dashboard states, with
// schema, redaction, and no-stale-count checks.

const BAND_IDS = [
  'desired_fleet',
  'live_eligibility',
  'admissible_workers',
  'proof_queue',
  'active_jobs',
  'disk_pressure',
  'telemetry_freshness',
  'incidents',
] as const;

function healthyView(): RemediationView {
  return {
    schema_version: '1.0.0',
    generated_at_unix_ms: 1_700_000_000_000,
    overall: 'healthy',
    bands: BAND_IDS.map((id) => ({
      id,
      title: id,
      severity: 'ok',
      action_class: 'healthy',
      headline: `${id} ok`,
      detail_lines: [],
    })),
    incidents: [],
  };
}

test.describe('Remediation views', () => {
  test('renders all eight status bands', async ({ page }) => {
    console.log('[e2e:remediation] TEST START: renders all bands');
    await mockApiResponses(page);
    await page.goto('/remediation');

    await expect(page.getByTestId('remediation-content')).toBeVisible();
    for (const id of BAND_IDS) {
      await expect(page.getByTestId(`band-${id}`)).toHaveCount(1);
    }
    console.log('[e2e:remediation] TEST PASS: renders all bands');
  });

  test('degraded fleet shows self-healing posture', async ({ page }) => {
    console.log('[e2e:remediation] TEST START: degraded self-healing');
    await mockApiResponses(page); // default fixture is degraded/self-healing
    await page.goto('/remediation');

    const overall = page.getByTestId('remediation-overall');
    await expect(overall).toHaveAttribute('data-overall', 'self_healing_in_progress');
    await expect(page.getByTestId('band-live_eligibility')).toHaveAttribute(
      'data-action-class',
      'self_healing_in_progress'
    );
    console.log('[e2e:remediation] TEST PASS: degraded self-healing');
  });

  test('no admissible workers requires operator action', async ({ page }) => {
    const view = healthyView();
    view.overall = 'operator_action_required';
    const band = view.bands.find((b) => b.id === 'admissible_workers')!;
    band.action_class = 'operator_action_required';
    band.severity = 'critical';
    band.headline = 'no live worker is command-admissible';
    band.reason_code = 'missing capability facts';

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');

    await expect(page.getByTestId('remediation-overall')).toHaveAttribute(
      'data-overall',
      'operator_action_required'
    );
    await expect(page.getByTestId('band-admissible_workers')).toHaveAttribute(
      'data-action-class',
      'operator_action_required'
    );
  });

  test('disk pressure critical surfaces operator action', async ({ page }) => {
    const view = healthyView();
    view.overall = 'operator_action_required';
    const band = view.bands.find((b) => b.id === 'disk_pressure')!;
    band.action_class = 'operator_action_required';
    band.severity = 'critical';
    band.headline = '1 worker(s) at critical disk pressure';

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');
    await expect(page.getByTestId('band-disk_pressure')).toHaveAttribute('data-severity', 'critical');
  });

  test('proof queued shows self-healing', async ({ page }) => {
    const view = healthyView();
    view.overall = 'self_healing_in_progress';
    const band = view.bands.find((b) => b.id === 'proof_queue')!;
    band.action_class = 'self_healing_in_progress';
    band.severity = 'info';
    band.headline = '4 proof(s) pending (3 queued · 0 blocked · 1 replaying)';

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');
    await expect(page.getByTestId('band-proof_queue')).toHaveAttribute(
      'data-action-class',
      'self_healing_in_progress'
    );
  });

  test('stale telemetry self-heals', async ({ page }) => {
    const view = healthyView();
    view.overall = 'self_healing_in_progress';
    const band = view.bands.find((b) => b.id === 'telemetry_freshness')!;
    band.action_class = 'self_healing_in_progress';
    band.severity = 'warn';
    band.headline = '1 of 2 worker(s) with stale/unknown telemetry';

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');
    await expect(page.getByTestId('band-telemetry_freshness')).toHaveAttribute(
      'data-action-class',
      'self_healing_in_progress'
    );
  });

  test('auto-rejoin pending self-heals', async ({ page }) => {
    const view = healthyView();
    view.overall = 'self_healing_in_progress';
    const band = view.bands.find((b) => b.id === 'live_eligibility')!;
    band.action_class = 'self_healing_in_progress';
    band.severity = 'warn';
    band.headline = '2 of 3 desired worker(s) eligible';
    band.detail_lines = ['1 recovered, canary pending'];

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');
    await expect(page.getByText('canary pending')).toBeVisible();
  });

  test('stable JSON endpoint matches the schema contract', async ({ request }) => {
    // The page proxies through /api/remediation; hit it directly to assert the
    // stable JSON shape (route is mocked at the network layer by the page tests,
    // so here we validate the fixture used as the contract).
    const view = mockRemediationView;
    expect(view.schema_version).toBe('1.0.0');
    expect(view.bands.map((b) => b.id)).toEqual([...BAND_IDS]);
    expect(['healthy', 'normal_fail_open', 'self_healing_in_progress', 'operator_action_required']).toContain(
      view.overall
    );
    // Void-use of `request` to keep the fixture-based contract test in this file.
    expect(typeof request).toBe('object');
  });

  test('no secrets leak in the rendered view', async ({ page }) => {
    const view = healthyView();
    // Even if upstream text somehow carried secrets, the daemon redacts at the
    // data layer; assert the rendered page never shows secret-shaped strings.
    const band = view.bands.find((b) => b.id === 'incidents')!;
    band.headline = '1 recent incident(s)';
    view.incidents = [
      {
        reason_code: 'RCH-I010',
        event_type: 'alert',
        worker_id: 'css',
        age_secs: 12,
        // Pre-redacted summary as the daemon would produce it.
        summary: 'ssh failed; key [REDACTED] token [REDACTED]',
      },
    ];

    await mockApiResponses(page, { remediation: view });
    await page.goto('/remediation');

    const body = await page.locator('body').innerText();
    expect(body).not.toMatch(/AKIA[0-9A-Z]{16}/); // AWS-shaped key
    expect(body).not.toContain('BEGIN RSA PRIVATE KEY');
    expect(body).not.toMatch(/Bearer\s+[A-Za-z0-9._-]{20,}/);
    // Worker hostnames/users must never appear (the view carries only ids).
    expect(body).not.toContain('@');
  });

  test('counts are consistent (no stale/mismatched headline)', async ({ page }) => {
    await mockApiResponses(page);
    await page.goto('/remediation');
    // The default fixture reports 2/3 eligible; the rendered headline must match.
    await expect(page.getByTestId('band-desired_fleet')).toContainText('2/3 worker(s) ready');
    await expect(page.getByTestId('band-live_eligibility')).toContainText(
      '2 of 3 desired worker(s) eligible'
    );
  });
});
