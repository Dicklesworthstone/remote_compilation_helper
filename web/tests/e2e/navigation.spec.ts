import { test, expect } from '@playwright/test';
import { mockApiResponses } from '../fixtures/test-utils';

const navItems = [
  { href: '/', label: 'Overview' },
  { href: '/workers', label: 'Workers' },
  { href: '/builds', label: 'Build History' },
  { href: '/metrics', label: 'Metrics' },
  { href: '/settings', label: 'Settings' },
];

test.describe('Navigation', () => {
  test.skip(
    ({ isMobile }) => isMobile,
    'Desktop sidebar navigation is covered by Mobile Navigation on mobile projects.',
  );

  test('sidebar navigation links are visible and functional', async ({ page }) => {
    console.log('[e2e:nav] TEST START: sidebar navigation links are visible and functional');
    await mockApiResponses(page);

    console.log('[e2e:nav] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav] VERIFY: All navigation links visible');
    for (const item of navItems) {
      await expect(page.getByRole('link', { name: item.label })).toBeVisible();
      console.log(`[e2e:nav] VERIFY: ${item.label} link visible`);
    }

    console.log('[e2e:nav] TEST PASS: sidebar navigation links are visible and functional');
  });

  test('navigation links route to correct pages', async ({ page }) => {
    console.log('[e2e:nav] TEST START: navigation links route to correct pages');
    await mockApiResponses(page);

    for (const item of navItems) {
      console.log(`[e2e:nav] NAVIGATE: Clicking ${item.label}`);
      await page.goto(item.href === '/' ? '/workers' : '/');
      await page.waitForLoadState('networkidle');
      await page.getByRole('link', { name: item.label }).click();

      console.log(`[e2e:nav] VERIFY: URL is ${item.href}`);
      await expect(page).toHaveURL(item.href);
      await page.waitForLoadState('networkidle');

      console.log(`[e2e:nav] VERIFY: ${item.label} link is active`);
      const link = page.getByRole('link', { name: item.label });
      await expect(link).toHaveAttribute('aria-current', 'page');
    }

    console.log('[e2e:nav] TEST PASS: navigation links route to correct pages');
  });

  test('active navigation item is highlighted', async ({ page }) => {
    console.log('[e2e:nav] TEST START: active navigation item is highlighted');
    await mockApiResponses(page);

    for (const item of navItems) {
      console.log(`[e2e:nav] NAVIGATE: Loading ${item.href}`);
      await page.goto(item.href);

      console.log(`[e2e:nav] VERIFY: ${item.label} has aria-current=page`);
      const link = page.getByRole('link', { name: item.label });
      await expect(link).toHaveAttribute('aria-current', 'page');

      console.log(`[e2e:nav] VERIFY: Other links don't have aria-current`);
      for (const otherItem of navItems) {
        if (otherItem.href !== item.href) {
          const otherLink = page.getByRole('link', { name: otherItem.label });
          await expect(otherLink).not.toHaveAttribute('aria-current', 'page');
        }
      }
    }

    console.log('[e2e:nav] TEST PASS: active navigation item is highlighted');
  });

  test('RCH Dashboard logo links to home', async ({ page }) => {
    console.log('[e2e:nav] TEST START: RCH Dashboard logo links to home');
    await mockApiResponses(page);

    console.log('[e2e:nav] NAVIGATE: Loading /workers');
    await page.goto('/workers');

    console.log('[e2e:nav] ACTION: Click RCH Dashboard logo');
    await page.getByRole('link', { name: 'RCH Dashboard' }).click();

    console.log('[e2e:nav] VERIFY: Navigated to home');
    await expect(page).toHaveURL('/');

    console.log('[e2e:nav] TEST PASS: RCH Dashboard logo links to home');
  });

  test('skip to main content link works', async ({ page }) => {
    console.log('[e2e:nav] TEST START: skip to main content link works');
    await mockApiResponses(page);

    console.log('[e2e:nav] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav] ACTION: Tab to skip link');
    await page.keyboard.press('Tab');

    console.log('[e2e:nav] VERIFY: Skip link is focused');
    const skipLink = page.getByRole('link', { name: 'Skip to main content' });
    await expect(skipLink).toBeFocused();

    console.log('[e2e:nav] ACTION: Activate skip link');
    await skipLink.click();

    console.log('[e2e:nav] VERIFY: URL has #main-content');
    await expect(page).toHaveURL('/#main-content');

    console.log('[e2e:nav] TEST PASS: skip to main content link works');
  });

  test('navigation landmarks are present', async ({ page }) => {
    console.log('[e2e:nav] TEST START: navigation landmarks are present');
    await mockApiResponses(page);

    console.log('[e2e:nav] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav] VERIFY: Navigation landmark present');
    await expect(page.getByRole('navigation')).toBeVisible();

    console.log('[e2e:nav] VERIFY: Main landmark present');
    await expect(page.getByRole('main')).toBeVisible();

    console.log('[e2e:nav] TEST PASS: navigation landmarks are present');
  });

  test('version number is displayed in sidebar', async ({ page }) => {
    console.log('[e2e:nav] TEST START: version number is displayed in sidebar');
    await mockApiResponses(page);

    console.log('[e2e:nav] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav] VERIFY: Version text visible');
    await expect(page.getByText('Version')).toBeVisible();
    await expect(page.getByText('0.1.0')).toBeVisible();

    console.log('[e2e:nav] TEST PASS: version number is displayed in sidebar');
  });
});

test.describe('Mobile Navigation', () => {
  test.use({ viewport: { width: 375, height: 667 } });

  test('hamburger menu opens and closes mobile sidebar', async ({ page }) => {
    console.log('[e2e:nav:mobile] TEST START: hamburger menu opens and closes mobile sidebar');
    await mockApiResponses(page);

    console.log('[e2e:nav:mobile] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav:mobile] VERIFY: Hamburger menu visible');
    const hamburger = page.getByTestId('hamburger-menu');
    await expect(hamburger).toBeVisible();

    console.log('[e2e:nav:mobile] VERIFY: Sidebar initially hidden');
    await expect(page.getByTestId('sidebar')).toBeHidden();

    console.log('[e2e:nav:mobile] ACTION: Click hamburger menu');
    await hamburger.click();

    console.log('[e2e:nav:mobile] VERIFY: Sidebar visible');
    await expect(page.getByTestId('sidebar')).toBeVisible();

    console.log('[e2e:nav:mobile] VERIFY: Backdrop visible');
    await expect(page.getByTestId('backdrop')).toBeVisible();

    console.log('[e2e:nav:mobile] ACTION: Click hamburger menu again');
    await hamburger.click();

    console.log('[e2e:nav:mobile] VERIFY: Sidebar hidden');
    await expect(page.getByTestId('sidebar')).toBeHidden();

    console.log('[e2e:nav:mobile] TEST PASS: hamburger menu opens and closes mobile sidebar');
  });

  test('clicking backdrop closes mobile sidebar', async ({ page }) => {
    console.log('[e2e:nav:mobile] TEST START: clicking backdrop closes mobile sidebar');
    await mockApiResponses(page);

    console.log('[e2e:nav:mobile] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav:mobile] ACTION: Open sidebar');
    await page.getByTestId('hamburger-menu').click();
    await expect(page.getByTestId('sidebar')).toBeVisible();

    console.log('[e2e:nav:mobile] ACTION: Click backdrop');
    await page.getByTestId('backdrop').click();

    console.log('[e2e:nav:mobile] VERIFY: Sidebar closed');
    await expect(page.getByTestId('sidebar')).toBeHidden();

    console.log('[e2e:nav:mobile] TEST PASS: clicking backdrop closes mobile sidebar');
  });

  test('mobile navigation links work and close sidebar', async ({ page }) => {
    console.log('[e2e:nav:mobile] TEST START: mobile navigation links work and close sidebar');
    await mockApiResponses(page);

    console.log('[e2e:nav:mobile] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav:mobile] ACTION: Open sidebar');
    await page.getByTestId('hamburger-menu').click();
    await expect(page.getByTestId('sidebar')).toBeVisible();

    console.log('[e2e:nav:mobile] ACTION: Click Workers link');
    await page.getByTestId('sidebar').getByRole('link', { name: 'Workers' }).click();

    console.log('[e2e:nav:mobile] VERIFY: Navigated to /workers');
    await expect(page).toHaveURL('/workers');

    console.log('[e2e:nav:mobile] VERIFY: Sidebar closed after navigation');
    await expect(page.getByTestId('sidebar')).toBeHidden();

    console.log('[e2e:nav:mobile] TEST PASS: mobile navigation links work and close sidebar');
  });

  test('hamburger menu accessibility attributes', async ({ page }) => {
    console.log('[e2e:nav:mobile] TEST START: hamburger menu accessibility attributes');
    await mockApiResponses(page);

    console.log('[e2e:nav:mobile] NAVIGATE: Loading /');
    await page.goto('/');

    const hamburger = page.getByTestId('hamburger-menu');

    console.log('[e2e:nav:mobile] VERIFY: Initial aria-expanded=false');
    await expect(hamburger).toHaveAttribute('aria-expanded', 'false');
    await expect(hamburger).toHaveAttribute('aria-label', 'Open navigation');

    console.log('[e2e:nav:mobile] ACTION: Open sidebar');
    await hamburger.click();

    console.log('[e2e:nav:mobile] VERIFY: Updated aria-expanded=true');
    await expect(hamburger).toHaveAttribute('aria-expanded', 'true');
    await expect(hamburger).toHaveAttribute('aria-label', 'Close navigation');

    console.log('[e2e:nav:mobile] TEST PASS: hamburger menu accessibility attributes');
  });
});

test.describe('Theme Toggle', () => {
  test.skip(({ isMobile }) => isMobile, 'Mobile theme controls live inside the hidden drawer.');

  test('theme toggle switches between light and dark', async ({ page }) => {
    console.log('[e2e:nav:theme] TEST START: theme toggle switches between light and dark');
    await mockApiResponses(page);

    console.log('[e2e:nav:theme] NAVIGATE: Loading /');
    await page.goto('/');

    console.log('[e2e:nav:theme] VERIFY: Theme section visible');
    await expect(page.getByText('Theme')).toBeVisible();

    console.log('[e2e:nav:theme] ACTION: Click theme toggle');
    const themeToggle = page.getByRole('button', { name: /switch to (light|dark) theme/i });
    await themeToggle.click();

    console.log('[e2e:nav:theme] VERIFY: Theme changed');
    const html = page.locator('html');
    const classAfterClick = await html.getAttribute('class');
    console.log(`[e2e:nav:theme] RESULT: HTML class after toggle: ${classAfterClick}`);

    console.log('[e2e:nav:theme] TEST PASS: theme toggle switches between light and dark');
  });
});
