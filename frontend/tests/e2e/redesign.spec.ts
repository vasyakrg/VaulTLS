/**
 * VaulTLS frontend redesign — Playwright E2E smoke tests
 *
 * NOTE: These tests require a running VaulTLS backend.
 * They were not executed locally during Task 11 (no live backend available).
 * Run with: npx playwright test tests/e2e/redesign.spec.ts
 * Configure BASE_URL via PLAYWRIGHT_BASE_URL env var or playwright.config.ts baseURL.
 */

import { test, expect, type Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function openApp(page: Page) {
  await page.goto(BASE_URL);
  // Wait for Vue to mount
  await page.waitForSelector('.auth-wrapper, .vt-sidebar', { timeout: 10_000 });
}

// ---------------------------------------------------------------------------
// 1. Login page renders
// ---------------------------------------------------------------------------

test('login form is visible on first load', async ({ page }) => {
  await openApp(page);
  // Either the login card or setup card must be present
  const loginCard = page.locator('.auth-card, .setup-card');
  await expect(loginCard.first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// 2. Sidebar collapse persists via cookie (vaultls_sidebar)
// ---------------------------------------------------------------------------

test('sidebar collapse state persists via cookie after reload', async ({ page }) => {
  // Log in first — requires a seeded backend; skip gracefully if no backend
  await openApp(page);

  // If we landed on login page, authenticate
  const loginBtn = page.locator('button[type="submit"]');
  if (await loginBtn.isVisible().catch(() => false)) {
    await page.fill('input[type="email"]', process.env.E2E_EMAIL ?? 'admin@example.com');
    await page.fill('input[type="password"], input[autocomplete="current-password"]',
      process.env.E2E_PASSWORD ?? 'admin');
    await loginBtn.click();
    await page.waitForSelector('.vt-sidebar', { timeout: 10_000 });
  }

  // Sidebar must be present and expanded by default
  const sidebar = page.locator('.vt-sidebar');
  await expect(sidebar).toBeVisible();
  await expect(sidebar).not.toHaveClass(/collapsed/);

  // Click the collapse button
  const collapseBtn = page.locator('.vt-collapse');
  await collapseBtn.click();
  await expect(sidebar).toHaveClass(/collapsed/);

  // Verify cookie was written
  const cookies = await page.context().cookies();
  const sidebarCookie = cookies.find(c => c.name === 'vaultls_sidebar');
  expect(sidebarCookie?.value).toBe('collapsed');

  // Reload and verify state persists
  await page.reload();
  await page.waitForSelector('.vt-sidebar', { timeout: 10_000 });
  const sidebarAfter = page.locator('.vt-sidebar');
  await expect(sidebarAfter).toHaveClass(/collapsed/);

  // Restore expanded state
  await page.locator('.vt-collapse').click();
  await expect(page.locator('.vt-sidebar')).not.toHaveClass(/collapsed/);
});

// ---------------------------------------------------------------------------
// 3. Theme toggle — html.dark class toggling
// ---------------------------------------------------------------------------

test('theme toggle adds and removes dark class on <html>', async ({ page }) => {
  await openApp(page);

  // Navigate to app (login page is fine — theme applies globally)
  // Set light mode first via button
  const lightBtn = page.locator('.vt-theme-btn').first();
  const darkBtn = page.locator('.vt-theme-btn').nth(1);

  // If sidebar is not visible (login page), test via localStorage manipulation
  const hasSidebar = await page.locator('.vt-sidebar').isVisible().catch(() => false);

  if (hasSidebar) {
    // Click light mode button
    await lightBtn.click();
    const htmlClass = await page.locator('html').getAttribute('class');
    expect(htmlClass ?? '').not.toContain('dark');

    // Click dark mode button
    await darkBtn.click();
    const htmlClassDark = await page.locator('html').getAttribute('class');
    expect(htmlClassDark ?? '').toContain('dark');

    // Switch back to light
    await lightBtn.click();
    const htmlClassLight = await page.locator('html').getAttribute('class');
    expect(htmlClassLight ?? '').not.toContain('dark');
  } else {
    // On login page: use localStorage to simulate theme and verify via reload
    await page.evaluate(() => localStorage.setItem('theme', 'dark'));
    await page.reload();
    await page.waitForSelector('html', { timeout: 5_000 });
    const cls = await page.locator('html').getAttribute('class');
    expect(cls ?? '').toContain('dark');

    await page.evaluate(() => localStorage.setItem('theme', 'light'));
    await page.reload();
    await page.waitForSelector('html', { timeout: 5_000 });
    const clsLight = await page.locator('html').getAttribute('class');
    expect(clsLight ?? '').not.toContain('dark');
  }
});
