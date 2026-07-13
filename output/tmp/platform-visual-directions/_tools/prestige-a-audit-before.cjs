const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const baseUrl = 'http://127.0.0.1:8765/direction-a-prestige-1/';
const root = path.resolve(__dirname, '..', 'prestige-a-final-evidence', 'audit-before');
fs.mkdirSync(root, { recursive: true });

async function captureIntermediate(page, label, delay) {
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(delay);
  await page.screenshot({ path: path.join(root, `${label}.png`) });
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const results = { browser: 'Playwright Chromium 1.61.1', baseUrl, checks: {} };

  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const desktopPage = await desktop.newPage();
  await captureIntermediate(desktopPage, '01-desktop-reveal-120ms', 120);
  await captureIntermediate(desktopPage, '02-desktop-reveal-420ms', 420);
  await captureIntermediate(desktopPage, '03-desktop-settled', 1500);
  results.checks.desktop = await desktopPage.evaluate(() => ({
    ready: document.body.classList.contains('is-ready'),
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth,
    consoleReady: true,
  }));
  await desktop.close();

  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await mobile.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(root, '04-mobile-settled.png') });

  const closedState = await page.evaluate(() => ({
    navAriaHidden: document.querySelector('#primary-nav')?.getAttribute('aria-hidden'),
    navInert: document.querySelector('#primary-nav')?.inert,
    focusableClosedLinks: [...document.querySelectorAll('#primary-nav a')].filter(link => link.tabIndex >= 0).length,
    bodyOverflow: getComputedStyle(document.body).overflow,
  }));

  const toggle = page.locator('.menu-toggle');
  await toggle.focus();
  await toggle.click();
  await page.waitForTimeout(380);
  await page.screenshot({ path: path.join(root, '05-mobile-menu-open.png') });
  const openState = await page.evaluate(() => ({
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    activeClass: document.querySelector('#primary-nav')?.classList.contains('is-open'),
    activeElement: document.activeElement?.className,
    bodyOverflow: getComputedStyle(document.body).overflow,
    bodyMenuOpen: document.body.classList.contains('menu-open'),
  }));

  await page.locator('#primary-nav a').first().focus();
  await page.keyboard.press('Escape');
  const escapeState = await page.evaluate(() => ({
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    activeElementTag: document.activeElement?.tagName,
    activeElementClass: document.activeElement?.className,
    focusRestored: document.activeElement === document.querySelector('.menu-toggle'),
  }));

  await toggle.click();
  await page.setViewportSize({ width: 800, height: 844 });
  await page.waitForTimeout(100);
  const resizeState = await page.evaluate(() => ({
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    activeClass: document.querySelector('#primary-nav')?.classList.contains('is-open'),
    bodyMenuOpen: document.body.classList.contains('menu-open'),
  }));
  results.checks.mobileNavigation = { closedState, openState, escapeState, resizeState };
  results.checks.errors = errors;
  await mobile.close();

  const reduced = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
  const reducedPage = await reduced.newPage();
  await reducedPage.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  await reducedPage.waitForTimeout(200);
  await reducedPage.screenshot({ path: path.join(root, '06-reduced-motion-top.png') });
  results.checks.reducedMotion = await reducedPage.evaluate(() => ({
    heroProgress: getComputedStyle(document.documentElement).getPropertyValue('--hero-progress').trim(),
    headlineTransform: getComputedStyle(document.querySelector('.reveal-line > span')).transform,
    visualTransform: getComputedStyle(document.querySelector('.hero-visual')).transform,
  }));
  await reduced.close();

  await browser.close();
  fs.writeFileSync(path.join(root, 'audit-before.json'), JSON.stringify(results, null, 2));
  process.stdout.write(JSON.stringify(results, null, 2));
}

main().catch(error => { console.error(error); process.exitCode = 1; });
