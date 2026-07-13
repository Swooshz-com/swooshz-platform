const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const number = Number(process.argv[2]);
if (![1, 2, 3].includes(number)) {
  throw new Error('Usage: node capture-prestige-study.cjs <1|2|3>');
}

const study = {
  key: `prestige-${number}`,
  route: `direction-a-prestige-${number}`,
  transition: number === 1 ? '#platform' : number === 2 ? '#sequence' : '#theatre',
  theatre: number === 3,
};
const baseUrl = 'http://127.0.0.1:8765';
const root = path.resolve(__dirname, '..', 'prestige-evidence');
const screenshotsDir = path.join(root, 'screenshots');
const videosDir = path.join(root, 'videos');
const rawVideosDir = path.join(videosDir, 'raw');
for (const folder of [root, screenshotsDir, videosDir, rawVideosDir]) {
  fs.mkdirSync(folder, { recursive: true });
}

async function settle(page, delay = 650) {
  await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(delay);
}

async function pageMetrics(page) {
  return page.evaluate(() => ({
    viewportWidth: innerWidth,
    viewportHeight: innerHeight,
    scrollWidth: document.documentElement.scrollWidth,
    scrollHeight: document.documentElement.scrollHeight,
    horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
    h1Visible: Boolean(document.querySelector('h1')?.getBoundingClientRect().height),
    bodyTextLength: document.body.innerText.length,
  }));
}

async function captureScreens(browser) {
  const results = {};
  for (const configuration of [
    { label: 'desktop', viewport: { width: 1440, height: 900 }, mobile: false },
    { label: 'mobile', viewport: { width: 390, height: 844 }, mobile: true },
  ]) {
    const context = await browser.newContext({
      viewport: configuration.viewport,
      reducedMotion: 'no-preference',
      isMobile: configuration.mobile,
      hasTouch: configuration.mobile,
    });
    const page = await context.newPage();
    page.setDefaultTimeout(8000);
    await page.goto(`${baseUrl}/${study.route}/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await settle(page, 2400);
    await page.screenshot({ path: path.join(screenshotsDir, `${study.key}-${configuration.label}-first.png`) });
    await page.screenshot({ path: path.join(screenshotsDir, `${study.key}-${configuration.label}-study.png`), fullPage: true, animations: 'disabled' });
    results[configuration.label] = await pageMetrics(page);

    if (configuration.mobile) {
      await page.evaluate(() => scrollTo(0, 0));
      await page.waitForTimeout(120);
      const toggle = page.locator('.menu-toggle');
      await toggle.click({ force: true, timeout: 5000 });
      await page.waitForTimeout(250);
      await page.screenshot({ path: path.join(screenshotsDir, `${study.key}-mobile-menu.png`) });
      results.mobile.menuExpanded = await toggle.getAttribute('aria-expanded');
    }
    await context.close();
  }

  for (const configuration of [
    { label: 'desktop', viewport: { width: 1440, height: 900 }, mobile: false },
    { label: 'mobile', viewport: { width: 390, height: 844 }, mobile: true },
  ]) {
    const context = await browser.newContext({
      viewport: configuration.viewport,
      reducedMotion: 'reduce',
      isMobile: configuration.mobile,
      hasTouch: configuration.mobile,
    });
    const page = await context.newPage();
    page.setDefaultTimeout(8000);
    await page.goto(`${baseUrl}/${study.route}/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await settle(page, 250);
    await page.screenshot({
      path: path.join(screenshotsDir, `${study.key}-reduced-${configuration.label}.png`),
      animations: 'disabled',
    });
    results[`reduced_${configuration.label}`] = await pageMetrics(page);
    await context.close();
  }
  return results;
}

async function record(browser, mode) {
  const mobile = mode === 'mobile-load';
  const viewport = mobile ? { width: 390, height: 844 } : { width: 1440, height: 900 };
  const context = await browser.newContext({
    viewport,
    reducedMotion: 'no-preference',
    isMobile: mobile,
    hasTouch: mobile,
    recordVideo: { dir: rawVideosDir, size: viewport },
  });
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  const video = page.video();
  await page.goto(`${baseUrl}/${study.route}/`, { waitUntil: 'domcontentloaded', timeout: 10000 });

  if (mode.endsWith('load')) {
    await settle(page, 2900);
    if (!mobile) {
      const cta = page.locator('.button').first();
      if (await cta.isVisible().catch(() => false)) {
        await cta.hover();
        await page.waitForTimeout(500);
      }
    }
  } else {
    await settle(page, 500);
    const target = await page.evaluate(({ selector, theatre }) => {
      const element = document.querySelector(selector);
      if (!element) return document.documentElement.scrollHeight - innerHeight;
      if (theatre) return element.offsetTop + Math.max(innerHeight, element.offsetHeight - innerHeight) * 0.76;
      return element.offsetTop + Math.min(innerHeight * 0.55, element.offsetHeight * 0.25);
    }, { selector: study.transition, theatre: study.theatre });
    for (let step = 0; step <= 70; step += 1) {
      const progress = step / 70;
      const eased = 1 - Math.pow(1 - progress, 3);
      await page.evaluate((y) => scrollTo(0, y), target * eased);
      await page.waitForTimeout(38);
    }
    await page.waitForTimeout(600);
  }

  await page.close();
  await context.close();
  const rawPath = await video.path();
  const namedPath = path.join(videosDir, `${study.key}-${mode}.webm`);
  if (fs.existsSync(namedPath)) fs.unlinkSync(namedPath);
  fs.renameSync(rawPath, namedPath);
  return path.relative(root, namedPath).replaceAll('\\', '/');
}

async function responsiveChecks(browser) {
  const checks = [];
  for (const width of [320, 390, 768, 1440, 1920]) {
    const height = width <= 390 ? 844 : width === 768 ? 1024 : 900;
    const mobile = width <= 390;
    const context = await browser.newContext({ viewport: { width, height }, isMobile: mobile, hasTouch: mobile });
    const page = await context.newPage();
    page.setDefaultTimeout(8000);
    const errors = [];
    page.on('pageerror', error => errors.push(String(error)));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.goto(`${baseUrl}/${study.route}/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await settle(page, 220);
    const result = await page.evaluate(() => {
      const visible = element => {
        if (!element) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && Number(style.opacity) > 0;
      };
      const cta = document.querySelector('.button');
      const heroImage = document.querySelector('main img');
      return {
        scrollWidth: document.documentElement.scrollWidth,
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        h1Visible: visible(document.querySelector('h1')),
        ctaVisible: visible(cta),
        ctaHeight: cta?.getBoundingClientRect().height || 0,
        imageLoaded: Boolean(heroImage?.complete && heroImage?.naturalWidth),
        bodyTextLength: document.body.innerText.length,
      };
    });
    checks.push({ width, height, ...result, errors });
    await context.close();
  }
  return checks;
}

async function interactionChecks(browser) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.goto(`${baseUrl}/${study.route}/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
  await settle(page, 200);
  const button = page.locator('.menu-toggle');
  await button.focus();
  const focusVisible = await button.evaluate(element => getComputedStyle(element).outlineStyle !== 'none');
  await button.click({ force: true });
  const result = await page.evaluate(() => {
    const toggle = document.querySelector('.menu-toggle');
    const navigation = document.querySelector('.primary-nav');
    const toggleRect = toggle?.getBoundingClientRect();
    return {
      expanded: toggle?.getAttribute('aria-expanded'),
      menuVisible: navigation ? getComputedStyle(navigation).pointerEvents !== 'none' : false,
      menuButtonSize: toggleRect ? { width: toggleRect.width, height: toggleRect.height } : null,
      blankLinks: [...document.querySelectorAll('a')].filter(link => !link.textContent.trim() && !link.getAttribute('aria-label')).length,
      landmarks: {
        main: Boolean(document.querySelector('main')),
        footer: Boolean(document.querySelector('footer')),
        skipLink: Boolean(document.querySelector('.skip-link')),
      },
      headings: { h1: document.querySelectorAll('h1').length, h2: document.querySelectorAll('h2').length },
    };
  });
  await context.close();
  return { ...result, focusVisible, errors };
}

async function attempt(label, operation, output) {
  try {
    output[label] = await operation();
  } catch (error) {
    output[label] = { error: String(error?.stack || error) };
  }
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const output = { browser: 'Playwright Chromium 1.61.1', baseUrl, study, createdAt: new Date().toISOString() };
  await attempt('screenshots', () => captureScreens(browser), output);
  await attempt('desktopLoadVideo', () => record(browser, 'desktop-load'), output);
  await attempt('desktopScrollVideo', () => record(browser, 'desktop-scroll'), output);
  await attempt('mobileLoadVideo', () => record(browser, 'mobile-load'), output);
  await attempt('responsive', () => responsiveChecks(browser), output);
  await attempt('interactions', () => interactionChecks(browser), output);
  await browser.close();
  fs.writeFileSync(path.join(root, `${study.key}-qa.json`), JSON.stringify(output, null, 2));
  process.stdout.write(JSON.stringify(output, null, 2));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
