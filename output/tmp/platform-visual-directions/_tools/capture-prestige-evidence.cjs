const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const baseUrl = 'http://127.0.0.1:8765';
const root = path.resolve(__dirname, '..', 'prestige-evidence');
const screenshotsDir = path.join(root, 'screenshots');
const videosDir = path.join(root, 'videos');
const rawVideosDir = path.join(videosDir, 'raw');
for (const folder of [root, screenshotsDir, videosDir, rawVideosDir]) fs.mkdirSync(folder, { recursive: true });

const studies = [
  { key: 'prestige-1', route: 'direction-a-prestige-1', transition: '#platform' },
  { key: 'prestige-2', route: 'direction-a-prestige-2', transition: '#sequence' },
  { key: 'prestige-3', route: 'direction-a-prestige-3', transition: '#theatre', theatre: true }
];

async function ready(page, delay = 1700) {
  await page.waitForLoadState('domcontentloaded');
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(delay);
}

async function captureScreens(browser, study) {
  const results = {};
  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'no-preference' });
  const desktopPage = await desktop.newPage();
  await desktopPage.goto(`${baseUrl}/${study.route}/`);
  await ready(desktopPage);
  await desktopPage.screenshot({ path: path.join(screenshotsDir, `${study.key}-desktop-first.png`), fullPage: false });
  await desktopPage.screenshot({ path: path.join(screenshotsDir, `${study.key}-desktop-study.png`), fullPage: true, animations: 'disabled' });
  results.desktop = await desktopPage.evaluate(() => ({ width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth, scrollHeight: document.documentElement.scrollHeight }));
  await desktop.close();

  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'no-preference', isMobile: true, hasTouch: true });
  const mobilePage = await mobile.newPage();
  await mobilePage.goto(`${baseUrl}/${study.route}/`);
  await ready(mobilePage);
  await mobilePage.screenshot({ path: path.join(screenshotsDir, `${study.key}-mobile-first.png`), fullPage: false });
  await mobilePage.screenshot({ path: path.join(screenshotsDir, `${study.key}-mobile-study.png`), fullPage: true, animations: 'disabled' });
  await mobilePage.locator('.menu-toggle').click();
  await mobilePage.waitForTimeout(450);
  await mobilePage.screenshot({ path: path.join(screenshotsDir, `${study.key}-mobile-menu.png`), fullPage: false });
  results.mobile = await mobilePage.evaluate(() => ({ width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth, scrollHeight: document.documentElement.scrollHeight, menuExpanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded') }));
  await mobile.close();

  for (const [label, viewport, mobileMode] of [
    ['desktop', { width: 1440, height: 900 }, false],
    ['mobile', { width: 390, height: 844 }, true]
  ]) {
    const reduced = await browser.newContext({ viewport, reducedMotion: 'reduce', isMobile: mobileMode, hasTouch: mobileMode });
    const reducedPage = await reduced.newPage();
    await reducedPage.goto(`${baseUrl}/${study.route}/`);
    await ready(reducedPage, 300);
    await reducedPage.screenshot({ path: path.join(screenshotsDir, `${study.key}-reduced-${label}.png`), fullPage: false, animations: 'disabled' });
    results[`reduced_${label}`] = await reducedPage.evaluate(() => ({
      h1Visible: Boolean(document.querySelector('h1')?.getBoundingClientRect().height),
      bodyTextLength: document.body.innerText.length,
      scrollWidth: document.documentElement.scrollWidth,
      viewportWidth: innerWidth
    }));
    await reduced.close();
  }
  return results;
}

async function record(browser, study, mode) {
  const mobile = mode === 'mobile-load';
  const viewport = mobile ? { width: 390, height: 844 } : { width: 1440, height: 900 };
  const context = await browser.newContext({
    viewport,
    reducedMotion: 'no-preference',
    isMobile: mobile,
    hasTouch: mobile,
    recordVideo: { dir: rawVideosDir, size: viewport }
  });
  const page = await context.newPage();
  const video = page.video();
  await page.goto(`${baseUrl}/${study.route}/`);

  if (mode.endsWith('load')) {
    await ready(page, 2500);
    const cta = page.locator('.button').first();
    if (!mobile && await cta.isVisible().catch(() => false)) {
      await cta.hover();
      await page.waitForTimeout(650);
    }
  } else {
    await ready(page, 650);
    const target = await page.evaluate(({ selector, theatre }) => {
      const element = document.querySelector(selector);
      if (!element) return document.documentElement.scrollHeight - innerHeight;
      if (theatre) return element.offsetTop + Math.max(innerHeight, element.offsetHeight - innerHeight) * .72;
      return element.offsetTop + Math.min(innerHeight * .42, element.offsetHeight * .2);
    }, { selector: study.transition, theatre: Boolean(study.theatre) });
    for (let index = 0; index <= 84; index += 1) {
      const eased = 1 - Math.pow(1 - index / 84, 3);
      await page.evaluate((y) => window.scrollTo(0, y), target * eased);
      await page.waitForTimeout(42);
    }
    await page.waitForTimeout(700);
  }

  await context.close();
  const rawPath = await video.path();
  const namedPath = path.join(videosDir, `${study.key}-${mode}.webm`);
  if (fs.existsSync(namedPath)) fs.unlinkSync(namedPath);
  fs.renameSync(rawPath, namedPath);
  return namedPath;
}

async function responsiveChecks(browser, study) {
  const checks = [];
  for (const width of [320, 390, 768, 1440, 1920]) {
    const height = width <= 390 ? 844 : width === 768 ? 1024 : 900;
    const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'no-preference', isMobile: width <= 390, hasTouch: width <= 390 });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
    await page.goto(`${baseUrl}/${study.route}/`);
    await ready(page, 300);
    const result = await page.evaluate(() => {
      const visible = (element) => {
        if (!element) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && Number(style.opacity) > 0;
      };
      const cta = document.querySelector('.button');
      const h1 = document.querySelector('h1');
      const heroImage = document.querySelector('main img');
      return {
        viewportWidth: innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        title: document.title,
        h1Visible: visible(h1),
        h1Text: h1?.textContent.trim().replace(/\s+/g, ' '),
        ctaVisible: visible(cta),
        ctaHeight: cta?.getBoundingClientRect().height || 0,
        imageLoaded: Boolean(heroImage?.complete && heroImage?.naturalWidth),
        bodyTextLength: document.body.innerText.length,
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1
      };
    });
    checks.push({ width, height, ...result, errors });
    await context.close();
  }
  return checks;
}

async function interactionChecks(browser, study) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'no-preference', isMobile: true, hasTouch: true });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.goto(`${baseUrl}/${study.route}/`);
  await ready(page, 300);
  const button = page.locator('.menu-toggle');
  await button.focus();
  const focus = await button.evaluate((element) => getComputedStyle(element).outlineStyle !== 'none');
  await button.click();
  const result = await page.evaluate(() => {
    const links = [...document.querySelectorAll('.primary-nav a')];
    return {
      expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
      menuVisible: getComputedStyle(document.querySelector('.primary-nav')).pointerEvents !== 'none',
      menuButtonSize: (() => { const rect = document.querySelector('.menu-toggle').getBoundingClientRect(); return { width: rect.width, height: rect.height }; })(),
      navLinkHeights: links.map((link) => link.getBoundingClientRect().height),
      blankLinks: [...document.querySelectorAll('a')].filter((link) => !link.textContent.trim() && !link.getAttribute('aria-label')).length,
      landmarks: { main: Boolean(document.querySelector('main')), footer: Boolean(document.querySelector('footer')), skipLink: Boolean(document.querySelector('.skip-link')) },
      headings: { h1: document.querySelectorAll('h1').length, h2: document.querySelectorAll('h2').length }
    };
  });
  await context.close();
  return { ...result, focusVisible: focus, errors };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const summary = { browser: 'Playwright Chromium', baseUrl, studies: {} };

  for (const study of studies) {
    const screenshots = await captureScreens(browser, study);
    const videos = [];
    videos.push(await record(browser, study, 'desktop-load'));
    videos.push(await record(browser, study, 'desktop-scroll'));
    videos.push(await record(browser, study, 'mobile-load'));
    const responsive = await responsiveChecks(browser, study);
    const interactions = await interactionChecks(browser, study);
    summary.studies[study.key] = { route: study.route, screenshots, videos, responsive, interactions };
  }

  await browser.close();
  fs.writeFileSync(path.join(root, 'qa-summary.json'), JSON.stringify(summary, null, 2));
  process.stdout.write(JSON.stringify(summary, null, 2));
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
