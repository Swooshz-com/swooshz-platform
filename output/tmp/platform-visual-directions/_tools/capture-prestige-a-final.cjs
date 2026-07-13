const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const url = 'file:///C:/Users/xPass/GitHub%20Projects/swooshz-platform/_tmp/platform-visual-directions/direction-a-prestige-1/index.html';
const evidence = path.resolve(__dirname, '..', 'prestige-a-final-evidence');
const screenshots = path.join(evidence, 'screenshots');
const frames = path.join(screenshots, 'initial-load-frames');
for (const folder of [evidence, screenshots, frames]) fs.mkdirSync(folder, { recursive: true });

const summary = {
  browser: 'Playwright Chromium 1.61.1',
  url,
  capturedAt: new Date().toISOString(),
  responsive: [],
  interactions: {},
  motion: {},
  errors: [],
};

function attachErrors(page, label) {
  page.on('pageerror', error => summary.errors.push({ label, type: 'pageerror', message: String(error) }));
  page.on('console', message => {
    if (message.type() === 'error') summary.errors.push({ label, type: 'console', message: message.text() });
  });
}

async function settle(page, delay = 1200) {
  await page.waitForLoadState('domcontentloaded');
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(delay);
}

async function closeContext(context) {
  await Promise.race([context.close(), new Promise(resolve => setTimeout(resolve, 4000))]);
}

async function main() {
  const browser = await chromium.launch({ headless: true });

  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const desktopPage = await desktop.newPage();
  attachErrors(desktopPage, 'desktop');
  await desktopPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await desktopPage.evaluate(() => document.fonts.ready);
  await desktopPage.evaluate(() => {
    const root = document.documentElement;
    root.classList.add('motion-enabled');
    root.classList.remove('is-ready');
    void root.offsetWidth;
    window.setTimeout(() => root.classList.add('is-ready'), 60);
  });
  let elapsed = 0;
  for (const moment of [120, 300, 620, 1100]) {
    await desktopPage.waitForTimeout(moment - elapsed);
    elapsed = moment;
    await desktopPage.screenshot({ path: path.join(frames, `${String(moment).padStart(4, '0')}ms.png`) });
    summary.motion[`${moment}ms`] = await desktopPage.evaluate(() => ({
      ready: document.documentElement.classList.contains('is-ready'),
      headlineOpacity: getComputedStyle(document.querySelector('.reveal-line > span')).opacity,
      headlineTransform: getComputedStyle(document.querySelector('.reveal-line > span')).transform,
      ctaOpacity: getComputedStyle(document.querySelector('.hero-actions')).opacity,
      artworkOpacity: getComputedStyle(document.querySelector('.hero-visual')).opacity,
      h1Height: document.querySelector('h1').getBoundingClientRect().height,
    }));
  }
  await desktopPage.screenshot({ path: path.join(screenshots, 'desktop-first.png') });
  await desktopPage.screenshot({ path: path.join(screenshots, 'desktop-full-study.png'), fullPage: true, animations: 'disabled' });

  await desktopPage.evaluate(() => { document.documentElement.style.scrollBehavior = 'auto'; scrollTo(0, 650); });
  await desktopPage.waitForTimeout(120);
  const downProgress = await desktopPage.evaluate(() => Number(getComputedStyle(document.documentElement).getPropertyValue('--hero-progress')));
  await desktopPage.evaluate(() => scrollTo(0, 0));
  await desktopPage.waitForTimeout(120);
  const upProgress = await desktopPage.evaluate(() => Number(getComputedStyle(document.documentElement).getPropertyValue('--hero-progress')));
  await desktopPage.evaluate(() => {
    for (const y of [900, 120, 760, 40, 620, 0]) scrollTo(0, y);
  });
  await desktopPage.waitForTimeout(120);
  const rapidProgress = await desktopPage.evaluate(() => Number(getComputedStyle(document.documentElement).getPropertyValue('--hero-progress')));
  summary.interactions.scroll = {
    downProgress,
    upProgress,
    rapidProgress,
    valid: downProgress > 0 && upProgress === 0 && rapidProgress === 0,
  };
  await desktopPage.evaluate(() => document.documentElement.style.removeProperty('scroll-behavior'));

  const visualBox = await desktopPage.locator('.hero-visual').boundingBox();
  if (visualBox) {
    await desktopPage.mouse.move(visualBox.x + visualBox.width * .68, visualBox.y + visualBox.height * .45);
    await desktopPage.waitForTimeout(60);
  }
  const pointerMoved = await desktopPage.evaluate(() => ({
    x: getComputedStyle(document.documentElement).getPropertyValue('--pointer-x').trim(),
    y: getComputedStyle(document.documentElement).getPropertyValue('--pointer-y').trim(),
  }));
  await desktopPage.mouse.move(10, 10);
  await desktopPage.waitForTimeout(80);
  const pointerLeave = await desktopPage.evaluate(() => ({
    x: getComputedStyle(document.documentElement).getPropertyValue('--pointer-x').trim(),
    y: getComputedStyle(document.documentElement).getPropertyValue('--pointer-y').trim(),
  }));
  const backgroundPage = await desktop.newPage();
  await backgroundPage.goto('about:blank');
  await backgroundPage.bringToFront();
  await desktopPage.waitForTimeout(80);
  await desktopPage.bringToFront();
  const pointerReturn = await desktopPage.evaluate(() => ({
    x: getComputedStyle(document.documentElement).getPropertyValue('--pointer-x').trim(),
    y: getComputedStyle(document.documentElement).getPropertyValue('--pointer-y').trim(),
    ready: document.documentElement.classList.contains('is-ready'),
  }));
  summary.interactions.pointerAndTabReturn = { pointerMoved, pointerLeave, pointerReturn };
  await closeContext(desktop);

  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const mobilePage = await mobile.newPage();
  attachErrors(mobilePage, 'mobile');
  await mobilePage.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await settle(mobilePage);
  await mobilePage.screenshot({ path: path.join(screenshots, 'mobile-first.png') });
  await mobilePage.screenshot({ path: path.join(screenshots, 'mobile-full-study.png'), fullPage: true, animations: 'disabled' });

  const toggle = mobilePage.locator('.menu-toggle');
  await toggle.focus();
  await mobilePage.screenshot({ path: path.join(screenshots, 'keyboard-focus.png') });
  await mobilePage.keyboard.press('Tab');
  const closedMenuTab = await mobilePage.evaluate(() => ({
    activeClass: document.activeElement?.className,
    activeText: document.activeElement?.textContent.trim(),
    navHidden: document.querySelector('#primary-nav')?.getAttribute('aria-hidden'),
    navInert: document.querySelector('#primary-nav')?.inert,
  }));

  await toggle.focus();
  await toggle.click();
  await mobilePage.waitForTimeout(380);
  await mobilePage.screenshot({ path: path.join(screenshots, 'mobile-menu-open.png') });
  const openMenu = await mobilePage.evaluate(() => ({
    activeText: document.activeElement?.textContent.trim(),
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    navHidden: document.querySelector('#primary-nav')?.getAttribute('aria-hidden'),
    navInert: document.querySelector('#primary-nav')?.inert,
    bodyOverflow: getComputedStyle(document.body).overflow,
    scrollY,
  }));
  await mobilePage.mouse.wheel(0, 500);
  await mobilePage.waitForTimeout(100);
  const scrollWhileOpen = await mobilePage.evaluate(() => scrollY);
  await mobilePage.keyboard.press('Escape');
  const escaped = await mobilePage.evaluate(() => ({
    focusRestored: document.activeElement === document.querySelector('.menu-toggle'),
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    bodyOverflow: getComputedStyle(document.body).overflow,
  }));

  await toggle.click();
  await mobilePage.waitForTimeout(80);
  await mobilePage.setViewportSize({ width: 1200, height: 844 });
  await mobilePage.waitForTimeout(120);
  const desktopResize = await mobilePage.evaluate(() => ({
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    navHidden: document.querySelector('#primary-nav')?.getAttribute('aria-hidden'),
    navInert: document.querySelector('#primary-nav')?.inert,
    openClass: document.querySelector('#primary-nav')?.classList.contains('is-open'),
    bodyOpen: document.body.classList.contains('menu-open'),
  }));
  await mobilePage.setViewportSize({ width: 390, height: 844 });
  await mobilePage.waitForTimeout(120);
  await toggle.click();
  await mobilePage.waitForTimeout(80);
  await mobilePage.evaluate(() => dispatchEvent(new Event('orientationchange')));
  await mobilePage.waitForTimeout(140);
  const orientationReset = await mobilePage.evaluate(() => ({
    expanded: document.querySelector('.menu-toggle')?.getAttribute('aria-expanded'),
    navHidden: document.querySelector('#primary-nav')?.getAttribute('aria-hidden'),
    navInert: document.querySelector('#primary-nav')?.inert,
    bodyOpen: document.body.classList.contains('menu-open'),
  }));
  const touchPointer = await mobilePage.evaluate(() => ({
    x: getComputedStyle(document.documentElement).getPropertyValue('--pointer-x').trim(),
    y: getComputedStyle(document.documentElement).getPropertyValue('--pointer-y').trim(),
  }));
  summary.interactions.navigation = { closedMenuTab, openMenu, scrollWhileOpen, escaped, desktopResize, orientationReset, touchPointer };
  await closeContext(mobile);

  for (const configuration of [
    { name: 'mobile-320.png', width: 320, height: 844, mobile: true },
    { name: null, width: 768, height: 1024, mobile: false },
    { name: null, width: 844, height: 390, mobile: true },
    { name: null, width: 1920, height: 900, mobile: false },
  ]) {
    const context = await browser.newContext({ viewport: { width: configuration.width, height: configuration.height }, isMobile: configuration.mobile, hasTouch: configuration.mobile });
    const page = await context.newPage();
    attachErrors(page, `responsive-${configuration.width}`);
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await settle(page, 1000);
    if (configuration.name) await page.screenshot({ path: path.join(screenshots, configuration.name) });
    summary.responsive.push(await page.evaluate(({ width, height }) => {
      const cta = document.querySelector('.button-primary').getBoundingClientRect();
      const art = document.querySelector('.hero-visual').getBoundingClientRect();
      return {
        width,
        height,
        innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        ctaVisible: cta.top < innerHeight && cta.bottom > 0,
        ctaFullyVisible: cta.top >= 0 && cta.bottom <= innerHeight,
        ctaBottom: Math.round(cta.bottom),
        artworkVisible: art.top < innerHeight && art.bottom > 0,
        heroIndexDisplay: getComputedStyle(document.querySelector('.hero-index')).display,
      };
    }, configuration));
    await closeContext(context);
  }

  for (const configuration of [
    { name: 'reduced-motion-desktop.png', width: 1440, height: 900, mobile: false, label: 'desktop' },
    { name: 'reduced-motion-mobile.png', width: 390, height: 844, mobile: true, label: 'mobile' },
  ]) {
    const context = await browser.newContext({ viewport: { width: configuration.width, height: configuration.height }, isMobile: configuration.mobile, hasTouch: configuration.mobile, reducedMotion: 'reduce' });
    const page = await context.newPage();
    attachErrors(page, `reduced-${configuration.label}`);
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await settle(page, 180);
    await page.screenshot({ path: path.join(screenshots, configuration.name), animations: 'disabled' });
    const topState = await page.evaluate(() => ({
      scrollY,
      heroProgress: getComputedStyle(document.documentElement).getPropertyValue('--hero-progress').trim(),
      headlineOpacity: getComputedStyle(document.querySelector('.reveal-line > span')).opacity,
      headlineTransform: getComputedStyle(document.querySelector('.reveal-line > span')).transform,
      artworkOpacity: getComputedStyle(document.querySelector('.hero-visual')).opacity,
      artworkTransform: getComputedStyle(document.querySelector('.hero-visual')).transform,
      cueAnimation: getComputedStyle(document.querySelector('.scroll-cue i'), '::after').animationName,
    }));
    await page.evaluate(() => scrollTo(0, 700));
    await page.waitForTimeout(100);
    const scrolledProgress = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--hero-progress').trim());
    summary.interactions[`reduced-${configuration.label}`] = { topState, scrolledProgress };
    await closeContext(context);
  }

  summary.passed = summary.errors.length === 0
    && summary.responsive.every(item => !item.horizontalOverflow && item.ctaVisible && item.artworkVisible)
    && summary.interactions.scroll.valid
    && summary.interactions.navigation.closedMenuTab.navInert
    && summary.interactions.navigation.openMenu.activeText === 'The idea'
    && summary.interactions.navigation.scrollWhileOpen === summary.interactions.navigation.openMenu.scrollY
    && summary.interactions.navigation.escaped.focusRestored
    && !summary.interactions.navigation.desktopResize.openClass
    && !summary.interactions.navigation.orientationReset.bodyOpen
    && summary.interactions['reduced-desktop'].topState.heroProgress === '0'
    && summary.interactions['reduced-mobile'].topState.heroProgress === '0';

  fs.writeFileSync(path.join(evidence, 'qa-summary.json'), JSON.stringify(summary, null, 2));
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 5000))]);
  process.exit(summary.passed ? 0 : 1);
}

main().catch(error => {
  fs.writeFileSync(path.join(evidence, 'qa-error.txt'), String(error?.stack || error));
  process.exit(1);
});
