const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const url = 'http://127.0.0.1:8765/direction-a-prestige-1/';
const root = path.resolve(__dirname, '..', 'prestige-a-final-evidence', 'recordings');
const raw = path.join(root, 'raw');
fs.mkdirSync(raw, { recursive: true });

async function record(browser, name, configuration, action) {
  const context = await browser.newContext({
    viewport: configuration.viewport,
    isMobile: configuration.mobile,
    hasTouch: configuration.mobile,
    recordVideo: { dir: raw, size: configuration.viewport },
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  const video = page.video();
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await action(page);
  await context.close();
  const source = await video.path();
  const destination = path.join(root, `${name}.webm`);
  if (fs.existsSync(destination)) fs.unlinkSync(destination);
  fs.renameSync(source, destination);
  return { file: path.basename(destination), bytes: fs.statSync(destination).size, errors };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const output = {};
  output.initialLoad = await record(browser, 'prestige-a-initial-load', { viewport: { width: 1440, height: 900 }, mobile: false }, async page => {
    await page.waitForTimeout(2100);
    await page.locator('.button-primary').hover();
    await page.waitForTimeout(500);
  });
  output.mainScroll = await record(browser, 'prestige-a-main-scroll', { viewport: { width: 1440, height: 900 }, mobile: false }, async page => {
    await page.waitForTimeout(1300);
    const target = await page.evaluate(() => document.querySelector('#platform').offsetTop - innerHeight * .12);
    await page.evaluate(async y => {
      const root = document.documentElement;
      root.style.scrollBehavior = 'auto';
      const animate = (from, to, duration) => new Promise(resolve => {
        const start = performance.now();
        const tick = now => {
          const progress = Math.min(1, (now - start) / duration);
          const eased = progress < .5 ? 4 * progress * progress * progress : 1 - Math.pow(-2 * progress + 2, 3) / 2;
          scrollTo(0, from + (to - from) * eased);
          if (progress < 1) requestAnimationFrame(tick);
          else resolve();
        };
        requestAnimationFrame(tick);
      });
      await animate(0, y, 2500);
      await new Promise(resolve => setTimeout(resolve, 350));
      await animate(y, 0, 1650);
      root.style.removeProperty('scroll-behavior');
    }, target);
    await page.waitForTimeout(450);
  });
  output.mobileMenu = await record(browser, 'prestige-a-mobile-menu', { viewport: { width: 390, height: 844 }, mobile: true }, async page => {
    await page.waitForTimeout(1000);
    const toggle = page.locator('.menu-toggle');
    await toggle.focus();
    await page.waitForTimeout(350);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(900);
    await page.keyboard.press('Tab');
    await page.waitForTimeout(350);
    await page.keyboard.press('Tab');
    await page.waitForTimeout(350);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(700);
  });
  fs.writeFileSync(path.join(root, 'recordings.json'), JSON.stringify(output, null, 2));
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 4000))]);
  process.exit(Object.values(output).every(item => item.errors.length === 0 && item.bytes > 100000) ? 0 : 1);
}

main().catch(error => {
  fs.writeFileSync(path.join(root, 'recording-error.txt'), String(error?.stack || error));
  process.exit(1);
});
