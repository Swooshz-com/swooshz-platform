const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const url = 'file:///C:/Users/xPass/GitHub%20Projects/swooshz-platform/_tmp/platform-visual-directions/direction-a-prestige-1/index.html';
const root = path.resolve(__dirname, '..', 'prestige-a-final-evidence', 'screenshots', 'initial-load-frames');
fs.mkdirSync(root, { recursive: true });

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(1100);
  await page.evaluate(async () => {
    const root = document.documentElement;
    const reset = document.createElement('style');
    reset.id = 'motion-frame-reset';
    reset.textContent = 'html.motion-frame-reset *, html.motion-frame-reset *::before, html.motion-frame-reset *::after { transition: none !important; }';
    document.head.append(reset);
    root.classList.add('motion-frame-reset', 'motion-enabled');
    root.classList.remove('is-ready');
    document.getAnimations().forEach(animation => animation.cancel());
    void root.offsetWidth;
    await new Promise(resolve => requestAnimationFrame(resolve));
    root.classList.remove('motion-frame-reset');
    void root.offsetWidth;
    await new Promise(resolve => requestAnimationFrame(resolve));
    root.classList.add('is-ready');
    await new Promise(resolve => requestAnimationFrame(resolve));
  });

  const output = {};
  for (const moment of [0, 120, 360, 720, 1100]) {
    await page.evaluate(time => {
      document.getAnimations().filter(animation => animation instanceof CSSTransition).forEach(animation => {
        animation.pause();
        animation.currentTime = time;
      });
    }, moment);
    await page.screenshot({ path: path.join(root, `${String(moment).padStart(4, '0')}ms.png`) });
    output[`${moment}ms`] = await page.evaluate(() => ({
      eyebrowOpacity: getComputedStyle(document.querySelector('.eyebrow')).opacity,
      headlineOpacity: [...document.querySelectorAll('.reveal-line > span')].map(element => getComputedStyle(element).opacity),
      headlineTransform: [...document.querySelectorAll('.reveal-line > span')].map(element => getComputedStyle(element).transform),
      ledeOpacity: getComputedStyle(document.querySelector('.hero-lede')).opacity,
      ctaOpacity: getComputedStyle(document.querySelector('.hero-actions')).opacity,
      artworkOpacity: getComputedStyle(document.querySelector('.hero-visual')).opacity,
      artworkClip: getComputedStyle(document.querySelector('.hero-visual')).clipPath,
      h1Visible: document.querySelector('h1').getBoundingClientRect().height > 0,
      ctaVisible: document.querySelector('.button-primary').getBoundingClientRect().height >= 50,
    }));
  }

  fs.writeFileSync(path.resolve(root, '..', '..', 'motion-frames.json'), JSON.stringify(output, null, 2));
  await Promise.race([context.close(), new Promise(resolve => setTimeout(resolve, 3000))]);
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 3000))]);
  process.exit(0);
}

main().catch(error => {
  fs.writeFileSync(path.resolve(root, '..', '..', 'motion-frames-error.txt'), String(error?.stack || error));
  process.exit(1);
});
