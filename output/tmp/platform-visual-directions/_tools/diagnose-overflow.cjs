const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

(async () => {
  const browser = await chromium.launch({ headless: true });
  for (const number of [1, 2, 3]) {
    for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }, { width: 320, height: 844 }]) {
      const mobile = viewport.width <= 390;
      const context = await browser.newContext({ viewport, isMobile: mobile, hasTouch: mobile });
      const page = await context.newPage();
      await page.goto(`http://127.0.0.1:8765/direction-a-prestige-${number}/`, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(200);
      const result = await page.evaluate(() => {
        const documentWidth = document.documentElement.scrollWidth;
        const overflowers = [...document.querySelectorAll('body *')].map(element => {
          const rect = element.getBoundingClientRect();
          return {
            tag: element.tagName.toLowerCase(),
            className: typeof element.className === 'string' ? element.className : '',
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        }).filter(item => item.right > innerWidth + 1 || item.left < -1)
          .sort((a, b) => Math.max(b.right - innerWidth, -b.left) - Math.max(a.right - innerWidth, -a.left))
          .slice(0, 12);
        return { innerWidth, documentWidth, overflowers };
      });
      process.stdout.write(JSON.stringify({ number, requested: viewport.width, ...result }) + '\n');
      await context.close();
    }
  }
  await browser.close();
})().catch(error => { console.error(error); process.exitCode = 1; });
