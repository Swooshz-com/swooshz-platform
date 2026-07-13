const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const root = path.resolve(__dirname, '..', 'prestige-reference-captures');
fs.mkdirSync(root, { recursive: true });

const references = [
  ['bang-olufsen', 'https://www.bang-olufsen.com/en/int'],
  ['aman', 'https://www.aman.com/'],
  ['audemars-piguet', 'https://www.audemarspiguet.com/com/en/home.html']
];

async function main() {
  const browser = await chromium.launch({ headless: true });
  const results = [];
  for (const [name, url] of references) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'no-preference' });
    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await page.waitForTimeout(5000);
      for (const label of [/accept all/i, /accept cookies/i, /allow all/i, /agree/i]) {
        const button = page.getByRole('button', { name: label }).first();
        if (await button.isVisible().catch(() => false)) {
          await button.click({ timeout: 2000 }).catch(() => {});
          break;
        }
      }
      await page.waitForTimeout(1200);
      await page.screenshot({ path: path.join(root, `${name}-desktop-first.png`), fullPage: false, animations: 'disabled' });
      const metrics = await page.evaluate(() => {
        const rect = (element) => element ? (() => { const box = element.getBoundingClientRect(); return { x: box.x, y: box.y, width: box.width, height: box.height }; })() : null;
        const bodyStyle = getComputedStyle(document.body);
        const h1 = document.querySelector('h1');
        const h1Style = h1 ? getComputedStyle(h1) : null;
        const firstImage = [...document.images].find((image) => image.getBoundingClientRect().height > 160) || document.images[0];
        return {
          title: document.title,
          body: { background: bodyStyle.background, color: bodyStyle.color, fontFamily: bodyStyle.fontFamily },
          h1: h1 ? { text: h1.textContent.trim().replace(/\s+/g, ' ').slice(0, 260), rect: rect(h1), fontFamily: h1Style.fontFamily, fontSize: h1Style.fontSize, fontWeight: h1Style.fontWeight, lineHeight: h1Style.lineHeight, letterSpacing: h1Style.letterSpacing, color: h1Style.color } : null,
          firstLargeImage: rect(firstImage),
          imageCount: document.images.length,
          videoCount: document.querySelectorAll('video').length,
          sectionCount: document.querySelectorAll('section').length,
          documentHeight: document.documentElement.scrollHeight,
          viewport: { width: innerWidth, height: innerHeight }
        };
      });
      results.push({ name, requestedUrl: url, finalUrl: page.url(), metrics });
    } catch (error) {
      results.push({ name, requestedUrl: url, error: String(error) });
    }
    await context.close();
  }
  await browser.close();
  fs.writeFileSync(path.join(root, 'luxury-metrics.json'), JSON.stringify(results, null, 2));
  process.stdout.write(JSON.stringify(results, null, 2));
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
