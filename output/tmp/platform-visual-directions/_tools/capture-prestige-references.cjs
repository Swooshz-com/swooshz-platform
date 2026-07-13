const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const root = path.resolve(__dirname, '..', 'prestige-reference-captures');
fs.mkdirSync(root, { recursive: true });

const references = [
  ['linear', 'https://linear.app/'],
  ['framer', 'https://www.framer.com/'],
  ['stripe', 'https://stripe.com/'],
  ['aesop', 'https://www.aesop.com/'],
  ['rimowa', 'https://www.rimowa.com/ww/en/home']
];

async function dismissConsent(page) {
  const labels = [/accept all/i, /accept cookies/i, /allow all/i, /agree/i, /continue without/i];
  for (const label of labels) {
    const button = page.getByRole('button', { name: label }).first();
    if (await button.isVisible().catch(() => false)) {
      await button.click({ timeout: 2000 }).catch(() => {});
      await page.waitForTimeout(500);
      return;
    }
  }
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const results = [];

  for (const [name, url] of references) {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      deviceScaleFactor: 1,
      reducedMotion: 'no-preference'
    });
    const page = await context.newPage();
    const consoleErrors = [];
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await page.waitForTimeout(4500);
      await dismissConsent(page);
      await page.waitForTimeout(1200);
      await page.screenshot({
        path: path.join(root, `${name}-desktop-first.png`),
        fullPage: false,
        animations: 'disabled'
      });

      const metrics = await page.evaluate(() => {
        const style = (element) => element ? getComputedStyle(element) : null;
        const rect = (element) => {
          if (!element) return null;
          const box = element.getBoundingClientRect();
          return { x: box.x, y: box.y, width: box.width, height: box.height };
        };
        const body = document.body;
        const header = document.querySelector('header');
        const h1 = document.querySelector('h1');
        const firstImage = [...document.images].find((image) => image.getBoundingClientRect().height > 160) || document.images[0];
        const bodyStyle = style(body);
        const headerStyle = style(header);
        const h1Style = style(h1);
        const moving = [...document.querySelectorAll('*')].slice(0, 1400).filter((element) => {
          const computed = getComputedStyle(element);
          return computed.animationName !== 'none' || computed.transitionDuration !== '0s' || computed.transform !== 'none';
        }).length;
        return {
          title: document.title,
          body: {
            background: bodyStyle?.background,
            color: bodyStyle?.color,
            fontFamily: bodyStyle?.fontFamily
          },
          header: header ? {
            rect: rect(header),
            position: headerStyle?.position,
            background: headerStyle?.background,
            borderBottom: headerStyle?.borderBottom
          } : null,
          h1: h1 ? {
            text: h1.textContent.trim().replace(/\s+/g, ' ').slice(0, 260),
            rect: rect(h1),
            fontFamily: h1Style?.fontFamily,
            fontSize: h1Style?.fontSize,
            fontWeight: h1Style?.fontWeight,
            lineHeight: h1Style?.lineHeight,
            letterSpacing: h1Style?.letterSpacing,
            color: h1Style?.color
          } : null,
          firstLargeImage: rect(firstImage),
          sectionCount: document.querySelectorAll('section').length,
          imageCount: document.images.length,
          videoCount: document.querySelectorAll('video').length,
          canvasCount: document.querySelectorAll('canvas').length,
          elementsWithMotionStyles: moving,
          documentHeight: document.documentElement.scrollHeight,
          viewport: { width: innerWidth, height: innerHeight }
        };
      });
      results.push({ name, requestedUrl: url, finalUrl: page.url(), metrics, consoleErrors: consoleErrors.slice(0, 12) });
    } catch (error) {
      results.push({ name, requestedUrl: url, error: String(error) });
    } finally {
      await context.close();
    }
  }

  await browser.close();
  fs.writeFileSync(path.join(root, 'metrics.json'), JSON.stringify(results, null, 2));
  process.stdout.write(JSON.stringify(results, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
