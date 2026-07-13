const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const url = 'http://127.0.0.1:8765/direction-a-prestige-1/';
const evidenceRoot = path.resolve(__dirname, '..', 'prestige-a-final-evidence');
const recordingsRoot = path.join(evidenceRoot, 'recordings');
const framesRoot = path.join(recordingsRoot, 'screencast-frames');
fs.mkdirSync(framesRoot, { recursive: true });

async function prepare(page) {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(1100);
}

async function capture(browser, name, viewport, mobile, action) {
  const folder = path.join(framesRoot, name);
  fs.mkdirSync(folder, { recursive: true });
  const context = await browser.newContext({ viewport, isMobile: mobile, hasTouch: mobile });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await prepare(page);
  const session = await context.newCDPSession(page);
  const frames = [];
  let index = 0;
  let done = false;
  let actionError = null;
  const actionPromise = action(page).catch(error => { actionError = error; }).finally(() => { done = true; });
  while (!done) {
    const screenshot = await session.send('Page.captureScreenshot', { format: 'jpeg', quality: 82, fromSurface: true });
    const filename = `frame-${String(index++).padStart(5, '0')}.jpg`;
    fs.writeFileSync(path.join(folder, filename), Buffer.from(screenshot.data, 'base64'));
    frames.push({ filename });
    await new Promise(resolve => setTimeout(resolve, 45));
  }
  await actionPromise;
  if (actionError) throw actionError;
  const finalScreenshot = await session.send('Page.captureScreenshot', { format: 'jpeg', quality: 82, fromSurface: true });
  const finalFilename = `frame-${String(index++).padStart(5, '0')}.jpg`;
  fs.writeFileSync(path.join(folder, finalFilename), Buffer.from(finalScreenshot.data, 'base64'));
  frames.push({ filename: finalFilename });
  await context.close();
  if (frames.length < 3) throw new Error(`${name} produced only ${frames.length} browser frames`);
  return { name, viewport, frames, errors };
}

function timeline(captureResult, fps = 12) {
  const { name, frames } = captureResult;
  const durations = {
    'prestige-a-initial-load': 3.2,
    'prestige-a-main-scroll': 4.8,
    'prestige-a-mobile-menu': 3.6,
  };
  const duration = durations[name];
  const frameCount = Math.max(2, Math.round(duration * fps));
  const urls = [];
  for (let step = 0; step < frameCount; step += 1) {
    const sourceIndex = Math.min(frames.length - 1, Math.round((step / (frameCount - 1)) * (frames.length - 1)));
    urls.push(`http://127.0.0.1:8765/prestige-a-final-evidence/recordings/screencast-frames/${name}/${frames[sourceIndex].filename}`);
  }
  return { urls, duration, fps };
}

async function encode(browser, captureResult) {
  const { name, viewport } = captureResult;
  const sequence = timeline(captureResult);
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:8765/', { waitUntil: 'commit', timeout: 30000 });
  const downloadPromise = page.waitForEvent('download', { timeout: 120000 });
  await page.evaluate(async ({ urls, width, height, fps, filename }) => {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d', { alpha: false });
    const stream = canvas.captureStream(fps);
    const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp8')
      ? 'video/webm;codecs=vp8'
      : 'video/webm';
    const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3200000 });
    const chunks = [];
    recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
    const stopped = new Promise(resolve => { recorder.onstop = resolve; });
    recorder.start();
    const frameDelay = 1000 / fps;
    for (const source of urls) {
      const image = new Image();
      image.src = source;
      await image.decode();
      context.drawImage(image, 0, 0, width, height);
      await new Promise(resolve => setTimeout(resolve, frameDelay));
    }
    await new Promise(resolve => setTimeout(resolve, frameDelay * 2));
    recorder.stop();
    await stopped;
    const blob = new Blob(chunks, { type: mimeType });
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(blob);
    anchor.download = filename;
    anchor.click();
  }, {
    urls: sequence.urls,
    width: viewport.width,
    height: viewport.height,
    fps: sequence.fps,
    filename: `${name}.webm`,
  });
  const download = await downloadPromise;
  const destination = path.join(recordingsRoot, `${name}.webm`);
  await download.saveAs(destination);
  await context.close();
  return {
    file: path.basename(destination),
    bytes: fs.statSync(destination).size,
    duration: Number(sequence.duration.toFixed(2)),
    width: viewport.width,
    height: viewport.height,
    sourceFrames: captureResult.frames.length,
    encodedFrames: sequence.urls.length,
    errors: captureResult.errors,
  };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const initial = await capture(browser, 'prestige-a-initial-load', { width: 1440, height: 900 }, false, async page => {
    await page.evaluate(async () => {
      const root = document.documentElement;
      const reset = document.createElement('style');
      reset.textContent = 'html.screencast-reset *, html.screencast-reset *::before, html.screencast-reset *::after { transition: none !important; }';
      document.head.append(reset);
      root.classList.add('screencast-reset', 'motion-enabled');
      root.classList.remove('is-ready');
      void root.offsetWidth;
      await new Promise(resolve => requestAnimationFrame(resolve));
      root.classList.remove('screencast-reset');
      void root.offsetWidth;
    });
    await page.waitForTimeout(220);
    await page.evaluate(() => document.documentElement.classList.add('is-ready'));
    await page.waitForTimeout(1350);
    await page.locator('.button-primary').hover();
    await page.waitForTimeout(450);
  });
  const scroll = await capture(browser, 'prestige-a-main-scroll', { width: 1440, height: 900 }, false, async page => {
    const target = await page.evaluate(() => document.querySelector('#platform').offsetTop - innerHeight * .12);
    await page.evaluate(async y => {
      const root = document.documentElement;
      root.style.scrollBehavior = 'auto';
      const animate = (from, to, duration) => new Promise(resolve => {
        const start = performance.now();
        const tick = now => {
          const progress = Math.min(1, (now - start) / duration);
          const eased = progress < .5 ? 4 * progress ** 3 : 1 - Math.pow(-2 * progress + 2, 3) / 2;
          scrollTo(0, from + (to - from) * eased);
          if (progress < 1) requestAnimationFrame(tick);
          else resolve();
        };
        requestAnimationFrame(tick);
      });
      await animate(0, y, 2300);
      await new Promise(resolve => setTimeout(resolve, 350));
      await animate(y, 0, 1500);
      root.style.removeProperty('scroll-behavior');
    }, target);
    await page.waitForTimeout(350);
  });
  const menu = await capture(browser, 'prestige-a-mobile-menu', { width: 390, height: 844 }, true, async page => {
    const toggle = page.locator('.menu-toggle');
    await toggle.focus();
    await page.waitForTimeout(300);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(850);
    await page.keyboard.press('Tab');
    await page.waitForTimeout(320);
    await page.keyboard.press('Tab');
    await page.waitForTimeout(320);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(650);
  });

  const output = {};
  for (const result of [initial, scroll, menu]) {
    output[result.name] = await encode(browser, result);
  }
  fs.writeFileSync(path.join(recordingsRoot, 'recordings.json'), JSON.stringify(output, null, 2));
  fs.rmSync(framesRoot, { recursive: true, force: true });
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 4000))]);
  process.exit(Object.values(output).every(item => item.bytes > 100000 && item.errors.length === 0) ? 0 : 1);
}

main().catch(error => {
  fs.writeFileSync(path.join(recordingsRoot, 'screencast-error.txt'), String(error?.stack || error));
  process.exit(1);
});
