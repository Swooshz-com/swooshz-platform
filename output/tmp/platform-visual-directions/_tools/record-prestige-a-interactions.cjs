const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const url = 'http://127.0.0.1:8765/direction-a-prestige-1/';
const recordings = path.resolve(__dirname, '..', 'prestige-a-final-evidence', 'recordings');
const framesRoot = path.join(recordings, 'interaction-frames');
fs.mkdirSync(framesRoot, { recursive: true });

async function prepare(page) {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(1100);
}

async function frame(page, folder, frames) {
  const filename = `frame-${String(frames.length).padStart(5, '0')}.jpg`;
  await page.screenshot({ path: path.join(folder, filename), type: 'jpeg', quality: 82, timeout: 60000 });
  frames.push(filename);
}

async function encode(browser, name, viewport, sourceFrames, duration) {
  const fps = 12;
  const count = Math.round(duration * fps);
  const urls = [];
  for (let step = 0; step < count; step += 1) {
    const index = Math.min(sourceFrames.length - 1, Math.round((step / (count - 1)) * (sourceFrames.length - 1)));
    urls.push(`http://127.0.0.1:8765/prestige-a-final-evidence/recordings/interaction-frames/${name}/${sourceFrames[index]}`);
  }
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:8765/', { waitUntil: 'commit', timeout: 30000 });
  const downloadPromise = page.waitForEvent('download', { timeout: 120000 });
  await page.evaluate(async ({ urls, width, height, fps, filename }) => {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d', { alpha: false });
    const stream = canvas.captureStream(0);
    const track = stream.getVideoTracks()[0];
    const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp8') ? 'video/webm;codecs=vp8' : 'video/webm';
    const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3200000 });
    const chunks = [];
    recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
    const stopped = new Promise(resolve => { recorder.onstop = resolve; });
    recorder.start();
    for (const source of urls) {
      const image = new Image();
      image.src = source;
      await image.decode();
      context.drawImage(image, 0, 0, width, height);
      track.requestFrame();
      await new Promise(resolve => setTimeout(resolve, 1000 / fps));
    }
    recorder.stop();
    await stopped;
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(new Blob(chunks, { type: mimeType }));
    anchor.download = filename;
    anchor.click();
  }, { urls, width: viewport.width, height: viewport.height, fps, filename: `${name}.webm` });
  const download = await downloadPromise;
  const destination = path.join(recordings, `${name}.webm`);
  await download.saveAs(destination);
  await context.close();
  return { file: path.basename(destination), bytes: fs.statSync(destination).size, duration, width: viewport.width, height: viewport.height, sourceFrames: sourceFrames.length, encodedFrames: urls.length, errors: [] };
}

async function captureScroll(browser) {
  const name = 'prestige-a-main-scroll';
  const viewport = { width: 1440, height: 900 };
  const folder = path.join(framesRoot, name);
  fs.rmSync(folder, { recursive: true, force: true });
  fs.mkdirSync(folder, { recursive: true });
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await prepare(page);
  const frames = [];
  const target = await page.evaluate(() => document.querySelector('#platform').offsetTop - innerHeight * .12);
  await page.evaluate(() => document.documentElement.style.scrollBehavior = 'auto');
  for (let step = 0; step <= 12; step += 1) {
    const progress = step / 12;
    const eased = progress < .5 ? 4 * progress ** 3 : 1 - Math.pow(-2 * progress + 2, 3) / 2;
    await page.evaluate(y => scrollTo(0, y), target * eased);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await frame(page, folder, frames);
  }
  for (let step = 1; step <= 8; step += 1) {
    const progress = step / 8;
    const eased = progress * progress * (3 - 2 * progress);
    await page.evaluate(y => scrollTo(0, y), target * (1 - eased));
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await frame(page, folder, frames);
  }
  await context.close();
  if (errors.length) throw new Error(`Scroll recording errors: ${errors.join('; ')}`);
  return { name, viewport, frames, duration: 4.8 };
}

async function captureMenu(browser) {
  const name = 'prestige-a-mobile-menu';
  const viewport = { width: 390, height: 844 };
  const folder = path.join(framesRoot, name);
  fs.rmSync(folder, { recursive: true, force: true });
  fs.mkdirSync(folder, { recursive: true });
  const context = await browser.newContext({ viewport, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await prepare(page);
  const frames = [];
  const toggle = page.locator('.menu-toggle');
  await frame(page, folder, frames);
  await toggle.focus();
  await frame(page, folder, frames);
  await page.keyboard.press('Enter');
  for (const delay of [80, 120, 180]) {
    await page.waitForTimeout(delay);
    await frame(page, folder, frames);
  }
  await page.keyboard.press('Tab');
  await frame(page, folder, frames);
  await page.keyboard.press('Tab');
  await frame(page, folder, frames);
  await page.keyboard.press('Escape');
  for (const delay of [80, 140, 180]) {
    await page.waitForTimeout(delay);
    await frame(page, folder, frames);
  }
  await context.close();
  if (errors.length) throw new Error(`Menu recording errors: ${errors.join('; ')}`);
  return { name, viewport, frames, duration: 3.6 };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const scroll = await captureScroll(browser);
  const menu = await captureMenu(browser);
  fs.writeFileSync(path.join(recordings, 'interaction-frame-manifest.json'), JSON.stringify({ scroll, menu }, null, 2));
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 4000))]);
  process.exit(0);
}

main().catch(error => {
  fs.writeFileSync(path.join(recordings, 'interaction-recording-error.txt'), String(error?.stack || error));
  process.exit(1);
});
