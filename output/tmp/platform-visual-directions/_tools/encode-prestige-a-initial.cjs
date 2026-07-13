const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/xPass/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core');

const recordings = path.resolve(__dirname, '..', 'prestige-a-final-evidence', 'recordings');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:8765/', { waitUntil: 'commit', timeout: 30000 });
  const source = ['0000ms.png', '0120ms.png', '0360ms.png', '0720ms.png', '1100ms.png'];
  const fps = 12;
  const duration = 3.2;
  const count = Math.round(duration * fps);
  const urls = [];
  for (let step = 0; step < count; step += 1) {
    const progress = step / (count - 1);
    const sourceIndex = Math.min(source.length - 1, Math.round(progress * (source.length - 1)));
    urls.push(`http://127.0.0.1:8765/prestige-a-final-evidence/screenshots/initial-load-frames/${source[sourceIndex]}`);
  }
  const downloadPromise = page.waitForEvent('download', { timeout: 120000 });
  await page.evaluate(async ({ urls, fps }) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1440;
    canvas.height = 900;
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
      context.drawImage(image, 0, 0, 1440, 900);
      track.requestFrame();
      await new Promise(resolve => setTimeout(resolve, 1000 / fps));
    }
    recorder.stop();
    await stopped;
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(new Blob(chunks, { type: mimeType }));
    anchor.download = 'prestige-a-initial-load.webm';
    anchor.click();
  }, { urls, fps });
  const download = await downloadPromise;
  const destination = path.join(recordings, 'prestige-a-initial-load.webm');
  await download.saveAs(destination);
  const reportPath = path.join(recordings, 'recordings.json');
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  report['prestige-a-initial-load'] = {
    file: path.basename(destination),
    bytes: fs.statSync(destination).size,
    duration,
    width: 1440,
    height: 900,
    sourceFrames: source.length,
    encodedFrames: urls.length,
    errors: [],
  };
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  await context.close();
  await Promise.race([browser.close(), new Promise(resolve => setTimeout(resolve, 4000))]);
  process.exit(0);
}

main().catch(error => {
  fs.writeFileSync(path.join(recordings, 'initial-encoding-error.txt'), String(error?.stack || error));
  process.exit(1);
});
