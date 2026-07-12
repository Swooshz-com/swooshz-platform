import { createServer } from "node:http";
import { copyFile, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { chromium } from "playwright";

import {
  readPublicSiteAsset,
  renderAboutPage,
  renderAdminShellPage,
  renderAppShellPage,
  renderContactPage,
  renderLandingPage,
  renderLoginPage,
  renderResourceArticlePage,
  renderResourcesPage,
  renderRequestAccessPage,
  renderSolutionsPage,
} from "../dist/index.js";

const publicRoutes = [
  { slug: "home", path: "/", render: renderLandingPage },
  { slug: "solutions", path: "/solutions", render: renderSolutionsPage },
  { slug: "resources", path: "/resources", render: renderResourcesPage },
  { slug: "resource-article", path: "/resources/platform-launch-boundaries", render: renderResourceArticlePage },
  { slug: "about", path: "/about", render: renderAboutPage },
  { slug: "contact", path: "/contact", render: renderContactPage },
  { slug: "request-access", path: "/request-access", render: renderRequestAccessPage },
  { slug: "login", path: "/login", render: renderLoginPage },
];

const outputArgument = readArgument("--output") ?? "public-site-evidence";
const outputRoot = resolve(outputArgument);
const headSha = process.env.EVIDENCE_HEAD_SHA?.trim() || "local-uncommitted";

if (basename(outputRoot) !== "public-site-evidence") {
  throw new Error("Evidence output directory must be named public-site-evidence.");
}

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });

const routeRenderers = new Map(publicRoutes.map((route) => [route.path, route.render]));
routeRenderers.set("/app", renderAppShellPage);
routeRenderers.set("/app/admin", renderAdminShellPage);

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");

    if (requestUrl.pathname.startsWith("/public-assets/")) {
      const asset = await readPublicSiteAsset(requestUrl.pathname);

      if (!asset) return writeResponse(response, 404, { "content-type": "text/plain" }, "Not found");

      return writeResponse(response, asset.statusCode, asset.headers, Buffer.from(asset.body));
    }

    if (requestUrl.pathname.startsWith("/api/platform/")) {
      return writeResponse(response, 401, { "content-type": "application/json", "cache-control": "no-store" }, JSON.stringify({ outcome: "denied" }));
    }

    const render = routeRenderers.get(requestUrl.pathname);
    if (!render) return writeResponse(response, 404, { "content-type": "text/plain" }, "Not found");

    return writeResponse(response, 200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }, render());
  } catch {
    return writeResponse(response, 500, { "content-type": "text/plain", "cache-control": "no-store" }, "Evidence server error");
  }
});

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});

const address = server.address();
if (!address || typeof address === "string") throw new Error("Evidence server did not expose a TCP address.");
const origin = `http://127.0.0.1:${address.port}`;
const browser = await chromium.launch({ headless: true });
const consoleFailures = [];

try {
  assertRenderedAssetsAreVersioned();
  const contrastResults = await assertPublicAnchorContrast(browser, origin);
  await captureRouteMatrix(browser, origin, { width: 1440, height: 900 }, "desktop");
  await captureRouteMatrix(browser, origin, { width: 390, height: 844 }, "mobile");
  await createContactSheet(browser, "desktop", 2, 640);
  await createContactSheet(browser, "mobile", 4, 300);

  await capturePage(browser, origin, "/", { width: 2560, height: 1440 }, "screenshots/home-large-2560x1440.png");
  await capturePage(browser, origin, "/", { width: 1440, height: 900 }, "screenshots/home-standard-1440x900.png");
  await capturePage(browser, origin, "/", { width: 1366, height: 768 }, "screenshots/home-short-1366x768.png");
  await capturePage(browser, origin, "/", { width: 844, height: 390 }, "screenshots/home-short-landscape-844x390.png");
  await captureMenuOpen(browser, origin);
  await captureSkipLinkFocus(browser, origin);
  await capturePage(browser, origin, "/", { width: 1440, height: 900 }, "screenshots/reduced-motion-desktop.png", { reducedMotion: "reduce" });
  await capturePage(browser, origin, "/", { width: 390, height: 844 }, "screenshots/reduced-motion-mobile.png", { reducedMotion: "reduce", isMobile: true, hasTouch: true });

  for (const route of ["/app", "/app/admin"]) {
    const slug = route === "/app" ? "app" : "admin";
    await capturePage(browser, origin, route, { width: 1440, height: 900 }, `screenshots/${slug}-desktop.png`);
    await capturePage(browser, origin, route, { width: 390, height: 844 }, `screenshots/${slug}-mobile.png`, { isMobile: true, hasTouch: true });
  }

  await recordVideo(browser, origin, "scroll-down.webm", { width: 1440, height: 900 }, scrollDown);
  await recordVideo(browser, origin, "scroll-up.webm", { width: 1440, height: 900 }, scrollUp);
  await recordVideo(browser, origin, "mobile-free-scroll.webm", { width: 390, height: 844 }, mobileFreeScroll, { isMobile: true, hasTouch: true });
  await recordVideo(browser, origin, "mobile-menu.webm", { width: 390, height: 844 }, mobileMenu, { isMobile: true, hasTouch: true });
  await rm(join(outputRoot, "videos", ".raw"), { recursive: true, force: true });

  if (consoleFailures.length) {
    throw new Error(`Browser console failures: ${consoleFailures.join(" | ")}`);
  }

  const files = await listFiles(outputRoot);
  const manifest = {
    artifact: "prestige-a-public-site-evidence",
    headSha,
    generatedAt: new Date().toISOString(),
    browser: `Chromium ${browser.version()}`,
    captureOrigin: origin,
    cacheStrategy: "SHA-256 content-addressed URLs with immutable caching; logical aliases revalidate",
    contrastResults,
    files,
  };
  await writeFile(join(outputRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "README.md"), renderReadme(manifest), "utf8");
} finally {
  await browser.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}

console.log(JSON.stringify({ outcome: "captured", headSha, outputRoot }, null, 2));

async function captureRouteMatrix(browserInstance, baseUrl, viewport, label) {
  for (const route of publicRoutes) {
    await capturePage(browserInstance, baseUrl, route.path, viewport, `screenshots/${label}/${route.slug}.png`, {
      isMobile: label === "mobile",
      hasTouch: label === "mobile",
    });
  }
}

async function capturePage(browserInstance, baseUrl, route, viewport, relativePath, options = {}) {
  const context = await browserInstance.newContext({
    viewport,
    deviceScaleFactor: 1,
    reducedMotion: options.reducedMotion ?? "no-preference",
    isMobile: options.isMobile ?? false,
    hasTouch: options.hasTouch ?? false,
  });
  const page = await context.newPage();
  watchConsole(page, relativePath);
  await loadReady(page, `${baseUrl}${route}`);
  const path = join(outputRoot, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await page.screenshot({ path, fullPage: false });
  await context.close();
}

async function captureMenuOpen(browserInstance, baseUrl) {
  const context = await browserInstance.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  watchConsole(page, "mobile-menu-open");
  await loadReady(page, `${baseUrl}/`);
  await page.locator("[data-public-menu-toggle]").click();
  await page.locator("[data-public-menu-toggle]").waitFor({ state: "visible" });
  if (await page.locator("[data-public-menu-toggle]").getAttribute("aria-expanded") !== "true") throw new Error("Mobile menu did not open.");
  await page.waitForTimeout(420);
  const path = join(outputRoot, "screenshots/mobile-menu-open.png");
  await mkdir(dirname(path), { recursive: true });
  await page.screenshot({ path });
  await context.close();
}

async function captureSkipLinkFocus(browserInstance, baseUrl) {
  const context = await browserInstance.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  watchConsole(page, "skip-link-focus");
  await loadReady(page, `${baseUrl}/`);
  await focusByKeyboard(page, ".public-skip-link");
  const path = join(outputRoot, "screenshots/skip-link-focus.png");
  await mkdir(dirname(path), { recursive: true });
  await page.screenshot({ path });
  await context.close();
}

async function assertPublicAnchorContrast(browserInstance, baseUrl) {
  const cases = [
    { id: "home-primary", route: "/", selector: ".prestige-hero-actions .public-button" },
    { id: "login-primary", route: "/login", selector: ".login-actions .public-button" },
    { id: "navigation-primary", route: "/", selector: ".public-nav-cta" },
  ];
  const results = [];

  for (const testCase of cases) {
    for (const state of ["default", "hover", "keyboard-focus"]) {
      const context = await browserInstance.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
      const page = await context.newPage();
      watchConsole(page, `contrast-${testCase.id}-${state}`);
      await loadReady(page, `${baseUrl}${testCase.route}`);
      const locator = page.locator(testCase.selector).first();
      await locator.waitFor({ state: "visible" });

      if (state === "hover") {
        await locator.hover();
        await page.waitForTimeout(380);
      } else if (state === "keyboard-focus") {
        await focusByKeyboard(page, testCase.selector);
        await page.waitForTimeout(380);
      }

      const measurement = await measureAnchorContrast(locator);
      assertContrastMeasurement(testCase.id, state, measurement);
      results.push({ id: testCase.id, state, ...measurement });
      await context.close();
    }
  }

  const skipContext = await browserInstance.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const skipPage = await skipContext.newPage();
  watchConsole(skipPage, "contrast-skip-link-keyboard-focus");
  await loadReady(skipPage, `${baseUrl}/`);
  await focusByKeyboard(skipPage, ".public-skip-link");
  const skipMeasurement = await measureAnchorContrast(skipPage.locator(".public-skip-link"));
  assertContrastMeasurement("skip-link", "keyboard-focus", skipMeasurement);
  results.push({ id: "skip-link", state: "keyboard-focus", ...skipMeasurement });
  await skipContext.close();

  return results;
}

async function focusByKeyboard(page, selector) {
  for (let index = 0; index < 40; index += 1) {
    await page.keyboard.press("Tab");
    if (await page.locator(selector).evaluate((element) => element === document.activeElement)) return;
  }
  throw new Error(`Keyboard focus did not reach ${selector}.`);
}

async function measureAnchorContrast(locator) {
  const measurement = await locator.evaluate((element) => {
    const foreground = getComputedStyle(element).color;
    const pseudo = getComputedStyle(element, "::before");
    const pseudoTransform = pseudo.transform;
    const pseudoVisible = pseudo.content !== "none" &&
      pseudo.backgroundColor !== "rgba(0, 0, 0, 0)" &&
      (pseudoTransform === "none" || /matrix\([^,]+,[^,]+,[^,]+,[^,]+,\s*0(?:\.0+)?,\s*0(?:\.0+)?\)/.test(pseudoTransform));
    let background = pseudoVisible ? pseudo.backgroundColor : getComputedStyle(element).backgroundColor;
    let ancestor = element.parentElement;

    while (background === "rgba(0, 0, 0, 0)" && ancestor) {
      background = getComputedStyle(ancestor).backgroundColor;
      ancestor = ancestor.parentElement;
    }

    const arrow = element.querySelector("b");
    return {
      foreground,
      background,
      arrowForeground: arrow ? getComputedStyle(arrow).color : null,
      pseudoVisible,
      pseudoTransform,
    };
  });

  return {
    ...measurement,
    contrast: contrastRatio(measurement.foreground, measurement.background),
    arrowContrast: measurement.arrowForeground
      ? contrastRatio(measurement.arrowForeground, measurement.background)
      : null,
  };
}

function assertContrastMeasurement(id, state, measurement) {
  if (measurement.contrast < 4.5) {
    throw new Error(`${id} ${state} contrast ${measurement.contrast.toFixed(2)}:1 is below 4.5:1 (${measurement.foreground} on ${measurement.background}).`);
  }
  if (measurement.arrowContrast !== null && measurement.arrowContrast < 3) {
    throw new Error(`${id} ${state} arrow contrast ${measurement.arrowContrast.toFixed(2)}:1 is below 3:1.`);
  }
}

function contrastRatio(foreground, background) {
  const foregroundLuminance = relativeLuminance(parseRgb(foreground));
  const backgroundLuminance = relativeLuminance(parseRgb(background));
  const lighter = Math.max(foregroundLuminance, backgroundLuminance);
  const darker = Math.min(foregroundLuminance, backgroundLuminance);
  return Number(((lighter + 0.05) / (darker + 0.05)).toFixed(3));
}

function parseRgb(value) {
  const channels = value.match(/[\d.]+/g)?.slice(0, 3).map(Number);
  if (!channels || channels.length !== 3) throw new Error(`Unsupported computed color: ${value}`);
  return channels;
}

function relativeLuminance(channels) {
  const [red, green, blue] = channels.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}
async function createContactSheet(browserInstance, label, columns, imageWidth) {
  const captures = [];

  for (const route of publicRoutes) {
    const bytes = await readFileBuffer(join(outputRoot, "screenshots", label, `${route.slug}.png`));
    captures.push({ label: `${route.path} - ${label}`, dataUrl: `data:image/png;base64,${bytes.toString("base64")}` });
  }

  const context = await browserInstance.newContext({ viewport: { width: columns * (imageWidth + 28) + 28, height: 900 } });
  const page = await context.newPage();
  await page.setContent(`<!doctype html><style>body{margin:0;padding:28px;background:#081d33;color:white;font:600 16px Arial}.grid{display:grid;grid-template-columns:repeat(${columns},${imageWidth}px);gap:28px}.shot{display:grid;gap:9px}.shot img{display:block;width:${imageWidth}px;height:auto;background:white;box-shadow:0 12px 30px #0006}.label{letter-spacing:.03em}</style><div class="grid">${captures.map((capture) => `<div class="shot"><div class="label">${escapeHtml(capture.label)}</div><img src="${capture.dataUrl}" alt=""></div>`).join("")}</div>`);
  const path = join(outputRoot, "contact-sheets", `${label}-public-routes.png`);
  await mkdir(dirname(path), { recursive: true });
  await page.screenshot({ path, fullPage: true });
  await context.close();
}

async function recordVideo(browserInstance, baseUrl, fileName, viewport, action, options = {}) {
  const rawDirectory = join(outputRoot, "videos", ".raw", fileName.replace(/\.webm$/, ""));
  await mkdir(rawDirectory, { recursive: true });
  const context = await browserInstance.newContext({
    viewport,
    deviceScaleFactor: 1,
    isMobile: options.isMobile ?? false,
    hasTouch: options.hasTouch ?? false,
    recordVideo: { dir: rawDirectory, size: viewport },
  });
  const page = await context.newPage();
  watchConsole(page, fileName);
  await loadReady(page, `${baseUrl}/`);
  const video = page.video();
  await action(page);
  await context.close();
  const rawPath = await video.path();
  const finalPath = join(outputRoot, "videos", fileName);
  await copyFile(rawPath, finalPath);
}

async function scrollDown(page) {
  for (let index = 0; index < 6; index += 1) {
    await page.mouse.wheel(0, 660);
    await page.waitForTimeout(850);
  }
}

async function scrollUp(page) {
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await page.waitForTimeout(900);
  for (let index = 0; index < 6; index += 1) {
    await page.mouse.wheel(0, -660);
    await page.waitForTimeout(850);
  }
}

async function mobileFreeScroll(page) {
  const session = await page.context().newCDPSession(page);
  for (let gesture = 0; gesture < 3; gesture += 1) {
    await dispatchSwipe(session, 195, 700, 195, 220);
    await page.waitForTimeout(500);
  }
}

async function mobileMenu(page) {
  const toggle = page.locator("[data-public-menu-toggle]");
  await toggle.click();
  await page.waitForTimeout(900);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(700);
  await toggle.click();
  await page.waitForTimeout(900);
}

async function dispatchSwipe(session, startX, startY, endX, endY) {
  await session.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: startX, y: startY }] });
  for (let step = 1; step <= 12; step += 1) {
    const progress = step / 12;
    await session.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: startX + (endX - startX) * progress, y: startY + (endY - startY) * progress }] });
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 22));
  }
  await session.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
}

async function loadReady(page, url) {
  const response = await page.goto(url, { waitUntil: "networkidle" });
  if (!response?.ok()) throw new Error(`Evidence route failed: ${url} (${response?.status() ?? "no response"})`);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(180);
}

function watchConsole(page, label) {
  page.on("console", (message) => {
    const text = message.text();
    const expectedSignedOutDenial = /screenshots\/(?:app|admin)-/.test(label) &&
      text === "Failed to load resource: the server responded with a status of 401 (Unauthorized)";
    if (message.type() === "error" && !expectedSignedOutDenial) consoleFailures.push(`${label}: ${text}`);
  });
  page.on("pageerror", (error) => consoleFailures.push(`${label}: ${error.message}`));
}

function assertRenderedAssetsAreVersioned() {
  for (const route of publicRoutes) {
    const html = route.render();
    const assetUrls = html.match(/\/public-assets\/[^\s"',)]+/g) ?? [];
    if (!assetUrls.length || assetUrls.some((url) => !/^\/public-assets\/[a-f0-9]{16}\//.test(url))) {
      throw new Error(`Rendered page contains an unversioned public asset: ${route.path}`);
    }
  }
}

async function listFiles(root) {
  const results = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.name === ".raw") continue;
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      for (const child of await listFiles(path)) results.push(`${entry.name}/${child}`);
    } else if (!entry.name.startsWith(".")) {
      results.push(entry.name);
    }
  }
  return results.sort();
}

function renderReadme(manifest) {
  const contrastRows = manifest.contrastResults
    .map((result) => `| ${result.id} | ${result.state} | ${result.contrast.toFixed(3)}:1 | ${result.arrowContrast === null ? "n/a" : `${result.arrowContrast.toFixed(3)}:1`} |`)
    .join("\n");

  return `# Prestige A public-site review evidence\n\n- Exact amended head: \`${manifest.headSha}\`\n- Browser: ${manifest.browser}\n- Generated: ${manifest.generatedAt}\n- Cache strategy: ${manifest.cacheStrategy}\n\n## Computed contrast\n\n| Target | State | Text | Arrow |\n| --- | --- | ---: | ---: |\n${contrastRows}\n\nThis artifact was generated from the checked-out pull-request head by the public-site evidence workflow. It contains desktop/mobile route contact sheets, required responsive and reduced-motion captures, the focused skip link, portal/admin regression screenshots, and real Chromium recordings for desktop and mobile interactions.\n`;
}

function writeResponse(response, statusCode, headers, body) {
  response.statusCode = statusCode;
  for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
  response.end(body);
}

function readArgument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

async function readFileBuffer(path) {
  const { readFile } = await import("node:fs/promises");
  return readFile(path);
}

function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}
