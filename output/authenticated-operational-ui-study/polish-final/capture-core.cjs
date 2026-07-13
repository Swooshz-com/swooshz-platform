const { chromium } = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");

const root = __dirname;
const version = process.env.POLISH_VERSION || "v1";
const output = path.join(root, "evidence", `core-${version}`);
fs.mkdirSync(output, { recursive: true });

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".woff2": "font/woff2"
};

const server = http.createServer((request, response) => {
  const pathname = new URL(request.url, "http://127.0.0.1").pathname;
  if (pathname === "/favicon.ico") {
    response.writeHead(204);
    response.end();
    return;
  }
  const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const target = path.resolve(root, relative);
  if (!target.startsWith(root) || !fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    response.writeHead(404);
    response.end("Not found");
    return;
  }
  response.writeHead(200, { "content-type": contentTypes[path.extname(target)] || "application/octet-stream" });
  fs.createReadStream(target).pipe(response);
});

async function inspect(page) {
  return page.evaluate(() => {
    const visible = element => Boolean(element) && getComputedStyle(element).display !== "none" && getComputedStyle(element).visibility !== "hidden" && element.getBoundingClientRect().height > 0;
    const rect = selector => {
      const element = document.querySelector(selector);
      if (!visible(element)) return null;
      const box = element.getBoundingClientRect();
      return Object.fromEntries(["x", "y", "width", "height", "bottom", "right"].map(key => [key, Math.round(box[key])]));
    };
    const routineFonts = [...document.querySelectorAll("body *")]
      .filter(element => visible(element) && element.textContent.trim() && !element.classList.contains("sr-only"))
      .map(element => Number.parseFloat(getComputedStyle(element).fontSize))
      .filter(Number.isFinite);
    const bodyText = document.body.innerText.trim();
    return {
      viewport: { width: innerWidth, height: innerHeight },
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      scrollHeight: document.documentElement.scrollHeight,
      noHorizontalOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      meaningfulBodyText: bodyText.length > 100,
      frameworkOverlay: Boolean(document.querySelector("nextjs-portal, vite-error-overlay, #webpack-dev-server-client-overlay")),
      description: rect(".product-description"),
      launchButton: rect("#launch-button"),
      launchUnit: rect(".launch-unit"),
      productIcon: rect(".quote-document-icon"),
      memberSurface: rect(".member-surface"),
      sectionSelector: rect(".mobile-section-selector"),
      smallestRoutineFont: Math.min(...routineFonts),
      bodyFont: Number.parseFloat(getComputedStyle(document.body).fontSize),
      pageTitleFont: Number.parseFloat(getComputedStyle(document.querySelector("h1")).fontSize),
      productDescriptionVisible: visible(document.querySelector(".product-description")),
      launchActionVisibleInViewport: (() => {
        const button = document.querySelector("#launch-button");
        return visible(button) && button.getBoundingClientRect().bottom <= innerHeight;
      })()
    };
  });
}

(async () => {
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROME || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
  });
  const errors = [];
  const warnings = [];
  const pages = {};

  const screens = [
    { key: "desktop-launcher", view: "launcher", width: 1440, height: 900 },
    { key: "desktop-members", view: "members", width: 1440, height: 900 },
    { key: "mobile-launcher-390", view: "launcher", width: 390, height: 844 },
    { key: "mobile-members-390", view: "members", width: 390, height: 844 }
  ];

  for (const screen of screens) {
    const page = await browser.newPage({ viewport: { width: screen.width, height: screen.height }, reducedMotion: "reduce" });
    page.on("console", message => {
      const entry = `${screen.key}: ${message.text()}`;
      if (message.type() === "error") errors.push(entry);
      if (message.type() === "warning") warnings.push(entry);
    });
    page.on("pageerror", error => errors.push(`${screen.key}: ${error.message}`));
    page.on("request", request => {
      if (!request.url().startsWith(origin)) errors.push(`${screen.key}: external request ${request.url()}`);
    });
    await page.goto(`${origin}/?view=${screen.view}`, { waitUntil: "networkidle" });
    await page.evaluate(() => document.fonts.ready);
    pages[screen.key] = {
      url: await page.url(),
      title: await page.title(),
      ...(await inspect(page))
    };
    await page.screenshot({ path: path.join(output, `${screen.key}.png`), fullPage: false });
    await page.close();
  }

  await browser.close();
  server.close();
  const payload = { version, origin: "localhost ephemeral", errors, warnings, pages };
  fs.writeFileSync(path.join(root, `polish-${version}-metrics.json`), JSON.stringify(payload, null, 2));
  const failures = [];
  for (const [key, value] of Object.entries(pages)) {
    if (!value.meaningfulBodyText) failures.push(`${key}: blank or incomplete page`);
    if (value.frameworkOverlay) failures.push(`${key}: framework overlay detected`);
    if (!value.noHorizontalOverflow) failures.push(`${key}: horizontal overflow ${value.scrollWidth}/${value.clientWidth}`);
    if (value.smallestRoutineFont < 14) failures.push(`${key}: routine text below 14px (${value.smallestRoutineFont})`);
    if (key.includes("launcher") && !value.productDescriptionVisible) failures.push(`${key}: product description hidden`);
    if (key.includes("mobile-launcher") && !value.launchActionVisibleInViewport) failures.push(`${key}: launch action outside first viewport`);
  }
  if (errors.length || failures.length) throw new Error([...errors, ...failures].join("\n"));
  console.log(JSON.stringify(payload, null, 2));
})().catch(error => {
  console.error(error);
  server.close();
  process.exit(1);
});
