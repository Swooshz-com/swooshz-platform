const { chromium } = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");

const root = __dirname;
const output = path.join(root, "evidence", "supporting");
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

async function facts(page) {
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
    const longEmail = [...document.querySelectorAll(".member-identity small")].at(-1);
    const keyTargetHeights = [
      ".mobile-menu-button",
      ".mobile-section-selector:not([hidden])",
      ".add-member-button",
      ".member-action button",
      "#launch-button",
      ".modal-panel:not([hidden]) .icon-button",
      ".modal-panel:not([hidden]) .primary-button",
      ".modal-panel:not([hidden]) .secondary-button",
      "#member-menu:not([hidden]) button"
    ].flatMap(selector => [...document.querySelectorAll(selector)])
      .filter(visible)
      .map(element => Math.round(element.getBoundingClientRect().height));
    return {
      viewport: { width: innerWidth, height: innerHeight },
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      scrollHeight: document.documentElement.scrollHeight,
      noHorizontalOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      bodyTextLength: document.body.innerText.trim().length,
      frameworkOverlay: Boolean(document.querySelector("nextjs-portal, vite-error-overlay, #webpack-dev-server-client-overlay")),
      smallestRoutineFont: Math.min(...routineFonts),
      minimumKeyTargetHeight: keyTargetHeights.length ? Math.min(...keyTargetHeights) : null,
      description: rect(".product-description"),
      launchButton: rect("#launch-button"),
      sectionSelector: rect(".mobile-section-selector:not([hidden])"),
      modal: rect(".modal-panel:not([hidden])"),
      actionMenu: rect("#member-menu:not([hidden])"),
      focused: document.activeElement?.id || document.activeElement?.textContent?.trim().slice(0, 80) || document.activeElement?.tagName,
      landmarks: {
        header: document.querySelectorAll("header").length,
        nav: document.querySelectorAll("nav").length,
        main: document.querySelectorAll("main").length
      },
      visibleH1Count: [...document.querySelectorAll("h1")].filter(visible).length,
      longEmailWraps: longEmail ? getComputedStyle(longEmail).whiteSpace !== "nowrap" && longEmail.scrollWidth <= longEmail.parentElement.clientWidth : null,
      productDescriptionVisible: visible(document.querySelector(".product-description")),
      launchActionVisibleInViewport: (() => {
        const button = document.querySelector("#launch-button");
        return visible(button) && button.getBoundingClientRect().bottom <= innerHeight;
      })()
    };
  });
}

async function prepareState(page, state) {
  if (state === "add-member") {
    await page.locator("[data-open-add-member]").click();
  } else if (state === "member-menu") {
    await page.locator("[data-member-menu]").first().click();
  } else if (state === "confirmation") {
    await page.locator("[data-member-menu]").first().click();
    await page.locator("#member-menu [data-confirm='disable-member']").click();
  } else if (state === "focus-launch") {
    await page.locator("#launch-button").focus();
  }
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
  const results = {};

  const screens = [
    { key: "desktop-product-access", url: "?view=access", width: 1440, height: 900 },
    { key: "desktop-pending-approvals", url: "?view=pending", width: 1440, height: 900 },
    { key: "desktop-audit-activity", url: "?view=audit", width: 1440, height: 900 },
    { key: "desktop-add-member-modal", url: "?view=members", width: 1440, height: 900, state: "add-member" },
    { key: "desktop-member-action-menu", url: "?view=members", width: 1440, height: 900, state: "member-menu" },
    { key: "desktop-confirmation-modal", url: "?view=members", width: 1440, height: 900, state: "confirmation" },
    { key: "desktop-launch-failure", url: "?view=launcher&state=failure", width: 1440, height: 900 },
    { key: "desktop-product-access-unavailable", url: "?view=launcher&state=unavailable", width: 1440, height: 900 },
    { key: "mobile-product-access", url: "?view=access", width: 390, height: 844 },
    { key: "mobile-add-member-modal", url: "?view=members", width: 390, height: 844, state: "add-member" },
    { key: "mobile-member-action", url: "?view=members", width: 390, height: 844, state: "member-menu" },
    { key: "mobile-confirmation", url: "?view=members", width: 390, height: 844, state: "confirmation" },
    { key: "launcher-320", url: "?view=launcher", width: 320, height: 844 },
    { key: "members-320", url: "?view=members", width: 320, height: 844 },
    { key: "keyboard-focus", url: "?view=launcher", width: 1440, height: 900, state: "focus-launch" },
    { key: "zoom-200", url: "?view=members", width: 720, height: 450, deviceScaleFactor: 2 }
  ];

  for (const screen of screens) {
    const page = await browser.newPage({
      viewport: { width: screen.width, height: screen.height },
      deviceScaleFactor: screen.deviceScaleFactor || 1,
      reducedMotion: "reduce"
    });
    page.on("console", message => {
      const entry = `${screen.key}: ${message.text()}`;
      if (message.type() === "error") errors.push(entry);
      if (message.type() === "warning") warnings.push(entry);
    });
    page.on("pageerror", error => errors.push(`${screen.key}: ${error.message}`));
    page.on("request", request => {
      if (!request.url().startsWith(origin)) errors.push(`${screen.key}: external request ${request.url()}`);
    });
    await page.goto(`${origin}/${screen.url}`, { waitUntil: "networkidle" });
    await page.evaluate(() => document.fonts.ready);
    await prepareState(page, screen.state);
    await page.waitForTimeout(80);
    results[screen.key] = { url: await page.url(), title: await page.title(), ...(await facts(page)) };
    await page.screenshot({ path: path.join(output, `${screen.key}.png`), fullPage: false });
    await page.close();
  }

  const interaction = {};
  const members = await browser.newPage({ viewport: { width: 390, height: 844 }, reducedMotion: "reduce" });
  await members.goto(`${origin}/?view=members`, { waitUntil: "networkidle" });
  const addButton = members.locator("[data-open-add-member]");
  await addButton.click();
  await members.waitForFunction(() => document.activeElement?.id === "member-email");
  interaction.modalFocusEntry = await members.evaluate(() => document.activeElement?.id);
  interaction.addDialogSemantics = await members.locator("#add-member-modal").evaluate(element => ({ role: element.getAttribute("role"), ariaModal: element.getAttribute("aria-modal"), labelledBy: element.getAttribute("aria-labelledby") }));
  await members.keyboard.press("Shift+Tab");
  interaction.focusContainedAfterReverseTab = await members.evaluate(() => Boolean(document.activeElement?.closest("#add-member-modal")));
  await members.keyboard.press("Escape");
  interaction.focusRestoredAfterEscape = await addButton.evaluate(element => document.activeElement === element);
  await members.locator("[data-member-menu]").first().click();
  interaction.memberMenuVisible = await members.locator("#member-menu").isVisible();
  interaction.memberMenuFirstFocus = await members.evaluate(() => document.activeElement?.textContent?.trim());
  await members.keyboard.press("Escape");
  interaction.memberMenuClosedWithEscape = !(await members.locator("#member-menu").isVisible());
  await members.locator("[data-member-menu]").first().click();
  await members.locator("#member-menu [data-confirm='disable-member']").click();
  interaction.confirmDialogSemantics = await members.locator("#confirm-modal").evaluate(element => ({ role: element.getAttribute("role"), ariaModal: element.getAttribute("aria-modal"), labelledBy: element.getAttribute("aria-labelledby"), describedBy: element.getAttribute("aria-describedby") }));
  await members.keyboard.press("Escape");
  interaction.confirmClosedWithEscape = !(await members.locator("#confirm-modal").isVisible());
  await members.locator("#section-selector").click();
  interaction.mobileSectionMenuItems = await members.locator("#section-menu a").allTextContents();
  await members.keyboard.press("Escape");
  interaction.mobileSectionMenuClosedWithEscape = !(await members.locator("#section-menu").isVisible());
  await members.locator(".mobile-menu-button").click();
  interaction.mobileAccountMenuVisible = await members.locator(".action-menu").filter({ hasText: "Account details" }).isVisible();
  await members.keyboard.press("Escape");
  interaction.reducedMotionDuration = await members.locator(".member-row").first().evaluate(element => getComputedStyle(element).transitionDuration);
  interaction.longEmailWraps = await members.locator(".member-identity small").last().evaluate(element => element.scrollWidth <= element.parentElement.clientWidth && getComputedStyle(element).whiteSpace !== "nowrap");
  await members.close();

  const launcher = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await launcher.goto(`${origin}/?view=launcher`, { waitUntil: "networkidle" });
  await launcher.locator("#mobile-workspace").click();
  interaction.workspaceSwitch = await launcher.locator("#mobile-workspace strong").textContent();
  await launcher.locator("#launch-button").click();
  interaction.launchBusy = await launcher.locator("#launch-button span").textContent();
  interaction.launchBusyDisabled = await launcher.locator("#launch-button").isDisabled();
  await launcher.waitForTimeout(720);
  interaction.launchFailureVisible = await launcher.locator("#launch-feedback").isVisible();
  interaction.launchFailureCopy = await launcher.locator("#launch-feedback").innerText();
  await launcher.locator("[data-retry-launch]").click();
  interaction.retryBusy = await launcher.locator("#launch-button span").textContent();
  await launcher.close();

  await browser.close();
  server.close();

  const payload = { origin: "localhost ephemeral", browser: "Installed Google Chrome via Playwright", errors, warnings, results, interaction };
  fs.writeFileSync(path.join(root, "support-validation.json"), JSON.stringify(payload, null, 2));
  const failures = [];
  for (const [key, value] of Object.entries(results)) {
    if (value.bodyTextLength < 100) failures.push(`${key}: blank or incomplete page`);
    if (value.frameworkOverlay) failures.push(`${key}: framework overlay detected`);
    if (!value.noHorizontalOverflow) failures.push(`${key}: horizontal overflow ${value.scrollWidth}/${value.clientWidth}`);
    if (value.smallestRoutineFont < 14) failures.push(`${key}: routine text below 14px (${value.smallestRoutineFont})`);
    if (value.viewport.width <= 390 && value.minimumKeyTargetHeight !== null && value.minimumKeyTargetHeight < 44) failures.push(`${key}: key target below 44px (${value.minimumKeyTargetHeight})`);
    if ((key === "launcher-320") && (!value.productDescriptionVisible || !value.launchActionVisibleInViewport)) failures.push(`${key}: required product description or action missing from first viewport`);
    if (value.visibleH1Count !== 1) failures.push(`${key}: expected one visible h1, found ${value.visibleH1Count}`);
  }
  if (interaction.modalFocusEntry !== "member-email") failures.push(`add-member: expected focus entry on member-email, got ${interaction.modalFocusEntry}`);
  if (!interaction.focusContainedAfterReverseTab || !interaction.focusRestoredAfterEscape) failures.push("add-member: focus containment/restoration failed");
  if (!interaction.memberMenuClosedWithEscape || !interaction.confirmClosedWithEscape || !interaction.mobileSectionMenuClosedWithEscape) failures.push("keyboard: Escape close failed");
  if (!interaction.launchBusyDisabled || !interaction.launchFailureVisible) failures.push("launch: busy/failure flow failed");
  if (errors.length || failures.length) throw new Error([...errors, ...failures].join("\n"));
  console.log(JSON.stringify(payload, null, 2));
})().catch(error => {
  console.error(error);
  server.close();
  process.exit(1);
});
