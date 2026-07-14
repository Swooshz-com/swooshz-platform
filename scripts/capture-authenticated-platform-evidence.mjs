import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { chromium } from "playwright";

import {
  assertAllowedEvidenceRequest,
  assertSyntheticIdentitySafety,
  requiredAuthenticatedInteractions,
  requiredAuthenticatedScreenshots,
  validateAuthenticatedEvidenceSummary,
  validateEvidenceHeadSha,
} from "./authenticated-platform-evidence-contract.mjs";
import {
  readPublicSiteAsset,
  renderAdminShellPage,
  renderAppShellPage,
} from "../dist/index.js";

const headSha = validateEvidenceHeadSha(process.env.EVIDENCE_HEAD_SHA);
const checkedOutHead = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim().toLowerCase();
if (checkedOutHead !== headSha) throw new Error(`Evidence head mismatch: checked out ${checkedOutHead}, requested ${headSha}.`);

const outputRoot = resolve(readArgument("--output") ?? `authenticated-platform-evidence-${headSha}`);
if (basename(outputRoot) !== `authenticated-platform-evidence-${headSha}`) {
  throw new Error(`Evidence output directory must be named authenticated-platform-evidence-${headSha}.`);
}

const now = "2026-07-14T00:00:00.000Z";
const earlier = "2026-07-13T08:00:00.000Z";
const csrfValue = "synthetic-evidence-only";
const membersPayload = {
  outcome: "listed",
  workspaceId: "workspace-example-primary",
  members: [
    member("membership-owner-example", "user-owner-example", "Alex Example", "alex@example.invalid", "owner", "active"),
    member("membership-admin-example", "user-admin-example", "Morgan Example", "morgan@example.invalid", "admin", "active"),
    member("membership-member-example", "user-member-example", "Casey Example", "casey@example.invalid", "member", "active"),
    member("membership-disabled-example", "user-disabled-example", "Taylor Example", "taylor@example.invalid", "member", "disabled"),
  ],
};
const approvalsPayload = {
  outcome: "listed",
  workspaceId: "workspace-example-primary",
  approvals: [
    { approvalId: "approval-example-one", workspaceId: "workspace-example-primary", email: "pending@example.invalid", role: "member", status: "pending", createdAt: earlier, updatedAt: earlier },
    { approvalId: "approval-example-two", workspaceId: "workspace-example-primary", email: "admin.pending@example.invalid", role: "admin", status: "pending", createdAt: now, updatedAt: now },
  ],
};
const entitlementsPayload = {
  outcome: "listed",
  workspaceId: "workspace-example-primary",
  entitlements: [
    { entitlementId: "entitlement-example-sqag", appId: "app-example-sqag", appKey: "sqag", appName: "Swooshz Quote Auto Generator", appStatus: "private_preview", status: "enabled", grantedByUserId: "user-owner-example", updatedAt: now },
  ],
};
const auditPayload = {
  outcome: "listed",
  workspaceId: "workspace-example-primary",
  events: [
    { eventId: "audit-example-one", workspaceId: "workspace-example-primary", actorUserId: "user-owner-example", actorDisplayName: "Alex Example", actorEmail: "alex@example.invalid", eventType: "workspace.membership.added", targetType: "membership", targetId: "membership-member-example", targetLabel: "Casey Example", createdAt: now, metadata: { newRole: "member", newStatus: "active" } },
    { eventId: "audit-example-two", workspaceId: "workspace-example-primary", actorUserId: "user-admin-example", actorDisplayName: "Morgan Example", actorEmail: "morgan@example.invalid", eventType: "workspace.app_entitlement.enabled", targetType: "app_entitlement", targetId: "entitlement-example-sqag", targetLabel: "Swooshz Quote Auto Generator access", createdAt: earlier, metadata: { appKey: "sqag", previousStatus: "disabled", newStatus: "enabled" } },
  ],
};

assertSyntheticIdentitySafety({ membersPayload, approvalsPayload, entitlementsPayload, auditPayload });
assertFixtureContracts();
await rm(outputRoot, { recursive: true, force: true });
await mkdir(join(outputRoot, "screenshots"), { recursive: true });
await mkdir(join(outputRoot, "contact-sheets"), { recursive: true });

const routeRenderers = new Map([
  ["/app", renderAppShellPage],
  ["/app/admin", renderAdminShellPage],
]);
const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    if (requestUrl.pathname.startsWith("/public-assets/")) {
      const asset = await readPublicSiteAsset(requestUrl.pathname);
      if (!asset) return writeResponse(response, 404, { "content-type": "text/plain" }, "Not found");
      return writeResponse(response, asset.statusCode, asset.headers, Buffer.from(asset.body));
    }
    if (requestUrl.pathname.startsWith("/api/platform/")) {
      return writeResponse(response, 500, { "content-type": "application/json", "cache-control": "no-store" }, JSON.stringify({ outcome: "evidence_interception_required" }));
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
const captures = [];
const interactions = [];
const consoleErrors = [];
const pageErrors = [];
const blockedExternalRequests = [];
const unexpectedApiRequests = [];

try {
  await captureLauncherEvidence();
  await captureAdminEvidence();
  await runInteractionChecks();

  recordInteraction("no-horizontal-overflow", captures.every((capture) => !capture.horizontalOverflow), JSON.stringify(captures.filter((capture) => capture.horizontalOverflow)));
  recordInteraction("no-console-or-page-errors", consoleErrors.length === 0 && pageErrors.length === 0, [...consoleErrors, ...pageErrors].join(" | "));
  await createCoreContactSheet();

  const screenshots = (await readdir(join(outputRoot, "screenshots"))).filter((name) => name.endsWith(".png")).sort();
  const summary = {
    artifact: `authenticated-platform-evidence-${headSha}`,
    headSha,
    generatedAt: new Date().toISOString(),
    browser: `Chromium ${browser.version()}`,
    captureOrigin: origin,
    safety: {
      productionAuthenticationBypass: false,
      productionEnvironmentFlag: false,
      externalProviderCalls: false,
      databaseCalls: false,
      routeInterceptionOnly: true,
      identities: "Synthetic .invalid identities only",
    },
    syntheticFixtureSummary: {
      identityDomain: "example.invalid",
      workspaces: 2,
      members: membersPayload.members.length,
      pendingApprovals: approvalsPayload.approvals.length,
      entitlements: entitlementsPayload.entitlements.length,
      auditEvents: auditPayload.events.length,
    },
    screenshots,
    captures,
    interactions,
    consoleErrors,
    pageErrors,
    blockedExternalRequests,
    unexpectedApiRequests,
  };
  if (unexpectedApiRequests.length) throw new Error(`Unhandled production API contracts: ${unexpectedApiRequests.join(" | ")}`);
  validateAuthenticatedEvidenceSummary(summary);
  await writeFile(join(outputRoot, "browser-check-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "interaction-check-results.json"), `${JSON.stringify(interactions, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "viewport-browser-metadata.json"), `${JSON.stringify({ headSha, browser: summary.browser, captures }, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "README.md"), renderReadme(summary), "utf8");
  const files = await listFiles(outputRoot);
  await writeFile(join(outputRoot, "manifest.json"), `${JSON.stringify({ artifact: summary.artifact, headSha, files }, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ outcome: "captured", artifact: summary.artifact, headSha, screenshots: screenshots.length, interactions: interactions.length, outputRoot }, null, 2));
} finally {
  await browser.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function captureLauncherEvidence() {
  await capture({ name: "launcher-desktop-available.png", route: "/app", viewport: { width: 1440, height: 900 }, scenario: "available" });
  await capture({ name: "launcher-mobile-390-available.png", route: "/app", viewport: { width: 390, height: 844 }, scenario: "available", mobile: true, after: assertLauncherPrimaryContent });
  await capture({ name: "launcher-mobile-320-available.png", route: "/app", viewport: { width: 320, height: 844 }, scenario: "available", mobile: true, after: assertLauncherPrimaryContent });
  await capture({ name: "launcher-multiple-workspaces.png", route: "/app", viewport: { width: 1440, height: 900 }, scenario: "multiple" });
  await capture({ name: "launcher-product-unavailable.png", route: "/app", viewport: { width: 1440, height: 900 }, scenario: "unavailable" });
  await capture({ name: "launcher-controlled-launch-failure.png", route: "/app", viewport: { width: 1440, height: 900 }, scenario: "available", after: async (page) => {
    await page.getByRole("button", { name: "Open product" }).click();
    await page.getByText("We could not open the product. Try again.", { exact: true }).waitFor();
  } });
  await capture({ name: "launcher-keyboard-focus.png", route: "/app", viewport: { width: 1440, height: 900 }, scenario: "available", after: async (page) => {
    await focusByKeyboard(page, "#launchButton");
  } });
}

async function captureAdminEvidence() {
  const desktop = { width: 1440, height: 900 };
  await capture({ name: "admin-desktop-members.png", route: "/app/admin", viewport: desktop, scenario: "admin" });
  await capture({ name: "admin-desktop-pending-approvals.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: (page) => page.locator('[data-admin-nav="pending-approvals"]').click() });
  await capture({ name: "admin-desktop-product-access.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: (page) => page.locator('[data-admin-nav="app-access"]').click() });
  await capture({ name: "admin-desktop-audit-activity.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: (page) => page.locator('[data-admin-nav="activity"]').click() });
  await capture({ name: "admin-desktop-action-disclosure.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: async (page) => {
    await page.getByRole("button", { name: "Manage" }).first().click();
  } });
  await capture({ name: "admin-desktop-add-member-modal.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: (page) => page.getByRole("button", { name: "Add member" }).click() });
  await capture({ name: "admin-desktop-add-member-busy.png", route: "/app/admin", viewport: desktop, scenario: "admin", after: async (page) => {
    await page.getByRole("button", { name: "Add member" }).click();
    await page.locator('input[name="email"]').fill("new.teammate@example.invalid");
    await page.locator("#addMemberForm").evaluate((form) => form.requestSubmit());
    await page.getByRole("button", { name: "Adding member..." }).waitFor();
  }, afterScreenshot: async (page) => {
    await page.locator("#addMemberModal").waitFor({ state: "hidden" });
  } });
  await capture({ name: "admin-mobile-390-members.png", route: "/app/admin", viewport: { width: 390, height: 844 }, scenario: "admin", mobile: true });
  await capture({ name: "admin-mobile-390-product-access.png", route: "/app/admin", viewport: { width: 390, height: 844 }, scenario: "admin", mobile: true, after: (page) => page.locator("#adminSectionSelect").selectOption("app-access") });
  await capture({ name: "admin-mobile-390-add-member-modal.png", route: "/app/admin", viewport: { width: 390, height: 844 }, scenario: "admin", mobile: true, after: (page) => page.getByRole("button", { name: "Add member" }).click() });
  await capture({ name: "admin-mobile-320-members.png", route: "/app/admin", viewport: { width: 320, height: 844 }, scenario: "admin", mobile: true });
  await capture({ name: "admin-enlarged-layout-200pct-equivalent.png", route: "/app/admin", viewport: { width: 720, height: 450 }, scenario: "admin" });
}

async function runInteractionChecks() {
  console.log("Running authenticated interaction checks...");
  await withPage({ viewport: { width: 1440, height: 900 }, scenario: "admin" }, async (page) => {
    await loadAuthenticated(page, "/app/admin");
    const reached = [];
    const activated = [];
    let ariaCurrentValid = true;
    for (let step = 0; step < 50 && reached.length < 4; step += 1) {
      await page.keyboard.press("Tab");
      const section = await page.evaluate(() => document.activeElement?.getAttribute("data-admin-nav"));
      if (!section || reached.includes(section)) continue;
      reached.push(section);
      const key = reached.length % 2 === 0 ? "Space" : "Enter";
      await page.keyboard.press(key);
      const current = await page.locator('[data-admin-nav][aria-current="page"]').evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-admin-nav")));
      ariaCurrentValid = ariaCurrentValid && current.length === 1 && current[0] === section;
      activated.push(section);
    }
    recordInteraction("keyboard-tab-reaches-four-admin-buttons", reached.length === 4, reached.join(","));
    recordInteraction("enter-or-space-activates-each-admin-section", activated.length === 4, activated.join(","));
    recordInteraction("active-section-alone-has-aria-current-page", ariaCurrentValid, JSON.stringify(activated));
  });

  await withPage({ viewport: { width: 390, height: 844 }, scenario: "admin", mobile: true }, async (page) => {
    await loadAuthenticated(page, "/app/admin");
    await page.locator("#adminSectionSelect").selectOption("app-access");
    recordInteraction("mobile-selector-changes-sections", await page.locator('[data-admin-section="app-access"]').isVisible(), await page.locator("#adminPageTitle").textContent());
  });

  await withPage({ viewport: { width: 1440, height: 900 }, scenario: "admin" }, async (page) => {
    await loadAuthenticated(page, "/app/admin");
    const triggers = page.getByRole("button", { name: "Manage" });
    const ids = await triggers.evaluateAll((nodes) => nodes.map((node) => ({ id: node.id, controls: node.getAttribute("aria-controls") })));
    recordInteraction("unique-disclosure-ids", ids.length >= 2 && new Set(ids.flatMap((item) => [item.id, item.controls])).size === ids.length * 2, JSON.stringify(ids));
    const first = triggers.nth(0);
    const second = triggers.nth(1);
    await first.click();
    const firstPanelId = await first.getAttribute("aria-controls");
    const firstPanel = page.locator(`#${firstPanelId}`);
    recordInteraction("manage-opens-action-disclosure", await firstPanel.isVisible() && await first.getAttribute("aria-expanded") === "true", firstPanelId);
    recordInteraction("disclosure-focuses-first-action", await firstPanel.locator("button").first().evaluate((node) => node === document.activeElement), await page.evaluate(() => document.activeElement?.textContent));
    await page.keyboard.press("Tab");
    recordInteraction("disclosure-tab-reaches-next-action", await firstPanel.locator("button").nth(1).evaluate((node) => node === document.activeElement), await page.evaluate(() => document.activeElement?.textContent));
    await page.keyboard.press("Escape");
    recordInteraction("disclosure-escape-closes-and-restores-focus", await firstPanel.isHidden() && await first.evaluate((node) => node === document.activeElement), await page.evaluate(() => document.activeElement?.id));
    await first.click();
    await second.focus();
    await page.keyboard.press("Enter");
    const secondPanel = page.locator(`#${await second.getAttribute("aria-controls")}`);
    recordInteraction("opening-another-disclosure-closes-previous", await firstPanel.isHidden() && await secondPanel.isVisible(), "second disclosure open");
    await page.locator("#adminPageTitle").click();
    const focusStrandedInHiddenPanel = await page.evaluate(() => Boolean(document.activeElement?.closest?.(".action-menu-panel")?.hidden));
    recordInteraction("outside-click-closes-disclosure-safely", await secondPanel.isHidden() && !focusStrandedInHiddenPanel, await page.evaluate(() => document.activeElement?.id || document.activeElement?.tagName));
  });

  await withPage({ viewport: { width: 1440, height: 900 }, scenario: "admin" }, async (page) => {
    await loadAuthenticated(page, "/app/admin");
    const opener = page.getByRole("button", { name: "Add member" });
    await opener.click();
    const modal = page.locator("#addMemberModal");
    const email = modal.locator('input[name="email"]');
    recordInteraction("add-member-modal-receives-focus", await email.evaluate((node) => node === document.activeElement), await page.evaluate(() => document.activeElement?.getAttribute("name")));
    const close = page.locator("#closeAddMemberModalButton");
    const submit = page.locator("#addMemberSubmitButton");
    await submit.focus();
    await page.keyboard.press("Tab");
    const forwardContained = await close.evaluate((node) => node === document.activeElement);
    await page.keyboard.press("Shift+Tab");
    const reverseContained = await submit.evaluate((node) => node === document.activeElement);
    recordInteraction("add-member-modal-focus-contained", forwardContained && reverseContained, `${forwardContained}/${reverseContained}`);
    await page.keyboard.press("Escape");
    recordInteraction("add-member-modal-escape-restores-focus", await modal.isHidden() && await opener.evaluate((node) => node === document.activeElement), await page.evaluate(() => document.activeElement?.id));
  });

  const launcherVisibility = captures.filter((capture) => ["launcher-mobile-390-available.png", "launcher-mobile-320-available.png"].includes(capture.name)).every((capture) => capture.primaryContentVisible === true);
  recordInteraction("launcher-primary-content-visible-at-390-and-320", launcherVisibility, JSON.stringify(captures.filter((capture) => capture.primaryContentVisible !== undefined)));
}

async function capture({ name, route, viewport, scenario, mobile = false, after, afterScreenshot }) {
  await withPage({ viewport, scenario, mobile }, async (page) => {
    await loadAuthenticated(page, route);
    if (after) await after(page);
    await page.waitForTimeout(120);
    const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    const metadata = { name, route, scenario, viewport, horizontalOverflow };
    if (route === "/app" && viewport.width <= 390 && scenario === "available") metadata.primaryContentVisible = await launcherPrimaryContentVisible(page);
    await page.screenshot({ path: join(outputRoot, "screenshots", name), fullPage: false });
    if (afterScreenshot) await afterScreenshot(page);
    captures.push(metadata);
    console.log(`Captured ${name}`);
  });
}

async function withPage(options, action) {
  const context = await browser.newContext({
    viewport: options.viewport,
    deviceScaleFactor: 1,
    isMobile: options.mobile ?? false,
    hasTouch: options.mobile ?? false,
    reducedMotion: "reduce",
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    let parsed;
    try {
      parsed = assertAllowedEvidenceRequest(request.url(), origin);
    } catch {
      blockedExternalRequests.push(request.url());
      await route.abort("blockedbyclient");
      return;
    }
    if (!parsed.pathname.startsWith("/api/platform/")) {
      await route.continue();
      return;
    }
    const synthetic = syntheticApiResponse(request.method(), parsed, options.scenario);
    if (!synthetic) {
      unexpectedApiRequests.push(`${request.method()} ${parsed.pathname}${parsed.search}`);
      await route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ outcome: "unhandled_evidence_contract" }) });
      return;
    }
    if (synthetic.delay) await new Promise((resolveDelay) => setTimeout(resolveDelay, synthetic.delay));
    await route.fulfill({ status: synthetic.status, headers: { "cache-control": "no-store" }, contentType: "application/json", body: JSON.stringify(synthetic.body) });
  });
  const page = await context.newPage();
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(`${options.scenario}: ${message.text()}`); });
  page.on("pageerror", (error) => pageErrors.push(`${options.scenario}: ${error.message}`));
  try { await action(page); } finally { await context.close(); }
}

function syntheticApiResponse(method, url, scenario) {
  if (method === "GET" && url.pathname === "/api/platform/session/context") return { status: 200, body: contextPayload(scenario) };
  if (method === "GET" && url.pathname === "/api/platform/session/csrf") return { status: 200, body: { outcome: "issued", csrfToken: csrfValue, expiresAt: "2026-07-14T01:00:00.000Z" } };
  if (method === "GET" && /\/workspaces\/[^/]+\/members$/.test(url.pathname)) return { status: 200, body: membersPayload };
  if (method === "GET" && /\/workspaces\/[^/]+\/member-approvals$/.test(url.pathname)) return { status: 200, body: approvalsPayload };
  if (method === "GET" && /\/workspaces\/[^/]+\/app-entitlements$/.test(url.pathname)) return { status: 200, body: entitlementsPayload };
  if (method === "GET" && /\/workspaces\/[^/]+\/audit-events$/.test(url.pathname)) return { status: 200, body: auditPayload };
  if (method === "POST" && url.pathname === "/api/platform/apps/launch/open") return { status: 200, body: { outcome: "error", message: "Controlled evidence launch failure." } };
  if (method === "POST" && /\/workspaces\/[^/]+\/members\/add$/.test(url.pathname)) return { status: 201, delay: 900, body: { outcome: "pending_approval_created", approval: approvalsPayload.approvals[0] } };
  if (method === "POST" && /\/workspaces\/[^/]+\/(?:members|member-approvals|app-entitlements)\//.test(url.pathname)) return { status: 200, delay: 500, body: { outcome: "updated" } };
  if (method === "POST" && url.pathname === "/api/platform/logout") return { status: 200, body: { outcome: "logged_out" } };
  return null;
}

function contextPayload(scenario) {
  const accessAllowed = scenario !== "unavailable";
  const workspaces = [workspace("workspace-example-primary", "example-primary", "Example Primary", accessAllowed)];
  if (scenario === "multiple") workspaces.push(workspace("workspace-example-secondary", "example-secondary", "Example Secondary", true, "admin"));
  return {
    outcome: "authenticated",
    user: { userId: "user-owner-example", email: "alex@example.invalid", displayName: "Alex Example", status: "active" },
    selectedWorkspaceId: "workspace-example-primary",
    workspaces,
  };
}

function workspace(workspaceId, workspaceSlug, workspaceName, allowed, membershipRole = "owner") {
  return {
    workspaceId,
    workspaceSlug,
    workspaceName,
    workspaceStatus: "active",
    membershipRole,
    membershipStatus: "active",
    apps: [{ appId: "app-example-sqag", appKey: "sqag", appName: "Swooshz Quote Auto Generator", appStatus: "private_preview", access: { result: allowed ? "allowed" : "denied", allowed, message: allowed ? "Access allowed." : "Access denied." } }],
  };
}

function member(membershipId, id, displayName, email, role, status) {
  return { membershipId, role, status, createdAt: earlier, updatedAt: now, user: { id, email, displayName, status: "active", lastLoginAt: status === "active" ? now : earlier } };
}

function assertFixtureContracts() {
  const context = contextPayload("multiple");
  assert.equal(context.outcome, "authenticated");
  assert.equal(context.user.userId, "user-owner-example");
  assert.equal(context.workspaces.length, 2);
  assert.equal(context.workspaces[0].apps[0].access.allowed, true);
  assert.equal(membersPayload.outcome, "listed");
  assert.ok(membersPayload.members.every((item) => item.membershipId && item.user?.id && item.user?.email));
  assert.equal(approvalsPayload.outcome, "listed");
  assert.ok(approvalsPayload.approvals.every((item) => item.approvalId && item.status === "pending"));
  assert.equal(entitlementsPayload.outcome, "listed");
  assert.equal(entitlementsPayload.entitlements[0].appKey, "sqag");
  assert.equal(auditPayload.outcome, "listed");
  assert.ok(auditPayload.events.every((item) => item.eventId && item.eventType && item.targetType));
}

async function loadAuthenticated(page, route) {
  const response = await page.goto(`${origin}${route}`, { waitUntil: "networkidle" });
  if (!response?.ok()) throw new Error(`Renderer route failed: ${route} (${response?.status() ?? "no response"})`);
  if (route === "/app") await page.locator("#launchUnit").waitFor({ state: "visible" });
  else await page.locator('[data-admin-section="members"]').waitFor({ state: "visible" });
  await page.evaluate(() => document.fonts.ready);
}

async function focusByKeyboard(page, selector) {
  for (let index = 0; index < 50; index += 1) {
    await page.keyboard.press("Tab");
    if (await page.locator(selector).evaluate((node) => node === document.activeElement)) return;
  }
  throw new Error(`Keyboard focus did not reach ${selector}.`);
}

async function assertLauncherPrimaryContent(page) {
  assert.equal(await launcherPrimaryContentVisible(page), true, "Launcher description and Open product must remain in the first useful viewport.");
}

async function launcherPrimaryContentVisible(page) {
  const description = page.getByText("Available to your workspace.", { exact: true });
  const button = page.getByRole("button", { name: "Open product" });
  if (!(await description.isVisible()) || !(await button.isVisible())) return false;
  const descriptionBox = await description.boundingBox();
  const buttonBox = await button.boundingBox();
  const height = page.viewportSize()?.height ?? 0;
  return Boolean(descriptionBox && buttonBox && descriptionBox.y + descriptionBox.height <= height && buttonBox.y + buttonBox.height <= height);
}

function recordInteraction(id, passed, detail = "") {
  if (!requiredAuthenticatedInteractions.includes(id)) throw new Error(`Unexpected interaction check id: ${id}`);
  interactions.push({ id, passed: passed === true, detail: String(detail ?? "") });
}

async function createCoreContactSheet() {
  const names = [
    "launcher-desktop-available.png", "launcher-mobile-390-available.png", "launcher-product-unavailable.png", "launcher-controlled-launch-failure.png",
    "admin-desktop-members.png", "admin-desktop-pending-approvals.png", "admin-desktop-product-access.png", "admin-desktop-audit-activity.png",
    "admin-desktop-action-disclosure.png", "admin-desktop-add-member-modal.png", "admin-mobile-390-members.png", "admin-mobile-390-add-member-modal.png",
  ];
  const cards = [];
  for (const name of names) {
    const bytes = await readFile(join(outputRoot, "screenshots", name));
    cards.push(`<figure><figcaption>${escapeHtml(name)}</figcaption><img src="data:image/png;base64,${bytes.toString("base64")}" alt=""></figure>`);
  }
  const context = await browser.newContext({ viewport: { width: 1380, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  await page.setContent(`<!doctype html><style>body{margin:0;padding:24px;background:#071b30;color:#fff;font:600 13px Arial}.grid{display:grid;grid-template-columns:repeat(3,420px);gap:24px}figure{margin:0;display:grid;gap:8px}figcaption{overflow-wrap:anywhere}img{width:420px;height:auto;background:#fff;box-shadow:0 10px 24px #0008}</style><main class="grid">${cards.join("")}</main>`);
  await page.screenshot({ path: join(outputRoot, "contact-sheets", "authenticated-platform-core.png"), fullPage: true });
  await context.close();
}

function renderReadme(summary) {
  return `# Authenticated Swooshz Platform exact-head evidence\n\n- Exact head SHA: \`${summary.headSha}\`\n- Browser: ${summary.browser}\n- Artifact: \`${summary.artifact}\`\n- Renderer: production \`renderAppShellPage\` and \`renderAdminShellPage\` output\n- Authentication evidence method: Playwright-only same-origin API interception with deterministic synthetic \`.invalid\` identities\n- Production auth bypass added: No\n- External provider calls: None\n- Database calls: None\n- External browser requests: None\n\n## Contents\n\n- \`browser-check-summary.json\`: capture, browser, viewport, overflow, error, and safety summary.\n- \`interaction-check-results.json\`: required keyboard, disclosure, selector, and modal checks.\n- \`viewport-browser-metadata.json\`: exact viewport and Chromium metadata.\n- \`screenshots/\`: individual authenticated launcher and administration states.\n- \`contact-sheets/authenticated-platform-core.png\`: concise core review sheet.\n- \`manifest.json\`: artifact file listing tied to the exact head.\n\nAll ${summary.interactions.length} recorded interaction checks passed. All ${summary.screenshots.length} screenshots were generated from the exact checked-out head.\n`;
}

async function listFiles(root) {
  const results = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) for (const child of await listFiles(path)) results.push(`${entry.name}/${child}`);
    else if (!entry.name.startsWith(".")) results.push(entry.name);
  }
  return results.sort();
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

function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}