import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  handleNodePlatformHttpRequest,
} from "../dist/index.js";
import { AuthCallbackError, readAuthConfig } from "../dist/auth/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const allowedOrigin = "https://platform.example.test";
const sessionId = "session_owner_example";
const validCsrfToken = "csrf-token-valid-example";
const issuedCsrfToken = "issued-csrf-token-reference";
const issuedCsrfTokenHash = "hash_issued_csrf_token_reference";
const csrfExpiresAt = "2026-06-27T00:15:00.000Z";
const rawLaunchToken = "synthetic-raw-launch-token-reference";
const launchTokenHash = "app-launch:v1:hmac-sha256:synthetic_hash_reference";
const launchTokenExpiresAt = "2026-06-27T00:05:00.000Z";
const sqagServiceSecret = "synthetic-sqag-service-secret-value-32-chars";
const validationGrantId = "grant_abcdefghijklmnopqrstuvwxyz_1234567890";
const finalizationHandle = "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456";
const finalizationHandleHash = createHash("sha256").update(finalizationHandle).digest("hex");
const finalizationExpiresAt = "2026-06-27T00:02:00.000Z";
const authState = "synthetic-browser-state-reference";
const authNonce = "synthetic-browser-nonce-reference";
const authStateHash = "hash_synthetic_browser_state_reference";
const authBrowserBindingHash = "browser_binding_hash_reference";
const authNonceHash = "hash_synthetic_browser_nonce_reference";
const providerAuthorizationUrl =
  "https://auth.example.invalid/oauth2/authorize?request=synthetic-authorization";
const privateUrl =
  "https://private.example.test/path?csrf=raw-csrf-token&db=postgresql://private-host";
const authConfig = readAuthConfig({
  AUTH_PROVIDER_KEY: "Example-OIDC",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
});

test("GET /healthz returns 200 safe JSON without platform repositories", async () => {
  const { response, body } = await request({
    method: "GET",
    url: "/healthz",
    dependencies: createAdapterFixture().dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "application/json; charset=utf-8");
  assert.deepEqual(body, {
    outcome: "ok",
    service: "swooshz-platform",
  });
  assertResponseIsPrivacySafe(response);
});

test("GET / renders the framework-free landing page as no-store HTML", async () => {
  const { response } = await rawRequest({
    method: "GET",
    url: "/",
    dependencies: createAdapterFixture().dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Swooshz Platform/);
  assert.match(response.body, /\/login/);
  assert.match(response.body, /\/solutions/);
  assertResponseIsPrivacySafe(response);
});

test("GET /solutions renders the public products page as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/solutions",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Swooshz Quote Auto Generator/);
  assert.match(response.body, /One focused product, reached through one trusted place\./);
  assert.doesNotMatch(response.body, /Vendor workflow pending|Unavailable until confirmed|SEO \/ GEO \/ Seozilla/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /resources renders the safe public resources page as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/resources",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Insights & Resources|Resources/);
  assert.match(response.body, /Content pending editorial review/i);
  assert.match(response.body, /href="\/resources\/platform-launch-boundaries"/);
  assert.doesNotMatch(response.body, /<form|<input|<textarea|newsletter|subscribe/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /resources/platform-launch-boundaries renders the safe article page as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/resources/platform-launch-boundaries",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /How Swooshz Platform launches its workspace product safely/);
  assert.match(response.body, /Article template pending editorial approval/i);
  assert.match(response.body, /Swooshz Quote Auto Generator/);
  assert.doesNotMatch(response.body, /<form|<input|<textarea|newsletter|subscribe|<pre|<code/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /about renders the safe public about page as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/about",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /About Swooshz/);
  assert.match(response.body, /Swooshz Quote Auto Generator/);
  assert.doesNotMatch(response.body, /Vendor workflow pending|Unavailable until confirmed|SEO \/ GEO \/ Seozilla/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /contact renders the safe public access enquiry page as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/contact",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Access enquiry/);
  assert.match(response.body, /Do not send secrets/i);
  assert.doesNotMatch(response.body, /<form|<input|<textarea|Submit Inquiry/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /request-access renders the safe public request access state as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/request-access",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Request Access/);
  assert.match(response.body, /No public signup is available/);
  assert.match(response.body, /This page does not create an account/);
  assert.doesNotMatch(response.body, /<form|<input|<textarea|Submit Request/i);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /login renders provider-backed access entry as no-store HTML", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/login?signedOut=1",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /Secure Access Portal/);
  assert.match(response.body, /\/api\/platform\/auth\/start/);
  assert.match(response.body, /No public signup is available/);
  assert.doesNotMatch(response.body, /type="password"|Forgot\?/);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /app renders the browser shell as no-store HTML without requiring session or CSRF", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/app",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /\/api\/platform\/session\/context/);
  assert.match(response.body, /\/api\/platform\/apps\/launch/);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("GET /app/admin renders the admin shell as no-store HTML without requiring session or CSRF", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response } = await rawRequest({
    method: "GET",
    url: "/app/admin?workspaceId=workspace_koncept_images",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.match(response.body, /\/api\/platform\/session\/context/);
  assert.match(response.body, /\/api\/platform\/session\/csrf/);
  assert.match(response.body, /\/api\/platform\/workspaces\//);
  assert.match(response.body, /\/members/);
  assert.match(response.body, /\/role\?role=/);
  assert.match(response.body, /\/disable/);
  assert.match(response.body, /\/reactivate/);
  assert.match(response.body, /\/app-entitlements/);
  assert.match(response.body, /\/audit-events\?limit=50/);
  assert.match(response.body, /\/sqag\/status\?status=/);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("POST /app returns 405 with Allow GET without touching repositories", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response, body } = await request({
    method: "POST",
    url: "/app",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, "GET");
  assert.deepEqual(body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assertNoStoreHeaders(response.headers);
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("unknown route returns safe 404 JSON", async () => {
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/private?token=raw-session-token",
  });

  assert.equal(response.statusCode, 404);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Route not found.",
  });
  assertResponseIsPrivacySafe(response);
});

test("www is redirect-only before UI auth and internal service routing", async () => {
  const fixture = createAdapterFixture();
  fixture.dependencies.originConfig.publicBaseUrl = "https://swooshz.com";
  const callback = await rawRequest({ method: "GET", url: "/api/platform/auth/callback?utm_source=test&code=private-code&next=https://evil.test", headers: { host: "www.swooshz.com" }, dependencies: fixture.dependencies });
  assert.equal(callback.response.statusCode, 308);
  assert.equal(callback.response.headers.location, "https://swooshz.com/api/platform/auth/callback?utm_source=test");
  assert.equal(callback.response.headers["set-cookie"], undefined);
  assert.equal(callback.response.body, "");
  assert.equal(fixture.calls.authStateConsume, 0);
  const internal = await rawRequest({ method: "POST", url: "/api/internal/sqag/access/validate?ref=uat", headers: { host: "www.swooshz.com", "x-sqag-service-authorization": "not-used" }, dependencies: fixture.dependencies });
  assert.equal(internal.response.statusCode, 308);
  assert.equal(internal.response.headers.location, "https://swooshz.com/api/internal/sqag/access/validate?ref=uat");
  assert.equal(internal.response.headers["set-cookie"], undefined);
});

test("production host ownership rejects unknown malformed and ported hosts", async () => {
  for (const host of ["evil.example", "www.swooshz.com:443", "swooshz.com:443", ""]) {
    const fixture = createAdapterFixture();
    fixture.dependencies.originConfig.publicBaseUrl = "https://swooshz.com";
    const { response } = await rawRequest({ method: "GET", url: "/", headers: { host }, dependencies: fixture.dependencies });
    assert.equal(response.statusCode, 421);
    assert.equal(response.headers["set-cookie"], undefined);
  }
});

test("wrong method for a known route returns safe 405 JSON", async () => {
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=sqag",
  });

  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, "GET");
  assert.deepEqual(body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assert.equal(response.headers["content-type"], "application/json; charset=utf-8");
  assertResponseIsPrivacySafe(response);
});

test("app-access route parses workspaceId appKey and session cookie correctly", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      cookie: `swooshz_session=${sessionId}; unrelated=value`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(body.outcome, "allowed");
  assert.equal(body.workspaceId, "workspace_koncept_images");
  assert.equal(body.appKey, "sqag");
  assert.equal(fixture.calls.sessionsFindById, 2);
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("app-access route denies missing session safely through handler path", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=sqag",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "missing_session",
  });
  assert.equal(fixture.calls.sessionsFindById, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("app-access route does not require CSRF", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(body.outcome, "allowed");
  assert.equal(fixture.calls.csrfValidate, 0);
});

test("session context route returns safe no-store context and does not require CSRF", async () => {
  const fixture = createAdapterFixture({
    csrfThrows: true,
  });
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/context?workspaceId=workspace_koncept_images",
    headers: {
      cookie: `swooshz_session=${sessionId}; unrelated=value`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(body.outcome, "authenticated");
  assert.equal(body.user.userId, "user_owner_example");
  assert.equal(body.selectedWorkspaceId, "workspace_koncept_images");
  assert.deepEqual(body.workspaces[0].apps[0].access, {
    result: "allowed",
    allowed: true,
    message: "Access allowed.",
  });
  assert.equal(fixture.calls.sessionsFindById, 1);
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("session context route handles missing cookie and wrong method safely", async () => {
  const missing = await request({
    method: "GET",
    url: "/api/platform/session/context",
  });
  const wrongMethod = await request({
    method: "POST",
    url: "/api/platform/session/context",
  });

  assert.equal(missing.response.statusCode, 401);
  assertNoStoreHeaders(missing.response.headers);
  assert.deepEqual(missing.body, {
    outcome: "unauthenticated",
    reason: "missing_session",
  });
  assert.equal(wrongMethod.response.statusCode, 405);
  assert.equal(wrongMethod.response.headers.allow, "GET");
  assert.deepEqual(wrongMethod.body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assertResponseIsPrivacySafe(missing.response);
  assertResponseIsPrivacySafe(wrongMethod.response);
});

test("CSRF issuance route issues a token for an active browser session", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/csrf",
    headers: {
      cookie: `swooshz_session=${sessionId}; unrelated=value`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(body, {
    outcome: "issued",
    csrfToken: issuedCsrfToken,
    expiresAt: csrfExpiresAt,
  });
  assertNoStoreHeaders(response.headers);
  assert.equal(fixture.calls.sessionsFindById, 1);
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.calls.csrfTokenCreate, 1);
  assert.equal(fixture.records.csrfTokens[0].tokenHash, issuedCsrfTokenHash);
  assert.equal(fixture.records.csrfTokens[0].csrfToken, undefined);
  assert.doesNotMatch(JSON.stringify(fixture.records.csrfTokens), new RegExp(issuedCsrfToken));
});

test("CSRF issuance route returns safe 405 for wrong method", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/session/csrf",
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, "GET");
  assert.deepEqual(body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assert.equal(fixture.calls.csrfTokenCreate, 0);
  assertResponseIsPrivacySafe(response);
});

test("app launch route is POST-only and requires query inputs", async () => {
  const fixture = createAdapterFixture();
  const get = await request({
    method: "GET",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: logoutHeaders(),
    dependencies: fixture.dependencies,
  });
  const missingQuery = await request({
    method: "POST",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images",
    headers: logoutHeaders(),
    dependencies: fixture.dependencies,
  });

  assert.equal(get.response.statusCode, 405);
  assert.equal(get.response.headers.allow, "POST");
  assertNoStoreHeaders(get.response.headers);
  assert.deepEqual(get.body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assert.equal(missingQuery.response.statusCode, 400);
  assertNoStoreHeaders(missingQuery.response.headers);
  assert.deepEqual(missingQuery.body, {
    outcome: "error",
    message: "Required query parameters are missing.",
  });
  assert.equal(fixture.records.appLaunchTokens.length, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(get.response);
  assertResponseIsPrivacySafe(missingQuery.response);
});

test("app launch route validates Origin and CSRF before creating a token", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      cookie: `swooshz_session=${sessionId}`,
      "x-csrf-token": validCsrfToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(fixture.records.appLaunchTokens.length, 0);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("app launch route disables direct browser raw-token responses after valid CSRF", async () => {
  const fixture = createAdapterFixture({
    app: { launchUrl: "https://apps.example.invalid/sqag" },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: logoutHeaders(),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 410);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Direct launch token responses are disabled. Use the server-side launch handoff.",
  });
  assert.deepEqual(fixture.calls.order.slice(0, 2), ["csrf"]);
  assert.equal(fixture.calls.csrfValidate, 1);
  assert.equal(fixture.records.appLaunchTokens.length, 0);
  assert.doesNotMatch(JSON.stringify(fixture.records.appLaunchTokens), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(response), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(response), new RegExp(launchTokenHash));
  assertResponseIsPrivacySafe(response);
});

test("SQAG browser launch handoff consumes token server-side and returns safe launch URL", async () => {
  const fixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
    },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(response.headers["x-sqag-finalization-handle"], "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456");
  assert.deepEqual(body, {
    outcome: "launch_opened",
    appKey: "sqag",
    workspaceId: "workspace_koncept_images",
    launchUrl: "https://quote.swooshz.com/",
    finalizationUrl: "https://quote.swooshz.com/api/auth/platform/finalize",
  });
  assert.equal(fixture.records.appLaunchTokens.length, 1);
  assert.equal(fixture.records.appLaunchTokens[0].tokenHash, launchTokenHash);
  assert.equal("launchToken" in fixture.records.appLaunchTokens[0], false);
  assert.deepEqual(fixture.calls.sqagLaunchRequests, [
    {
      url: "https://quote.swooshz.com/api/platform/launch",
      method: "POST",
      token: rawLaunchToken,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(response), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(body), new RegExp(rawLaunchToken));
  assert.doesNotMatch(response.headers.location ?? "", new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(response.headers), new RegExp(rawLaunchToken));
  assertResponseIsPrivacySafe(response);
});

test("upstream reserved Platform cookie is never relayed", async () => {
  const fixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
      setCookie: "SwOoShZ_SeSsIoN=attacker-controlled; Domain=.example.invalid; Path=/api/platform; HttpOnly; SameSite=Lax; Secure",
    },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(body.outcome, "launch_opened");
  assert.equal(response.headers["set-cookie"], undefined);
  assertResponseIsPrivacySafe(response);
});

test("mixed upstream SQAG and reserved cookies are never relayed", async () => {
  const fixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
      setCookie: [
        "swooshz_quote_session=safe-session; Path=/; HttpOnly; SameSite=Lax; Secure",
        "SWOOSHZ_SESSION=attacker-session; Path=/; HttpOnly; SameSite=Lax; Secure",
      ],
    },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(body.outcome, "launch_opened");
  assertResponseIsPrivacySafe(response);
});

test("upstream multiple SQAG cookies are never relayed", async () => {
  const safeCookies = [
    "swooshz_quote_session=safe-session; Path=/; HttpOnly; SameSite=Lax; Secure",
    "swooshz_quote_device=safe-device; Path=/; HttpOnly; SameSite=Strict; Secure",
  ];
  const fixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
      setCookie: safeCookies,
    },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(body.outcome, "launch_opened");
  assertResponseIsPrivacySafe(response);
});

test("upstream token-reflecting SQAG cookie is ignored and never relayed", async () => {
  const fixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
      setCookie: `swooshz_quote_session=${rawLaunchToken}; Path=/; HttpOnly; SameSite=Lax; Secure`,
    },
  });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.headers["set-cookie"], undefined);
  assert.doesNotMatch(JSON.stringify(response), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(body), new RegExp(rawLaunchToken));
  assertResponseIsPrivacySafe(response);
});

test("upstream combined or malformed SQAG cookies are never relayed", async () => {
  for (const setCookie of [
    "swooshz_quote_session=safe; Path=/; HttpOnly; SameSite=Lax; Secure, swooshz_session=bad; Path=/; HttpOnly",
    "swooshz_quote_session=safe\r\nInjected: value; Path=/; HttpOnly; SameSite=Lax; Secure",
    `swooshz_quote_session=${"x".repeat(4097)}; Path=/; HttpOnly; SameSite=Lax; Secure`,
  ]) {
    const fixture = createAdapterFixture({
      sqagLaunchHandoff: { baseUrl: "http://127.0.0.1:8765", setCookie },
    });
    const { response } = await request({
      method: "POST",
      url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
      headers: { ...logoutHeaders(), host: "127.0.0.1:4317" },
      dependencies: fixture.dependencies,
    });

    assert.equal(response.statusCode, 200);
    assert.equal(response.headers["set-cookie"], undefined);
    assertNoStoreHeaders(response.headers);
  }
});

test("SQAG browser launch rejects duplicate finalization handle response headers", async () => {
  const fixture = createAdapterFixture({ sqagLaunchHandoff: { baseUrl: "http://127.0.0.1:8765", finalizationHandle: ["finalization_handle_abcdefghijklmnopqrstuvwxyz_123456", "finalization_handle_other_abcdefghijklmnopqrstuvwxyz_123456"] } });
  const { response } = await request({ method: "POST", url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag", headers: { ...logoutHeaders(), host: "127.0.0.1:4317" }, dependencies: fixture.dependencies });
  assert.equal(response.statusCode, 502);
  assert.equal(response.headers["x-sqag-finalization-handle"], undefined);
});

test("SQAG internal finalization routes enforce service auth and atomic replay denial", async () => {
  const fixture = createAdapterFixture();
  const boundary = attachAccessValidationGrantCapability(fixture);
  const serviceHeaders = { "x-sqag-service-authorization": sqagServiceSecret };

  const unauthorized = await request({
    method: "POST",
    url: "/api/internal/sqag/finalizations/register",
    headers: { "x-sqag-service-authorization": "wrong-service-secret" },
    body: JSON.stringify({
      validationGrantId,
      handleHashSha256: finalizationHandleHash,
      expiresAt: finalizationExpiresAt,
      intendedSqagOrigin: boundary.origin,
    }),
    dependencies: fixture.dependencies,
  });
  assert.equal(unauthorized.response.statusCode, 403);
  assert.deepEqual(unauthorized.body, { outcome: "error", message: "SQAG service request denied." });
  assert.equal(boundary.grant.handleHash, null);

  const registration = await rawRequest({
    method: "POST",
    url: "/api/internal/sqag/finalizations/register",
    headers: serviceHeaders,
    body: JSON.stringify({
      validationGrantId,
      handleHashSha256: finalizationHandleHash,
      expiresAt: finalizationExpiresAt,
      intendedSqagOrigin: boundary.origin,
    }),
    dependencies: fixture.dependencies,
  });
  assert.equal(registration.response.statusCode, 204);
  assertNoStoreHeaders(registration.response.headers);
  assert.equal(registration.response.body, "");
  assert.equal(boundary.grant.handleHash, finalizationHandleHash);

  const consumeHeaders = {
    ...serviceHeaders,
    "x-sqag-finalization-handle": finalizationHandle,
  };
  const consumed = await request({
    method: "POST",
    url: "/api/internal/sqag/finalizations/consume",
    headers: consumeHeaders,
    body: JSON.stringify({ intendedSqagOrigin: boundary.origin }),
    dependencies: fixture.dependencies,
  });
  assert.equal(consumed.response.statusCode, 200);
  assertNoStoreHeaders(consumed.response.headers);
  assert.deepEqual(consumed.body, {
    validationGrantId,
    userId: "user_owner_example",
    workspaceId: "workspace_koncept_images",
    appKey: "sqag",
    launchTokenExpiresAt,
    currentRole: "owner",
  });

  const replay = await request({
    method: "POST",
    url: "/api/internal/sqag/finalizations/consume",
    headers: consumeHeaders,
    body: JSON.stringify({ intendedSqagOrigin: boundary.origin }),
    dependencies: fixture.dependencies,
  });
  assert.equal(replay.response.statusCode, 403);
  assert.deepEqual(replay.body, { outcome: "error", message: "SQAG service request denied." });
  assertResponseIsPrivacySafe(replay.response);
});

test("SQAG internal validation and revoke routes re-check bindings and fail closed", async () => {
  const fixture = createAdapterFixture();
  const boundary = attachAccessValidationGrantCapability(fixture, { consumed: true });
  const headers = {
    "x-sqag-service-authorization": sqagServiceSecret,
    "x-sqag-validation-grant": validationGrantId,
  };

  const validation = await request({
    method: "POST",
    url: "/api/internal/sqag/access/validate",
    headers,
    body: JSON.stringify({ workspaceId: "workspace_koncept_images", appKey: "sqag" }),
    dependencies: fixture.dependencies,
  });
  assert.equal(validation.response.statusCode, 200);
  assertNoStoreHeaders(validation.response.headers);
  assert.equal(validation.body.valid, true);
  assert.equal(validation.body.validationGrantId, validationGrantId);
  assert.equal(validation.body.currentRole, "owner");

  const wrongWorkspace = await request({
    method: "POST",
    url: "/api/internal/sqag/access/validate",
    headers,
    body: JSON.stringify({ workspaceId: "workspace_other", appKey: "sqag" }),
    dependencies: fixture.dependencies,
  });
  assert.equal(wrongWorkspace.response.statusCode, 403);
  assert.deepEqual(wrongWorkspace.body, { outcome: "error", message: "SQAG service request denied." });

  const revoked = await rawRequest({
    method: "POST",
    url: "/api/internal/sqag/access/revoke",
    headers,
    body: "{}",
    dependencies: fixture.dependencies,
  });
  assert.equal(revoked.response.statusCode, 204);
  assertNoStoreHeaders(revoked.response.headers);
  assert.equal(boundary.grant.revokedAt, now);

  const afterRevoke = await request({
    method: "POST",
    url: "/api/internal/sqag/access/validate",
    headers,
    body: JSON.stringify({ workspaceId: "workspace_koncept_images", appKey: "sqag" }),
    dependencies: fixture.dependencies,
  });
  assert.equal(afterRevoke.response.statusCode, 403);
  assert.deepEqual(afterRevoke.body, { outcome: "error", message: "SQAG service request denied." });
  assertResponseIsPrivacySafe(afterRevoke.response);
});

test("SQAG internal routes reject malformed input and repository failures generically", async () => {
  const fixture = createAdapterFixture();
  attachAccessValidationGrantCapability(fixture, { consumed: true });
  const headers = {
    "x-sqag-service-authorization": sqagServiceSecret,
    "x-sqag-validation-grant": validationGrantId,
  };

  const malformed = await request({
    method: "POST",
    url: "/api/internal/sqag/access/validate",
    headers,
    body: "{private malformed provider body",
    dependencies: fixture.dependencies,
  });
  assert.equal(malformed.response.statusCode, 403);
  assert.deepEqual(malformed.body, { outcome: "error", message: "SQAG service request denied." });
  assert.doesNotMatch(malformed.response.body, /private malformed provider body/);

  fixture.repositories.sessions.findById = async () => {
    throw new Error("private database failure postgresql://private-host");
  };
  const failed = await request({
    method: "POST",
    url: "/api/internal/sqag/access/validate",
    headers,
    body: JSON.stringify({ workspaceId: "workspace_koncept_images", appKey: "sqag" }),
    dependencies: fixture.dependencies,
  });
  assert.equal(failed.response.statusCode, 403);
  assert.deepEqual(failed.body, { outcome: "error", message: "SQAG service request denied." });
  assertResponseIsPrivacySafe(failed.response);
});

test("SQAG browser launch handoff fails safely without session access config or safe cookie host", async () => {
  const missingSession = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      origin: allowedOrigin,
      "x-csrf-token": validCsrfToken,
      host: "127.0.0.1:4317",
    },
    dependencies: createAdapterFixture({
      sqagLaunchHandoff: {
        baseUrl: "http://127.0.0.1:8765",
      },
    }).dependencies,
  });
  const missingConfigFixture = createAdapterFixture();
  const missingConfig = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: missingConfigFixture.dependencies,
  });
  const unsafeHostFixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://localhost:8765",
    },
  });
  const unsafeHost = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: unsafeHostFixture.dependencies,
  });

  assert.equal(missingSession.response.statusCode, 401);
  assertNoStoreHeaders(missingSession.response.headers);
  assert.deepEqual(missingSession.body, {
    outcome: "unauthenticated",
    reason: "missing_session",
  });
  assert.equal(missingConfig.response.statusCode, 503);
  assertNoStoreHeaders(missingConfig.response.headers);
  assert.deepEqual(missingConfig.body, {
    outcome: "error",
    message: "SQAG browser launch is not configured.",
  });
  assert.equal(unsafeHost.response.statusCode, 503);
  assertNoStoreHeaders(unsafeHost.response.headers);
  assert.deepEqual(unsafeHost.body, {
    outcome: "error",
    message: "SQAG browser launch is not configured.",
  });
  assert.equal(missingConfigFixture.records.appLaunchTokens.length, 0);
  assert.equal(unsafeHostFixture.records.appLaunchTokens.length, 0);
  assert.deepEqual(missingConfigFixture.calls.sqagLaunchRequests, []);
  assert.deepEqual(unsafeHostFixture.calls.sqagLaunchRequests, []);
  assertResponseIsPrivacySafe(missingSession.response);
  assertResponseIsPrivacySafe(missingConfig.response);
  assertResponseIsPrivacySafe(unsafeHost.response);
});

test("SQAG browser launch handoff rejects non-SQAG keys and fails closed for consume failure", async () => {
  const wrongAppFixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
    },
  });
  const wrongApp = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=other",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: wrongAppFixture.dependencies,
  });
  const legacyKeyFixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
    },
  });
  const legacyKey = await request({
    method: "POST",
    url: `/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=${"k"}qag`,
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: legacyKeyFixture.dependencies,
  });
  const consumeFailureFixture = createAdapterFixture({
    sqagLaunchHandoff: {
      baseUrl: "http://127.0.0.1:8765",
      status: 502,
      body: { status: "blocked", errors: ["private provider payload"] },
    },
  });
  const consumeFailure = await request({
    method: "POST",
    url: "/api/platform/apps/launch/open?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      ...logoutHeaders(),
      host: "127.0.0.1:4317",
    },
    dependencies: consumeFailureFixture.dependencies,
  });

  assert.equal(wrongApp.response.statusCode, 403);
  assertNoStoreHeaders(wrongApp.response.headers);
  assert.equal(wrongApp.body.outcome, "denied");
  assert.equal(wrongApp.body.reason, "app_access_denied");
  assert.equal(wrongAppFixture.records.appLaunchTokens.length, 0);
  assert.deepEqual(wrongAppFixture.calls.sqagLaunchRequests, []);
  assert.equal(legacyKey.response.statusCode, 403);
  assertNoStoreHeaders(legacyKey.response.headers);
  assert.equal(legacyKey.body.outcome, "denied");
  assert.equal(legacyKey.body.reason, "app_access_denied");
  assert.equal(legacyKeyFixture.records.appLaunchTokens.length, 0);
  assert.deepEqual(legacyKeyFixture.calls.sqagLaunchRequests, []);
  assert.equal(consumeFailure.response.statusCode, 502);
  assertNoStoreHeaders(consumeFailure.response.headers);
  assert.deepEqual(consumeFailure.body, {
    outcome: "error",
    message: "SQAG browser launch could not be completed.",
  });
  assert.equal(consumeFailureFixture.records.appLaunchTokens.length, 1);
  assert.equal(consumeFailureFixture.records.appLaunchTokens[0].tokenHash, launchTokenHash);
  assert.equal("launchToken" in consumeFailureFixture.records.appLaunchTokens[0], false);
  assert.equal(consumeFailureFixture.calls.sqagLaunchRequests[0].token, rawLaunchToken);
  assert.doesNotMatch(JSON.stringify(consumeFailure.response), /private provider payload/);
  assert.doesNotMatch(JSON.stringify(consumeFailure.response), new RegExp(rawLaunchToken));
  assertResponseIsPrivacySafe(wrongApp.response);
  assertResponseIsPrivacySafe(legacyKey.response);
  assertResponseIsPrivacySafe(consumeFailure.response);
});

test("app launch consume route is POST-only and requires appKey", async () => {
  const fixture = createAdapterFixture({ withLaunchConsumeToken: true });
  const get = await request({
    method: "GET",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });
  const missingAppKey = await request({
    method: "POST",
    url: "/api/platform/apps/launch/consume",
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(get.response.statusCode, 405);
  assert.equal(get.response.headers.allow, "POST");
  assertNoStoreHeaders(get.response.headers);
  assert.equal(missingAppKey.response.statusCode, 400);
  assertNoStoreHeaders(missingAppKey.response.headers);
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.records.appLaunchTokens[0].consumedAt, null);
  assertResponseIsPrivacySafe(get.response);
  assertResponseIsPrivacySafe(missingAppKey.response);
});

test("app launch consume route consumes token without browser cookie or CSRF", async () => {
  const fixture = createAdapterFixture({ withLaunchConsumeToken: true });

  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(body, {
    outcome: "consumed",
    user: {
      userId: "user_owner_example",
      email: "owner@example.com",
      displayName: "Owner Example",
      status: "active",
    },
    workspace: {
      workspaceId: "workspace_koncept_images",
      workspaceSlug: "koncept-images-pte-ltd",
      workspaceName: "Koncept Images Pte Ltd",
    },
    app: {
      appKey: "sqag",
      appName: "SQAG",
    },
    membershipRole: "owner",
    launchTokenExpiresAt,
  });
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.records.appLaunchTokens[0].consumedAt, now);
  assertResponseIsPrivacySafe(response);
});

test("app launch consume route rejects legacy SQAG key without consuming token", async () => {
  const fixture = createAdapterFixture({ withLaunchConsumeToken: true });

  const { response, body } = await request({
    method: "POST",
    url: `/api/platform/apps/launch/consume?appKey=${"k"}qag`,
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 401);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(body, {
    outcome: "invalid",
    reason: "app_mismatch",
  });
  assert.equal(fixture.records.appLaunchTokens[0].consumedAt, null);
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(response);
});

test("app launch consume route rejects missing or replayed token safely", async () => {
  const fixture = createAdapterFixture({ withLaunchConsumeToken: true });
  const missing = await request({
    method: "POST",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    dependencies: fixture.dependencies,
  });
  const first = await request({
    method: "POST",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });
  const replay = await request({
    method: "POST",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(missing.response.statusCode, 401);
  assertNoStoreHeaders(missing.response.headers);
  assert.deepEqual(missing.body, {
    outcome: "invalid",
    reason: "missing_launch_token",
  });
  assert.equal(first.response.statusCode, 200);
  assert.equal(replay.response.statusCode, 401);
  assertNoStoreHeaders(replay.response.headers);
  assert.deepEqual(replay.body, {
    outcome: "invalid",
    reason: "consumed_launch_token",
  });
  assert.equal(fixture.calls.csrfValidate, 0);
  assertResponseIsPrivacySafe(missing.response);
  assertResponseIsPrivacySafe(replay.response);
});

test("app launch consume route ignores launch tokens in query strings", async () => {
  const fixture = createAdapterFixture({ withLaunchConsumeToken: true });
  const { response, body } = await request({
    method: "POST",
    url: `/api/platform/apps/launch/consume?appKey=sqag&launchToken=${encodeURIComponent(rawLaunchToken)}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 401);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(body, {
    outcome: "invalid",
    reason: "missing_launch_token",
  });
  assert.equal(fixture.records.appLaunchTokens[0].consumedAt, null);
  assertResponseIsPrivacySafe(response);
});

test("auth start route redirects to provider and stores only state references", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, providerAuthorizationUrl);
  assertNoStoreHeaders(response.headers);
  const bindingCookies = setCookieHeaders(response);
  assert.equal(bindingCookies.length, 1);
  assert.match(bindingCookies[0], /^swooshz_auth_state=browser_binding_hash_reference;/);
  assert.match(bindingCookies[0], /HttpOnly/);
  assert.match(bindingCookies[0], /Path=\/api\/platform\/auth\/callback/);
  assert.match(bindingCookies[0], /SameSite=Lax/);
  assert.match(bindingCookies[0], /Max-Age=600/);
  assert.match(bindingCookies[0], /Secure/);
  assert.deepEqual(body, { outcome: "redirecting" });
  assert.equal(fixture.calls.authStateStore, 1);
  assert.deepEqual(fixture.records.authStates[0], {
    providerKey: "example-oidc",
    stateHash: authStateHash,
    nonceHash: authNonceHash,
    redirectUri: "https://platform.example.invalid/api/platform/auth/callback",
    createdAt: now,
    expiresAt: "2026-06-27T00:10:00.000Z",
  });
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), /synthetic-browser-state-reference/);
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), /synthetic-browser-nonce-reference/);
  assertResponseIsPrivacySafe(response);
});

test("auth callback route sets a browser session cookie on success", async () => {
  const fixture = createAdapterFixture();
  const start = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });
  const bindingCookie = requestCookieFromSetCookie(setCookieHeaders(start.response)[0]);
  const { response, body } = await request({
    method: "GET",
    headers: {
      cookie: bindingCookie,
    },
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${authState}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "/app");
  const callbackCookies = setCookieHeaders(response);
  assert.equal(callbackCookies.length, 2);
  assert.match(callbackCookies[0], /^swooshz_session=session_auth_callback_1;/);
  assert.match(callbackCookies[0], /HttpOnly/);
  assert.match(callbackCookies[0], /Path=\/api\/platform/);
  assert.match(callbackCookies[0], /Secure/);
  assert.match(callbackCookies[1], /^swooshz_auth_state=;/);
  assert.match(callbackCookies[1], /Path=\/api\/platform\/auth\/callback/);
  assert.match(callbackCookies[1], /Max-Age=0/);
  assert.match(callbackCookies[1], /Secure/);
  assert.deepEqual(body, { outcome: "authenticated" });
  assert.equal(fixture.calls.authStateConsume, 1);
  assert.equal(fixture.calls.authTokenExchange, 1);
  assert.equal(fixture.calls.authIdentityResolve, 1);
  assert.doesNotMatch(JSON.stringify(body), /session_auth_callback_1/);
  assertResponseIsPrivacySafe(response);
});

test("auth callback missing code or state renders safe browser error page", async () => {
  const fixture = createAdapterFixture();
  const start = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });
  const bindingCookie = requestCookieFromSetCookie(setCookieHeaders(start.response)[0]);
  const { response, body } = await request({
    method: "GET",
    headers: {
      cookie: bindingCookie,
    },
    url: `/api/platform/auth/callback?state=${authState}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assertNoStoreHeaders(response.headers);
  assert.equal(response.headers["x-auth-failure"], "auth_callback_failed");
  assert.match(body, /Access not approved/);
  assert.match(body, /href="\/api\/platform\/auth\/start"/);
  assert.doesNotMatch(body, /synthetic-auth-code|synthetic-browser-state-reference|provider-subject/i);
  assert.equal(setCookieHeaders(response).length, 1);
  assert.match(setCookieHeaders(response)[0], /^swooshz_auth_state=;/);
  assert.match(setCookieHeaders(response)[0], /Max-Age=0/);
  assert.equal(fixture.calls.authStateConsume, 0);
  assert.equal(fixture.calls.authTokenExchange, 0);
  assert.equal(fixture.calls.authIdentityResolve, 0);
  assertResponseIsPrivacySafe(response);
});

test("auth callback unapproved provider account renders safe retry UI", async () => {
  const fixture = createAdapterFixture({ authIdentityErrorCode: "email_not_allowed" });
  const start = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });
  const bindingCookie = requestCookieFromSetCookie(setCookieHeaders(start.response)[0]);
  const { response, body } = await request({
    method: "GET",
    headers: {
      cookie: bindingCookie,
    },
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${authState}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assert.equal(response.headers["x-auth-failure"], "access_not_approved");
  assert.match(body, /Access not approved/);
  assert.match(body, /Try another Google account/);
  assert.match(body, /href="\/api\/platform\/auth\/start"/);
  assert.equal(setCookieHeaders(response).length, 1);
  assert.match(setCookieHeaders(response)[0], /^swooshz_auth_state=;/);
  assert.match(setCookieHeaders(response)[0], /Max-Age=0/);
  assert.equal(fixture.calls.authStateConsume, 1);
  assert.equal(fixture.calls.authTokenExchange, 1);
  assert.equal(fixture.calls.authIdentityResolve, 1);
  assert.doesNotMatch(body, /synthetic-auth-code|synthetic-browser-state-reference/);
  assert.doesNotMatch(body, /email_not_allowed|AUTH_ALLOWED_EMAILS|provider-subject|raw-claim/i);
  assertResponseIsPrivacySafe(response);
});

test("transferred OIDC callback cannot authenticate a browser without the initiating binding", async () => {
  const fixture = createAdapterFixture();
  const start = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });
  const browserABinding = requestCookieFromSetCookie(
    setCookieHeaders(start.response)[0],
  );

  const browserB = await request({
    method: "GET",
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${authState}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(browserB.response.statusCode, 400);
  assertNoStoreHeaders(browserB.response.headers);
  assert.equal(fixture.calls.authStateConsume, 0);
  assert.equal(fixture.calls.authTokenExchange, 0);
  assert.equal(fixture.calls.authIdentityResolve, 0);
  assert.equal(setCookieHeaders(browserB.response).length, 1);
  assert.match(setCookieHeaders(browserB.response)[0], /^swooshz_auth_state=;/);
  assert.doesNotMatch(JSON.stringify(browserB.body), /session_auth_callback_1|browser_binding_hash_reference/);
  assertResponseIsPrivacySafe(browserB.response);

  const browserA = await request({
    method: "GET",
    headers: { cookie: browserABinding },
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${authState}`,
    dependencies: fixture.dependencies,
  });

  assert.equal(browserA.response.statusCode, 302);
  assert.equal(fixture.calls.authStateConsume, 1);
  assert.equal(fixture.calls.authTokenExchange, 1);
  assert.equal(fixture.calls.authIdentityResolve, 1);
  assert.match(setCookieHeaders(browserA.response)[0], /^swooshz_session=/);
  assertResponseIsPrivacySafe(browserA.response);
});

test("consumed OIDC callback state and cleared browser binding cannot be replayed", async () => {
  const fixture = createAdapterFixture();
  const start = await request({
    method: "GET",
    url: "/api/platform/auth/start",
    dependencies: fixture.dependencies,
  });
  const bindingCookie = requestCookieFromSetCookie(setCookieHeaders(start.response)[0]);
  const callbackUrl = `/api/platform/auth/callback?code=synthetic-auth-code&state=${authState}`;

  const first = await request({
    method: "GET",
    headers: { cookie: bindingCookie },
    url: callbackUrl,
    dependencies: fixture.dependencies,
  });
  const replay = await request({
    method: "GET",
    headers: { cookie: bindingCookie },
    url: callbackUrl,
    dependencies: fixture.dependencies,
  });
  const afterClear = await request({
    method: "GET",
    url: callbackUrl,
    dependencies: fixture.dependencies,
  });

  assert.equal(first.response.statusCode, 302);
  assert.equal(replay.response.statusCode, 400);
  assert.equal(afterClear.response.statusCode, 400);
  assert.equal(fixture.calls.authStateConsume, 2);
  assert.equal(fixture.calls.authTokenExchange, 1);
  assert.equal(fixture.calls.authIdentityResolve, 1);
  assert.equal(setCookieHeaders(replay.response).length, 1);
  assert.match(setCookieHeaders(replay.response)[0], /^swooshz_auth_state=;/);
  assert.doesNotMatch(setCookieHeaders(replay.response)[0], /^swooshz_session=/);
  assert.equal(setCookieHeaders(afterClear.response).length, 1);
  assert.match(setCookieHeaders(afterClear.response)[0], /^swooshz_auth_state=;/);
  assertResponseIsPrivacySafe(replay.response);
  assertResponseIsPrivacySafe(afterClear.response);
});

test("auth route wrong methods return safe 405 responses", async () => {
  const start = await request({
    method: "POST",
    url: "/api/platform/auth/start",
  });
  const callback = await request({
    method: "POST",
    url: "/api/platform/auth/callback?code=synthetic-auth-code&state=synthetic-state",
  });

  assert.equal(start.response.statusCode, 405);
  assert.equal(start.response.headers.allow, "GET");
  assert.deepEqual(start.body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assert.equal(callback.response.statusCode, 405);
  assert.equal(callback.response.headers.allow, "GET");
  assertResponseIsPrivacySafe(start.response);
  assertResponseIsPrivacySafe(callback.response);
});

test("logout POST validates request security before revocation", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: logoutHeaders(),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(body, { outcome: "logged_out" });
  assert.deepEqual(fixture.calls.order, ["csrf", "sessionsFindById", "sessionsRevoke"]);
  assert.equal(fixture.records.sessions[0].revokedAt, now);
  assert.match(response.headers["set-cookie"], /^swooshz_session=;/);
  assert.match(response.headers["set-cookie"], /Max-Age=0/);
  assert.match(response.headers["set-cookie"], /Secure/);
  assertResponseIsPrivacySafe(response);
});

test("logout denies missing Origin or Referer safely", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: {
      cookie: `swooshz_session=${sessionId}`,
      "x-csrf-token": validCsrfToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "missing_origin",
  });
  assert.equal(fixture.records.sessions[0].revokedAt, null);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("logout denies missing CSRF token safely", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: {
      origin: allowedOrigin,
      cookie: `swooshz_session=${sessionId}`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "missing_csrf_token",
  });
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("logout denies invalid CSRF token safely without revoking session", async () => {
  const fixture = createAdapterFixture({
    csrfValid: false,
  });
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: logoutHeaders({ csrfToken: "raw-csrf-token-private" }),
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(body, {
    outcome: "denied",
    reason: "invalid_csrf_token",
  });
  assert.equal(fixture.calls.csrfValidate, 1);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assert.equal(fixture.records.sessions[0].revokedAt, null);
  assertResponseIsPrivacySafe(response);
});

test("logout accepts valid Referer and valid CSRF token", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: {
      referer: `${allowedOrigin}/settings?return=private`,
      cookie: `swooshz_session=${sessionId}`,
      "x-csrf-token": validCsrfToken,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(body, { outcome: "logged_out" });
  assert.equal(fixture.calls.csrfValidate, 1);
  assert.equal(fixture.calls.sessionsRevoke, 1);
});

test("security denial does not echo raw origin path query token or storage details", async () => {
  const fixture = createAdapterFixture();
  const { response } = await request({
    method: "POST",
    url: "/api/platform/logout",
    headers: {
      origin: privateUrl,
      cookie: `swooshz_session=raw-session-token-private`,
      "x-csrf-token": "raw-csrf-token-private",
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 403);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("adapter-specific Node imports do not leak into domain platform auth or non-adapter HTTP services", async () => {
  const checkedFiles = [
    ...(await listFiles("src/accounts")),
    ...(await listFiles("src/apps")),
    ...(await listFiles("src/access")),
    ...(await listFiles("src/platform")),
    ...(await listFiles("src/auth")),
    "src/http/handlers.ts",
    "src/http/session-cookie.ts",
    "src/http/request-security.ts",
    "src/http/csrf.ts",
    "src/http/origin-validation.ts",
    "src/http/route-contracts.ts",
  ];

  for (const filePath of checkedFiles) {
    const contents = await readFile(filePath, "utf8");
    assert.doesNotMatch(contents, /node:http/);
  }
});

test("Node HTTP adapter does not import frontend SQAG provider SDK framework live DB or migrations", async () => {
  const contents = await readFile("src/http/node-adapter.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

async function request({
  method,
  url,
  headers = {},
  body,
  dependencies = createAdapterFixture().dependencies,
}) {
  const response = await handleNodePlatformHttpRequest(dependencies, {
    method,
    url,
    headers,
    body,
  });

  return {
    response,
    body: parseResponseBody(response),
  };
}

function parseResponseBody(response) {
  if (response.headers["content-type"] === "text/html; charset=utf-8") {
    return response.body;
  }

  return JSON.parse(response.body);
}

async function rawRequest({
  method,
  url,
  headers = {},
  body,
  dependencies = createAdapterFixture().dependencies,
}) {
  const response = await handleNodePlatformHttpRequest(dependencies, {
    method,
    url,
    headers,
    body,
  });

  return { response };
}

function createAdapterFixture(overrides = {}) {
  const records = {
    users: [
      {
        id: "user_owner_example",
        email: "owner@example.com",
        displayName: "Owner Example",
        status: "active",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      },
    ],
    providerIdentities: [],
    sessions: [
      {
        id: sessionId,
        userId: "user_owner_example",
        createdAt: earlier,
        expiresAt: future,
        lastSeenAt: earlier,
        revokedAt: null,
      },
    ],
    workspaces: [
      {
        id: "workspace_koncept_images",
        slug: "koncept-images-pte-ltd",
        displayName: "Koncept Images Pte Ltd",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ],
    memberships: [
      {
        id: "membership_owner_example",
        workspaceId: "workspace_koncept_images",
        userId: "user_owner_example",
        role: "owner",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ],
    apps: [
      {
        id: "app_sqag",
        key: "sqag",
        name: "SQAG",
        status: "private_preview",
        launchUrl: null,
        ...overrides.app,
        createdAt: now,
        updatedAt: now,
      },
    ],
    appEntitlements: [
      {
        id: "entitlement_koncept_sqag",
        workspaceId: "workspace_koncept_images",
        appId: "app_sqag",
        status: "enabled",
        grantedByUserId: "user_owner_example",
        createdAt: now,
        updatedAt: now,
      },
    ],
    auditEvents: [],
    csrfTokens: [],
    authStates: [],
    appLaunchTokens: [],
  };
  if (overrides.withLaunchConsumeToken) {
    records.appLaunchTokens.push({
      id: "app_launch_token_1",
      sessionId,
      userId: "user_owner_example",
      workspaceId: "workspace_koncept_images",
      appId: "app_sqag",
      tokenHash: launchTokenHash,
      createdAt: now,
      expiresAt: launchTokenExpiresAt,
      consumedAt: null,
      revokedAt: null,
    });
  }
  const repositories = createInMemoryPlatformRepositories(records);
  repositories.appLaunchTokens = {
    async create(record) {
      records.appLaunchTokens.push(record);
      return record;
    },
    async findByTokenHash(tokenHash) {
      return records.appLaunchTokens.find((record) => record.tokenHash === tokenHash) ?? null;
    },
    async consumeUnconsumed(id, consumedAt) {
      const record = records.appLaunchTokens.find((candidate) => candidate.id === id);
      if (!record || record.consumedAt || record.revokedAt) {
        return null;
      }

      record.consumedAt = consumedAt;
      return record;
    },
  };
  const calls = instrumentRepositories(repositories);
  calls.sqagLaunchRequests = [];
  let authStateConsumed = false;
  const dependencies = {
    repositories,
    now: () => now,
    cookie: { secure: true },
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenIssuer: {
      tokens: {
        async createBoundedForSession(record) {
          calls.csrfTokenCreate += 1;
          records.csrfTokens.push(record);
          return record;
        },
        async findBySessionAndTokenHash() {
          return null;
        },
      },
      tokenFactory: {
        async createToken() {
          return issuedCsrfToken;
        },
      },
      tokenHasher: {
        async hashToken(token) {
          assert.equal(token, issuedCsrfToken);
          return issuedCsrfTokenHash;
        },
      },
      idFactory: {
        createId() {
          return `csrf_record_${records.csrfTokens.length + 1}`;
        },
      },
    },
    csrfTokenValidator: {
      async validate(input) {
        calls.order.push("csrf");
        calls.csrfValidate += 1;

        if (overrides.csrfThrows) {
          throw new Error("validator exploded raw-csrf-token postgresql://private-host");
        }

        assert.equal(input.now, now);
        assert.equal(input.sessionId, sessionId);
        assert.doesNotMatch(input.csrfToken, /postgresql:\/\/private-host/);

        return { valid: overrides.csrfValid !== false };
      },
    },
    authStart: {
      authConfig,
      oidcAdapter: createAuthOidcAdapter(calls, overrides),
      stateStore: {
        async storeState(record) {
          calls.authStateStore += 1;
          records.authStates.push(record);
          return record;
        },
      },
      stateFactory: {
        createState() {
          return authState;
        },
      },
      nonceFactory: {
        createNonce() {
          return authNonce;
        },
      },
      stateReferenceFactory(value) {
        return hashAuthReference(value);
      },
      ttlSeconds: 600,
    },
    authCallback: {
      authConfig,
      oidcAdapter: createAuthOidcAdapter(calls, overrides),
      stateStore: {
        async consumeState(input) {
          calls.authStateConsume += 1;
          assert.equal(input.stateHash, authStateHash);
          if (authStateConsumed) {
            return null;
          }

          authStateConsumed = true;
          return {
            providerKey: "example-oidc",
            stateHash: authStateHash,
            nonceHash: authNonceHash,
            redirectUri: "https://platform.example.invalid/api/platform/auth/callback",
            createdAt: earlier,
            expiresAt: future,
          };
        },
      },
      stateReferenceFactory(value) {
        return hashAuthReference(value);
      },
      platformIdentityResolver: {
        async resolveAuthenticatedIdentity(input) {
          calls.authIdentityResolve += 1;
          if (overrides.authIdentityErrorCode) {
            throw new AuthCallbackError(
              overrides.authIdentityErrorCode,
              "Authentication callback could not be completed.",
            );
          }

          return {
            platformUserId: "user_owner_example",
            providerIdentityId: "provider_identity_auth_callback_1",
            session: {
              id: "session_auth_callback_1",
              userId: "user_owner_example",
              createdAt: input.now,
              expiresAt: future,
              lastSeenAt: input.now,
              revokedAt: null,
            },
          };
        },
      },
    },
    appLaunchIntent: {
      repositories,
      launchTokenFactory: {
        async createToken() {
          return rawLaunchToken;
        },
      },
      launchTokenHasher: {
        async hashToken(token) {
          assert.equal(token, rawLaunchToken);
          return launchTokenHash;
        },
      },
      launchTokenIdFactory: {
        createId() {
          return `app_launch_token_${records.appLaunchTokens.length + 1}`;
        },
      },
      ttlSeconds: 300,
    },
    appLaunchTokenConsume: {
      repositories,
      launchTokenHasher: {
        async hashToken(token) {
          assert.equal(token, rawLaunchToken);
          return launchTokenHash;
        },
      },
    },
  };
  if (overrides.sqagLaunchHandoff) {
    dependencies.sqagBrowserLaunch = {
      baseUrl: overrides.sqagLaunchHandoff.baseUrl === "http://127.0.0.1:8765" ? "https://quote.swooshz.com" : overrides.sqagLaunchHandoff.baseUrl,
      serviceSecret: "synthetic-sqag-service-secret-value-32-chars",
      httpClient: {
        async post(input) {
          calls.sqagLaunchRequests.push({
            url: input.url,
            method: "POST",
            token: input.headers["x-app-launch-token"],
          });
          assert.deepEqual(Object.keys(input.headers), ["x-app-launch-token", "x-sqag-service-authorization"]);
          assert.equal(input.headers.cookie, undefined);
          return {
            status: overrides.sqagLaunchHandoff.status ?? 200,
            headers: {
              "x-sqag-finalization-handle": overrides.sqagLaunchHandoff.finalizationHandle ?? "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456",
              "set-cookie": overrides.sqagLaunchHandoff.setCookie ??
                "swooshz_quote_session=safe-sqag-session; Path=/; HttpOnly; SameSite=Lax; Secure",
            },
            body: overrides.sqagLaunchHandoff.body ?? {
              status: "platform_session_created",
              redirect_url: "/",
            },
          };
        },
      },
    };
  }

  return { records, repositories, calls, dependencies };
}

function attachAccessValidationGrantCapability(fixture, overrides = {}) {
  const origin = "https://quote.swooshz.com";
  const grant = {
    id: validationGrantId,
    sessionId,
    userId: "user_owner_example",
    workspaceId: "workspace_koncept_images",
    appId: "app_sqag",
    intendedOrigin: origin,
    launchTokenExpiresAt,
    handleHash: overrides.consumed ? finalizationHandleHash : null,
    handleExpiresAt: overrides.consumed ? finalizationExpiresAt : null,
    consumedAt: overrides.consumed ? now : null,
    revokedAt: null,
    createdAt: now,
  };
  fixture.repositories.accessValidationGrants = {
    async create(record) {
      Object.assign(grant, record);
      return grant;
    },
    async findById(id) {
      return id === grant.id ? grant : null;
    },
    async registerHandle(id, hash, expiresAt) {
      if (id !== grant.id || grant.handleHash || grant.revokedAt || grant.consumedAt) return null;
      grant.handleHash = hash;
      grant.handleExpiresAt = expiresAt;
      return grant;
    },
    async consumeByHandleHash(hash, consumedAt) {
      if (hash !== grant.handleHash || grant.revokedAt || grant.consumedAt) return null;
      grant.consumedAt = consumedAt;
      return grant;
    },
    async revoke(id, revokedAt) {
      if (id !== grant.id || grant.revokedAt) return null;
      grant.revokedAt = revokedAt;
      return grant;
    },
  };
  fixture.dependencies.accessValidationGrant = {
    serviceSecret: sqagServiceSecret,
    service: {
      repositories: fixture.repositories,
      intendedSqagOrigin: origin,
      grantIdFactory: () => validationGrantId,
      handleHasher: (rawHandle) => createHash("sha256").update(rawHandle).digest("hex"),
    },
  };
  return { origin, grant };
}

function instrumentRepositories(repositories) {
  const calls = {
    order: [],
    sessionsFindById: 0,
    sessionsRevoke: 0,
    csrfValidate: 0,
    csrfTokenCreate: 0,
    authStateStore: 0,
    authStateConsume: 0,
    authTokenExchange: 0,
    authIdentityResolve: 0,
  };

  const originalFindById = repositories.sessions.findById.bind(repositories.sessions);
  repositories.sessions.findById = async (id) => {
    calls.order.push("sessionsFindById");
    calls.sessionsFindById += 1;
    return originalFindById(id);
  };

  const originalRevoke = repositories.sessions.revoke.bind(repositories.sessions);
  repositories.sessions.revoke = async (id, revokedAt) => {
    calls.order.push("sessionsRevoke");
    calls.sessionsRevoke += 1;
    return originalRevoke(id, revokedAt);
  };

  return calls;
}

function createAuthOidcAdapter(calls, overrides) {
  return {
    async buildAuthorizationUrl(input) {
      assert.equal(input.state, authState);
      assert.equal(input.nonce, authNonce);
      return { url: providerAuthorizationUrl };
    },
    async exchangeCodeForTokens(input) {
      calls.authTokenExchange += 1;

      if (overrides.authProviderFails) {
        throw new Error("provider exploded synthetic-auth-code raw-claim postgresql://private-host");
      }

      assert.equal(input.code, "synthetic-auth-code");
      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
      };
    },
    async verifyTokens() {
      return {
        providerKey: "example-oidc",
        providerSubject: "provider-subject-123",
        verifiedEmail: "owner@example.com",
        displayName: "Synthetic Owner",
        metadata: { emailVerified: true },
      };
    },
  };
}

function hashAuthReference(value) {
  if (value === authState) {
    return authStateHash;
  }

  if (value === authNonce) {
    return authNonceHash;
  }

  if (value === "browser-binding:" + authStateHash) {
    return authBrowserBindingHash;
  }

  return "hash_unknown_reference";
}

function setCookieHeaders(response) {
  const value = response.headers["set-cookie"];

  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

function requestCookieFromSetCookie(setCookie) {
  return setCookie.split(";", 1)[0];
}

function logoutHeaders({ csrfToken = validCsrfToken } = {}) {
  return {
    origin: allowedOrigin,
    cookie: `swooshz_session=${sessionId}`,
    "x-csrf-token": csrfToken,
  };
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listFiles(path)));
    } else if (entry.isFile() && path.endsWith(".ts")) {
      files.push(path);
    }
  }

  return files;
}

function assertResponseIsPrivacySafe(response) {
  const serialized = JSON.stringify(response);

  assert.doesNotMatch(serialized, /raw-session-token|session-secret|provider-token/i);
  assert.doesNotMatch(serialized, /raw-csrf-token|csrf-secret|auth-code|raw-claim/i);
  assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
  assert.doesNotMatch(serialized, /synthetic-auth-code|synthetic-browser-state-reference/i);
  assert.doesNotMatch(serialized, /synthetic-browser-nonce-reference|synthetic-client-secret/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|database exploded/i);
  assert.doesNotMatch(serialized, /private\.example\.test|\/path\?/i);
  assert.doesNotMatch(
    serialized,
    new RegExp(`${"logo"}_${"data"}_${"url"}|${"data"}:${"image"}|pricing|quote export`, "i"),
  );
}

function assertNoStoreHeaders(headers) {
  assert.equal(headers["cache-control"], "no-store, no-cache, must-revalidate");
  assert.equal(headers.pragma, "no-cache");
  assert.equal(headers.expires, "0");
}
