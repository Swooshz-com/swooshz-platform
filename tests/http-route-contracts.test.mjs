import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HTTP_ROUTE_CONTRACTS,
  getHttpRouteContract,
} from "../dist/index.js";

test("route manifest includes only approved initial platform routes", () => {
  assert.deepEqual(
    HTTP_ROUTE_CONTRACTS.map((route) => route.id),
    [
      "healthz",
      "platform_auth_start",
      "platform_auth_callback",
      "platform_session_app_access",
      "platform_session_context",
      "platform_session_csrf",
      "platform_logout",
    ],
  );
  assert.deepEqual(
    HTTP_ROUTE_CONTRACTS.map((route) => `${route.method} ${route.path}`),
    [
      "GET /healthz",
      "GET /api/platform/auth/start",
      "GET /api/platform/auth/callback",
      "GET /api/platform/session/app-access",
      "GET /api/platform/session/context",
      "GET /api/platform/session/csrf",
      "POST /api/platform/logout",
    ],
  );
});

test("state-changing browser-cookie routes require CSRF protection", () => {
  const stateChangingRoutes = HTTP_ROUTE_CONTRACTS.filter(
    (route) => route.method !== "GET",
  );

  assert.equal(stateChangingRoutes.length, 1);
  assert.equal(stateChangingRoutes[0].id, "platform_logout");
  assert.deepEqual(stateChangingRoutes[0].csrf, {
    required: true,
    strategy: "origin_referer_and_csrf_token",
  });
});

test("auth start route is GET-only and does not require browser session or CSRF", () => {
  const route = getHttpRouteContract("platform_auth_start");

  assert.equal(route.method, "GET");
  assert.equal(route.path, "/api/platform/auth/start");
  assert.equal(route.browserSession, "none");
  assert.equal(route.csrf.required, false);
  assert.equal(route.csrf.strategy, "none");
  assert.deepEqual(route.requiredQuery, []);
  assert.equal(route.handlerContract, "handleAuthStartRequest");
});

test("auth callback route is GET-only and relies on OIDC state instead of generic CSRF", () => {
  const route = getHttpRouteContract("platform_auth_callback");

  assert.equal(route.method, "GET");
  assert.equal(route.path, "/api/platform/auth/callback");
  assert.equal(route.browserSession, "none");
  assert.equal(route.csrf.required, false);
  assert.equal(route.csrf.strategy, "none");
  assert.deepEqual(route.requiredQuery, ["code", "state"]);
  assert.equal(route.handlerContract, "handleAuthCallbackRequest");
});

test("protected app-access route requires browser session cookie and safe query inputs", () => {
  const route = getHttpRouteContract("platform_session_app_access");

  assert.equal(route.method, "GET");
  assert.equal(route.browserSession, "required");
  assert.equal(route.csrf.required, false);
  assert.deepEqual(route.requiredQuery, ["workspaceId", "appKey"]);
  assert.equal(route.handlerContract, "handleProtectedAppAccessRequest");
});

test("session context route is GET-only read-only and requires browser session", () => {
  const route = getHttpRouteContract("platform_session_context");

  assert.equal(route.method, "GET");
  assert.equal(route.path, "/api/platform/session/context");
  assert.equal(route.browserSession, "required");
  assert.equal(route.csrf.required, false);
  assert.equal(route.csrf.strategy, "none");
  assert.deepEqual(route.requiredQuery, []);
  assert.equal(route.handlerContract, "handleSessionContextRequest");
  assert.equal(route.idempotent, true);
});

test("logout route is POST-only, cookie-aware, idempotent, and CSRF-protected", () => {
  const route = getHttpRouteContract("platform_logout");

  assert.equal(route.method, "POST");
  assert.equal(route.browserSession, "optional");
  assert.equal(route.csrf.required, true);
  assert.equal(route.idempotent, true);
  assert.equal(route.handlerContract, "handleLogoutRequest");
});

test("CSRF issuance route is GET-only, session-protected, and does not require CSRF", () => {
  const route = getHttpRouteContract("platform_session_csrf");

  assert.equal(route.method, "GET");
  assert.equal(route.path, "/api/platform/session/csrf");
  assert.equal(route.browserSession, "required");
  assert.equal(route.csrf.required, false);
  assert.equal(route.csrf.strategy, "none");
  assert.deepEqual(route.requiredQuery, []);
  assert.equal(route.handlerContract, "handleCsrfTokenIssueRequest");
});

test("route manifest does not include launch tokens KQAG adapter or frontend dashboard work", () => {
  const serialized = JSON.stringify(HTTP_ROUTE_CONTRACTS);

  assert.doesNotMatch(serialized, /launchToken|launch_token|redirectUrl|redirect_url/i);
  assert.doesNotMatch(serialized, /kqag|quote|pricing|pdf|xlsx/i);
  assert.doesNotMatch(serialized, /frontend|dashboard|react|next|vite/i);
});

test("route contract module does not import DB frontend KQAG provider SDK or live server modules", async () => {
  const contents = await readFile("src/http/route-contracts.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

test("pure domain modules do not import HTTP modules", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/http|\.{1,2}\/http|\.{1,2}\/\.{1,2}\/http/);
    assert.doesNotMatch(contents, /route-contracts|handlers|session-cookie/);
  }
});
