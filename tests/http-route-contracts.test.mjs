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
      "platform_landing_page",
      "platform_app_shell",
      "platform_admin_shell",
      "healthz",
      "platform_auth_start",
      "platform_auth_callback",
      "platform_session_app_access",
      "platform_session_context",
      "platform_session_csrf",
      "platform_workspace_members",
      "platform_workspace_member_add",
      "platform_workspace_member_role",
      "platform_workspace_member_disable",
      "platform_workspace_app_entitlements",
      "platform_workspace_kqag_entitlement_status",
      "platform_workspace_audit_events",
      "platform_app_launch",
      "platform_kqag_launch_open",
      "platform_app_launch_consume",
      "platform_logout",
    ],
  );
  assert.deepEqual(
    HTTP_ROUTE_CONTRACTS.map((route) => `${route.method} ${route.path}`),
    [
      "GET /",
      "GET /app",
      "GET /app/admin",
      "GET /healthz",
      "GET /api/platform/auth/start",
      "GET /api/platform/auth/callback",
      "GET /api/platform/session/app-access",
      "GET /api/platform/session/context",
      "GET /api/platform/session/csrf",
      "GET /api/platform/workspaces/:workspaceId/members",
      "POST /api/platform/workspaces/:workspaceId/members/add",
      "POST /api/platform/workspaces/:workspaceId/members/:membershipId/role",
      "POST /api/platform/workspaces/:workspaceId/members/:membershipId/disable",
      "GET /api/platform/workspaces/:workspaceId/app-entitlements",
      "POST /api/platform/workspaces/:workspaceId/app-entitlements/kqag/status",
      "GET /api/platform/workspaces/:workspaceId/audit-events",
      "POST /api/platform/apps/launch",
      "POST /api/platform/apps/launch/open",
      "POST /api/platform/apps/launch/consume",
      "POST /api/platform/logout",
    ],
  );
});

test("route manifest marks adapter-wired routes as implemented", () => {
  assert.ok(HTTP_ROUTE_CONTRACTS.length > 0);

  for (const route of HTTP_ROUTE_CONTRACTS) {
    assert.equal(route.implemented, true);
  }
});

test("state-changing browser-cookie routes require CSRF protection", () => {
  const stateChangingRoutes = HTTP_ROUTE_CONTRACTS.filter(
    (route) => route.method !== "GET" && route.browserSession !== "none",
  );

  assert.deepEqual(
    stateChangingRoutes.map((route) => route.id),
    [
      "platform_workspace_member_add",
      "platform_workspace_member_role",
      "platform_workspace_member_disable",
      "platform_workspace_kqag_entitlement_status",
      "platform_app_launch",
      "platform_kqag_launch_open",
      "platform_logout",
    ],
  );

  for (const route of stateChangingRoutes) {
    assert.deepEqual(route.csrf, {
      required: true,
      strategy: "origin_referer_and_csrf_token",
    });
  }
});

test("browser page routes are GET-only HTML without CSRF or required browser session", () => {
  const landing = getHttpRouteContract("platform_landing_page");
  const appShell = getHttpRouteContract("platform_app_shell");
  const adminShell = getHttpRouteContract("platform_admin_shell");

  assert.deepEqual(
    [landing, appShell, adminShell].map((route) => ({
      method: route.method,
      browserSession: route.browserSession,
      csrf: route.csrf,
      responseKind: route.responseKind,
      requiredQuery: route.requiredQuery,
      idempotent: route.idempotent,
    })),
    [
      {
        method: "GET",
        browserSession: "none",
        csrf: { required: false, strategy: "none" },
        responseKind: "html",
        requiredQuery: [],
        idempotent: true,
      },
      {
        method: "GET",
        browserSession: "none",
        csrf: { required: false, strategy: "none" },
        responseKind: "html",
        requiredQuery: [],
        idempotent: true,
      },
      {
        method: "GET",
        browserSession: "none",
        csrf: { required: false, strategy: "none" },
        responseKind: "html",
        requiredQuery: [],
        idempotent: true,
      },
    ],
  );
  assert.equal(landing.path, "/");
  assert.equal(landing.handlerContract, "renderLandingPage");
  assert.equal(appShell.path, "/app");
  assert.equal(appShell.handlerContract, "renderAppShellPage");
  assert.equal(adminShell.path, "/app/admin");
  assert.equal(adminShell.handlerContract, "renderAdminShellPage");
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
  assert.equal(route.responseKind, "json");
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

test("workspace admin member routes are session-protected and contract-driven", () => {
  const list = getHttpRouteContract("platform_workspace_members");
  const add = getHttpRouteContract("platform_workspace_member_add");
  const role = getHttpRouteContract("platform_workspace_member_role");
  const disable = getHttpRouteContract("platform_workspace_member_disable");

  assert.equal(list.method, "GET");
  assert.equal(list.path, "/api/platform/workspaces/:workspaceId/members");
  assert.equal(list.browserSession, "required");
  assert.equal(list.csrf.required, false);
  assert.deepEqual(list.requiredQuery, []);
  assert.equal(list.handlerContract, "handleWorkspaceMembersAdminRequest");

  assert.equal(add.method, "POST");
  assert.equal(add.path, "/api/platform/workspaces/:workspaceId/members/add");
  assert.equal(add.browserSession, "required");
  assert.deepEqual(add.csrf, {
    required: true,
    strategy: "origin_referer_and_csrf_token",
  });
  assert.deepEqual(add.requiredQuery, ["email", "role"]);
  assert.equal(add.handlerContract, "handleWorkspaceMemberAddRequest");
  assert.equal(add.idempotent, false);

  assert.equal(role.method, "POST");
  assert.equal(role.path, "/api/platform/workspaces/:workspaceId/members/:membershipId/role");
  assert.equal(role.browserSession, "required");
  assert.deepEqual(role.csrf, {
    required: true,
    strategy: "origin_referer_and_csrf_token",
  });
  assert.deepEqual(role.requiredQuery, ["role"]);
  assert.equal(role.handlerContract, "handleWorkspaceMemberRoleChangeRequest");

  assert.equal(disable.method, "POST");
  assert.equal(disable.path, "/api/platform/workspaces/:workspaceId/members/:membershipId/disable");
  assert.equal(disable.browserSession, "required");
  assert.deepEqual(disable.csrf, {
    required: true,
    strategy: "origin_referer_and_csrf_token",
  });
  assert.deepEqual(disable.requiredQuery, []);
  assert.equal(disable.handlerContract, "handleWorkspaceMembershipDisableRequest");
});

test("workspace admin app entitlement routes are KQAG-scoped and session-protected", () => {
  const list = getHttpRouteContract("platform_workspace_app_entitlements");
  const status = getHttpRouteContract("platform_workspace_kqag_entitlement_status");

  assert.equal(list.method, "GET");
  assert.equal(list.path, "/api/platform/workspaces/:workspaceId/app-entitlements");
  assert.equal(list.browserSession, "required");
  assert.equal(list.csrf.required, false);
  assert.deepEqual(list.requiredQuery, []);
  assert.equal(list.handlerContract, "handleWorkspaceAppEntitlementsAdminRequest");

  assert.equal(status.method, "POST");
  assert.equal(status.path, "/api/platform/workspaces/:workspaceId/app-entitlements/kqag/status");
  assert.equal(status.browserSession, "required");
  assert.deepEqual(status.csrf, {
    required: true,
    strategy: "origin_referer_and_csrf_token",
  });
  assert.deepEqual(status.requiredQuery, ["status"]);
  assert.equal(status.handlerContract, "handleWorkspaceKqagEntitlementStatusRequest");
  assert.equal(status.idempotent, false);
});

test("workspace admin audit event route is read-only session-protected and not CSRF-protected", () => {
  const route = getHttpRouteContract("platform_workspace_audit_events");

  assert.equal(route.method, "GET");
  assert.equal(route.path, "/api/platform/workspaces/:workspaceId/audit-events");
  assert.equal(route.browserSession, "required");
  assert.deepEqual(route.csrf, {
    required: false,
    strategy: "none",
  });
  assert.deepEqual(route.requiredQuery, []);
  assert.equal(route.handlerContract, "handleWorkspaceAuditEventsAdminRequest");
  assert.equal(route.responseKind, "json");
  assert.equal(route.idempotent, true);
});

test("app launch intent route is POST-only session-protected and CSRF-protected", () => {
  const route = getHttpRouteContract("platform_app_launch");

  assert.equal(route.method, "POST");
  assert.equal(route.path, "/api/platform/apps/launch");
  assert.equal(route.browserSession, "required");
  assert.equal(route.csrf.required, true);
  assert.equal(route.csrf.strategy, "origin_referer_and_csrf_token");
  assert.deepEqual(route.requiredQuery, ["workspaceId", "appKey"]);
  assert.equal(route.handlerContract, "handleAppLaunchIntentRequest");
  assert.equal(route.idempotent, false);
});

test("KQAG launch open route is POST-only session-protected and CSRF-protected", () => {
  const route = getHttpRouteContract("platform_kqag_launch_open");

  assert.equal(route.method, "POST");
  assert.equal(route.path, "/api/platform/apps/launch/open");
  assert.equal(route.browserSession, "required");
  assert.equal(route.csrf.required, true);
  assert.equal(route.csrf.strategy, "origin_referer_and_csrf_token");
  assert.deepEqual(route.requiredQuery, ["workspaceId", "appKey"]);
  assert.equal(route.handlerContract, "handleKqagBrowserLaunchRequest");
  assert.equal(route.idempotent, false);
});

test("app launch token consume route is POST-only token-protected and not CSRF-protected", () => {
  const route = getHttpRouteContract("platform_app_launch_consume");

  assert.equal(route.method, "POST");
  assert.equal(route.path, "/api/platform/apps/launch/consume");
  assert.equal(route.browserSession, "none");
  assert.equal(route.csrf.required, false);
  assert.equal(route.csrf.strategy, "none");
  assert.deepEqual(route.requiredQuery, ["appKey"]);
  assert.equal(route.handlerContract, "handleAppLaunchTokenConsumeRequest");
  assert.equal(route.idempotent, false);
});

test("route manifest does not include quote app storage or frontend dashboard work", () => {
  const serialized = JSON.stringify(HTTP_ROUTE_CONTRACTS);

  assert.doesNotMatch(serialized, /quote|pricing|pdf|xlsx/i);
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
