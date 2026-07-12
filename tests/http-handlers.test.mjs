import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  handleCsrfTokenIssueRequest,
  handleAppLaunchTokenConsumeRequest,
  handleAppLaunchIntentRequest,
  handleLogoutRequest,
  handleProtectedAppAccessRequest,
  handleSessionContextRequest,
} from "../dist/index.js";
import { createInMemoryPlatformRepositories } from "./helpers/in-memory-platform-repositories.mjs";

const now = "2026-06-27T00:00:00.000Z";
const earlier = "2026-06-26T23:00:00.000Z";
const future = "2026-06-27T01:00:00.000Z";
const past = "2026-06-26T22:00:00.000Z";
const privateStorageError =
  "database exploded postgresql://private-host raw-session-token SQL select *";
const issuedCsrfToken = "issued-csrf-token-reference";
const issuedCsrfTokenHash = "hash_issued_csrf_token_reference";
const csrfExpiresAt = "2026-06-27T00:15:00.000Z";
const rawLaunchToken = "synthetic-raw-launch-token-reference";
const launchTokenHash = "app-launch:v1:hmac-sha256:synthetic_hash_reference";
const launchTokenExpiresAt = "2026-06-27T00:05:00.000Z";

test("protected app-access handler returns 401 for missing cookie without reading app-access repositories", async () => {
  const { repositories, calls } = httpFixture();

  const response = await handleProtectedAppAccessRequest(repositories, {
    headers: {},
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, {
    outcome: "denied",
    reason: "missing_session",
  });
  assert.equal(calls.sessionsFindById, 0);
  assert.equal(calls.usersFindById, 0);
  assert.equal(calls.membershipsFindForUserInWorkspace, 0);
  assert.equal(calls.appsFindByKey, 0);
});

test("protected app-access handler returns 401 for revoked and expired sessions", async () => {
  const revoked = httpFixture({
    session: { revokedAt: earlier },
  });
  const expired = httpFixture({
    session: { expiresAt: past },
  });

  const revokedResponse = await handleProtectedAppAccessRequest(
    revoked.repositories,
    requestWithCookie("session_owner_example"),
  );
  const expiredResponse = await handleProtectedAppAccessRequest(
    expired.repositories,
    requestWithCookie("session_owner_example"),
  );

  assert.deepEqual(revokedResponse, {
    status: 401,
    body: {
      outcome: "denied",
      reason: "revoked_session",
    },
  });
  assert.deepEqual(expiredResponse, {
    status: 401,
    body: {
      outcome: "denied",
      reason: "expired_session",
    },
  });
});

test("protected app-access handler returns 200 safe body for allowed access", async () => {
  const { repositories } = httpFixture();

  const response = await handleProtectedAppAccessRequest(
    repositories,
    requestWithCookie("session_owner_example"),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    outcome: "allowed",
    userId: "user_owner_example",
    workspaceId: "workspace_koncept_images",
    appKey: "sqag",
    decision: {
      result: "allowed",
      allowed: true,
      message: "Access allowed.",
    },
  });
  assertResponseIsPrivacySafe(response);
});

test("protected app-access handler returns 403 safe body for app-access denial", async () => {
  const { repositories } = httpFixture({ role: "viewer" });

  const response = await handleProtectedAppAccessRequest(
    repositories,
    requestWithCookie("session_viewer_example"),
  );

  assert.equal(response.status, 403);
  assert.deepEqual(response.body, {
    outcome: "denied",
    reason: "app_access_denied",
    decision: {
      result: "role_not_permitted",
      allowed: false,
      message: "The current role cannot launch this app.",
    },
  });
  assertResponseIsPrivacySafe(response);
});

test("protected app-access handler returns 500 safe body for service failure", async () => {
  const { repositories } = httpFixture({
    failUserFind: true,
  });

  const response = await handleProtectedAppAccessRequest(
    repositories,
    requestWithCookie("session_owner_example"),
  );

  assert.equal(response.status, 500);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "App access decision could not be completed.",
  });
  assertResponseIsPrivacySafe(response);
});

test("session context handler returns 401 for missing cookie without repository reads", async () => {
  const { repositories, calls } = httpFixture();

  const response = await handleSessionContextRequest(repositories, {
    headers: {},
    now,
  });

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, {
    outcome: "unauthenticated",
    reason: "missing_session",
  });
  assertNoStoreHeaders(response.headers);
  assert.equal(calls.sessionsFindById, 0);
  assert.equal(calls.usersFindById, 0);
  assertResponseIsPrivacySafe(response);
});

test("session context handler returns 200 safe context for active session", async () => {
  const { repositories, calls } = httpFixture();

  const response = await handleSessionContextRequest(repositories, {
    headers: {
      cookie: "swooshz_session=session_owner_example; unrelated=value",
    },
    now,
    selectedWorkspaceId: "workspace_koncept_images",
  });

  assert.equal(response.status, 200);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.body.outcome, "authenticated");
  assert.equal(response.body.user.userId, "user_owner_example");
  assert.equal(response.body.selectedWorkspaceId, "workspace_koncept_images");
  assert.deepEqual(
    response.body.workspaces.map((workspace) => ({
      workspaceId: workspace.workspaceId,
      apps: workspace.apps.map((app) => app.access.result),
    })),
    [
      {
        workspaceId: "workspace_koncept_images",
        apps: ["allowed"],
      },
    ],
  );
  assert.equal(calls.sessionsFindById, 1);
  assert.equal(calls.membershipsListForUser, 1);
  assert.equal(calls.csrfValidate ?? 0, 0);
  assertResponseIsPrivacySafe(response);
});

test("session context handler returns 500 safe body for repository failure", async () => {
  const { repositories } = httpFixture({ failUserFind: true });

  const response = await handleSessionContextRequest(repositories, {
    headers: {
      cookie: "swooshz_session=session_owner_example",
    },
    now,
  });

  assert.equal(response.status, 500);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Session context could not be loaded.",
  });
  assertNoStoreHeaders(response.headers);
  assertResponseIsPrivacySafe(response);
});

test("logout handler clears cookie safely when cookie is missing", async () => {
  const { repositories, calls } = httpFixture();

  const response = await handleLogoutRequest(
    { sessions: repositories.sessions },
    {
      headers: {},
      now,
      cookie: { secure: true },
    },
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { outcome: "logged_out" });
  assert.match(response.headers["set-cookie"], /^swooshz_session=;/);
  assert.match(response.headers["set-cookie"], /Max-Age=0/);
  assert.match(response.headers["set-cookie"], /Secure/);
  assert.equal(calls.sessionsFindById, 0);
  assert.equal(calls.sessionsRevoke, 0);
});

test("logout handler revokes active session and returns safe idempotent response", async () => {
  const { repositories, records, calls } = httpFixture();

  const response = await handleLogoutRequest(
    { sessions: repositories.sessions },
    logoutRequestWithCookie("session_owner_example"),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { outcome: "logged_out" });
  assert.equal(records.sessions[0].revokedAt, now);
  assert.equal(calls.sessionsFindById, 1);
  assert.equal(calls.sessionsRevoke, 1);
  assertResponseIsPrivacySafe(response);
});

test("logout handler remains safe for already revoked and not found sessions", async () => {
  const alreadyRevoked = httpFixture({
    session: { revokedAt: earlier },
  });
  const notFound = httpFixture({
    sessions: [],
  });

  const alreadyRevokedResponse = await handleLogoutRequest(
    { sessions: alreadyRevoked.repositories.sessions },
    logoutRequestWithCookie("session_owner_example"),
  );
  const notFoundResponse = await handleLogoutRequest(
    { sessions: notFound.repositories.sessions },
    logoutRequestWithCookie("session_owner_example"),
  );

  assert.equal(alreadyRevokedResponse.status, 200);
  assert.equal(notFoundResponse.status, 200);
  assert.deepEqual(alreadyRevokedResponse.body, { outcome: "logged_out" });
  assert.deepEqual(notFoundResponse.body, { outcome: "logged_out" });
  assert.equal(alreadyRevoked.records.sessions[0].revokedAt, earlier);
});

test("logout handler returns privacy-safe response for revocation failure", async () => {
  const { repositories } = httpFixture({
    failRevoke: true,
  });

  const response = await handleLogoutRequest(
    { sessions: repositories.sessions },
    logoutRequestWithCookie("session_owner_example"),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { outcome: "logged_out" });
  assertResponseIsPrivacySafe(response);
});

test("CSRF issue handler denies missing session cookie safely", async () => {
  const { repositories, calls } = httpFixture();
  const csrf = csrfIssueFixture();

  const response = await handleCsrfTokenIssueRequest(
    { sessions: repositories.sessions, csrf: csrf.dependencies },
    {
      headers: {},
      now,
      ttlSeconds: 900,
    },
  );

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, {
    outcome: "denied",
    reason: "missing_session",
  });
  assertNoStoreHeaders(response.headers);
  assert.equal(calls.sessionsFindById, 0);
  assert.equal(csrf.records.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("CSRF issue handler denies unknown revoked and expired sessions safely", async () => {
  const unknown = httpFixture({ sessions: [] });
  const revoked = httpFixture({ session: { revokedAt: earlier } });
  const expired = httpFixture({ session: { expiresAt: past } });

  const unknownResponse = await handleCsrfTokenIssueRequest(
    { sessions: unknown.repositories.sessions, csrf: csrfIssueFixture().dependencies },
    csrfIssueRequestWithCookie("session_owner_example"),
  );
  const revokedResponse = await handleCsrfTokenIssueRequest(
    { sessions: revoked.repositories.sessions, csrf: csrfIssueFixture().dependencies },
    csrfIssueRequestWithCookie("session_owner_example"),
  );
  const expiredResponse = await handleCsrfTokenIssueRequest(
    { sessions: expired.repositories.sessions, csrf: csrfIssueFixture().dependencies },
    csrfIssueRequestWithCookie("session_owner_example"),
  );

  assert.deepEqual(unknownResponse.body, {
    outcome: "denied",
    reason: "unknown_session",
  });
  assert.deepEqual(revokedResponse.body, {
    outcome: "denied",
    reason: "revoked_session",
  });
  assert.deepEqual(expiredResponse.body, {
    outcome: "denied",
    reason: "expired_session",
  });
  assert.equal(unknownResponse.status, 401);
  assert.equal(revokedResponse.status, 401);
  assert.equal(expiredResponse.status, 401);
  assertNoStoreHeaders(unknownResponse.headers);
  assertNoStoreHeaders(revokedResponse.headers);
  assertNoStoreHeaders(expiredResponse.headers);
  assertResponseIsPrivacySafe(unknownResponse);
  assertResponseIsPrivacySafe(revokedResponse);
  assertResponseIsPrivacySafe(expiredResponse);
});

test("CSRF issue handler issues a token for an active session and stores only the token hash", async () => {
  const { repositories } = httpFixture();
  const csrf = csrfIssueFixture();

  const response = await handleCsrfTokenIssueRequest(
    { sessions: repositories.sessions, csrf: csrf.dependencies },
    csrfIssueRequestWithCookie("session_owner_example"),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    outcome: "issued",
    csrfToken: issuedCsrfToken,
    expiresAt: csrfExpiresAt,
  });
  assertNoStoreHeaders(response.headers);
  assert.equal("tokenHash" in response.body, false);
  assert.equal(csrf.records.length, 1);
  assert.equal(csrf.records[0].sessionId, "session_owner_example");
  assert.equal(csrf.records[0].tokenHash, issuedCsrfTokenHash);
  assert.equal(csrf.records[0].csrfToken, undefined);
  assert.doesNotMatch(JSON.stringify(csrf.records), new RegExp(issuedCsrfToken));
});

test("CSRF issue handler handles token lifecycle failures safely", async () => {
  const failures = [
    "failTokenFactory",
    "failHash",
    "failId",
    "failCreate",
    "invalidTtl",
    "invalidNow",
  ];

  for (const failure of failures) {
    const { repositories } = httpFixture();
    const csrf = csrfIssueFixture({ [failure]: true });
    const response = await handleCsrfTokenIssueRequest(
      { sessions: repositories.sessions, csrf: csrf.dependencies },
      csrfIssueRequestWithCookie("session_owner_example", {
        ttlSeconds: failure === "invalidTtl" ? 0 : 900,
        now: failure === "invalidNow" ? "not-a-date raw-session-token" : now,
      }),
    );

    assert.equal(response.status, 500);
    assert.deepEqual(response.body, {
      outcome: "error",
      message: "CSRF token could not be issued.",
    });
    assertNoStoreHeaders(response.headers);
    assertResponseIsPrivacySafe(response);
  }
});

test("app launch handler returns 401 for missing cookie without creating a token", async () => {
  const { repositories, records } = httpFixture();
  const launch = launchIssueFixture(records);

  const response = await handleAppLaunchIntentRequest(launch.dependencies, {
    headers: {},
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 401);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "unauthenticated",
    reason: "missing_session",
  });
  assert.equal(records.appLaunchTokens.length, 0);
});

test("app launch handler returns 400 for missing query fields without creating a token", async () => {
  const { records } = httpFixture();
  const launch = launchIssueFixture(records);

  const response = await handleAppLaunchIntentRequest(launch.dependencies, {
    headers: {
      cookie: "swooshz_session=session_owner_example",
    },
    selectedWorkspaceId: "",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 400);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Required query parameters are missing.",
  });
  assert.equal(records.appLaunchTokens.length, 0);
});

test("app launch handler disables direct responses before app-access token creation", async () => {
  const { records } = httpFixture({ role: "viewer" });
  const launch = launchIssueFixture(records);

  const response = await handleAppLaunchIntentRequest(launch.dependencies, {
    headers: {
      cookie: "swooshz_session=session_viewer_example",
    },
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 410);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Direct launch token responses are disabled. Use the server-side launch handoff.",
  });
  assert.equal(records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("app launch handler disables direct browser raw-token responses", async () => {
  const { records } = httpFixture({
    app: { launchUrl: "https://apps.example.invalid/sqag" },
  });
  const launch = launchIssueFixture(records);

  const response = await handleAppLaunchIntentRequest(launch.dependencies, {
    headers: {
      cookie: "swooshz_session=session_owner_example",
    },
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 410);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Direct launch token responses are disabled. Use the server-side launch handoff.",
  });
  assert.equal(records.appLaunchTokens.length, 0);
  assert.doesNotMatch(JSON.stringify(records.appLaunchTokens), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(response), new RegExp(rawLaunchToken));
  assert.doesNotMatch(JSON.stringify(response), new RegExp(launchTokenHash));
});

test("app launch handler does not touch launch-token storage when direct responses are disabled", async () => {
  const { records } = httpFixture();
  const launch = launchIssueFixture(records, { failCreate: true });

  const response = await handleAppLaunchIntentRequest(launch.dependencies, {
    headers: {
      cookie: "swooshz_session=session_owner_example",
    },
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 410);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "Direct launch token responses are disabled. Use the server-side launch handoff.",
  });
  assert.equal(records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("app launch consume handler requires token header and appKey safely", async () => {
  const { records } = httpFixture();
  const consume = launchConsumeFixture(records, { defaultToken: true });

  const missingToken = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
    headers: {},
    appKey: "sqag",
    now,
  });
  const missingAppKey = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    appKey: "",
    now,
  });

  assert.equal(missingToken.status, 401);
  assertNoStoreHeaders(missingToken.headers);
  assert.deepEqual(missingToken.body, {
    outcome: "invalid",
    reason: "missing_launch_token",
  });
  assert.equal(missingAppKey.status, 400);
  assertNoStoreHeaders(missingAppKey.headers);
  assert.deepEqual(missingAppKey.body, {
    outcome: "error",
    message: "Required query parameters are missing.",
  });
  assert.equal(records.appLaunchTokens[0].consumedAt, null);
  assertResponseIsPrivacySafe(missingToken);
  assertResponseIsPrivacySafe(missingAppKey);
});

test("app launch consume handler denies invalid consumed and expired tokens safely", async () => {
  for (const [overrides, reason] of [
    [{ appLaunchTokens: [] }, "invalid_launch_token"],
    [{ launchToken: { consumedAt: earlier } }, "consumed_launch_token"],
    [{ launchToken: { expiresAt: past } }, "expired_launch_token"],
  ]) {
    const { records } = httpFixture();
    const consume = launchConsumeFixture(records, {
      defaultToken: !Object.hasOwn(overrides, "appLaunchTokens"),
      ...overrides,
    });

    const response = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
      headers: {
        "x-app-launch-token": rawLaunchToken,
      },
      appKey: "sqag",
      now,
    });

    assert.equal(response.status, 401);
    assertNoStoreHeaders(response.headers);
    assert.deepEqual(response.body, {
      outcome: "invalid",
      reason,
    });
    assertResponseIsPrivacySafe(response);
  }
});

test("app launch consume handler denies app access without consuming token", async () => {
  const { records } = httpFixture({ role: "viewer" });
  const consume = launchConsumeFixture(records, { defaultToken: true });

  const response = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 403);
  assertNoStoreHeaders(response.headers);
  assert.equal(response.body.outcome, "denied");
  assert.equal(response.body.reason, "app_access_denied");
  assert.equal(records.appLaunchTokens[0].consumedAt, null);
  assertResponseIsPrivacySafe(response);
});

test("app launch consume handler returns safe launch context and consumes once", async () => {
  const { records } = httpFixture();
  const consume = launchConsumeFixture(records, { defaultToken: true });

  const response = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
    headers: {
      "x-app-launch-token": rawLaunchToken,
      cookie: "swooshz_session=raw-session-token-ignored",
    },
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 200);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
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
  assert.equal(records.appLaunchTokens[0].consumedAt, now);
  assertResponseIsPrivacySafe(response);
});

test("app launch consume handler returns privacy-safe failure body", async () => {
  const { records } = httpFixture();
  const consume = launchConsumeFixture(records, {
    defaultToken: true,
    failFindByTokenHash: true,
  });

  const response = await handleAppLaunchTokenConsumeRequest(consume.dependencies, {
    headers: {
      "x-app-launch-token": rawLaunchToken,
    },
    appKey: "sqag",
    now,
  });

  assert.equal(response.status, 500);
  assertNoStoreHeaders(response.headers);
  assert.deepEqual(response.body, {
    outcome: "error",
    message: "App launch token could not be consumed.",
  });
  assertResponseIsPrivacySafe(response);
});

test("HTTP modules do not import DB, frontend, SQAG, provider SDK, or live server modules", async () => {
  const httpFiles = (await listFiles("src/http")).filter(
    (filePath) => ![
      "src/http/node-adapter.ts",
      "src/http/node-server.ts",
    ].includes(filePath.replaceAll("\\", "/")),
  );

  for (const filePath of httpFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|sqag)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono|node:http)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
  }
});

test("pure domain modules do not import HTTP auth or platform handler modules", async () => {
  const pureDomainFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
  ];

  for (const filePath of pureDomainFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/http|\.{1,2}\/http|\.{1,2}\/\.{1,2}\/http/);
    assert.doesNotMatch(contents, /src\/auth|\.{1,2}\/auth|\.{1,2}\/\.{1,2}\/auth/);
    assert.doesNotMatch(
      contents,
      /protected-app-access|session-revocation|handlers/,
    );
  }
});

function httpFixture(overrides = {}) {
  const workspace = {
    id: "workspace_koncept_images",
    slug: "koncept-images-pte-ltd",
    displayName: "Koncept Images Pte Ltd",
    status: "active",
    createdAt: now,
    updatedAt: now,
  };
  const app = {
    id: "app_sqag",
    key: "sqag",
    name: "SQAG",
    status: "private_preview",
    launchUrl: null,
    ...overrides.app,
    createdAt: now,
    updatedAt: now,
  };
  const usersByRole = Object.fromEntries(
    ["owner", "admin", "member", "viewer"].map((role) => [
      role,
      {
        id: `user_${role}_example`,
        email: `${role}@example.com`,
        displayName: `${role[0].toUpperCase()}${role.slice(1)} Example`,
        status: "active",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      },
    ]),
  );
  const role = overrides.role ?? "owner";
  const user = { ...usersByRole[role], ...overrides.user };
  const session = {
    id: `session_${role}_example`,
    userId: user.id,
    createdAt: earlier,
    expiresAt: future,
    lastSeenAt: earlier,
    revokedAt: null,
    ...overrides.session,
  };
  const memberships = Object.entries(usersByRole).map(([membershipRole, membershipUser]) => ({
    id: `membership_${membershipRole}_example`,
    workspaceId: workspace.id,
    userId: membershipUser.id,
    role: membershipRole,
    status: "active",
    createdAt: now,
    updatedAt: now,
  }));
  const entitlement = {
    id: "entitlement_koncept_sqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
  };
  const records = {
    users: overrides.users ?? [user],
    providerIdentities: [],
    sessions: overrides.sessions ?? [session],
    workspaces: overrides.workspaces ?? [workspace],
    memberships: overrides.memberships ?? memberships,
    apps: overrides.apps ?? [app],
    appEntitlements: overrides.appEntitlements ?? [entitlement],
    auditEvents: [],
    appLaunchTokens: overrides.appLaunchTokens ?? [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const calls = instrumentRepositories(repositories, overrides);

  return { records, repositories, calls };
}

function requestWithCookie(sessionId) {
  return {
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  };
}

function logoutRequestWithCookie(sessionId) {
  return {
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    now,
    cookie: { secure: true },
  };
}

function csrfIssueRequestWithCookie(sessionId, overrides = {}) {
  return {
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    now,
    ttlSeconds: 900,
    ...overrides,
  };
}

function csrfIssueFixture(options = {}) {
  const records = [];
  const dependencies = {
    tokens: {
      async replaceForSession(record) {
        if (options.failCreate) {
          throw new Error(privateStorageError);
        }

        records.push(record);
        return record;
      },
      async findBySessionAndTokenHash() {
        return null;
      },
    },
    tokenFactory: {
      async createToken() {
        if (options.failTokenFactory) {
          throw new Error(privateStorageError);
        }

        return issuedCsrfToken;
      },
    },
    tokenHasher: {
      async hashToken(token) {
        if (options.failHash) {
          throw new Error(privateStorageError);
        }

        assert.equal(token, issuedCsrfToken);
        return issuedCsrfTokenHash;
      },
    },
    idFactory: {
      createId() {
        if (options.failId) {
          throw new Error(privateStorageError);
        }

        return `csrf_record_${records.length + 1}`;
      },
    },
  };

  return { records, dependencies };
}

function instrumentRepositories(repositories, options) {
  const calls = {
    sessionsFindById: 0,
    sessionsRevoke: 0,
    usersFindById: 0,
    membershipsListForUser: 0,
    membershipsFindForUserInWorkspace: 0,
    appsFindByKey: 0,
    appsListAll: 0,
    appEntitlementsListForWorkspace: 0,
  };

  const originalSessionFindById = repositories.sessions.findById.bind(repositories.sessions);
  repositories.sessions.findById = async (id) => {
    calls.sessionsFindById += 1;
    return originalSessionFindById(id);
  };

  const originalSessionRevoke = repositories.sessions.revoke.bind(repositories.sessions);
  repositories.sessions.revoke = async (id, revokedAt) => {
    calls.sessionsRevoke += 1;
    if (options.failRevoke) {
      throw new Error(privateStorageError);
    }

    return originalSessionRevoke(id, revokedAt);
  };

  const originalUserFindById = repositories.users.findById.bind(repositories.users);
  repositories.users.findById = async (id) => {
    calls.usersFindById += 1;
    if (options.failUserFind) {
      throw new Error(privateStorageError);
    }

    return originalUserFindById(id);
  };

  const originalMembershipFind =
    repositories.memberships.findForUserInWorkspace.bind(repositories.memberships);
  repositories.memberships.findForUserInWorkspace = async (userId, workspaceId) => {
    calls.membershipsFindForUserInWorkspace += 1;
    return originalMembershipFind(userId, workspaceId);
  };

  const originalMembershipList =
    repositories.memberships.listForUser.bind(repositories.memberships);
  repositories.memberships.listForUser = async (userId) => {
    calls.membershipsListForUser += 1;
    return originalMembershipList(userId);
  };

  const originalAppFindByKey = repositories.apps.findByKey.bind(repositories.apps);
  repositories.apps.findByKey = async (key) => {
    calls.appsFindByKey += 1;
    return originalAppFindByKey(key);
  };

  if (repositories.apps.listAll) {
    const originalAppsListAll = repositories.apps.listAll.bind(repositories.apps);
    repositories.apps.listAll = async () => {
      calls.appsListAll += 1;
      return originalAppsListAll();
    };
  }

  if (repositories.appEntitlements.listForWorkspace) {
    const originalListForWorkspace =
      repositories.appEntitlements.listForWorkspace.bind(repositories.appEntitlements);
    repositories.appEntitlements.listForWorkspace = async (workspaceId) => {
      calls.appEntitlementsListForWorkspace += 1;
      return originalListForWorkspace(workspaceId);
    };
  }

  return calls;
}

function launchIssueFixture(records, options = {}) {
  records.appLaunchTokens ??= [];
  const dependencies = {
    repositories: createInMemoryPlatformRepositories(records),
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
  };

  dependencies.repositories.appLaunchTokens = {
    async create(record) {
      if (options.failCreate) {
        throw new Error(privateStorageError);
      }

      records.appLaunchTokens.push(record);
      return record;
    },
  };

  return { dependencies };
}

function launchConsumeFixture(records, options = {}) {
  if (options.defaultToken) {
    const session = records.sessions[0];
    const user = records.users[0];
    const workspace = records.workspaces[0];
    const app = records.apps[0];

    records.appLaunchTokens.push({
      id: "app_launch_token_1",
      sessionId: session?.id ?? "missing_session",
      userId: user?.id ?? "missing_user",
      workspaceId: workspace?.id ?? "missing_workspace",
      appId: app?.id ?? "missing_app",
      tokenHash: launchTokenHash,
      createdAt: now,
      expiresAt: launchTokenExpiresAt,
      consumedAt: null,
      revokedAt: null,
      ...options.launchToken,
    });
  }

  const dependencies = {
    repositories: createInMemoryPlatformRepositories(records),
    launchTokenHasher: {
      async hashToken(token) {
        assert.equal(token, rawLaunchToken);
        return launchTokenHash;
      },
    },
  };

  dependencies.repositories.appLaunchTokens = {
    async create(record) {
      records.appLaunchTokens.push(record);
      return record;
    },
    async findByTokenHash(tokenHash) {
      if (options.failFindByTokenHash) {
        throw new Error(privateStorageError);
      }

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

  return { dependencies };
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
  assert.doesNotMatch(serialized, /auth-code|raw-claim|client-secret/i);
  assert.doesNotMatch(serialized, new RegExp(launchTokenHash));
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|database exploded/i);
}

function assertNoStoreHeaders(headers) {
  assert.deepEqual(headers, {
    "cache-control": "no-store, no-cache, must-revalidate",
    pragma: "no-cache",
    expires: "0",
  });
}
