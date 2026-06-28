import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  handleCsrfTokenIssueRequest,
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

test("protected app-access handler returns 401 for missing cookie without reading app-access repositories", async () => {
  const { repositories, calls } = httpFixture();

  const response = await handleProtectedAppAccessRequest(repositories, {
    headers: {},
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "kqag",
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
    appKey: "kqag",
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

test("HTTP modules do not import DB, frontend, KQAG, provider SDK, or live server modules", async () => {
  const httpFiles = (await listFiles("src/http")).filter(
    (filePath) => ![
      "src/http/node-adapter.ts",
      "src/http/node-server.ts",
    ].includes(filePath.replaceAll("\\", "/")),
  );

  for (const filePath of httpFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?|kqag)/i);
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
    id: "app_kqag",
    key: "kqag",
    name: "KQAG / SAQG",
    status: "private_preview",
    launchUrl: null,
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
    id: "entitlement_koncept_kqag",
    workspaceId: workspace.id,
    appId: app.id,
    status: "enabled",
    grantedByUserId: "user_owner_example",
    createdAt: now,
    updatedAt: now,
  };
  const records = {
    users: [user],
    providerIdentities: [],
    sessions: overrides.sessions ?? [session],
    workspaces: [workspace],
    memberships,
    apps: [app],
    appEntitlements: [entitlement],
    auditEvents: [],
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
    appKey: "kqag",
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
      async create(record) {
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
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|database exploded/i);
}

function assertNoStoreHeaders(headers) {
  assert.deepEqual(headers, {
    "cache-control": "no-store, no-cache, must-revalidate",
    pragma: "no-cache",
    expires: "0",
  });
}
