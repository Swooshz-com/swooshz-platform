import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  handleNodePlatformHttpRequest,
} from "../dist/index.js";
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
const privateUrl =
  "https://private.example.test/path?csrf=raw-csrf-token&db=postgresql://private-host";

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

test("wrong method for a known route returns safe 405 JSON", async () => {
  const { response, body } = await request({
    method: "POST",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=kqag",
  });

  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, "GET");
  assert.deepEqual(body, {
    outcome: "error",
    message: "Method not allowed.",
  });
  assertResponseIsPrivacySafe(response);
});

test("app-access route parses workspaceId appKey and session cookie correctly", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=kqag",
    headers: {
      cookie: `swooshz_session=${sessionId}; unrelated=value`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(body.outcome, "allowed");
  assert.equal(body.workspaceId, "workspace_koncept_images");
  assert.equal(body.appKey, "kqag");
  assert.equal(fixture.calls.sessionsFindById, 2);
  assert.equal(fixture.calls.csrfValidate, 0);
  assert.equal(fixture.calls.sessionsRevoke, 0);
  assertResponseIsPrivacySafe(response);
});

test("app-access route denies missing session safely through handler path", async () => {
  const fixture = createAdapterFixture();
  const { response, body } = await request({
    method: "GET",
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=kqag",
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
    url: "/api/platform/session/app-access?workspaceId=workspace_koncept_images&appKey=kqag",
    headers: {
      cookie: `swooshz_session=${sessionId}`,
    },
    dependencies: fixture.dependencies,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(body.outcome, "allowed");
  assert.equal(fixture.calls.csrfValidate, 0);
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

test("Node HTTP adapter does not import frontend KQAG provider SDK framework live DB or migrations", async () => {
  const contents = await readFile("src/http/node-adapter.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

async function request({
  method,
  url,
  headers = {},
  dependencies = createAdapterFixture().dependencies,
}) {
  const response = await handleNodePlatformHttpRequest(dependencies, {
    method,
    url,
    headers,
  });

  return {
    response,
    body: JSON.parse(response.body),
  };
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
        id: "app_kqag",
        key: "kqag",
        name: "KQAG / SAQG",
        status: "private_preview",
        launchUrl: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
    appEntitlements: [
      {
        id: "entitlement_koncept_kqag",
        workspaceId: "workspace_koncept_images",
        appId: "app_kqag",
        status: "enabled",
        grantedByUserId: "user_owner_example",
        createdAt: now,
        updatedAt: now,
      },
    ],
    auditEvents: [],
    csrfTokens: [],
  };
  const repositories = createInMemoryPlatformRepositories(records);
  const calls = instrumentRepositories(repositories);
  const dependencies = {
    repositories,
    now: () => now,
    cookie: { secure: true },
    originConfig: { allowedOrigins: [allowedOrigin] },
    csrfTokenIssuer: {
      tokens: {
        async create(record) {
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
  };

  return { records, repositories, calls, dependencies };
}

function instrumentRepositories(repositories) {
  const calls = {
    order: [],
    sessionsFindById: 0,
    sessionsRevoke: 0,
    csrfValidate: 0,
    csrfTokenCreate: 0,
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
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|select \*|database exploded/i);
  assert.doesNotMatch(serialized, /private\.example\.test|\/path\?|callback/i);
  assert.doesNotMatch(
    serialized,
    new RegExp(`${"logo"}_${"data"}_${"url"}|${"data"}:${"image"}|pricing|quote export`, "i"),
  );
}
