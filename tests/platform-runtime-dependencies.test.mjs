import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  createPlatformRuntimeDependencies,
  handleNodePlatformHttpRequest,
  PlatformRuntimeSecretConfigError,
  readPlatformRuntimeSecretConfig,
  issueCsrfTokenForSession,
} from "../dist/index.js";
import { readAuthConfig } from "../dist/auth/index.js";

const now = "2026-06-27T00:00:00.000Z";
const future = "2026-06-27T00:15:00.000Z";
const allowedOrigin = "https://platform.example.test";
const sessionId = "session_owner_example";
const userId = "user_owner_example";
const csrfSecret = "synthetic_csrf_hash_secret_32_chars_min";
const authStateHashSecret = "synthetic_auth_state_hash_secret_32_chars_min";
const appLaunchTokenHashSecret = "synthetic_app_launch_hash_secret_32_chars_min";
const rawTokenPattern = /csrf_[A-Za-z0-9_-]+|synthetic-raw-csrf-token|raw-csrf-token/i;
const rawAuthPattern =
  /synthetic-auth-code|synthetic-provider-token|synthetic-raw-claim|synthetic-client-secret|synthetic-session-secret|postgresql:\/\/private-host/i;
const rawLaunchTokenPattern =
  /synthetic-raw-launch-token|app-launch:v1:hmac-sha256:synthetic_hash_reference/i;
const issuerUrl = "https://issuer.example.invalid/";
const jwksUrl = "https://issuer.example.invalid/.well-known/jwks.json";
const authConfig = readAuthConfig({
  AUTH_PROVIDER_KEY: "Example-OIDC",
  AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
  AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
  AUTH_ISSUER_URL: issuerUrl,
  AUTH_JWKS_URL: jwksUrl,
  AUTH_CLIENT_ID: "synthetic-client-id",
  AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
  AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
  SESSION_SECRET: "synthetic-session-secret-value-32",
});

test("runtime secret config accepts strong synthetic CSRF hash secret", () => {
  const config = readPlatformRuntimeSecretConfig({
    CSRF_TOKEN_HASH_SECRET: csrfSecret,
  });

  assert.deepEqual(config, {
    csrfTokenHashSecret: csrfSecret,
  });
});

test("runtime secret config accepts strong synthetic auth state hash secret when auth is required", () => {
  const config = readPlatformRuntimeSecretConfig(
    {
      CSRF_TOKEN_HASH_SECRET: csrfSecret,
      AUTH_STATE_HASH_SECRET: authStateHashSecret,
    },
    { requireAuthStateHashSecret: true },
  );

  assert.deepEqual(config, {
    csrfTokenHashSecret: csrfSecret,
    authStateHashSecret,
  });
});

test("runtime secret config accepts strong synthetic app launch hash secret when launch issuer is required", () => {
  const config = readPlatformRuntimeSecretConfig(
    {
      CSRF_TOKEN_HASH_SECRET: csrfSecret,
      APP_LAUNCH_TOKEN_HASH_SECRET: appLaunchTokenHashSecret,
    },
    { requireAppLaunchTokenHashSecret: true },
  );

  assert.deepEqual(config, {
    csrfTokenHashSecret: csrfSecret,
    appLaunchTokenHashSecret,
  });
});

test("runtime secret config rejects missing blank and weak CSRF hash secrets safely", () => {
  for (const secret of [undefined, "", "   "]) {
    assert.throws(
      () => readPlatformRuntimeSecretConfig({ CSRF_TOKEN_HASH_SECRET: secret }),
      assertPrivacySafeSecretError("missing_csrf_token_hash_secret"),
    );
  }

  assert.throws(
    () => readPlatformRuntimeSecretConfig({ CSRF_TOKEN_HASH_SECRET: "short-secret" }),
    assertPrivacySafeSecretError("invalid_csrf_token_hash_secret"),
  );
});

test("runtime secret config rejects missing blank and weak auth state hash secrets safely", () => {
  for (const secret of [undefined, "", "   "]) {
    assert.throws(
      () => readPlatformRuntimeSecretConfig(
        {
          CSRF_TOKEN_HASH_SECRET: csrfSecret,
          AUTH_STATE_HASH_SECRET: secret,
        },
        { requireAuthStateHashSecret: true },
      ),
      assertPrivacySafeSecretError("missing_auth_state_hash_secret"),
    );
  }

  assert.throws(
    () => readPlatformRuntimeSecretConfig(
      {
        CSRF_TOKEN_HASH_SECRET: csrfSecret,
        AUTH_STATE_HASH_SECRET: "short-secret",
      },
      { requireAuthStateHashSecret: true },
    ),
    assertPrivacySafeSecretError("invalid_auth_state_hash_secret"),
  );
});

test("runtime secret config rejects missing blank and weak app launch hash secrets safely", () => {
  for (const secret of [undefined, "", "   "]) {
    assert.throws(
      () => readPlatformRuntimeSecretConfig(
        {
          CSRF_TOKEN_HASH_SECRET: csrfSecret,
          APP_LAUNCH_TOKEN_HASH_SECRET: secret,
        },
        { requireAppLaunchTokenHashSecret: true },
      ),
      assertPrivacySafeSecretError("missing_app_launch_token_hash_secret"),
    );
  }

  assert.throws(
    () => readPlatformRuntimeSecretConfig(
      {
        CSRF_TOKEN_HASH_SECRET: csrfSecret,
        APP_LAUNCH_TOKEN_HASH_SECRET: "short-secret",
      },
      { requireAppLaunchTokenHashSecret: true },
    ),
    assertPrivacySafeSecretError("invalid_app_launch_token_hash_secret"),
  );
});

test("runtime composition creates Node adapter dependencies without side effects", () => {
  const fixture = createRuntimeFixture();

  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: { csrfTokenHashSecret: csrfSecret },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    csrfTokenTtlSeconds: 600,
    csrfTokenByteLength: 32,
  });

  assert.ok(dependencies.repositories.users);
  assert.ok(dependencies.repositories.sessions);
  assert.ok(dependencies.csrfTokenIssuer);
  assert.ok(dependencies.csrfTokenValidator);
  assert.deepEqual(dependencies.cookie, { secure: true });
  assert.deepEqual(dependencies.originConfig, fixture.runtimeConfig.originConfig);
  assert.equal(dependencies.csrfTokenTtlSeconds, 600);
  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.migrate, 0);
  assert.equal(fixture.calls.connect, 0);
});

test("runtime composition wires app launch token issuer dependencies when enabled", async () => {
  const fixture = createRuntimeFixture({ withAppAccessRecords: true });

  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: {
      csrfTokenHashSecret: csrfSecret,
      appLaunchTokenHashSecret,
    },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    appLaunch: {
      tokenIdFactory: {
        createId() {
          return `app_launch_token_${fixture.records.appLaunchTokens.length + 1}`;
        },
      },
      ttlSeconds: 300,
    },
  });

  assert.ok(dependencies.appLaunchIntent);
  assert.equal(fixture.calls.connect, 0);
  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.migrate, 0);

  const issued = await issueCsrfTokenForSession(dependencies.csrfTokenIssuer, {
    sessionId,
    now,
    ttlSeconds: 900,
    purpose: "browser_session",
  });
  const response = await handleNodePlatformHttpRequest(dependencies, {
    method: "POST",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images&appKey=kqag",
    headers: {
      origin: allowedOrigin,
      cookie: `swooshz_session=${sessionId}`,
      "x-csrf-token": issued.csrfToken,
    },
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 201);
  assert.equal(body.outcome, "launch_intent_created");
  assert.equal(body.appKey, "kqag");
  assert.equal(body.workspaceId, "workspace_koncept_images");
  assert.equal(body.launchUrl, null);
  assert.match(body.launchToken, /^[A-Za-z0-9_-]+$/);
  assert.equal(body.launchTokenExpiresAt, "2026-06-27T00:05:00.000Z");
  assert.equal(fixture.records.appLaunchTokens.length, 1);
  assert.match(
    fixture.records.appLaunchTokens[0].tokenHash,
    /^app-launch:v1:hmac-sha256:/,
  );
  assert.equal("launchToken" in fixture.records.appLaunchTokens[0], false);
  assert.doesNotMatch(
    JSON.stringify(fixture.records.appLaunchTokens),
    new RegExp(body.launchToken),
  );
  assertResponseIsPrivacySafe(response);
});

test("runtime composition requires app launch hash secret when launch dependencies are supplied", () => {
  assert.throws(
    () => createPlatformRuntimeDependencies({
      db: createRuntimeFixture().db,
      runtimeConfig: createRuntimeFixture().runtimeConfig,
      secrets: { csrfTokenHashSecret: csrfSecret },
      now: () => now,
      appLaunch: {
        tokenIdFactory: {
          createId() {
            return "app_launch_token_1";
          },
        },
      },
    }),
    assertPrivacySafeSecretError("missing_app_launch_token_hash_secret"),
  );
});

test("composed CSRF issuer stores only token hashes through Drizzle repository", async () => {
  const fixture = createRuntimeFixture();
  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: { csrfTokenHashSecret: csrfSecret },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    csrfTokenTtlSeconds: 600,
  });

  const issued = await issueCsrfTokenForSession(dependencies.csrfTokenIssuer, {
    sessionId,
    now,
    ttlSeconds: 600,
    purpose: "browser_session",
  });

  const tokenHash = fixture.records.csrfTokens[0].tokenHash;

  assert.equal(issued.expiresAt, "2026-06-27T00:10:00.000Z");
  assert.equal(typeof issued.csrfToken, "string");
  assert.match(issued.csrfToken, /^[A-Za-z0-9_-]+$/);
  assert.equal(fixture.records.csrfTokens.length, 1);
  assert.equal(fixture.records.csrfTokens[0].id, "csrf_record_1");
  assert.equal(fixture.records.csrfTokens[0].sessionId, sessionId);
  assert.equal(fixture.records.csrfTokens[0].tokenHash, tokenHash);
  assert.match(tokenHash, /^csrf:v1:hmac-sha256:[A-Za-z0-9_-]+$/);
  assert.equal("csrfToken" in fixture.records.csrfTokens[0], false);
  assert.equal("rawToken" in fixture.records.csrfTokens[0], false);
  assert.doesNotMatch(JSON.stringify(fixture.records.csrfTokens), new RegExp(issued.csrfToken));
});

test("composed CSRF validator accepts a token issued by composed dependencies", async () => {
  const fixture = createRuntimeFixture();
  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: { csrfTokenHashSecret: csrfSecret },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return `csrf_record_${fixture.records.csrfTokens.length + 1}`;
      },
    },
    csrfTokenTtlSeconds: 900,
  });

  const issued = await issueCsrfTokenForSession(dependencies.csrfTokenIssuer, {
    sessionId,
    now,
    ttlSeconds: 900,
    purpose: "browser_session",
  });

  const result = await dependencies.csrfTokenValidator.validate({
    csrfToken: issued.csrfToken,
    sessionId,
    now,
  });

  assert.deepEqual(result, { valid: true });
  assert.doesNotMatch(JSON.stringify(result), rawTokenPattern);
});

test("runtime composition wires auth start without provider calls during creation", async () => {
  const fixture = createRuntimeFixture();
  const oidcAdapter = createNoNetworkOidcAdapter(fixture);

  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: {
      csrfTokenHashSecret: csrfSecret,
      authStateHashSecret,
    },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    auth: {
      authConfig,
      oidcAdapter,
      stateTtlSeconds: 600,
      sessionDurationMs: 60 * 60 * 1000,
      sessionIdFactory: () => "session_auth_runtime_1",
      userIdFactory: () => "user_auth_runtime_1",
      providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
    },
  });

  assert.ok(dependencies.authStart);
  assert.ok(dependencies.authCallback);
  assert.equal(fixture.calls.authBuildAuthorizationUrl, 0);
  assert.equal(fixture.calls.authExchangeCodeForTokens, 0);
  assert.equal(fixture.calls.authVerifyTokens, 0);
  assert.equal(fixture.calls.connect, 0);
  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.migrate, 0);

  const response = await handleNodePlatformHttpRequest(dependencies, {
    method: "GET",
    url: "/api/platform/auth/start",
    headers: {},
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "https://auth.example.invalid/authorize");
  assert.deepEqual(body, { outcome: "redirecting" });
  assert.equal(fixture.calls.authBuildAuthorizationUrl, 1);
  assert.equal(fixture.records.authStates.length, 1);
  assert.match(fixture.records.authStates[0].stateHash, /^auth-state:v1:hmac-sha256:/);
  assert.match(fixture.records.authStates[0].nonceHash, /^auth-state:v1:hmac-sha256:/);
  assert.equal(fixture.records.authStates[0].providerKey, "example-oidc");
  assert.equal(fixture.records.authStates[0].redirectUri, authConfig.redirectUri);
  assert.equal(fixture.records.authStates[0].createdAt.toISOString(), now);
  assert.equal(
    fixture.records.authStates[0].expiresAt.toISOString(),
    "2026-06-27T00:10:00.000Z",
  );
  assert.equal("state" in fixture.records.authStates[0], false);
  assert.equal("nonce" in fixture.records.authStates[0], false);
  assert.doesNotMatch(
    JSON.stringify(fixture.records.authStates),
    new RegExp(fixture.calls.lastAuthStartInput.state),
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.records.authStates),
    new RegExp(fixture.calls.lastAuthStartInput.nonce),
  );
  assertResponseIsPrivacySafe(response);
});

test("runtime composition wires auth callback through injected provider adapter and session cookie path", async () => {
  const fixture = createRuntimeFixture();
  fixture.records.users = [];
  fixture.records.sessions = [];
  const oidcAdapter = createNoNetworkOidcAdapter(fixture);
  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: {
      csrfTokenHashSecret: csrfSecret,
      authStateHashSecret,
    },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    auth: {
      authConfig,
      oidcAdapter,
      stateTtlSeconds: 600,
      sessionDurationMs: 60 * 60 * 1000,
      sessionIdFactory: () => "session_auth_runtime_1",
      userIdFactory: () => "user_auth_runtime_1",
      providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
    },
  });

  await handleNodePlatformHttpRequest(dependencies, {
    method: "GET",
    url: "/api/platform/auth/start",
    headers: {},
  });

  const response = await handleNodePlatformHttpRequest(dependencies, {
    method: "GET",
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${fixture.calls.lastAuthStartInput.state}`,
    headers: {},
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "/app");
  assert.match(response.headers["set-cookie"], /^swooshz_session=session_auth_runtime_1;/);
  assert.deepEqual(body, { outcome: "authenticated" });
  assert.equal(fixture.calls.authExchangeCodeForTokens, 1);
  assert.equal(fixture.calls.authVerifyTokens, 1);
  assert.equal(fixture.records.users.length, 1);
  assert.equal(fixture.records.providerIdentities.length, 1);
  assert.equal(fixture.records.sessions.length, 1);
  assert.equal(fixture.records.authStates[0].consumedAt.toISOString(), now);
  assert.doesNotMatch(JSON.stringify(body), rawAuthPattern);
  assert.doesNotMatch(JSON.stringify(response.headers), /synthetic-auth-code/);
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), new RegExp(fixture.calls.lastAuthStartInput.state));
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), new RegExp(fixture.calls.lastAuthStartInput.nonce));
  assertResponseIsPrivacySafe(response);
});

test("runtime composition can opt into generic OIDC without provider calls during creation", () => {
  const fixture = createRuntimeFixture();
  const httpCalls = [];

  const dependencies = createPlatformRuntimeDependencies({
    db: fixture.db,
    runtimeConfig: fixture.runtimeConfig,
    secrets: {
      csrfTokenHashSecret: csrfSecret,
      authStateHashSecret,
    },
    now: () => now,
    csrfTokenIdFactory: {
      createId() {
        return "csrf_record_1";
      },
    },
    auth: {
      authConfig,
      providerMode: "generic_oidc",
      genericOidcHttpClient: async (request) => {
        httpCalls.push(request);
        throw new Error("Synthetic HTTP client should not be called during composition.");
      },
      sessionDurationMs: 60 * 60 * 1000,
      sessionIdFactory: () => "session_auth_runtime_1",
      userIdFactory: () => "user_auth_runtime_1",
      providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
    },
  });

  assert.ok(dependencies.authStart);
  assert.ok(dependencies.authCallback);
  assert.equal(httpCalls.length, 0);
  assert.equal(fixture.calls.connect, 0);
  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.migrate, 0);
});

test("runtime generic OIDC mode validates required issuer and JWKS config safely", () => {
  const fixture = createRuntimeFixture();

  for (const invalidAuthConfig of [
    { ...authConfig, issuerUrl: null },
    { ...authConfig, jwksUrl: null },
  ]) {
    assert.throws(
      () => createPlatformRuntimeDependencies({
        db: fixture.db,
        runtimeConfig: fixture.runtimeConfig,
        secrets: {
          csrfTokenHashSecret: csrfSecret,
          authStateHashSecret,
        },
        now: () => now,
        csrfTokenIdFactory: {
          createId() {
            return "csrf_record_1";
          },
        },
        auth: {
          authConfig: invalidAuthConfig,
          providerMode: "generic_oidc",
          genericOidcHttpClient: async () => {
            throw new Error("Synthetic HTTP client should not be called.");
          },
          sessionDurationMs: 60 * 60 * 1000,
          sessionIdFactory: () => "session_auth_runtime_1",
          userIdFactory: () => "user_auth_runtime_1",
          providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
        },
      }),
      assertPrivacySafeRuntimeAuthConfigError,
    );
  }

  assert.throws(
    () => createPlatformRuntimeDependencies({
      db: fixture.db,
      runtimeConfig: fixture.runtimeConfig,
      secrets: {
        csrfTokenHashSecret: csrfSecret,
        authStateHashSecret,
      },
      now: () => now,
      csrfTokenIdFactory: {
        createId() {
          return "csrf_record_1";
        },
      },
      auth: {
        authConfig,
        providerMode: "generic_oidc",
        sessionDurationMs: 60 * 60 * 1000,
        sessionIdFactory: () => "session_auth_runtime_1",
        userIdFactory: () => "user_auth_runtime_1",
        providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
      },
    }),
    assertPrivacySafeRuntimeAuthConfigError,
  );
});

test("runtime composition errors do not expose private values", () => {
  assert.throws(
    () => createPlatformRuntimeDependencies({
      db: createRuntimeFixture().db,
      runtimeConfig: createRuntimeFixture().runtimeConfig,
      secrets: { csrfTokenHashSecret: "short-secret" },
      now: () => now,
    }),
    assertPrivacySafeSecretError("invalid_csrf_token_hash_secret"),
  );
});

test("runtime composition requires auth state hash secret when auth dependencies are supplied", () => {
  assert.throws(
    () => createPlatformRuntimeDependencies({
      db: createRuntimeFixture().db,
      runtimeConfig: createRuntimeFixture().runtimeConfig,
      secrets: { csrfTokenHashSecret: csrfSecret },
      now: () => now,
      auth: {
        authConfig,
        oidcAdapter: createNoNetworkOidcAdapter(createRuntimeFixture()),
        stateTtlSeconds: 600,
        sessionDurationMs: 60 * 60 * 1000,
        sessionIdFactory: () => "session_auth_runtime_1",
        userIdFactory: () => "user_auth_runtime_1",
        providerIdentityIdFactory: () => "provider_identity_auth_runtime_1",
      },
    }),
    assertPrivacySafeSecretError("missing_auth_state_hash_secret"),
  );
});

test("runtime composition modules do not import frontend KQAG provider SDK frameworks live DB clients or migrations", async () => {
  const files = [
    "src/runtime/platform-runtime-dependencies.ts",
    "src/runtime/runtime-secrets.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:pg|node-postgres|migrations?)/i);
    assert.doesNotMatch(contents, /DATABASE_URL|AUTH_CLIENT_SECRET|SESSION_SECRET/);
  }
});

test("crypto imports remain only in dedicated crypto adapter modules", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set([
    "src/auth/auth-state-crypto.ts",
    "src/auth/generic-oidc-jwks-verifier.ts",
    "src/http/csrf-token-crypto.ts",
    "src/platform/app-launch-token-crypto.ts",
  ]);

  for (const filePath of sourceFiles) {
    const normalized = filePath.replaceAll("\\", "/");
    const contents = await readFile(filePath, "utf8");

    if (allowed.has(normalized)) {
      continue;
    }

    assert.doesNotMatch(contents, /node:crypto|from\s+["']crypto["']/);
  }
});

function createRuntimeFixture(options = {}) {
  const calls = {
    connect: 0,
    listen: 0,
    migrate: 0,
    authBuildAuthorizationUrl: 0,
    authExchangeCodeForTokens: 0,
    authVerifyTokens: 0,
    lastAuthStartInput: null,
  };
  const records = {
    users: [
      {
        id: userId,
        email: "owner@example.com",
        displayName: "Owner Example",
        status: "active",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      },
    ],
    sessions: [
      {
        id: sessionId,
        userId,
        createdAt: now,
        expiresAt: future,
        lastSeenAt: now,
        revokedAt: null,
      },
    ],
    csrfTokens: [],
    authStates: [],
    providerIdentities: [],
    workspaces: options.withAppAccessRecords
      ? [
          {
            id: "workspace_koncept_images",
            slug: "koncept-images-pte-ltd",
            displayName: "Koncept Images Pte Ltd",
            status: "active",
            createdAt: now,
            updatedAt: now,
          },
        ]
      : [],
    memberships: options.withAppAccessRecords
      ? [
          {
            id: "membership_owner_example",
            workspaceId: "workspace_koncept_images",
            userId,
            role: "owner",
            status: "active",
            createdAt: now,
            updatedAt: now,
          },
        ]
      : [],
    apps: options.withAppAccessRecords
      ? [
          {
            id: "app_kqag",
            key: "kqag",
            name: "KQAG / SAQG",
            status: "private_preview",
            launchUrl: null,
            createdAt: now,
            updatedAt: now,
          },
        ]
      : [],
    appEntitlements: options.withAppAccessRecords
      ? [
          {
            id: "entitlement_koncept_kqag",
            workspaceId: "workspace_koncept_images",
            appId: "app_kqag",
            status: "enabled",
            grantedByUserId: userId,
            createdAt: now,
            updatedAt: now,
          },
        ]
      : [],
    appLaunchTokens: [],
  };

  return {
    calls,
    records,
    runtimeConfig: {
      host: "127.0.0.1",
      port: 3000,
      nodeEnv: "production",
      publicBaseUrl: allowedOrigin,
      originConfig: {
        allowedOrigins: [allowedOrigin],
        publicBaseUrl: allowedOrigin,
      },
      cookie: { secure: true },
    },
    db: createFakeDrizzleDb(records),
  };
}

function createFakeDrizzleDb(records) {
  return {
    select() {
      return {
        from(table) {
          return new FakeSelectResult(selectRows(table, records));
        },
      };
    },
    insert(table) {
      return {
        values(values) {
          const row = mapInsertValues(table, values);
          insertRow(table, records, row);

          return {
            returning() {
              return Promise.resolve([row]);
            },
          };
        },
      };
    },
    update(table) {
      return {
        set(values) {
          return {
            where() {
              return {
                returning() {
                  if (table === schema.authStates) {
                    const row = records.authStates[0];

                    if (!row) {
                      return Promise.resolve([]);
                    }

                    Object.assign(row, values);
                    return Promise.resolve([row]);
                  }

                  throw new Error("Only auth state updates are expected in this test.");
                },
              };
            },
          };
        },
      };
    },
  };
}

function selectRows(table, records) {
  if (table === schema.users) {
    return records.users;
  }

  if (table === schema.sessions) {
    return records.sessions;
  }

  if (table === schema.csrfTokens) {
    return records.csrfTokens;
  }

  if (table === schema.authStates) {
    return records.authStates.filter((row) => !row.consumedAt && !row.revokedAt);
  }

  if (table === schema.providerIdentities) {
    return records.providerIdentities;
  }

  if (table === schema.workspaces) {
    return records.workspaces;
  }

  if (table === schema.memberships) {
    return records.memberships;
  }

  if (table === schema.apps) {
    return records.apps;
  }

  if (table === schema.appEntitlements) {
    return records.appEntitlements;
  }

  if (table === schema.appLaunchTokens) {
    return records.appLaunchTokens;
  }

  return [];
}

function mapInsertValues(table, values) {
  if (table === schema.csrfTokens) {
    return {
      id: values.id,
      sessionId: values.sessionId,
      tokenHash: values.tokenHash,
      purpose: values.purpose,
      createdAt: values.createdAt,
      expiresAt: values.expiresAt,
      consumedAt: values.consumedAt,
      revokedAt: values.revokedAt,
      replacedByTokenId: values.replacedByTokenId,
    };
  }

  return { ...values };
}

function insertRow(table, records, row) {
  if (table === schema.csrfTokens) {
    records.csrfTokens.push(row);
    return;
  }

  if (table === schema.appLaunchTokens) {
    records.appLaunchTokens.push(row);
    return;
  }

  if (table === schema.authStates) {
    records.authStates.push(row);
    return;
  }

  if (table === schema.users) {
    records.users.push(row);
    return;
  }

  if (table === schema.providerIdentities) {
    records.providerIdentities.push(row);
    return;
  }

  if (table === schema.sessions) {
    records.sessions.push(row);
    return;
  }

  throw new Error("Unexpected table write in runtime composition test.");
}

function createNoNetworkOidcAdapter(fixture) {
  return {
    async buildAuthorizationUrl(input) {
      fixture.calls.authBuildAuthorizationUrl += 1;
      fixture.calls.lastAuthStartInput = input;

      return { url: "https://auth.example.invalid/authorize" };
    },
    async exchangeCodeForTokens(input) {
      fixture.calls.authExchangeCodeForTokens += 1;
      assert.equal(input.code, "synthetic-auth-code");

      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
      };
    },
    async verifyTokens(input) {
      fixture.calls.authVerifyTokens += 1;
      assert.equal(input.tokenExchange.tokenSetRef, "adapter_internal");
      assert.match(input.expectedNonceHash, /^auth-state:v1:hmac-sha256:/);

      return {
        providerKey: "example-oidc",
        providerSubject: "provider-subject-runtime",
        verifiedEmail: "runtime-owner@example.com",
        displayName: "Runtime Owner",
        metadata: { synthetic: true },
      };
    },
  };
}

function assertResponseIsPrivacySafe(response) {
  const serialized = JSON.stringify(response);

  assert.doesNotMatch(serialized, rawAuthPattern);
  assert.doesNotMatch(serialized, rawLaunchTokenPattern);
  assert.doesNotMatch(serialized, /raw-csrf-token|raw-session-token|private\.example\.test/i);
}

class FakeSelectResult {
  constructor(rows) {
    this.rows = rows;
  }

  limit(limit) {
    return Promise.resolve(this.rows.slice(0, limit));
  }

  where() {
    return this;
  }

  then(onFulfilled, onRejected) {
    return Promise.resolve(this.rows).then(onFulfilled, onRejected);
  }
}

function assertPrivacySafeSecretError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof PlatformRuntimeSecretConfigError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Platform runtime secret config is invalid.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, /raw-csrf-secret|postgresql:\/\/private-host/);
    assert.doesNotMatch(serialized, /private\.example\.test|raw-session-token|raw-csrf-token/);
    return true;
  };
}

function assertPrivacySafeRuntimeAuthConfigError(error) {
  assert.equal(error.name, "PlatformRuntimeAuthConfigError");
  assert.match(error.code, /^missing_generic_oidc_/);
  assert.equal(error.publicMessage, "Platform runtime auth config is invalid.");
  const serialized = JSON.stringify(error) + String(error.message ?? "");
  assert.doesNotMatch(serialized, /synthetic-client-secret|synthetic-session-secret/i);
  assert.doesNotMatch(serialized, /issuer\.example|auth\.example|https?:\/\//i);
  return true;
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
