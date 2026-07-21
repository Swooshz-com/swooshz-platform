import assert from "node:assert/strict";
import {
  createSign,
  generateKeyPairSync,
  randomUUID,
} from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { getTableName } from "drizzle-orm";

import {
  createAppLaunchIntent,
  createPlatformNodeBootstrap,
  PlatformNodeBootstrapError,
} from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const csrfSecret = "synthetic_csrf_hash_secret_32_chars_min";
const authStateHashSecret = "synthetic_auth_state_hash_secret_32_chars_min";
const appLaunchTokenHashSecret = "synthetic_app_launch_hash_secret_32_chars_min";
const databaseUrl =
  "postgres://example_user:example_pass@db.example.invalid:5432/swooshz_platform";
const privateUrl =
  "https://private.example.test/path?token=raw-session-token&db=postgresql://private-host";
const issuerUrl = "https://issuer.example.invalid/";
const jwksUrl = "https://issuer.example.invalid/.well-known/jwks.json";
const idTokenField = "id_" + "token";
const accessTokenField = "access_" + "token";

test("creating bootstrap object does not listen connect query or run migrations", () => {
  const fixture = createBootstrapFixture();

  createPlatformNodeBootstrap(fixture.input);

  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.databaseClientFactory, 0);
  assert.equal(fixture.calls.migrations, 0);
  assert.equal(fixture.calls.query, 0);
});

test("start calls listen with parsed host and port", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  const result = await bootstrap.start();

  assert.deepEqual(result, {
    host: "127.0.0.1",
    port: 4317,
  });
  assert.deepEqual(fixture.calls.listenArgs, [{ port: 4317, host: "127.0.0.1" }]);
  assert.equal(fixture.calls.databaseClientFactory, 1);
  assert.equal(fixture.calls.serverFactory, 1);
  assert.equal(fixture.lastServer.listening, true);
});

test("stop closes server and DB pool created by bootstrap", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  await bootstrap.stop();

  assert.equal(fixture.calls.closeServer, 1);
  assert.equal(fixture.calls.closeDatabase, 1);
  assert.equal(fixture.lastServer.listening, false);
});

test("stop before start is deterministic and safe", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.stop();

  assert.equal(fixture.calls.closeServer, 0);
  assert.equal(fixture.calls.closeDatabase, 0);
});

test("start is deterministic when called more than once", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("already_started"),
  );
  await bootstrap.stop();
  await bootstrap.start();

  assert.equal(fixture.calls.listen, 2);
  assert.equal(fixture.calls.closeServer, 1);
  assert.equal(fixture.calls.closeDatabase, 1);
});

test("start failure is privacy-safe and closes an opened DB client", async () => {
  const fixture = createBootstrapFixture({
    failListen: true,
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("server_start_failed"),
  );
  assert.equal(fixture.calls.closeDatabase, 1);
});

test("Node-style listen error event is privacy-safe closes DB and leaves bootstrap stopped", async () => {
  const fixture = createBootstrapFixture({
    listenOutcomes: ["error-event"],
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("server_start_failed"),
  );

  assert.equal(fixture.calls.closeDatabase, 1);
  assert.equal(bootstrap.getServer(), null);
  assert.equal(fixture.lastServer.listening, false);
  assert.equal(fixture.lastServer.listenerCount("error"), 0);
});

test("start can retry deterministically after a Node-style listen error event", async () => {
  const fixture = createBootstrapFixture({
    listenOutcomes: ["error-event", "success"],
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("server_start_failed"),
  );
  const retryResult = await bootstrap.start();

  assert.deepEqual(retryResult, {
    host: "127.0.0.1",
    port: 4317,
  });
  assert.equal(fixture.calls.closeDatabase, 1);
  assert.equal(fixture.calls.listen, 2);
  assert.equal(fixture.lastServer.listening, true);
  assert.equal(fixture.lastServer.listenerCount("error"), 0);
});

test("successful listen cleans up the temporary error listener", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();

  assert.equal(fixture.lastServer.listenerCount("error"), 0);
});

test("invalid runtime config is privacy-safe", async () => {
  const fixture = createBootstrapFixture({
    env: {
      PLATFORM_HTTP_PORT: "not-a-port-raw-session-token",
      DATABASE_URL: databaseUrl,
      CSRF_TOKEN_HASH_SECRET: csrfSecret,
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
});

test("invalid secret config is privacy-safe", async () => {
  const fixture = createBootstrapFixture({
    env: {
      PLATFORM_HTTP_PORT: "4317",
      DATABASE_URL: databaseUrl,
      CSRF_TOKEN_HASH_SECRET: "short-secret",
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
});

test("database client creation failure is privacy-safe", async () => {
  const fixture = createBootstrapFixture({
    failDatabaseClient: true,
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("database_client_failed"),
  );
});

test("bootstrap fails closed before listen when DATABASE_URL is malformed", async () => {
  const fixture = createBootstrapFixture({
    env: {
      DATABASE_URL: [
        "https",
        "://private-user:private-pass@private-host.invalid/swooshz_platform",
      ].join(""),
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("database_client_failed"),
  );
  assert.equal(fixture.calls.databaseClientFactory, 0);
  assert.equal(fixture.calls.listen, 0);
  assert.equal(fixture.calls.serverFactory, 0);
});

test("production bootstrap rejects non-HTTPS provider URLs before DB or listen", async () => {
  const fixture = createBootstrapFixture({
    withGenericAuth: true,
    env: {
      AUTH_TOKEN_URL: "http://auth.example.invalid/oauth2/token",
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
  assert.equal(fixture.calls.databaseClientFactory, 0);
  assert.equal(fixture.calls.serverFactory, 0);
  assert.equal(fixture.calls.listen, 0);
});

test("production bootstrap rejects unsafe hosted auth callback shape before DB or listen", async () => {
  const fixture = createBootstrapFixture({
    withGenericAuth: true,
    env: {
      AUTH_REDIRECT_URI: "https://swooshz.com/api/platform/auth/callback?code=raw-secret",
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
  assert.equal(fixture.calls.databaseClientFactory, 0);
  assert.equal(fixture.calls.serverFactory, 0);
  assert.equal(fixture.calls.listen, 0);
});

test("production bootstrap requires the exact canonical auth callback before DB or listen", async () => {
  const fixture = createBootstrapFixture({
    withGenericAuth: true,
    env: {
      AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
  assert.equal(fixture.calls.databaseClientFactory, 0);
  assert.equal(fixture.calls.serverFactory, 0);
  assert.equal(fixture.calls.listen, 0);
});

test("bootstrap composes runtime dependencies with secure cookie origin and CSRF config", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();

  const dependencies = fixture.calls.serverDependencies[0];
  assert.deepEqual(dependencies.cookie, { secure: true });
  assert.deepEqual(dependencies.originConfig, {
    allowedOrigins: ["https://swooshz.com"],
    publicBaseUrl: "https://swooshz.com",
  });
  assert.equal(dependencies.csrfTokenTtlSeconds, 321);
  assert.ok(dependencies.csrfTokenIssuer);
  assert.ok(dependencies.csrfTokenValidator);
  assert.ok(dependencies.appLaunchIntent);
});

test("bootstrap start wires app launch dependencies without issuing tokens", async () => {
  const fixture = createBootstrapFixture({ withAppAccessRecords: true });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  createPlatformNodeBootstrap(fixture.input);
  assert.equal(fixture.records.appLaunchTokens.length, 0);

  await bootstrap.start();

  assert.ok(fixture.calls.serverDependencies[0].appLaunchIntent);
  assert.ok(fixture.calls.serverDependencies[0].appLaunchTokenConsume);
  assert.equal(fixture.records.appLaunchTokens.length, 0);
  assert.equal(fixture.calls.migrations, 0);
});

test("bootstrap-created server disables direct browser launch-token responses", async () => {
  const fixture = createBootstrapFixture({ withAppAccessRecords: true });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  const { issueCsrfTokenForSession } = await import("../dist/index.js");
  const dependencies = fixture.calls.serverDependencies[0];
  const issued = await issueCsrfTokenForSession(dependencies.csrfTokenIssuer, {
    sessionId: "session_owner_example",
    now,
    ttlSeconds: 900,
    purpose: "browser_session",
  });
  const response = await fixture.lastServer.handle({
    method: "POST",
    url: "/api/platform/apps/launch?workspaceId=workspace_koncept_images&appKey=sqag",
    headers: {
      origin: "https://swooshz.com",
      cookie: "swooshz_session=session_owner_example",
      "x-csrf-token": issued.csrfToken,
    },
  });
  const body = JSON.parse(response.body);

  assert.equal(response.statusCode, 410);
  assert.deepEqual(body, {
    outcome: "error",
    message: "Direct launch token responses are disabled. Use the server-side launch handoff.",
  });
  assert.equal(fixture.records.appLaunchTokens.length, 0);
  assertResponseIsPrivacySafe(response);
});

test("bootstrap-created server can serve POST /api/platform/apps/launch/consume without cookie or CSRF", async () => {
  const fixture = createBootstrapFixture({ withAppAccessRecords: true });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  const dependencies = fixture.calls.serverDependencies[0];
  const launch = await createAppLaunchIntent(dependencies.appLaunchIntent, {
    sessionId: "session_owner_example",
    selectedWorkspaceId: "workspace_koncept_images",
    appKey: "sqag",
    now,
  });
  assert.equal(launch.outcome, "created");

  const consumeResponse = await fixture.lastServer.handle({
    method: "POST",
    url: "/api/platform/apps/launch/consume?appKey=sqag",
    headers: {
      "x-app-launch-token": launch.launchToken,
    },
  });
  const consumeBody = JSON.parse(consumeResponse.body);

  assert.equal(consumeResponse.statusCode, 200);
  assert.equal(consumeBody.outcome, "consumed");
  assert.equal(consumeBody.user.userId, "user_owner_example");
  assert.equal(consumeBody.workspace.workspaceId, "workspace_koncept_images");
  assert.equal(consumeBody.app.appKey, "sqag");
  assert.equal(consumeBody.membershipRole, "owner");
  assert.equal(fixture.records.appLaunchTokens[0].consumedAt.toISOString(), now);
  assert.doesNotMatch(JSON.stringify(consumeResponse), new RegExp(launch.launchToken));
  assertResponseIsPrivacySafe(consumeResponse);
});

test("bootstrap start can include auth dependencies without provider calls during creation or start", async () => {
  const fixture = createBootstrapFixture({ withAuth: true });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  assert.equal(fixture.calls.authBuildAuthorizationUrl, 0);
  await bootstrap.start();

  const dependencies = fixture.calls.serverDependencies[0];
  assert.ok(dependencies.authStart);
  assert.ok(dependencies.authCallback);
  assert.equal(fixture.calls.authBuildAuthorizationUrl, 0);
  assert.equal(fixture.calls.authExchangeCodeForTokens, 0);
  assert.equal(fixture.calls.authVerifyTokens, 0);
  assert.equal(fixture.calls.query, 0);
  assert.equal(fixture.calls.migrations, 0);
});

test("bootstrap-created server can serve GET /healthz with injected fake dependencies", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  const response = await fixture.lastServer.handle({
    method: "GET",
    url: "/healthz",
    headers: {},
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), {
    outcome: "ok",
    service: "swooshz-platform",
  });
});

test("bootstrap-created server can serve GET /api/platform/auth/start with injected fake auth dependencies", async () => {
  const fixture = createBootstrapFixture({ withAuth: true });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  const response = await fixture.lastServer.handle({
    method: "GET",
    url: "/api/platform/auth/start",
    headers: {},
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "https://auth.example.invalid/authorize");
  assert.equal(fixture.calls.authBuildAuthorizationUrl, 1);
  assert.equal(fixture.records.authStates.length, 1);
  assert.match(fixture.records.authStates[0].stateHash, /^auth-state:v1:hmac-sha256:/);
  assert.match(fixture.records.authStates[0].nonceHash, /^auth-state:v1:hmac-sha256:/);
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

test("bootstrap-created auth callback succeeds only through injected fake provider dependencies", async () => {
  const fixture = createBootstrapFixture({ withAuth: true });
  seedExistingAuthMember(fixture.records, {
    userId: "user_auth_bootstrap_1",
    email: "bootstrap-owner@example.com",
    providerSubject: "provider-subject-bootstrap",
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();
  const startResponse = await fixture.lastServer.handle({
    method: "GET",
    url: "/api/platform/auth/start",
    headers: {},
  });
  assert.equal(
    fixture.calls.serverDependencies[0].authCallback.stateReferenceFactory(
      fixture.calls.lastAuthStartInput.state,
    ),
    fixture.records.authStates[0].stateHash,
  );
  const bindingCookie = startResponse.headers["set-cookie"].split(";", 1)[0];
  const callbackUrl = `/api/platform/auth/callback?code=synthetic-auth-code&state=${fixture.calls.lastAuthStartInput.state}`;
  assert.equal(
    new URL(callbackUrl, "https://platform.example.invalid").searchParams.get("state"),
    fixture.calls.lastAuthStartInput.state,
  );
  const response = await fixture.lastServer.handle({
    method: "GET",
    url: callbackUrl,
    headers: { cookie: bindingCookie },
  });

  assert.equal(response.statusCode, 302, JSON.stringify({
    body: response.body,
    calls: {
      authExchangeCodeForTokens: fixture.calls.authExchangeCodeForTokens,
      authVerifyTokens: fixture.calls.authVerifyTokens,
    },
    recordCounts: {
      authStates: fixture.records.authStates.length,
      users: fixture.records.users.length,
      providerIdentities: fixture.records.providerIdentities.length,
      sessions: fixture.records.sessions.length,
    },
    authStateLifecycle: fixture.records.authStates.map((record) => ({
      consumedAt: record.consumedAt?.toISOString?.() ?? record.consumedAt ?? null,
      expiresAt: record.expiresAt?.toISOString?.() ?? record.expiresAt ?? null,
      providerKey: record.providerKey,
    })),
    dbOperations: fixture.calls.dbOperations,
  }));
  assert.equal(response.headers.location, "/app");
  assert.match(response.headers["set-cookie"][0], /^swooshz_session=session_auth_bootstrap_1;/);
  assert.equal(fixture.calls.authExchangeCodeForTokens, 1);
  assert.equal(fixture.calls.authVerifyTokens, 1);
  assert.equal(fixture.records.sessions.length, 1);
  assert.equal(fixture.records.authStates[0].consumedAt.toISOString(), now);
  assertResponseIsPrivacySafe(response);
});

test("bootstrap auth config failures are privacy-safe", async () => {
  const fixture = createBootstrapFixture({
    withAuth: true,
    env: {
      AUTH_STATE_HASH_SECRET: "short-secret",
    },
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await assert.rejects(
    () => bootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
  assert.equal(fixture.calls.authBuildAuthorizationUrl, 0);
  assert.equal(fixture.calls.databaseClientFactory, 0);
});

test("bootstrap generic OIDC mode requires explicit opt-in and config", async () => {
  for (const env of [
    { PLATFORM_AUTH_PROVIDER_MODE: "unknown-mode" },
    {
      PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc",
      AUTH_ISSUER_URL: undefined,
    },
    {
      PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc",
      AUTH_JWKS_URL: undefined,
    },
    {
      PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc",
      AUTH_STATE_HASH_SECRET: undefined,
    },
  ]) {
    const fixture = createBootstrapFixture({
      withGenericAuth: true,
      env,
    });
    const bootstrap = createPlatformNodeBootstrap(fixture.input);

    await assert.rejects(
      () => bootstrap.start(),
      assertPrivacySafeBootstrapError("invalid_config"),
    );
    assert.equal(fixture.calls.databaseClientFactory, 0);
    assert.equal(fixture.calls.genericOidcHttp, 0);
  }

  const missingHttpFixture = createBootstrapFixture({ withGenericAuth: true });
  delete missingHttpFixture.input.genericOidcHttpClient;
  const missingHttpBootstrap = createPlatformNodeBootstrap(missingHttpFixture.input);

  await assert.rejects(
    () => missingHttpBootstrap.start(),
    assertPrivacySafeBootstrapError("invalid_config"),
  );
  assert.equal(missingHttpFixture.calls.databaseClientFactory, 0);
  assert.equal(missingHttpFixture.calls.genericOidcHttp, 0);
});

test("bootstrap generic OIDC mode calls provider network only during callback", async () => {
  const fixture = createBootstrapFixture({ withGenericAuth: true });
  seedExistingAuthMember(fixture.records, {
    userId: "user_auth_bootstrap_1",
    email: "generic@example.com",
    providerSubject: "provider-subject-generic-bootstrap",
  });
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  createPlatformNodeBootstrap(fixture.input);
  assert.equal(fixture.calls.genericOidcHttp, 0);

  await bootstrap.start();
  assert.equal(fixture.calls.genericOidcHttp, 0);

  const startResponse = await fixture.lastServer.handle({
    method: "GET",
    url: "/api/platform/auth/start",
    headers: {},
  });
  const authorizationUrl = new URL(startResponse.headers.location);
  const state = authorizationUrl.searchParams.get("state");
  const nonce = authorizationUrl.searchParams.get("nonce");
  const bindingCookie = startResponse.headers["set-cookie"].split(";", 1)[0];

  assert.equal(startResponse.statusCode, 302);
  assert.equal(fixture.calls.genericOidcHttp, 0);
  assert.equal(fixture.records.authStates.length, 1);
  assert.match(fixture.records.authStates[0].stateHash, /^auth-state:v1:hmac-sha256:/);
  assert.match(fixture.records.authStates[0].nonceHash, /^auth-state:v1:hmac-sha256:/);
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), new RegExp(state));
  assert.doesNotMatch(JSON.stringify(fixture.records.authStates), new RegExp(nonce));

  fixture.syntheticIdToken = signJwt(fixture.keys, {
    iss: issuerUrl,
    aud: "synthetic-client-id",
    sub: "provider-subject-generic-bootstrap",
    exp: Math.floor(Date.parse(now) / 1000) + 300,
    iat: Math.floor(Date.parse(now) / 1000),
    nbf: Math.floor(Date.parse(now) / 1000) - 10,
    email: "GENERIC@Example.COM",
    email_verified: true,
    name: "Generic Bootstrap",
    nonce,
  });

  const response = await fixture.lastServer.handle({
    method: "GET",
    url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${state}`,
    headers: { cookie: bindingCookie },
  });

  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "/app");
  assert.match(response.headers["set-cookie"][0], /^swooshz_session=session_auth_bootstrap_1;/);
  assert.equal(fixture.calls.genericOidcHttp, 2);
  assert.deepEqual(
    fixture.calls.genericOidcHttpUrls,
    ["https://auth.example.invalid/oauth2/token", jwksUrl],
  );
  assert.equal(fixture.records.users.length, 1);
  assert.equal(fixture.records.providerIdentities.length, 1);
  assert.equal(fixture.records.sessions.length, 1);
  assert.equal(fixture.records.providerIdentities[0].providerSubject, "provider-subject-generic-bootstrap");
  assert.equal(fixture.records.users[0].email, "generic@example.com");
  assertResponseIsPrivacySafe(response);
});

test("bootstrap generic OIDC mode fails nonce mismatch and bad signature safely", async () => {
  for (const failure of ["nonce", "signature"]) {
    const fixture = createBootstrapFixture({ withGenericAuth: true });
    const bootstrap = createPlatformNodeBootstrap(fixture.input);
    await bootstrap.start();
    const startResponse = await fixture.lastServer.handle({
      method: "GET",
      url: "/api/platform/auth/start",
      headers: {},
    });
    const authorizationUrl = new URL(startResponse.headers.location);
    const state = authorizationUrl.searchParams.get("state");
    const nonce = authorizationUrl.searchParams.get("nonce");
    const bindingCookie = startResponse.headers["set-cookie"].split(";", 1)[0];
    const idToken = signJwt(fixture.keys, {
      iss: issuerUrl,
      aud: "synthetic-client-id",
      sub: "provider-subject-generic-bootstrap",
      exp: Math.floor(Date.parse(now) / 1000) + 300,
      iat: Math.floor(Date.parse(now) / 1000),
      nbf: Math.floor(Date.parse(now) / 1000) - 10,
      email: "GENERIC@Example.COM",
      email_verified: true,
      name: "Generic Bootstrap",
      nonce: failure === "nonce" ? "wrong-synthetic-nonce" : nonce,
    });

    fixture.syntheticIdToken =
      failure === "signature"
        ? `${idToken.split(".").slice(0, 2).join(".")}.invalid-signature`
        : idToken;

    const response = await fixture.lastServer.handle({
      method: "GET",
      url: `/api/platform/auth/callback?code=synthetic-auth-code&state=${state}`,
      headers: { cookie: bindingCookie },
    });

    assert.equal(response.statusCode, 400);
    assert.equal(fixture.records.sessions.length, 0);
    assertResponseIsPrivacySafe(response);
  }
});

test("bootstrap module does not import migrations frontend SQAG provider SDK or framework packages", async () => {
  const files = [
    "src/runtime/node-bootstrap.ts",
    "src/runtime/bootstrap-config.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /migrate|migrations|db-migrate/i);
    assert.doesNotMatch(contents, /DATABASE_URL\s*=|CSRF_TOKEN_HASH_SECRET\s*=/);
  }
});

test("node:http imports stay only in Node adapter and server runtime modules", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set([
    "src/http/node-adapter.ts",
    "src/http/node-server.ts",
  ]);

  for (const filePath of sourceFiles) {
    const normalized = filePath.replaceAll("\\", "/");
    const contents = await readFile(filePath, "utf8");

    if (allowed.has(normalized)) {
      continue;
    }

    assert.doesNotMatch(contents, /node:http/);
  }
});

function createBootstrapFixture(options = {}) {
  const calls = {
    databaseClientFactory: 0,
    serverFactory: 0,
    closeDatabase: 0,
    closeServer: 0,
    listen: 0,
    listenArgs: [],
    migrations: 0,
    query: 0,
    serverDependencies: [],
    authBuildAuthorizationUrl: 0,
    authExchangeCodeForTokens: 0,
    authVerifyTokens: 0,
    genericOidcHttp: 0,
    genericOidcHttpUrls: [],
    lastAuthStartInput: null,
    dbOperations: [],
  };
  const records = {
    users: options.withAppAccessRecords
      ? [
          {
            id: "user_owner_example",
            email: "owner@example.com",
            displayName: "Owner Example",
            status: "active",
            createdAt: now,
            updatedAt: now,
            lastLoginAt: now,
          },
        ]
      : [],
    providerIdentities: [],
    sessions: options.withAppAccessRecords
      ? [
          {
            id: "session_owner_example",
            userId: "user_owner_example",
            createdAt: now,
            expiresAt: "2026-06-27T01:00:00.000Z",
            lastSeenAt: now,
            revokedAt: null,
          },
        ]
      : [],
    csrfTokens: [],
    authStates: [],
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
            userId: "user_owner_example",
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
            id: "app_sqag",
            key: "sqag",
            name: "SQAG",
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
            id: "entitlement_koncept_sqag",
            workspaceId: "workspace_koncept_images",
            appId: "app_sqag",
            status: "enabled",
            grantedByUserId: "user_owner_example",
            createdAt: now,
            updatedAt: now,
          },
        ]
      : [],
    appLaunchTokens: [],
  };
  const db = createFakeDrizzleDb(calls, records);
  const env = {
    PLATFORM_HTTP_HOST: "127.0.0.1",
    PLATFORM_HTTP_PORT: "4317",
    PLATFORM_PUBLIC_BASE_URL: "https://swooshz.com",
    PLATFORM_ALLOWED_ORIGINS: "https://swooshz.com",
    PLATFORM_COOKIE_SECURE: "true",
    NODE_ENV: "production",
    DATABASE_URL: databaseUrl,
    CSRF_TOKEN_HASH_SECRET: csrfSecret,
    APP_LAUNCH_TOKEN_HASH_SECRET: appLaunchTokenHashSecret,
    ...(options.withAuth
      ? {
          AUTH_STATE_HASH_SECRET: authStateHashSecret,
          AUTH_PROVIDER_KEY: "Example-OIDC",
          AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
          AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
          AUTH_CLIENT_ID: "synthetic-client-id",
          AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
          AUTH_REDIRECT_URI: "https://swooshz.com/api/platform/auth/callback",
          SESSION_SECRET: "synthetic-session-secret-value-32",
        }
      : {}),
    ...(options.withGenericAuth
      ? {
          PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc",
          AUTH_STATE_HASH_SECRET: authStateHashSecret,
          AUTH_PROVIDER_KEY: "Example-OIDC",
          AUTH_ISSUER_URL: issuerUrl,
          AUTH_AUTHORIZATION_URL: "https://auth.example.invalid/oauth2/authorize",
          AUTH_TOKEN_URL: "https://auth.example.invalid/oauth2/token",
          AUTH_JWKS_URL: jwksUrl,
          AUTH_CLIENT_ID: "synthetic-client-id",
          AUTH_CLIENT_SECRET: "synthetic-client-secret-value",
          AUTH_REDIRECT_URI: "https://swooshz.com/api/platform/auth/callback",
          SESSION_SECRET: "synthetic-session-secret-value-32",
        }
      : {}),
    ...options.env,
  };
  const fixture = {
    calls,
    records,
    keys: createSyntheticKeyPair(),
    lastServer: null,
    syntheticIdToken: null,
    input: {
      env,
      now: () => now,
      csrfTokenTtlSeconds: 321,
      csrfTokenIdFactory: {
        createId() {
          return "csrf_record_bootstrap";
        },
      },
      ...(options.withAuth
        ? {
            oidcAdapter: createBootstrapOidcAdapter(calls),
            authSessionDurationMs: 60 * 60 * 1000,
            authSessionIdFactory: () => "session_auth_bootstrap_1",
            authUserIdFactory: () => "user_auth_bootstrap_1",
            authProviderIdentityIdFactory: () => "provider_identity_auth_bootstrap_1",
            authStateTtlSeconds: 600,
          }
        : {}),
      ...(options.withGenericAuth
        ? {
            genericOidcHttpClient: async (request) => {
              calls.genericOidcHttp += 1;
              calls.genericOidcHttpUrls.push(request.url);

              if (request.url === env.AUTH_TOKEN_URL) {
                return jsonResponse(200, {
                  [idTokenField]: fixture.syntheticIdToken,
                  [accessTokenField]: "synthetic-access-token-placeholder",
                  token_type: "Bearer",
                  expires_in: 300,
                });
              }

              if (request.url === env.AUTH_JWKS_URL) {
                return jsonResponse(200, {
                  keys: [fixture.keys.publicJwk],
                });
              }

              return jsonResponse(404, {
                error: "unexpected synthetic endpoint",
              });
            },
            authSessionDurationMs: 60 * 60 * 1000,
            authSessionIdFactory: () => "session_auth_bootstrap_1",
            authUserIdFactory: () => "user_auth_bootstrap_1",
            authProviderIdentityIdFactory: () => "provider_identity_auth_bootstrap_1",
            authStateTtlSeconds: 600,
          }
        : {}),
      databaseClientFactory(config) {
        calls.databaseClientFactory += 1;
        assert.equal(config.databaseUrl, env.DATABASE_URL);

        if (options.failDatabaseClient) {
          throw new Error(`DB failed ${databaseUrl} ${privateUrl}`);
        }

        return {
          db,
          async close() {
            calls.closeDatabase += 1;
          },
        };
      },
      serverFactory(dependencies) {
        calls.serverFactory += 1;
        calls.serverDependencies.push(dependencies);
        const listenOutcomes = options.listenOutcomes ?? [
          options.failListen ? "callback-error" : "success",
        ];
        const listenOutcome =
          listenOutcomes[Math.min(calls.serverFactory - 1, listenOutcomes.length - 1)];
        fixture.lastServer = createFakeServer({
          calls,
          dependencies,
          listenOutcome,
        });
        return fixture.lastServer;
      },
    },
  };

  return fixture;
}

function createSyntheticKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const kid = `synthetic-${randomUUID()}`;
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    alg: "RS256",
    kid,
    use: "sig",
  };

  return {
    kid,
    privateKey,
    publicJwk,
  };
}

function signJwt(keys, claims, headerOverrides = {}) {
  const header = {
    alg: "RS256",
    kid: keys.kid,
    typ: "JWT",
    ...headerOverrides,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .end()
    .sign(keys.privateKey);

  return `${signingInput}.${base64Url(signature)}`;
}

function base64UrlJson(value) {
  return base64Url(Buffer.from(JSON.stringify(value)));
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function seedExistingAuthMember(
  records,
  {
    userId,
    email,
    providerSubject,
    providerIdentityId = "provider_identity_auth_bootstrap_existing",
    workspaceId = "workspace_auth_bootstrap",
  },
) {
  records.users = [
    {
      id: userId,
      email,
      displayName: "Bootstrap Owner",
      status: "active",
      createdAt: now,
      updatedAt: now,
      lastLoginAt: now,
    },
  ];
  records.providerIdentities = [
    {
      id: providerIdentityId,
      userId,
      providerKey: "example-oidc",
      providerSubject,
      createdAt: now,
      updatedAt: now,
    },
  ];
  records.sessions = [];
  records.workspaces = [
    {
      id: workspaceId,
      slug: "auth-bootstrap",
      displayName: "Auth Bootstrap",
      status: "active",
      createdAt: now,
      updatedAt: now,
    },
  ];
  records.memberships = [
    {
      id: "membership_auth_bootstrap",
      workspaceId,
      userId,
      role: "owner",
      status: "active",
      createdAt: now,
      updatedAt: now,
    },
  ];
}

function createFakeServer({ calls, dependencies, listenOutcome }) {
  const listeners = new Map();
  const server = {
    listening: false,
    once(event, listener) {
      const eventListeners = listeners.get(event) ?? [];
      eventListeners.push(listener);
      listeners.set(event, eventListeners);
      return this;
    },
    off(event, listener) {
      removeListener(event, listener);
      return this;
    },
    removeListener(event, listener) {
      removeListener(event, listener);
      return this;
    },
    listenerCount(event) {
      return (listeners.get(event) ?? []).length;
    },
    listen(port, host, callback) {
      calls.listen += 1;
      calls.listenArgs.push({ port, host });

      if (listenOutcome === "callback-error") {
        callback(new Error(`listen failed ${privateUrl}`));
        return this;
      }

      if (listenOutcome === "error-event") {
        const error = new Error(`listen failed ${privateUrl}`);

        if (this.listenerCount("error") > 0) {
          emitOnce("error", error);
          return this;
        }

        callback();
        return this;
      }

      this.listening = true;
      callback();
      return this;
    },
    close(callback) {
      calls.closeServer += 1;
      this.listening = false;
      callback();
      return this;
    },
    async handle(request) {
      const { handleNodePlatformHttpRequest } = await import("../dist/index.js");
      return handleNodePlatformHttpRequest(dependencies, { ...request, headers: { host: "swooshz.com", ...request.headers } });
    },
  };

  function removeListener(event, listener) {
    const eventListeners = listeners.get(event) ?? [];
    listeners.set(
      event,
      eventListeners.filter((candidate) => candidate !== listener),
    );
  }

  function emitOnce(event, error) {
    const eventListeners = listeners.get(event) ?? [];
    listeners.set(event, []);

    for (const listener of eventListeners) {
      listener(error);
    }
  }

  return server;
}

function createFakeDrizzleDb(calls, records) {
  return {
    select() {
      calls.query += 1;
      return {
        from(table) {
          calls.dbOperations.push(`select:${readTableName(table)}`);
          return new FakeSelectResult(
            selectRows(table, records),
            calls,
            readTableName(table),
          );
        },
      };
    },
    insert(table) {
      calls.query += 1;
      calls.dbOperations.push(`insert:${readTableName(table)}`);
      return {
        values(values) {
          return {
            returning() {
              const row = { ...values };
              insertRow(table, records, row);
              return Promise.resolve([row]);
            },
          };
        },
      };
    },
    delete(table) {
      const tableName = readTableName(table);
      return {
        where() {
          if (tableName === "auth_states") records.authStates.splice(0);
          if (tableName === "csrf_tokens") {
            for (let index = records.csrfTokens.length - 1; index >= 0; index -= 1) {
              const token = records.csrfTokens[index];
              if (Date.parse(token.expiresAt) <= Date.parse(now) || token.consumedAt || token.revokedAt) {
                records.csrfTokens.splice(index, 1);
              }
            }
          }
          return Promise.resolve([]);
        },
      };
    },
    transaction(operation) {
      return operation(this);
    },
    update(table) {
      calls.query += 1;
      calls.dbOperations.push(`update:${readTableName(table)}`);
      return {
        set(values) {
          return {
            where() {
              return {
                returning() {
                  if (readTableName(table) === "auth_states") {
                    const row = records.authStates[0];

                    if (!row) {
                      return Promise.resolve([]);
                    }

                    Object.assign(row, values);
                    return Promise.resolve([row]);
                  }

                  if (readTableName(table) === "app_launch_tokens") {
                    const row = records.appLaunchTokens.find(
                      (candidate) => !candidate.consumedAt && !candidate.revokedAt,
                    );

                    if (!row) {
                      return Promise.resolve([]);
                    }

                    Object.assign(row, values);
                    return Promise.resolve([row]);
                  }

                  return Promise.resolve([]);
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
  if (!records) {
    return [];
  }

  switch (readTableName(table)) {
    case "users":
      return records.users;
    case "provider_identities":
      return records.providerIdentities;
    case "sessions":
      return records.sessions;
    case "csrf_tokens":
      return records.csrfTokens;
    case "auth_states":
      return records.authStates.filter((row) => !row.consumedAt && !row.revokedAt);
    case "workspaces":
      return records.workspaces;
    case "memberships":
      return records.memberships;
    case "apps":
      return records.apps;
    case "app_entitlements":
      return records.appEntitlements;
    case "app_launch_tokens":
      return records.appLaunchTokens;
    default:
      return [];
  }
}

function insertRow(table, records, row) {
  if (!records) {
    return;
  }

  switch (readTableName(table)) {
    case "users":
      records.users.push(row);
      return;
    case "provider_identities":
      records.providerIdentities.push(row);
      return;
    case "sessions":
      records.sessions.push(row);
      return;
    case "auth_states":
      records.authStates.push(row);
      return;
    case "csrf_tokens":
      records.csrfTokens.push(row);
      return;
    case "app_launch_tokens":
      records.appLaunchTokens.push(row);
      return;
    default:
      return;
  }
}

function readTableName(table) {
  try {
    return getTableName(table);
  } catch {
    return "";
  }
}

function createBootstrapOidcAdapter(calls) {
  return {
    async buildAuthorizationUrl(input) {
      calls.authBuildAuthorizationUrl += 1;
      calls.lastAuthStartInput = input;

      return { url: "https://auth.example.invalid/authorize" };
    },
    async exchangeCodeForTokens(input) {
      calls.authExchangeCodeForTokens += 1;
      assert.equal(input.code, "synthetic-auth-code");

      return {
        providerKey: input.providerKey,
        receivedAt: input.now,
        tokenSetRef: "adapter_internal",
      };
    },
    async verifyTokens(input) {
      calls.authVerifyTokens += 1;
      assert.equal(input.tokenExchange.tokenSetRef, "adapter_internal");

      return {
        providerKey: "example-oidc",
        providerSubject: "provider-subject-bootstrap",
        verifiedEmail: "bootstrap-owner@example.com",
        displayName: "Bootstrap Owner",
        metadata: { synthetic: true },
      };
    },
  };
}

class FakeSelectResult {
  constructor(rows = [], calls = null, tableName = "") {
    this.rows = rows;
    this.calls = calls;
    this.tableName = tableName;
  }

  limit() {
    this.calls?.dbOperations.push(`limit:${this.tableName}:${this.rows.length}`);
    return Promise.resolve(this.rows.slice(0, 1));
  }

  where() {
    this.calls?.dbOperations.push(`where:${this.tableName}`);
    return this;
  }

  then(onFulfilled, onRejected) {
    return Promise.resolve(this.rows).then(onFulfilled, onRejected);
  }
}

function assertPrivacySafeBootstrapError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof PlatformNodeBootstrapError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Platform node bootstrap could not be completed.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, /example_pass|db\.example\.invalid|postgres:\/\//);
    assert.doesNotMatch(serialized, /private\.example\.test|raw-session-token|raw-csrf-token/);
    assert.doesNotMatch(serialized, /CSRF_TOKEN_HASH_SECRET|AUTH_STATE_HASH_SECRET|DATABASE_URL/);
    return true;
  };
}

function assertResponseIsPrivacySafe(response) {
  const serialized = JSON.stringify(response);

  assert.doesNotMatch(serialized, /synthetic-auth-code|synthetic-client-secret/i);
  assert.doesNotMatch(serialized, /synthetic-session-secret|provider-token|raw-claim/i);
  assert.doesNotMatch(serialized, /app-launch:v1:hmac-sha256:/i);
  assert.doesNotMatch(serialized, /postgresql:\/\/private-host|private\.example\.test/i);
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
