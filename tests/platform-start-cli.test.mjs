import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createSecureAuthProviderIdentityIdFactory,
  createSecureAuthSessionIdFactory,
  createSecureAuthUserIdFactory,
} from "../dist/index.js";
import {
  PlatformStartCliError,
  createPlatformStartBootstrapInput,
  createPlatformStartGenericOidcHttpClient,
  createPlatformStartSqagBrowserLaunchHttpClient,
  createPlatformStartShutdownHandler,
  executePlatformStart,
  formatPlatformStartSummary,
} from "../scripts/platform-start.mjs";

const privateDatabaseUrl = "<private-database-url-placeholder>";
const privateMarker = "synthetic-private-marker-value";

test("platform:start package script exists and points at the explicit CLI", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(packageJson.scripts["platform:start"], "node scripts/platform-start.mjs");
});

test("importing platform start CLI does not start server connect DB run migrations or call providers", async () => {
  const source = await readFile("scripts/platform-start.mjs", "utf8");

  assert.match(
    source,
    /if \(process\.argv\[1\] && import\.meta\.url === pathToFileURL\(process\.argv\[1\]\)\.href\) {\s+await main\(\);\s+}/,
  );
  assert.doesNotMatch(source, /db-migrate|platform-seed-internal-access|migrate\(/i);
  assert.doesNotMatch(source, /from\s+["'][^"']*sqag/i);
});

test("start CLI builds bootstrap input from existing env contracts", () => {
  const env = createEnv({ PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc" });
  const calls = { fetch: 0 };
  const input = createPlatformStartBootstrapInput({
    env,
    fetchImplementation: async () => {
      calls.fetch += 1;
      throw new Error("fetch should not run during input creation");
    },
  });

  assert.equal(input.env, env);
  assert.equal(typeof input.genericOidcHttpClient, "function");
  assert.equal(typeof input.authSessionIdFactory, "function");
  assert.equal(typeof input.authUserIdFactory, "function");
  assert.equal(typeof input.authProviderIdentityIdFactory, "function");
  assert.equal(input.authSessionDurationMs, 60 * 60 * 1000);
  assert.equal(calls.fetch, 0);
});

test("start CLI builds SQAG server handoff input only from explicit env", () => {
  const env = createEnv({
    PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_SQAG_APP_BASE_URL: "http://127.0.0.1:8765",
  });
  const calls = { fetch: 0 };
  const input = createPlatformStartBootstrapInput({
    env,
    fetchImplementation: async () => {
      calls.fetch += 1;
      throw new Error("SQAG fetch should not run during input creation");
    },
  });

  assert.equal(input.sqagBrowserLaunch?.baseUrl, "http://127.0.0.1:8765/");
  assert.equal(typeof input.sqagBrowserLaunch?.httpClient.post, "function");
  assert.equal(calls.fetch, 0);
});

test("SQAG server handoff mode fails safely before listen when fetch or base URL is missing", () => {
  assert.throws(
    () =>
      createPlatformStartBootstrapInput({
        env: createEnv({
          PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
          PLATFORM_SQAG_APP_BASE_URL: "http://127.0.0.1:8765",
        }),
        fetchImplementation: undefined,
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
  assert.throws(
    () =>
      createPlatformStartBootstrapInput({
        env: createEnv({
          PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
          PLATFORM_SQAG_APP_BASE_URL: "",
        }),
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
});

test("production SQAG server handoff requires HTTPS base URL before bootstrap", () => {
  assert.throws(
    () =>
      createPlatformStartBootstrapInput({
        env: createEnv({
          NODE_ENV: "production",
          PLATFORM_PUBLIC_BASE_URL: "https://platform.example.invalid",
          PLATFORM_ALLOWED_ORIGINS: "https://platform.example.invalid",
          PLATFORM_COOKIE_SECURE: "true",
          AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
          PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
          PLATFORM_SQAG_APP_BASE_URL: "http://sqag.example.invalid",
        }),
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
  assert.throws(
    () =>
      createPlatformStartBootstrapInput({
        env: createEnv({
          NODE_ENV: "production",
          PLATFORM_PUBLIC_BASE_URL: "https://platform.example.invalid",
          PLATFORM_ALLOWED_ORIGINS: "https://platform.example.invalid",
          PLATFORM_COOKIE_SECURE: "true",
          AUTH_REDIRECT_URI: "https://platform.example.invalid/api/platform/auth/callback",
          PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
          PLATFORM_SQAG_APP_BASE_URL: "https://sqag.example.invalid?token=raw-secret",
        }),
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
});

test("generic OIDC fetch HTTP client does not call fetch until invoked", async () => {
  const calls = [];
  const httpClient = createPlatformStartGenericOidcHttpClient({
    fetchImplementation: async (url, init) => {
      calls.push({ url, init });
      return {
        ok: true,
        status: 200,
        async json() {
          return { ok: true };
        },
      };
    },
  });

  assert.equal(calls.length, 0);

  const response = await httpClient({
    url: "https://provider.example.invalid/token",
    method: "POST",
    headers: { accept: "application/json" },
    body: "grant_type=authorization_code",
  });

  assert.equal(response.ok, true);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.deepEqual(calls, [
    {
      url: "https://provider.example.invalid/token",
      init: {
        method: "POST",
        headers: { accept: "application/json" },
        body: "grant_type=authorization_code",
      },
    },
  ]);
});
test("SQAG handoff HTTP client does not relay upstream Set-Cookie values", async () => {
  const cookies = [
    "swooshz_quote_session=safe-session; Path=/; HttpOnly; SameSite=Lax; Secure",
    "swooshz_quote_device=safe-device; Path=/; HttpOnly; SameSite=Strict; Secure",
  ];
  const calls = [];
  const httpClient = createPlatformStartSqagBrowserLaunchHttpClient({
    fetchImplementation: async (url, init) => {
      calls.push({ url, init });
      return {
        status: 200,
        headers: {
          get(name) {
            return name === "x-sqag-finalization-handle" ? "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456" : null;
          },
          getSetCookie() {
            return cookies;
          },
        },
        async json() {
          return { status: "platform_session_created" };
        },
      };
    },
  });

  const response = await httpClient.post({
    url: "https://sqag.example.invalid/api/platform/launch",
    headers: { "x-app-launch-token": "synthetic-launch-token" },
  });

  assert.equal(response.status, 200);
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(response.headers["x-sqag-finalization-handle"], "finalization_handle_abcdefghijklmnopqrstuvwxyz_123456");
  assert.deepEqual(calls, [{
    url: "https://sqag.example.invalid/api/platform/launch",
    init: {
      method: "POST",
      headers: { "x-app-launch-token": "synthetic-launch-token" },
      redirect: "manual",
    },
  }]);
});


test("generic OIDC mode fails safely before listen when fetch is unavailable", () => {
  assert.throws(
    () =>
      createPlatformStartBootstrapInput({
        env: createEnv({ PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc" }),
        fetchImplementation: undefined,
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
});

test("executePlatformStart fails before bootstrap creation when generic OIDC fetch is unavailable", async () => {
  let bootstrapCalls = 0;

  await assert.rejects(
    () =>
      executePlatformStart({
        env: createEnv({ PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc" }),
        fetchImplementation: undefined,
        createBootstrap() {
          bootstrapCalls += 1;
          throw new Error("bootstrap should not be created");
        },
      }),
    assertPrivacySafeStartError("invalid_config"),
  );
  assert.equal(bootstrapCalls, 0);
});

test("executePlatformStart does not call provider fetch during generic OIDC startup", async () => {
  const calls = { fetch: 0, start: 0 };

  await executePlatformStart({
    env: createEnv({ PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc" }),
    fetchImplementation: async () => {
      calls.fetch += 1;
      throw new Error("provider fetch should not run during startup");
    },
    createBootstrap(input) {
      assert.equal(typeof input.genericOidcHttpClient, "function");
      return {
        async start() {
          calls.start += 1;
          return { host: "127.0.0.1", port: 4317 };
        },
        async stop() {},
      };
    },
    writeLine() {},
  });

  assert.equal(calls.start, 1);
  assert.equal(calls.fetch, 0);
});

test("executePlatformStart does not call SQAG fetch during server handoff startup", async () => {
  const calls = { fetch: 0, start: 0 };

  await executePlatformStart({
    env: createEnv({
      PLATFORM_SQAG_LAUNCH_MODE: "server_handoff",
      PLATFORM_SQAG_APP_BASE_URL: "http://127.0.0.1:8765",
    }),
    fetchImplementation: async () => {
      calls.fetch += 1;
      throw new Error("SQAG fetch should not run during startup");
    },
    createBootstrap(input) {
      assert.equal(input.sqagBrowserLaunch?.baseUrl, "http://127.0.0.1:8765/");
      assert.equal(typeof input.sqagBrowserLaunch?.httpClient.post, "function");
      return {
        async start() {
          calls.start += 1;
          return { host: "127.0.0.1", port: 4317 };
        },
        async stop() {},
      };
    },
    writeLine() {},
  });

  assert.equal(calls.start, 1);
  assert.equal(calls.fetch, 0);
});

test("executePlatformStart calls existing bootstrap start exactly once and logs safe summary", async () => {
  const calls = {
    bootstrapFactory: 0,
    start: 0,
    stop: 0,
    lines: [],
    signals: [],
  };
  const bootstrap = {
    async start() {
      calls.start += 1;
      return { host: "127.0.0.1", port: 4317 };
    },
    async stop() {
      calls.stop += 1;
    },
  };

  const result = await executePlatformStart({
    env: createEnv({
      NODE_ENV: "production",
      DATABASE_URL: privateDatabaseUrl,
      SESSION_SECRET: privateMarker,
    }),
    createBootstrap(input) {
      calls.bootstrapFactory += 1;
      assert.equal(input.env.DATABASE_URL, privateDatabaseUrl);
      return bootstrap;
    },
    writeLine(line) {
      calls.lines.push(line);
    },
    registerSignalHandler(signal, handler) {
      calls.signals.push({ signal, handler });
    },
  });

  assert.equal(result.bootstrap, bootstrap);
  assert.equal(calls.bootstrapFactory, 1);
  assert.equal(calls.start, 1);
  assert.equal(calls.stop, 0);
  assert.deepEqual(
    calls.signals.map((entry) => entry.signal),
    ["SIGINT", "SIGTERM"],
  );
  assert.match(calls.lines[0], /host=127\.0\.0\.1/);
  assert.match(calls.lines[0], /port=4317/);
  assert.match(calls.lines[0], /environment=production/);
  assert.match(calls.lines[0], /authMode=not_configured/);
  assertNoPrivateMaterial(calls.lines.join("\n"));
});

test("executePlatformStart reports startup failures safely", async () => {
  await assert.rejects(
    () =>
      executePlatformStart({
        env: createEnv({
          DATABASE_URL: privateDatabaseUrl,
          SESSION_SECRET: privateMarker,
        }),
        createBootstrap() {
          return {
            async start() {
              throw new Error(`boom ${privateDatabaseUrl} ${privateMarker}`);
            },
            async stop() {
              throw new Error("should not be called");
            },
          };
        },
        writeLine() {
          throw new Error("writeLine should not run");
        },
      }),
    assertPrivacySafeStartError("start_failed"),
  );
});

test("shutdown handler stops bootstrap and never prints private details", async () => {
  const calls = { stop: 0, exitCodes: [], lines: [], errors: [] };
  const handler = createPlatformStartShutdownHandler({
    bootstrap: {
      async stop() {
        calls.stop += 1;
      },
    },
    writeLine(line) {
      calls.lines.push(line);
    },
    writeError(line) {
      calls.errors.push(line);
    },
    exit(code) {
      calls.exitCodes.push(code);
    },
  });

  await handler();

  assert.equal(calls.stop, 1);
  assert.deepEqual(calls.exitCodes, [0]);
  assert.match(calls.lines.join("\n"), /Platform server stopped\./);
  assert.equal(calls.errors.length, 0);
  assertNoPrivateMaterial(JSON.stringify(calls));
});

test("shutdown handler failure is privacy-safe", async () => {
  const calls = { exitCodes: [], errors: [] };
  const handler = createPlatformStartShutdownHandler({
    bootstrap: {
      async stop() {
        throw new Error(`cannot close ${privateDatabaseUrl} ${privateMarker}`);
      },
    },
    writeLine() {
      throw new Error("writeLine should not run");
    },
    writeError(line) {
      calls.errors.push(line);
    },
    exit(code) {
      calls.exitCodes.push(code);
    },
  });

  await handler();

  assert.deepEqual(calls.exitCodes, [1]);
  assert.deepEqual(calls.errors, ["Platform server shutdown failed."]);
  assertNoPrivateMaterial(JSON.stringify(calls));
});

test("startup summary contains only safe fields", () => {
  const summary = formatPlatformStartSummary({
    host: "0.0.0.0",
    port: 4317,
    environment: "production",
    authMode: "generic_oidc",
    env: {
      DATABASE_URL: privateDatabaseUrl,
      AUTH_CLIENT_SECRET: privateMarker,
    },
  });

  assert.equal(
    summary,
    "Swooshz Platform server started. host=0.0.0.0 port=4317 environment=production authMode=generic_oidc",
  );
  assertNoPrivateMaterial(summary);
});

test("secure platform identity factories create opaque non-deterministic ids", () => {
  const sessionFactory = createSecureAuthSessionIdFactory();
  const userFactory = createSecureAuthUserIdFactory();
  const providerIdentityFactory = createSecureAuthProviderIdentityIdFactory();

  const sessionIdA = sessionFactory({ userId: "user", providerKey: "oidc", providerSubject: "subject", now: "now" });
  const sessionIdB = sessionFactory({ userId: "user", providerKey: "oidc", providerSubject: "subject", now: "now" });
  const userId = userFactory({ providerKey: "oidc", providerSubject: "subject", verifiedEmail: "person.invalid", now: "now" });
  const providerIdentityId = providerIdentityFactory({ userId: "user", providerKey: "oidc", providerSubject: "subject", now: "now" });

  assert.match(sessionIdA, /^session_[A-Za-z0-9_-]+$/);
  assert.match(sessionIdB, /^session_[A-Za-z0-9_-]+$/);
  assert.notEqual(sessionIdA, sessionIdB);
  assert.match(userId, /^user_[A-Za-z0-9_-]+$/);
  assert.match(providerIdentityId, /^provider_identity_[A-Za-z0-9_-]+$/);
  assertNoPrivateMaterial([sessionIdA, sessionIdB, userId, providerIdentityId].join("\n"));
});

test("platform start CLI keeps runtime boundaries clean", async () => {
  const files = [
    "scripts/platform-start.mjs",
    "src/auth/platform-identity-crypto.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /db-migrate|platform-seed-internal-access|drizzle-orm\/node-postgres\/migrator|migrate\(/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase|stripe)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /DATABASE_URL\s*=|CSRF_TOKEN_HASH_SECRET\s*=|AUTH_CLIENT_SECRET\s*=/);
  }

  const scriptFiles = await listFiles("scripts");
  assert.equal(
    scriptFiles.some((filePath) => /deploy|provision/i.test(filePath)),
    false,
  );
});

function createEnv(overrides = {}) {
  return {
    NODE_ENV: "development",
    PLATFORM_HTTP_HOST: "127.0.0.1",
    PLATFORM_HTTP_PORT: "4317",
    PLATFORM_PUBLIC_BASE_URL: "http://127.0.0.1:4317",
    PLATFORM_ALLOWED_ORIGINS: "http://127.0.0.1:4317",
    PLATFORM_COOKIE_SECURE: "false",
    DATABASE_URL: "<database-url-from-existing-service>",
    CSRF_TOKEN_HASH_SECRET: "synthetic_csrf_hash_secret_32_chars_min",
    APP_LAUNCH_TOKEN_HASH_SECRET: "synthetic_app_launch_hash_secret_32_chars_min",
    AUTH_STATE_HASH_SECRET: "synthetic_auth_state_hash_secret_32_chars_min",
    AUTH_PROVIDER_KEY: "Example-OIDC",
    AUTH_ISSUER_URL: "https://issuer.example.invalid/",
    AUTH_AUTHORIZATION_URL: "https://issuer.example.invalid/oauth2/authorize",
    AUTH_TOKEN_URL: "https://issuer.example.invalid/oauth2/token",
    AUTH_JWKS_URL: "https://issuer.example.invalid/.well-known/jwks.json",
    AUTH_CLIENT_ID: "synthetic-client-id",
    AUTH_CLIENT_SECRET: "synthetic-client-secret-placeholder",
    AUTH_REDIRECT_URI: "http://127.0.0.1:4317/api/platform/auth/callback",
    SESSION_SECRET: "synthetic_session_secret_32_chars_min",
    ...overrides,
  };
}

function assertPrivacySafeStartError(code) {
  return {
    name: "PlatformStartCliError",
    code,
    publicMessage: "Platform server could not be started.",
    message: "Platform server could not be started.",
  };
}

function assertNoPrivateMaterial(value) {
  assert.doesNotMatch(value, /private-database-url-placeholder/);
  assert.doesNotMatch(value, new RegExp(privateMarker));
  assert.doesNotMatch(value, /postgres:\/\/[^\\s>]+@/i);
  assert.doesNotMatch(value, /synthetic-private-marker-value/);
}

async function listFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...await listFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }

  return files;
}
