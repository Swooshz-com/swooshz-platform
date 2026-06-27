import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  createPlatformNodeBootstrap,
  PlatformNodeBootstrapError,
} from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const csrfSecret = "synthetic_csrf_hash_secret_32_chars_min";
const databaseUrl =
  "postgres://example_user:example_pass@db.example.invalid:5432/swooshz_platform";
const privateUrl =
  "https://private.example.test/path?token=raw-session-token&db=postgresql://private-host";

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

test("bootstrap composes runtime dependencies with secure cookie origin and CSRF config", async () => {
  const fixture = createBootstrapFixture();
  const bootstrap = createPlatformNodeBootstrap(fixture.input);

  await bootstrap.start();

  const dependencies = fixture.calls.serverDependencies[0];
  assert.deepEqual(dependencies.cookie, { secure: true });
  assert.deepEqual(dependencies.originConfig, {
    allowedOrigins: ["https://platform.example.test"],
    publicBaseUrl: "https://platform.example.test",
  });
  assert.equal(dependencies.csrfTokenTtlSeconds, 321);
  assert.ok(dependencies.csrfTokenIssuer);
  assert.ok(dependencies.csrfTokenValidator);
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

test("bootstrap module does not import migrations frontend KQAG provider SDK or framework packages", async () => {
  const files = [
    "src/runtime/node-bootstrap.ts",
    "src/runtime/bootstrap-config.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
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
  };
  const db = createFakeDrizzleDb(calls);
  const env = {
    PLATFORM_HTTP_HOST: "127.0.0.1",
    PLATFORM_HTTP_PORT: "4317",
    PLATFORM_PUBLIC_BASE_URL: "https://platform.example.test",
    PLATFORM_ALLOWED_ORIGINS: "https://platform.example.test",
    PLATFORM_COOKIE_SECURE: "true",
    NODE_ENV: "production",
    DATABASE_URL: databaseUrl,
    CSRF_TOKEN_HASH_SECRET: csrfSecret,
    ...options.env,
  };
  const fixture = {
    calls,
    lastServer: null,
    input: {
      env,
      now: () => now,
      csrfTokenTtlSeconds: 321,
      csrfTokenIdFactory: {
        createId() {
          return "csrf_record_bootstrap";
        },
      },
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
      return handleNodePlatformHttpRequest(dependencies, request);
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

function createFakeDrizzleDb(calls) {
  return {
    select() {
      calls.query += 1;
      return {
        from() {
          return {
            where() {
              return new FakeSelectResult([]);
            },
          };
        },
      };
    },
    insert() {
      calls.query += 1;
      return {
        values() {
          return {
            returning() {
              return Promise.resolve([]);
            },
          };
        },
      };
    },
    update() {
      calls.query += 1;
      return {
        set() {
          return {
            where() {
              return {
                returning() {
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

class FakeSelectResult {
  limit() {
    return Promise.resolve([]);
  }

  then(onFulfilled, onRejected) {
    return Promise.resolve([]).then(onFulfilled, onRejected);
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
    assert.doesNotMatch(serialized, /CSRF_TOKEN_HASH_SECRET|DATABASE_URL/);
    return true;
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
