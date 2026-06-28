import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  createPlatformRuntimeDependencies,
  PlatformRuntimeSecretConfigError,
  readPlatformRuntimeSecretConfig,
  issueCsrfTokenForSession,
} from "../dist/index.js";

const now = "2026-06-27T00:00:00.000Z";
const future = "2026-06-27T00:15:00.000Z";
const allowedOrigin = "https://platform.example.test";
const sessionId = "session_owner_example";
const userId = "user_owner_example";
const csrfSecret = "synthetic_csrf_hash_secret_32_chars_min";
const rawTokenPattern = /csrf_[A-Za-z0-9_-]+|synthetic-raw-csrf-token|raw-csrf-token/i;

test("runtime secret config accepts strong synthetic CSRF hash secret", () => {
  const config = readPlatformRuntimeSecretConfig({
    CSRF_TOKEN_HASH_SECRET: csrfSecret,
  });

  assert.deepEqual(config, {
    csrfTokenHashSecret: csrfSecret,
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

test("crypto imports remain only in the CSRF crypto adapter module", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set([
    "src/auth/auth-state-crypto.ts",
    "src/http/csrf-token-crypto.ts",
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

function createRuntimeFixture() {
  const calls = {
    connect: 0,
    listen: 0,
    migrate: 0,
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
          return {
            where() {
              return new FakeSelectResult(selectRows(table, records));
            },
          };
        },
      };
    },
    insert(table) {
      return {
        values(values) {
          if (table !== schema.csrfTokens) {
            throw new Error("Only CSRF token writes are expected in this test.");
          }

          const row = {
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
          records.csrfTokens.push(row);

          return {
            returning() {
              return Promise.resolve([row]);
            },
          };
        },
      };
    },
    update() {
      throw new Error("Runtime composition tests do not update records.");
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

  return [];
}

class FakeSelectResult {
  constructor(rows) {
    this.rows = rows;
  }

  limit(limit) {
    return Promise.resolve(this.rows.slice(0, limit));
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
