import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  mapAppLaunchTokenRow,
} from "../dist/db/mappers.js";
import {
  createDrizzleAppLaunchTokenRepository,
} from "../dist/db/app-launch-token-repository.js";

const createdAt = new Date("2026-06-27T00:00:00.000Z");
const expiresAt = new Date("2026-06-27T00:05:00.000Z");
const tokenHash = "app-launch:v1:hmac-sha256:synthetic_hash_reference";
const rawLaunchToken = "synthetic-raw-launch-token-reference";

const appLaunchTokenRow = {
  id: "app_launch_token_example",
  sessionId: "session_owner_example",
  userId: "user_owner_example",
  workspaceId: "workspace_koncept_images",
  appId: "app_sqag",
  tokenHash,
  createdAt,
  expiresAt,
  consumedAt: null,
  revokedAt: null,
};

test("maps app launch token rows to hash-only storage records", () => {
  assert.deepEqual(mapAppLaunchTokenRow(appLaunchTokenRow), {
    id: "app_launch_token_example",
    sessionId: "session_owner_example",
    userId: "user_owner_example",
    workspaceId: "workspace_koncept_images",
    appId: "app_sqag",
    tokenHash,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    consumedAt: null,
    revokedAt: null,
  });
  assert.equal("launchToken" in mapAppLaunchTokenRow(appLaunchTokenRow), false);
  assert.equal("rawToken" in mapAppLaunchTokenRow(appLaunchTokenRow), false);
});

test("Drizzle app launch token repository create stores only token hashes", async () => {
  const fakeDb = createFakeDrizzleDb({
    insertRows: new Map([[schema.appLaunchTokens, [appLaunchTokenRow]]]),
  });
  const repository = createDrizzleAppLaunchTokenRepository(fakeDb);

  const created = await repository.create(mapAppLaunchTokenRow(appLaunchTokenRow));

  assert.deepEqual(created, mapAppLaunchTokenRow(appLaunchTokenRow));
  const insert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.appLaunchTokens,
  );
  assert.ok(insert);
  assert.equal(insert.values.tokenHash, tokenHash);
  assert.equal("launchToken" in insert.values, false);
  assert.equal("rawToken" in insert.values, false);
  assert.doesNotMatch(JSON.stringify(insert.values), new RegExp(rawLaunchToken));
});

test("Drizzle app launch token repository finds records by token hash only", async () => {
  const fakeDb = createFakeDrizzleDb({
    selectRows: new Map([[schema.appLaunchTokens, [appLaunchTokenRow]]]),
  });
  const repository = createDrizzleAppLaunchTokenRepository(fakeDb);

  const found = await repository.findByTokenHash(tokenHash);

  assert.deepEqual(found, mapAppLaunchTokenRow(appLaunchTokenRow));
  assert.equal(fakeDb.calls.some((call) => call.operation === "select.where"), true);
  assert.doesNotMatch(serializePrimitiveCalls(fakeDb.calls), new RegExp(rawLaunchToken));
});

test("Drizzle app launch token repository consumes only unconsumed active records", async () => {
  const fakeDb = createFakeDrizzleDb({
    updateRows: new Map([[schema.appLaunchTokens, [{ ...appLaunchTokenRow, consumedAt: createdAt }]]]),
  });
  const repository = createDrizzleAppLaunchTokenRepository(fakeDb);

  const consumed = await repository.consumeUnconsumed(
    "app_launch_token_example",
    createdAt.toISOString(),
  );

  assert.equal(consumed.consumedAt, createdAt.toISOString());
  const updateSet = fakeDb.calls.find((call) => call.operation === "update.set");
  assert.ok(updateSet);
  assert.deepEqual(updateSet.values, { consumedAt: createdAt });
  assert.doesNotMatch(serializePrimitiveCalls(fakeDb.calls), new RegExp(rawLaunchToken));
});

test("Drizzle app launch token repository returns null when consume loses replay race", async () => {
  const fakeDb = createFakeDrizzleDb({
    updateRows: new Map([[schema.appLaunchTokens, []]]),
  });
  const repository = createDrizzleAppLaunchTokenRepository(fakeDb);

  const consumed = await repository.consumeUnconsumed(
    "app_launch_token_example",
    createdAt.toISOString(),
  );

  assert.equal(consumed, null);
});

test("app launch token adapter modules do not import frontend SQAG provider SDK live DB clients or frameworks", async () => {
  const files = [
    "src/platform/app-launch-token-crypto.ts",
    "src/db/app-launch-token-repository.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:pg|node-postgres)/i);
    assert.doesNotMatch(contents, /DATABASE_URL|AUTH_CLIENT_SECRET|SESSION_SECRET|CSRF_SECRET/);
  }
});

test("app launch token schema has hash-only lifecycle indexes and no raw token column", async () => {
  const schemaContents = await readFile("src/db/schema.ts", "utf8");

  assert.match(schemaContents, /appLaunchTokens/);
  assert.match(schemaContents, /tokenHash/);
  assert.doesNotMatch(schemaContents, /launchToken|rawToken/);
});

function createFakeDrizzleDb({ insertRows, selectRows, updateRows } = {}) {
  const calls = [];

  return {
    calls,
    select() {
      calls.push({ operation: "select" });

      return {
        from(table) {
          calls.push({ operation: "select.from", table });

          return {
            where(condition) {
              calls.push({ operation: "select.where", table, condition });

              return {
                limit(limit) {
                  calls.push({ operation: "select.limit", table, limit });
                  return Promise.resolve(selectRows?.get(table) ?? []);
                },
              };
            },
          };
        },
      };
    },
    insert(table) {
      calls.push({ operation: "insert", table });

      return {
        values(values) {
          calls.push({ operation: "insert.values", table, values });

          return {
            returning() {
              calls.push({ operation: "insert.returning", table });
              return Promise.resolve(insertRows?.get(table) ?? []);
            },
          };
        },
      };
    },
    update(table) {
      calls.push({ operation: "update", table });

      return {
        set(values) {
          calls.push({ operation: "update.set", table, values });

          return {
            where(condition) {
              calls.push({ operation: "update.where", table, condition });

              return {
                returning() {
                  calls.push({ operation: "update.returning", table });
                  return Promise.resolve(updateRows?.get(table) ?? []);
                },
              };
            },
          };
        },
      };
    },
  };
}

function serializePrimitiveCalls(calls) {
  return JSON.stringify(
    calls.map((call) => ({
      operation: call.operation,
      values: call.values,
      limit: call.limit,
    })),
  );
}
