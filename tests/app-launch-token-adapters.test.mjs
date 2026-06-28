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
  appId: "app_kqag",
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
    appId: "app_kqag",
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

test("app launch token adapter modules do not import frontend KQAG provider SDK live DB clients or frameworks", async () => {
  const files = [
    "src/platform/app-launch-token-crypto.ts",
    "src/db/app-launch-token-repository.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
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

function createFakeDrizzleDb({ insertRows } = {}) {
  const calls = [];

  return {
    calls,
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
  };
}
