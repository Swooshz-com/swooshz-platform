import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  mapAuthStateRow,
} from "../dist/db/mappers.js";
import {
  createDrizzleAuthStateStore,
} from "../dist/db/auth-state-repository.js";
import {
  AuthStateCryptoConfigError,
  createHmacAuthStateReferenceFactory,
  createSecureAuthNonceFactory,
  createSecureAuthStateFactory,
} from "../dist/auth/auth-state-crypto.js";

const createdAt = new Date("2026-06-27T00:00:00.000Z");
const expiresAt = new Date("2026-06-27T00:10:00.000Z");
const consumedAt = null;
const revokedAt = null;
const providerKey = "example-oidc";
const stateHash = "auth-state:v1:hash_synthetic_state_reference";
const nonceHash = "auth-state:v1:hash_synthetic_nonce_reference";
const rawState = "synthetic-raw-oidc-state-reference";
const rawNonce = "synthetic-raw-oidc-nonce-reference";
const strongSecret = "synthetic_auth_state_hash_secret_32_chars_min";
const redirectUri = "https://platform.example.invalid/api/platform/auth/callback";
const privateFailure =
  "storage exploded synthetic-raw-oidc-state-reference synthetic-raw-oidc-nonce-reference postgresql://private-host";

const authStateRow = {
  providerKey,
  stateHash,
  nonceHash,
  redirectUri,
  createdAt,
  expiresAt,
  consumedAt,
  revokedAt,
};

test("secure auth state and nonce factories return non-empty URL-safe values", () => {
  const state = createSecureAuthStateFactory().createState();
  const nonce = createSecureAuthNonceFactory().createNonce();

  assert.equal(typeof state, "string");
  assert.equal(typeof nonce, "string");
  assert.ok(state.length >= 43);
  assert.ok(nonce.length >= 43);
  assert.match(state, /^[A-Za-z0-9_-]+$/);
  assert.match(nonce, /^[A-Za-z0-9_-]+$/);
});

test("HMAC auth state reference factory is stable and differentiates values", () => {
  const referenceFactory = createHmacAuthStateReferenceFactory({
    secret: strongSecret,
  });

  const first = referenceFactory(rawState);
  const second = referenceFactory(rawState);
  const different = referenceFactory(rawNonce);

  assert.equal(first, second);
  assert.notEqual(first, different);
  assert.match(first, /^auth-state:v1:hmac-sha256:[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(first, new RegExp(rawState));
  assert.doesNotMatch(first, new RegExp(strongSecret));
});

test("HMAC auth state reference factory rejects weak or blank secrets safely", () => {
  for (const secret of ["", "   ", "short_secret"]) {
    assert.throws(
      () => createHmacAuthStateReferenceFactory({ secret }),
      assertPrivacySafeAuthStateCryptoError("invalid_secret"),
    );
  }
});

test("HMAC auth state reference errors do not expose raw state nonce or secret", () => {
  const referenceFactory = createHmacAuthStateReferenceFactory({
    secret: strongSecret,
  });

  assert.throws(
    () => referenceFactory(""),
    assertPrivacySafeAuthStateCryptoError("invalid_value"),
  );
});

test("maps auth state rows to storage-agnostic lifecycle records", () => {
  assert.deepEqual(mapAuthStateRow(authStateRow), {
    providerKey,
    stateHash,
    nonceHash,
    redirectUri,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    consumedAt: null,
    revokedAt: null,
  });
});

test("Drizzle auth state store stores only hashed state and nonce references", async () => {
  const fakeDb = createFakeDrizzleDb({
    insertRows: new Map([[schema.authStates, [authStateRow]]]),
  });
  const store = createDrizzleAuthStateStore(fakeDb);

  const created = await store.storeState(mapStoredAuthStateInput(authStateRow));

  assert.deepEqual(created, mapStoredAuthStateInput(authStateRow));
  const insert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.authStates,
  );
  assert.ok(insert);
  assert.equal(insert.values.stateHash, stateHash);
  assert.equal(insert.values.nonceHash, nonceHash);
  assert.equal("state" in insert.values, false);
  assert.equal("nonce" in insert.values, false);
  assert.doesNotMatch(JSON.stringify(insert.values), new RegExp(rawState));
  assert.doesNotMatch(JSON.stringify(insert.values), new RegExp(rawNonce));
});

test("Drizzle auth state store consumeState filters by provider key and state hash", async () => {
  const fakeDb = createFakeDrizzleDb({
    selectRows: new Map([[schema.authStates, [authStateRow]]]),
    updateRows: new Map([[schema.authStates, [{ ...authStateRow, consumedAt: createdAt }]]]),
  });
  const store = createDrizzleAuthStateStore(fakeDb);

  const consumed = await store.consumeState({
    providerKey,
    stateHash,
    now: createdAt.toISOString(),
  });

  assert.deepEqual(consumed, mapStoredAuthStateInput(authStateRow));
  assertTablesWereSelected(fakeDb, [schema.authStates]);
  assert.equal(fakeDb.calls.filter((call) => call.operation === "select.where").length, 1);
  assert.equal(fakeDb.calls.filter((call) => call.operation === "update.set").length, 1);
  const update = fakeDb.calls.find((call) => call.operation === "update.set");
  assert.ok(update.values.consumedAt instanceof Date);
  const safeCallPayload = JSON.stringify(
    fakeDb.calls.map(({ operation, values, limit }) => ({ operation, values, limit })),
  );
  assert.doesNotMatch(safeCallPayload, new RegExp(rawState));
  assert.doesNotMatch(safeCallPayload, new RegExp(rawNonce));
});

test("Drizzle auth state store returns null for missing consumed or revoked states", async () => {
  const missing = createDrizzleAuthStateStore(createFakeDrizzleDb());
  const alreadyConsumed = createDrizzleAuthStateStore(
    createFakeDrizzleDb({
      selectRows: new Map([[schema.authStates, [{ ...authStateRow, consumedAt: createdAt }]]]),
    }),
  );
  const revoked = createDrizzleAuthStateStore(
    createFakeDrizzleDb({
      selectRows: new Map([[schema.authStates, [{ ...authStateRow, revokedAt: createdAt }]]]),
    }),
  );

  assert.equal(
    await missing.consumeState({ providerKey, stateHash, now: createdAt.toISOString() }),
    null,
  );
  assert.equal(
    await alreadyConsumed.consumeState({
      providerKey,
      stateHash,
      now: createdAt.toISOString(),
    }),
    null,
  );
  assert.equal(
    await revoked.consumeState({ providerKey, stateHash, now: createdAt.toISOString() }),
    null,
  );
});

test("Drizzle auth state store preserves nullable lifecycle fields", async () => {
  const store = createDrizzleAuthStateStore(
    createFakeDrizzleDb({
      selectRows: new Map([[schema.authStates, [authStateRow]]]),
      updateRows: new Map([[schema.authStates, [{ ...authStateRow, consumedAt: createdAt }]]]),
    }),
  );

  const row = mapAuthStateRow(authStateRow);
  const consumed = await store.consumeState({
    providerKey,
    stateHash,
    now: createdAt.toISOString(),
  });

  assert.equal(row.consumedAt, null);
  assert.equal(row.revokedAt, null);
  assert.equal(consumed.providerKey, providerKey);
});

test("auth state crypto imports stay in dedicated crypto adapter modules", async () => {
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

test("auth state adapter modules do not import frontend KQAG provider SDK live DB or frameworks", async () => {
  const files = [
    "src/auth/auth-state-crypto.ts",
    "src/auth/auth-state-repositories.ts",
    "src/db/auth-state-repository.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:pg|node-postgres)/i);
    assert.doesNotMatch(contents, /DATABASE_URL|AUTH_CLIENT_SECRET|SESSION_SECRET/);
  }
});

function mapStoredAuthStateInput(row) {
  return {
    providerKey: row.providerKey,
    stateHash: row.stateHash,
    nonceHash: row.nonceHash,
    redirectUri: row.redirectUri,
    createdAt: row.createdAt instanceof Date ? row.createdAt.toISOString() : row.createdAt,
    expiresAt: row.expiresAt instanceof Date ? row.expiresAt.toISOString() : row.expiresAt,
  };
}

function assertPrivacySafeAuthStateCryptoError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof AuthStateCryptoConfigError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "Auth state crypto configuration is invalid.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, new RegExp(strongSecret));
    assert.doesNotMatch(serialized, new RegExp(rawState));
    assert.doesNotMatch(serialized, new RegExp(rawNonce));
    assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
    return true;
  };
}

function createFakeDrizzleDb({ selectRows, insertRows, updateRows } = {}) {
  const calls = [];

  return {
    calls,
    select() {
      return {
        from(table) {
          calls.push({ operation: "select.from", table });

          return {
            where(condition) {
              calls.push({ operation: "select.where", table, condition });
              return new FakeSelectResult(selectRows?.get(table) ?? [], calls, table);
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

          if (JSON.stringify(values).includes(privateFailure)) {
            throw new Error("Fake DB received private failure text.");
          }

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

function assertTablesWereSelected(fakeDb, expectedTables) {
  assert.deepEqual(
    fakeDb.calls
      .filter((call) => call.operation === "select.from")
      .map((call) => call.table),
    expectedTables,
  );
}

class FakeSelectResult {
  constructor(rows, calls, table) {
    this.rows = rows;
    this.calls = calls;
    this.table = table;
  }

  limit(limit) {
    this.calls.push({ operation: "select.limit", table: this.table, limit });
    return Promise.resolve(this.rows.slice(0, limit));
  }

  then(onFulfilled, onRejected) {
    return Promise.resolve(this.rows).then(onFulfilled, onRejected);
  }

  catch(onRejected) {
    return Promise.resolve(this.rows).catch(onRejected);
  }

  finally(onFinally) {
    return Promise.resolve(this.rows).finally(onFinally);
  }
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
