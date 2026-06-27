import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import * as schema from "../dist/db/schema.js";
import {
  mapCsrfTokenRow,
} from "../dist/db/mappers.js";
import {
  createDrizzleCsrfTokenRepository,
} from "../dist/db/csrf-token-repository.js";
import {
  CsrfTokenCryptoConfigError,
  createHmacCsrfTokenHasher,
  createSecureCsrfTokenFactory,
} from "../dist/http/csrf-token-crypto.js";

const createdAt = new Date("2026-06-27T00:00:00.000Z");
const expiresAt = new Date("2026-06-27T00:15:00.000Z");
const consumedAt = null;
const revokedAt = null;
const replacedByTokenId = null;
const sessionId = "session_owner_example";
const tokenHash = "csrf:v1:hash_synthetic_token_reference";
const rawToken = "synthetic-raw-csrf-token-reference";
const strongSecret = "synthetic_csrf_hash_secret_32_chars_min";
const privateFailure =
  "storage exploded synthetic-raw-csrf-token-reference csrf:v1:hash_synthetic_token_reference postgresql://private-host";

const csrfTokenRow = {
  id: "csrf_token_owner_example",
  sessionId,
  tokenHash,
  purpose: "browser_session",
  createdAt,
  expiresAt,
  consumedAt,
  revokedAt,
  replacedByTokenId,
};

test("secure token factory returns a non-empty header-safe token", async () => {
  const factory = createSecureCsrfTokenFactory();

  const token = await factory.createToken();

  assert.equal(typeof token, "string");
  assert.ok(token.length >= 43);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
});

test("HMAC token hasher is stable and differentiates token values", async () => {
  const hasher = createHmacCsrfTokenHasher({ secret: strongSecret });

  const first = await hasher.hashToken(rawToken);
  const second = await hasher.hashToken(rawToken);
  const different = await hasher.hashToken(`${rawToken}-different`);

  assert.equal(first, second);
  assert.notEqual(first, different);
  assert.match(first, /^csrf:v1:hmac-sha256:[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(first, new RegExp(rawToken));
  assert.doesNotMatch(first, new RegExp(strongSecret));
});

test("HMAC token hasher rejects weak or blank secrets safely", () => {
  for (const secret of ["", "   ", "short_secret"]) {
    assert.throws(
      () => createHmacCsrfTokenHasher({ secret }),
      assertPrivacySafeCryptoError("invalid_secret"),
    );
  }
});

test("HMAC token hasher errors do not expose secret or raw token", async () => {
  const hasher = createHmacCsrfTokenHasher({ secret: strongSecret });

  await assert.rejects(
    () => hasher.hashToken(""),
    assertPrivacySafeCryptoError("invalid_token"),
  );
});

test("maps CSRF token rows to storage-agnostic records", () => {
  assert.deepEqual(mapCsrfTokenRow(csrfTokenRow), {
    id: csrfTokenRow.id,
    sessionId,
    tokenHash,
    purpose: "browser_session",
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    consumedAt: null,
    revokedAt: null,
    replacedByTokenId: null,
  });
});

test("Drizzle CSRF repository create stores only token hashes", async () => {
  const fakeDb = createFakeDrizzleDb({
    insertRows: new Map([[schema.csrfTokens, [csrfTokenRow]]]),
  });
  const repository = createDrizzleCsrfTokenRepository(fakeDb);

  const created = await repository.create(mapCsrfTokenRow(csrfTokenRow));

  assert.deepEqual(created, mapCsrfTokenRow(csrfTokenRow));
  const insert = fakeDb.calls.find(
    (call) => call.operation === "insert.values" && call.table === schema.csrfTokens,
  );
  assert.ok(insert);
  assert.equal(insert.values.tokenHash, tokenHash);
  assert.equal("csrfToken" in insert.values, false);
  assert.equal("rawToken" in insert.values, false);
  assert.doesNotMatch(JSON.stringify(insert.values), new RegExp(rawToken));
});

test("Drizzle CSRF repository find filters by session token hash and purpose", async () => {
  const fakeDb = createFakeDrizzleDb({
    selectRows: new Map([[schema.csrfTokens, [csrfTokenRow]]]),
  });
  const repository = createDrizzleCsrfTokenRepository(fakeDb);

  const found = await repository.findBySessionAndTokenHash(
    sessionId,
    tokenHash,
    "browser_session",
  );

  assert.deepEqual(found, mapCsrfTokenRow(csrfTokenRow));
  assertTablesWereSelected(fakeDb, [schema.csrfTokens]);
  assert.equal(fakeDb.calls.filter((call) => call.operation === "select.where").length, 1);
  assert.equal(
    JSON.stringify(fakeDb.calls.map(({ operation, values, limit }) => ({
      operation,
      values,
      limit,
    }))).includes(rawToken),
    false,
  );
});

test("Drizzle CSRF repository preserves nullable lifecycle fields", async () => {
  const nullableRow = {
    ...csrfTokenRow,
    consumedAt: null,
    revokedAt: null,
    replacedByTokenId: null,
  };
  const repository = createDrizzleCsrfTokenRepository(
    createFakeDrizzleDb({
      selectRows: new Map([[schema.csrfTokens, [nullableRow]]]),
    }),
  );

  const found = await repository.findBySessionAndTokenHash(
    sessionId,
    tokenHash,
    "browser_session",
  );

  assert.equal(found.consumedAt, null);
  assert.equal(found.revokedAt, null);
  assert.equal(found.replacedByTokenId, null);
});

test("Drizzle CSRF repository returns null for missing token records", async () => {
  const repository = createDrizzleCsrfTokenRepository(createFakeDrizzleDb());

  assert.equal(
    await repository.findBySessionAndTokenHash(sessionId, tokenHash, "browser_session"),
    null,
  );
});

test("CSRF crypto imports stay in the crypto adapter module only", async () => {
  const sourceFiles = await listFiles("src");
  const allowed = new Set(["src/http/csrf-token-crypto.ts"]);

  for (const filePath of sourceFiles) {
    const normalized = filePath.replaceAll("\\", "/");
    const contents = await readFile(filePath, "utf8");

    if (allowed.has(normalized)) {
      continue;
    }

    assert.doesNotMatch(contents, /node:crypto|from\s+["']crypto["']/);
  }
});

test("CSRF adapter modules do not import frontend KQAG provider SDK live DB or frameworks", async () => {
  const files = [
    "src/http/csrf-token-crypto.ts",
    "src/db/csrf-token-repository.ts",
  ];

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase)/i);
    assert.doesNotMatch(contents, /from\s+["'][^"']*(?:pg|node-postgres)/i);
    assert.doesNotMatch(contents, /DATABASE_URL|AUTH_CLIENT_SECRET|SESSION_SECRET|CSRF_SECRET/);
  }
});

function assertPrivacySafeCryptoError(expectedCode) {
  return (error) => {
    assert.equal(error instanceof CsrfTokenCryptoConfigError, true);
    assert.equal(error.code, expectedCode);
    assert.equal(error.publicMessage, "CSRF token crypto configuration is invalid.");
    const serialized = JSON.stringify(error) + String(error.message ?? "");
    assert.doesNotMatch(serialized, new RegExp(strongSecret));
    assert.doesNotMatch(serialized, new RegExp(rawToken));
    assert.doesNotMatch(serialized, /postgresql:\/\/private-host|storage exploded/i);
    return true;
  };
}

function createFakeDrizzleDb({ selectRows, insertRows } = {}) {
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
