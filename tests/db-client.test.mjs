import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DatabaseConfigError,
  DATABASE_MIGRATIONS_CONFIRM_VALUE,
  assertMigrationExecutionAllowed,
  createDatabasePool,
  readDatabaseConfig,
  readOperatorDatabaseConfig,
} from "../dist/db/client.js";

const syntheticDatabaseUrl =
  "postgres://example_user:example_pass@db.example.invalid:5432/swooshz_platform";

test("readDatabaseConfig requires DATABASE_URL without leaking env values", () => {
  assert.throws(
    () =>
      readDatabaseConfig({
        DATABASE_URL: "",
        UNRELATED_SECRET_VALUE: "do-not-leak-this-value",
      }),
    (error) => {
      assert.equal(error instanceof Error, true);
      assert.match(error.message, /DATABASE_URL is required/);
      assert.doesNotMatch(error.message, /do-not-leak-this-value/);
      assert.doesNotMatch(error.message, /postgres:\/\//);
      return true;
    },
  );
});

test("readDatabaseConfig accepts a synthetic DATABASE_URL without printing it", () => {
  const config = readDatabaseConfig({
    DATABASE_URL: syntheticDatabaseUrl,
  });

  assert.equal(config.databaseUrl, syntheticDatabaseUrl);
  assert.equal(config.sslMode, undefined);
  assert.deepEqual(Object.keys(config).sort(), ["databaseUrl"]);
});

test("readDatabaseConfig rejects malformed DATABASE_URL values without leaking them", () => {
  for (const databaseUrl of [
    "not-a-postgres-url-with-private-pass",
    ["https", "://private-user:private-pass@db.example.invalid/swooshz_platform"].join(""),
    ["postgres", "://private-user:private-pass@/swooshz_platform"].join(""),
    ["postgres", "://private-user:private-pass@db.example.invalid"].join(""),
  ]) {
    assert.throws(
      () =>
        readDatabaseConfig({
          DATABASE_URL: databaseUrl,
        }),
      (error) => {
        assert.equal(error instanceof DatabaseConfigError, true);
        assert.equal(error.code, "invalid_database_url");
        assert.equal(error.publicMessage, "Database configuration is invalid.");
        assert.doesNotMatch(error.message, /private-user|private-pass|db\.example\.invalid/);
        assert.doesNotMatch(error.message, /not-a-postgres-url/);
        return true;
      },
    );
  }
});

test("readDatabaseConfig rejects unsupported SSL modes without leaking the URL", () => {
  assert.throws(
    () =>
      readDatabaseConfig({
        DATABASE_URL: syntheticDatabaseUrl,
        DATABASE_SSL_MODE: "prefer",
      }),
    (error) => {
      assert.equal(error instanceof Error, true);
      assert.match(error.message, /DATABASE_SSL_MODE/);
      assert.doesNotMatch(error.message, /example_pass/);
      assert.doesNotMatch(error.message, /db\.example\.invalid/);
      return true;
    },
  );
});

test("migration confirmation guard requires the documented exact value", () => {
  assert.throws(
    () => assertMigrationExecutionAllowed({ DATABASE_URL: syntheticDatabaseUrl }),
    /DATABASE_MIGRATIONS_CONFIRM/,
  );
  assert.throws(
    () =>
      assertMigrationExecutionAllowed({
        DATABASE_URL: syntheticDatabaseUrl,
        DATABASE_MIGRATIONS_CONFIRM: "local",
      }),
    /DATABASE_MIGRATIONS_CONFIRM/,
  );

  assert.doesNotThrow(() =>
    assertMigrationExecutionAllowed({
      DATABASE_URL: syntheticDatabaseUrl,
      DATABASE_MIGRATIONS_CONFIRM: DATABASE_MIGRATIONS_CONFIRM_VALUE,
    }),
  );
});

test("production operator connections require DATABASE_OPERATOR_URL", () => {
  assert.throws(
    () =>
      readOperatorDatabaseConfig({
        NODE_ENV: "production",
        DATABASE_URL: syntheticDatabaseUrl,
      }),
    (error) => {
      assert.equal(error instanceof DatabaseConfigError, true);
      assert.equal(error.code, "missing_database_operator_url");
      assert.doesNotMatch(error.message, /example_pass|db\.example\.invalid/);
      return true;
    },
  );
});

test("operator connections are separated in production with local fallback", () => {
  const operatorUrl =
    "postgres://operator_user:operator_pass@operator.example.invalid:5432/swooshz_platform";
  const production = readOperatorDatabaseConfig({
    NODE_ENV: "production",
    DATABASE_URL: syntheticDatabaseUrl,
    DATABASE_OPERATOR_URL: operatorUrl,
  });
  const development = readOperatorDatabaseConfig({
    NODE_ENV: "development",
    DATABASE_URL: syntheticDatabaseUrl,
  });

  assert.equal(production.databaseUrl, operatorUrl);
  assert.equal(development.databaseUrl, syntheticDatabaseUrl);
});

test("migration confirmation remains mandatory with operator URL", () => {
  const operatorUrl =
    "postgres://operator_user:operator_pass@operator.example.invalid:5432/swooshz_platform";
  assert.throws(
    () =>
      assertMigrationExecutionAllowed({
        NODE_ENV: "production",
        DATABASE_OPERATOR_URL: operatorUrl,
      }),
    /DATABASE_MIGRATIONS_CONFIRM/,
  );
  assert.equal(
    assertMigrationExecutionAllowed({
      NODE_ENV: "production",
      DATABASE_OPERATOR_URL: operatorUrl,
      DATABASE_MIGRATIONS_CONFIRM: DATABASE_MIGRATIONS_CONFIRM_VALUE,
    }).databaseUrl,
    operatorUrl,
  );
});
test("DB client module does not connect during import or pool creation", async () => {
  const pool = createDatabasePool(readDatabaseConfig({ DATABASE_URL: syntheticDatabaseUrl }));

  assert.equal(pool.totalCount, 0);
  assert.equal(pool.idleCount, 0);
  await pool.end();
});

test("migration command is explicit and delegates to guarded config", async () => {
  const script = await readFile("scripts/db-migrate.mjs", "utf8");

  assert.match(script, /assertMigrationExecutionAllowed/);
  assert.match(script, /migrate\(/);
  assert.doesNotMatch(script, /postinstall|prestart|npm test/);
  assert.doesNotMatch(script, /console\.log\(.*DATABASE_URL/);
});

test("pure domain and platform modules do not import DB client or migration runner", async () => {
  const storageAgnosticFiles = [
    "src/accounts/types.ts",
    "src/accounts/normalization.ts",
    "src/apps/types.ts",
    "src/access/decide-app-access.ts",
    "src/platform/repositories.ts",
    "src/platform/app-access-service.ts",
  ];

  for (const filePath of storageAgnosticFiles) {
    const contents = await readFile(filePath, "utf8");

    assert.doesNotMatch(contents, /src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/);
    assert.doesNotMatch(contents, /db\/client|client\.js|client\.ts/);
    assert.doesNotMatch(contents, /\bpg\b|node-postgres/);
    assert.doesNotMatch(contents, /migrator|db-migrate|migrations?/i);
  }
});
