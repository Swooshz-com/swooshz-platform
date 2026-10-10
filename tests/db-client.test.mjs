import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DatabaseConfigError,
  DATABASE_MIGRATIONS_CONFIRM_VALUE,
  assertRunnerOwnedFixtureMigrationExecutionAllowed,
  createDatabasePool,
  readDatabaseConfig,
  readRunnerOwnedFixtureDatabaseConfig,
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

const runnerOwnedFixture = {
  version: "runner-owned-database-fixture-v1",
  owner: "disposable-postgres-runner",
  databaseUrl: "postgres://fixture_user:fixture_pass@127.0.0.1:55432/swooshz_fixture",
};
const runnerEnvironment = {
  NODE_ENV: "test",
  RUNNER_OWNED_DATABASE_FIXTURE: "disposable-postgres-runner",
};

test("production direct operator credentials are rejected without parsing or leaking them", () => {
  assert.throws(
    () => readRunnerOwnedFixtureDatabaseConfig({ ...runnerEnvironment, DATABASE_OPERATOR_URL: syntheticDatabaseUrl }, runnerOwnedFixture),
    (error) => {
      assert.equal(error instanceof DatabaseConfigError, true);
      assert.equal(error.code, "direct_database_credential_prohibited");
      assert.doesNotMatch(error.message, /example_pass|db\.example\.invalid/);
      return true;
    },
  );
});

test("runner-owned direct execution requires test mode, runner proof, and loopback target", () => {
  assert.throws(
    () => readRunnerOwnedFixtureDatabaseConfig({ NODE_ENV: "production" }, runnerOwnedFixture),
    (error) => {
      assert.equal(error instanceof DatabaseConfigError, true);
      assert.equal(error.code, "runner_owned_fixture_required");
      return true;
    },
  );
  assert.throws(
    () => readRunnerOwnedFixtureDatabaseConfig(runnerEnvironment, { ...runnerOwnedFixture, databaseUrl: syntheticDatabaseUrl }),
    (error) => {
      assert.equal(error instanceof DatabaseConfigError, true);
      assert.equal(error.code, "runner_owned_fixture_required");
      return true;
    },
  );
  assert.equal(
    readRunnerOwnedFixtureDatabaseConfig(runnerEnvironment, runnerOwnedFixture).databaseUrl,
    runnerOwnedFixture.databaseUrl,
  );
});

test("runner-owned migration confirmation remains mandatory", () => {
  assert.throws(
    () => assertRunnerOwnedFixtureMigrationExecutionAllowed(runnerEnvironment, runnerOwnedFixture),
    /DATABASE_MIGRATIONS_CONFIRM/,
  );
  assert.equal(
    assertRunnerOwnedFixtureMigrationExecutionAllowed({
      ...runnerEnvironment,
      DATABASE_MIGRATIONS_CONFIRM: DATABASE_MIGRATIONS_CONFIRM_VALUE,
    }, runnerOwnedFixture).databaseUrl,
    runnerOwnedFixture.databaseUrl,
  );
});
test("DB client module does not connect during import or pool creation", async () => {
  const pool = createDatabasePool(readDatabaseConfig({ DATABASE_URL: syntheticDatabaseUrl }));

  assert.equal(pool.options.enableChannelBinding, true);
  assert.equal(pool.options.ssl, undefined);
  assert.equal(pool.totalCount, 0);
  assert.equal(pool.idleCount, 0);
  await pool.end();
});

test("DB client preserves explicit SSL-mode construction semantics", async () => {
  const requiredPool = createDatabasePool({
    databaseUrl: syntheticDatabaseUrl,
    sslMode: "require",
  });
  const disabledPool = createDatabasePool({
    databaseUrl: syntheticDatabaseUrl,
    sslMode: "disable",
  });

  try {
    assert.equal(requiredPool.options.ssl, true);
    assert.equal(disabledPool.options.ssl, false);
    assert.equal(requiredPool.options.enableChannelBinding, true);
    assert.equal(disabledPool.options.enableChannelBinding, true);
    assert.equal(requiredPool.totalCount, 0);
    assert.equal(requiredPool.idleCount, 0);
    assert.equal(disabledPool.totalCount, 0);
    assert.equal(disabledPool.idleCount, 0);
  } finally {
    await Promise.all([requiredPool.end(), disabledPool.end()]);
  }
});

test("migration command fails closed without a provider broker and has no direct pg path", async () => {
  const script = await readFile("scripts/db-migrate.mjs", "utf8");

  assert.match(script, /provider broker adapter/);
  assert.match(script, /DATABASE_OPERATOR_URL/);
  assert.doesNotMatch(script, /createDatabaseClient|new Pool|migrate\(/);
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
