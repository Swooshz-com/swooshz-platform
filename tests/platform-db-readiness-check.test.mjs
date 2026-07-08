import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  REQUIRED_PLATFORM_TABLES,
  createDatabaseReadinessReport,
  formatDatabaseReadinessReport,
} from "../dist/db/readiness.js";
import {
  readExpectedMigrationState,
  runPlatformDatabaseReadinessCheck,
} from "../scripts/platform-db-readiness-check.mjs";

const privateDatabaseUrl =
  ["postgres", "://private_user:private_pass@private-host.invalid:5432/swooshz_platform"].join("");
const privateErrorDetail =
  "connect ECONNREFUSED private-host.invalid private_user private_pass";
const expectedMigrationState = {
  latestTag: "0005_sqag_app_key_migration",
  latestCreatedAt: 1783479304000,
  migrationCount: 6,
};

test("platform DB readiness check package script exists", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(
    packageJson.scripts["platform:db-readiness-check"],
    "npm run build && node scripts/platform-db-readiness-check.mjs",
  );
});

test("DB readiness reports missing config without creating a DB client", async () => {
  let factoryCalls = 0;
  const report = await createDatabaseReadinessReport({
    env: {},
    expectedMigrationState,
    clientFactory() {
      factoryCalls += 1;
      throw new Error("client should not be created");
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "db_config_missing");
  assert.equal(report.checks.config, "missing");
  assert.equal(report.checks.reachability, "not_checked");
  assert.equal(report.checks.schema, "not_checked");
  assert.equal(factoryCalls, 0);
  assertNoUncheckedTableState(formatDatabaseReadinessReport(report).join("\n"));
});

test("DB readiness reports invalid config without leaking the connection string", async () => {
  const report = await createDatabaseReadinessReport({
    env: {
      DATABASE_URL: [
        "https",
        "://private_user:private_pass@private-host.invalid/swooshz_platform",
      ].join(""),
    },
    expectedMigrationState,
    clientFactory() {
      throw new Error("client should not be created");
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "db_config_invalid");
  assert.equal(report.checks.config, "invalid");
  assertNoPrivateMaterial(output);
});

test("DB readiness distinguishes unreachable databases and closes the client", async () => {
  const fixture = createFakeReadinessClient({
    failReachability: true,
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "db_unreachable");
  assert.equal(report.checks.config, "present");
  assert.equal(report.checks.reachability, "failed");
  assert.equal(report.checks.schema, "not_checked");
  assert.equal(fixture.calls.end, 1);
  assertNoUncheckedTableState(output);
  assertNoPrivateMaterial(output);
});

test("DB readiness reports schema not ready when platform tables are missing", async () => {
  const fixture = createFakeReadinessClient({
    existingTables: REQUIRED_PLATFORM_TABLES.filter((table) => table !== "sessions"),
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.reachability, "passed");
  assert.equal(report.checks.schema, "failed");
  assert.deepEqual(report.missingTables, ["sessions"]);
  assert.match(output, /required_tables_present=12\/13/);
  assert.match(output, /missing_tables=sessions/);
  assertNoPrivateMaterial(output);
});

test("DB readiness preserves missing tables when migration metadata is absent", async () => {
  const fixture = createFakeReadinessClient({
    existingTables: [],
    failMigrationState: true,
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.reachability, "passed");
  assert.equal(report.checks.schema, "failed");
  assert.equal(report.checks.migrations, "failed");
  assert.deepEqual(report.missingTables, [...REQUIRED_PLATFORM_TABLES]);
  assert.match(output, /required_tables_present=0\/13/);
  assert.match(output, /missing_tables=users,provider_identities/);
  assertNoPrivateMaterial(output);
});

test("DB readiness reports schema not ready when migrations are behind the journal", async () => {
  const fixture = createFakeReadinessClient({
    latestMigrationCreatedAt: 1782651725342,
    migrationCount: 4,
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migrations, "failed");
  assert.match(output, /migration_state=behind/);
  assert.match(output, /expected_latest_migration=0005_sqag_app_key_migration/);
  assertNoPrivateMaterial(output);
});

test("DB readiness reports ready when reachability tables and migrations match", async () => {
  const fixture = createFakeReadinessClient();
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, true);
  assert.equal(report.status, "ready");
  assert.equal(report.checks.config, "present");
  assert.equal(report.checks.reachability, "passed");
  assert.equal(report.checks.schema, "passed");
  assert.equal(report.checks.migrations, "passed");
  assert.match(output, /readiness_check=pass/);
  assert.match(output, /status=ready/);
  assertNoPrivateMaterial(output);
});

test("DB readiness CLI output is sanitized for failure states", async () => {
  const fixture = createFakeReadinessClient({
    failReachability: true,
  });
  const lines = [];
  const report = await runPlatformDatabaseReadinessCheck({
    env: { DATABASE_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
    writeLine(line) {
      lines.push(line);
    },
    writeError(line) {
      lines.push(line);
    },
  });
  const output = lines.join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "db_unreachable");
  assert.match(output, /readiness_check=fail/);
  assert.match(output, /status=db_unreachable/);
  assertNoPrivateMaterial(output);
});

test("DB readiness reads the latest migration state from the committed journal", async () => {
  const state = await readExpectedMigrationState();

  assert.deepEqual(state, expectedMigrationState);
});

function createFakeReadinessClient(options = {}) {
  const calls = {
    queries: [],
    end: 0,
  };
  const existingTables = options.existingTables ?? REQUIRED_PLATFORM_TABLES;
  const latestMigrationCreatedAt =
    options.latestMigrationCreatedAt ?? expectedMigrationState.latestCreatedAt;
  const migrationCount = options.migrationCount ?? expectedMigrationState.migrationCount;
  const client = {
    async query(sql, params) {
      calls.queries.push({ sql, params });

      if (/select\s+1/i.test(sql)) {
        if (options.failReachability) {
          throw new Error(privateErrorDetail);
        }

        return { rows: [{ ok: 1 }] };
      }

      if (/information_schema\.tables/i.test(sql)) {
        return {
          rows: existingTables.map((tableName) => ({ table_name: tableName })),
        };
      }

      if (/__drizzle_migrations/i.test(sql)) {
        if (options.failMigrationState) {
          throw new Error(privateErrorDetail);
        }

        return {
          rows: [
            {
              applied_count: String(migrationCount),
              latest_created_at: String(latestMigrationCreatedAt),
            },
          ],
        };
      }

      throw new Error(`unexpected query ${sql}`);
    },
    async end() {
      calls.end += 1;
    },
  };

  return { calls, client };
}

function assertNoPrivateMaterial(output) {
  assert.doesNotMatch(output, /private_user|private_pass|private-host/i);
  assert.doesNotMatch(output, /postgres:\/\/[^\\s>]+@/i);
  assert.doesNotMatch(output, /ECONNREFUSED/i);
}

function assertNoUncheckedTableState(output) {
  assert.doesNotMatch(output, /required_tables_present=/);
  assert.doesNotMatch(output, /missing_tables=/);
}
