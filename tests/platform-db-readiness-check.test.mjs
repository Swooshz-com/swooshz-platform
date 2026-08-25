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
  latestTag: "0010_admin_operator_viewer_role_collapse",
  latestCreatedAt: 1787479999088,
  migrationCount: 10,
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
      DATABASE_OPERATOR_URL: [
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
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
  assert.match(output, /required_tables_present=13\/14/);
  assert.match(output, /missing_tables=sessions/);
  assertNoPrivateMaterial(output);
});

test("DB readiness preserves missing tables when migration metadata is absent", async () => {
  const fixture = createFakeReadinessClient({
    existingTables: [],
    failMigrationState: true,
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
  assert.match(output, /required_tables_present=0\/14/);
  assert.match(output, /missing_tables=users,provider_identities/);
  assertNoPrivateMaterial(output);
});

test("current ledger still fails readiness when access validation grants are absent", async () => {
  const fixture = createFakeReadinessClient({
    existingTables: REQUIRED_PLATFORM_TABLES.filter(
      (table) => table !== "access_validation_grants",
    ),
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migrations, "passed");
  assert.deepEqual(report.missingTables, ["access_validation_grants"]);
});

test("production readiness fails closed without DATABASE_OPERATOR_URL", async () => {
  let factoryCalls = 0;
  const report = await createDatabaseReadinessReport({
    env: {
      NODE_ENV: "production",
      DATABASE_URL: privateDatabaseUrl,
    },
    expectedMigrationState,
    clientFactory() {
      factoryCalls += 1;
      throw new Error("client should not be created");
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "db_config_missing");
  assert.equal(factoryCalls, 0);
});
test("DB readiness reports schema not ready when migrations are behind the journal", async () => {
  const fixture = createFakeReadinessClient({
    latestMigrationCreatedAt: 1782651725342,
    migrationCount: 4,
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
  assert.match(
    output,
    new RegExp(`expected_latest_migration=${expectedMigrationState.latestTag}`),
  );
  assertNoPrivateMaterial(output);
});

test("DB readiness reports ready when reachability tables and migrations match", async () => {
  const fixture = createFakeReadinessClient();
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
  assert.equal(report.checks.migratorPosture, "passed");
  assert.match(output, /readiness_check=pass/);
  assert.match(output, /status=ready/);
  assertNoPrivateMaterial(output);
});
test("production-shaped canonical readiness does not require synthetic appdata", async () => {
  const fixture = createFakeReadinessClient({
    productionSchemas: ["public", "drizzle"],
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const postureQuery = getMigratorPostureQuery(fixture);

  assert.equal(report.ok, true);
  assert.equal(report.status, "ready");
  assert.doesNotMatch(postureQuery, /\bappdata\b/u);
});

test("missing canonical enum presence remains fail closed", async () => {
  const fixture = createFakeReadinessClient({
    migratorPosture: {
      canonical_enum_presence_exact: false,
    },
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migratorPosture, "failed");
});

test("canonical enum presence and ownership are required readiness inputs", async () => {
  const missingFixture = createFakeReadinessClient({
    migratorPosture: {
      canonical_enum_presence_exact: false,
    },
  });
  const missingReport = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return missingFixture.client;
    },
  });
  assert.equal(missingReport.checks.migratorPosture, "failed");

  const wrongOwnerFixture = createFakeReadinessClient({
    migratorPosture: {
      canonical_enum_presence_exact: false,
    },
  });
  const wrongOwnerReport = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return wrongOwnerFixture.client;
    },
  });
  assert.equal(wrongOwnerReport.checks.migratorPosture, "failed");
});

test("unknown non-extension relation drift remains fail closed", async () => {
  const fixture = createFakeReadinessClient({
    migratorPosture: {
      unknown_application_relation_drift_absent: false,
    },
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migratorPosture, "failed");
});

test("unknown non-extension routine drift remains fail closed", async () => {
  const fixture = createFakeReadinessClient({
    migratorPosture: {
      unknown_application_routine_drift_absent: false,
    },
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migratorPosture, "failed");
});

test("readiness classification explicitly separates extension, system, and dependency objects", async () => {
  const fixture = createFakeReadinessClient();
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const postureQuery = getMigratorPostureQuery(fixture);

  assert.equal(report.ok, true);
  assert.match(postureQuery, /pg_extension/u);
  assert.match(postureQuery, /pg_depend/u);
  assert.match(postureQuery, /deptype/u);
  assert.match(postureQuery, /nspname in \('public', 'drizzle'\)/u);
  assert.doesNotMatch(postureQuery, /nspname in \('public', 'appdata', 'drizzle'\)/u);
});
test("DB readiness fails closed when migrator posture drifts", async () => {
  const fixture = createFakeReadinessClient({
    migratorPosture: { database_owner_platform_app: false },
  });
  const report = await createDatabaseReadinessReport({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
    expectedMigrationState,
    clientFactory() {
      return fixture.client;
    },
  });
  const output = formatDatabaseReadinessReport(report).join("\n");

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.schema, "passed");
  assert.equal(report.checks.migrations, "passed");
  assert.equal(report.checks.migratorPosture, "failed");
  assert.match(output, /migrator_posture=failed/);
});


test("DB readiness CLI output is sanitized for failure states", async () => {
  const fixture = createFakeReadinessClient({
    failReachability: true,
  });
  const lines = [];
  const report = await runPlatformDatabaseReadinessCheck({
    env: { DATABASE_OPERATOR_URL: privateDatabaseUrl },
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
  const migratorPosture = {
    migrator_identity_exact: true,
    postgres_major_17: true,
    migrator_role_attributes_exact: true,
    migrator_creator_admin_edge_exact: true,
    migrator_database_connect_exact: true,
    migrator_database_create_absent: true,
    migrator_database_temporary_absent: true,
    database_owner_platform_app: true,
    public_schema_owner_pg_database_owner: true,
    migrator_public_schema_authority: true,
    drizzle_schema_migrator_authority: true,
    canonical_drizzle_ledger_relation_exact: true,
    canonical_dependent_relation_extension_membership_absent: true,
    application_schema_authority_exact: true,
    migration_ledger_owner_migrator: true,
    application_namespace_relation_owner_exact: true,
    required_application_table_owner_exact: true,
    canonical_enum_presence_exact: true,
    application_type_owner_exact: true,
    application_routine_owner_exact: true,
    unknown_application_relation_drift_absent: true,
    unknown_application_type_drift_absent: true,
    unknown_application_routine_drift_absent: true,
    public_relation_authority_absent: true,
    public_routine_authority_absent: true,
    public_default_acl_authority_absent: true,
    migrator_grant_option_absent: true,
    public_schema_acl_least_privilege: true,
    runtime_migration_ledger_access_absent: true,
    runtime_application_ownership_zero: true,
    ...(options.migratorPosture ?? {}),
  };
  const client = {
    async query(sql, params) {
      calls.queries.push({ sql, params });

      if (/migrator_identity_exact/i.test(sql)) {
        const posture = { ...migratorPosture };
        if (
          Array.isArray(options.productionSchemas) &&
          /\bappdata\b/u.test(sql)
        ) {
          posture.application_schema_authority_exact =
            options.productionSchemas.includes("appdata");
        }
        return { rows: [posture] };
      }
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
function getMigratorPostureQuery(fixture) {
  const postureQuery = fixture.calls.queries.find(({ sql }) =>
    /migrator_identity_exact/i.test(sql),
  )?.sql;
  assert.equal(typeof postureQuery, "string");
  return postureQuery;
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
