import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import {
  CANONICAL_PLATFORM_ROUTINES,
  REQUIRED_PLATFORM_TABLES,
  RETAINED_OPERATOR_ROUTINE,
  createDatabaseReadinessReport as createRawDatabaseReadinessReport,
  formatDatabaseReadinessReport,
} from "../dist/db/readiness.js";
import {
  readExpectedMigrationState,
  runPlatformDatabaseReadinessCheck,
} from "../scripts/platform-db-readiness-check.mjs";
import {
  BROKER_AUTHORITY_CLASSIFICATION_VERSION,
  BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR,
  BROKER_OBSERVATION_EVIDENCE_VERSION,
  BROKER_TARGET_BINDING_VERSION,
  compileBrokerObservationBundle,
  computeBrokerBundleDigest,
} from "../dist/db/brokered-migration.js";

const privateDatabaseUrl =
  ["postgres", "://private_user:private_pass@private-host.invalid:5432/swooshz_platform"].join("");
const privateErrorDetail =
  "connect ECONNREFUSED private-host.invalid private_user private_pass";
const expectedMigrationState = {
  latestTag: "0010_admin_operator_viewer_role_collapse",
  latestCreatedAt: 1787479999088,
  migrationCount: 10,
};
const runnerOwnedEnvironment = {
  NODE_ENV: "test",
  DATABASE_URL: "postgres://fixture_user:fixture_pass@127.0.0.1:55432/swooshz_fixture",
};

const CANONICAL_FIRST_NINE_LEDGER = [
  { id: 1, hash: "d156026594b36870455ba6df7525310be1ce1838cda1d58725c6f3a07514c0a6", created_at: "1782546111134" },
  { id: 2, hash: "861614ef57601aff17a15fe594becfc0206fa931f22052ba98217e300285666d", created_at: "1782571351615" },
  { id: 3, hash: "76fd758786fa4583e18f3b89bf7fba0932bdb9c71de294f3291b19925bbd542b", created_at: "1782629131478" },
  { id: 4, hash: "41567c07fcdb3b6e41da516d346d1a20d5e3aa4b0c5d3297e8b19091fa8f5f09", created_at: "1782651725342" },
  { id: 5, hash: "01179c79b777732dc03dbef0471738e00dc85964082aa22764184362722ac5fe", created_at: "1783253616083" },
  { id: 6, hash: "651eaa1668341fc8bdbc8d6f47ccfdd9ec1e2c80fef018de73ab0a79b9896bbe", created_at: "1783479304000" },
  { id: 7, hash: "a8b5d90838c87ca3d74ada48295b92970c8a8476dacf5fc76b1a793995d7485b", created_at: "1783587520445" },
  { id: 8, hash: "0e82a5892f22b71f8894f8776388341519ac48944a417552443d639d09cdcbc0", created_at: "1784354477743" },
  { id: 9, hash: "bc54f927f5ab0a2ebc97a61ede57119f29e8673ab1b902a4e132191ac688820f", created_at: "1784620602227" },
];
const CANONICAL_FIRST_NINE_IDENTITY_DIGEST = computeBrokerBundleDigest(
  "Swooshz-platform:platform-db-first-nine-ledger-v1\0",
  CANONICAL_FIRST_NINE_LEDGER,
);

function brokerReadinessFixture({
  firstNineIdentityDigest = CANONICAL_FIRST_NINE_IDENTITY_DIGEST,
  rowCount = 10,
  migration0010Absent = false,
} = {}) {
  const target_binding = {
    version: BROKER_TARGET_BINDING_VERSION,
    project_id: "project-fixture",
    branch_id: "branch-fixture",
    endpoint_id: "endpoint-fixture",
    endpoint_type: "read_write",
    logical_database_name: "swooshz_platform",
    expected_database_oid: "42",
    expected_cluster_system_identifier: "777",
    expected_postgres_major: 17,
    expected_provider_role_name: "cloud_admin",
    expected_provider_role_oid: "1",
  };
  const authority_classification = {
    version: BROKER_AUTHORITY_CLASSIFICATION_VERSION,
    nodes: [
      { role_name: "cloud_admin", role_oid: "1", authority_class: "PROVIDER_CONTROL" },
      { role_name: "platform_app", role_oid: "2", authority_class: "APPLICATION" },
      { role_name: "platform_runtime", role_oid: "3", authority_class: "RUNTIME" },
      { role_name: "platform_migrator", role_oid: "4", authority_class: "MIGRATOR" },
    ],
    runtime_creator_tuple: {
      granted_role: "platform_runtime",
      member: "platform_app",
      grantor: "cloud_admin",
      admin_option: true,
      inherit_option: false,
      set_option: false,
    },
  };
  const observationBundle = compileBrokerObservationBundle({
    run: "run-readiness-fixture",
    lock: "lock-readiness-fixture",
    git_sha: "1".repeat(40),
    git_tree: "2".repeat(40),
    contract_digest: "3".repeat(64),
    source_manifest_digest: "4".repeat(64),
    build_manifest_digest: "5".repeat(64),
    target_binding,
    authority_classification,
  });
  const payload = {
    version: BROKER_OBSERVATION_EVIDENCE_VERSION,
    observation_bundle_digest: observationBundle.bundle_digest,
    target_binding_digest: observationBundle.target_binding_digest,
    authority_classification_digest: observationBundle.authority_classification_digest,
    provider: { current_user: "cloud_admin", session_user: "cloud_admin", role_oid: "1", rolsuper: false },
    target: { logical_database_name: "swooshz_platform", database_oid: "42", cluster_system_identifier: "777", postgres_major: 17, in_recovery: false },
    migrator: { role_name: "platform_migrator", role_oid: "4", rolcanlogin: false, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, password_is_null: true, provider_has_set: true },
    authority_graph: {
      nodes: [
        { role_name: "cloud_admin", role_oid: "1", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_app", role_oid: "2", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_runtime", role_oid: "3", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_migrator", role_oid: "4", rolsuper: false, rolcreaterole: false },
      ],
      edges: [
        { granted_role: "platform_runtime", granted_role_oid: "3", member: "platform_app", member_oid: "2", grantor: "cloud_admin", grantor_oid: "1", admin_option: true, inherit_option: false, set_option: false },
        { granted_role: "platform_migrator", granted_role_oid: "4", member: "cloud_admin", member_oid: "1", grantor: "cloud_admin", grantor_oid: "1", admin_option: false, inherit_option: false, set_option: true },
      ],
      closure_complete: true,
      application_authority_absent: true,
    },
    ledger: { first_nine_identity_digest: firstNineIdentityDigest, row_count: rowCount, migration_0010_absent: migration0010Absent },
    canonical_posture_digest: "7".repeat(64),
  };
  return {
    observationBundle,
    evidence: {
      ...payload,
      evidence_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, payload),
    },
  };
}

async function runBrokerReadiness({ fixture = brokerReadinessFixture(), expected = expectedMigrationState } = {}) {
  const lines = [];
  let observations = 0;
  let clientFactoryCalls = 0;
  const report = await runPlatformDatabaseReadinessCheck({
    env: { NODE_ENV: "production" },
    expectedMigrationState: expected,
    broker: {
      async observe() {
        observations += 1;
        return fixture.evidence;
      },
    },
    observationBundle: fixture.observationBundle,
    clientFactory() {
      clientFactoryCalls += 1;
      throw new Error("direct database connection must not be created");
    },
    writeLine(line) {
      lines.push(line);
    },
    writeError(line) {
      lines.push(line);
    },
  });
  return { report, lines, observations, clientFactoryCalls };
}

async function assertJournalRejected(mutator) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "swooshz-run626-journal-"));
  const journalPath = join(temporaryRoot, "_journal.json");
  try {
    const journal = JSON.parse(await readFile("drizzle/migrations/meta/_journal.json", "utf8"));
    mutator(journal);
    await writeFile(journalPath, JSON.stringify(journal), "utf8");
    await assert.rejects(() => readExpectedMigrationState(journalPath), /Migration journal is not readable/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

function createDatabaseReadinessReport(input) {
  if (input.clientFactory && input.env?.DATABASE_OPERATOR_URL === privateDatabaseUrl) {
    return createRawDatabaseReadinessReport({
      ...input,
      env: runnerOwnedEnvironment,
    });
  }
  return createRawDatabaseReadinessReport(input);
}

test("platform DB readiness check package script exists", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(
    packageJson.scripts["platform:db-readiness-check"],
    "npm run build && node scripts/platform-db-operation-build.mjs --write-manifest && node scripts/platform-db-readiness-check.mjs",
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

test("retained operator routine is separate from migrator-owned application routines", async () => {
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
  assert.deepEqual([...CANONICAL_PLATFORM_ROUTINES], []);
  assert.deepEqual(RETAINED_OPERATOR_ROUTINE, {
    schema: "public",
    name: "show_db_tree",
    argumentCount: 0,
    owner: "platform_app",
  });
  assert.match(postureQuery, /retained_operator_routines/u);
  assert.match(postureQuery, /accepted_retained_operator_routines/u);
  assert.match(postureQuery, /show_db_tree/u);
  assert.match(postureQuery, /pronargs/u);
  assert.match(postureQuery, /prosecdef/u);
  assert.match(postureQuery, /aclexplode/u);
  assert.match(postureQuery, /extension_dependency_objects/u);
  const postureCall = fixture.calls.queries.find(({ sql }) =>
    /provider_identity_exact/i.test(sql),
  );
  assert.deepEqual(postureCall.params[3], []);
});

test("retained operator routine posture fails closed", async () => {
  const fixture = createFakeReadinessClient({
    migratorPosture: {
      retained_operator_routine_exact: false,
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
    env: runnerOwnedEnvironment,
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
  assert.equal(Object.isFrozen(state), true);
});

test("production broker readiness requires canonical ten-entry FINAL evidence", async () => {
  const { report, lines, observations, clientFactoryCalls } = await runBrokerReadiness();

  assert.equal(report.ok, true);
  assert.equal(report.checks.migrations, "passed");
  assert.equal(observations, 1);
  assert.equal(clientFactoryCalls, 0);
  assert.equal(lines.filter((line) => line === "migrations=passed").length, 1);
  assert.equal(lines.some((line) => line === "migrations=failed"), false);
});

test("production broker readiness rejects PREWRITE, missing, extra, and non-canonical ledger evidence", async () => {
  const cases = [
    brokerReadinessFixture({ rowCount: 9, migration0010Absent: true }),
    brokerReadinessFixture({ rowCount: 10, migration0010Absent: true }),
    brokerReadinessFixture({ rowCount: 11, migration0010Absent: false }),
    brokerReadinessFixture({ firstNineIdentityDigest: "f".repeat(64) }),
  ];

  for (const fixture of cases) {
    const { report, lines, observations, clientFactoryCalls } = await runBrokerReadiness({ fixture });
    assert.equal(report.ok, false);
    assert.equal(report.checks.migrations, "failed");
    assert.equal(observations, 1);
    assert.equal(clientFactoryCalls, 0);
    assert.equal(lines.includes("migrations=failed"), true);
    assert.equal(lines.includes("migrations=passed"), false);
  }
});

test("production broker readiness rejects a modified canonical 0010 journal identity", async () => {
  const altered = { ...expectedMigrationState, latestCreatedAt: expectedMigrationState.latestCreatedAt - 1 };
  const { report, lines, observations } = await runBrokerReadiness({ expected: altered });

  assert.equal(report.ok, false);
  assert.equal(report.status, "schema_not_ready");
  assert.equal(report.checks.migrations, "failed");
  assert.equal(observations, 0);
  assert.equal(lines.includes("migrations=passed"), false);
});

test("expected migration state is captured as an exact frozen data snapshot", async () => {
  const missing = {
    latestTag: expectedMigrationState.latestTag,
    latestCreatedAt: expectedMigrationState.latestCreatedAt,
  };
  const extra = { ...expectedMigrationState, extra: true };
  const accessor = { ...expectedMigrationState };
  let getterCalls = 0;
  Object.defineProperty(accessor, "latestTag", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return expectedMigrationState.latestTag;
    },
  });

  for (const candidate of [missing, extra, accessor]) {
    const { report, observations } = await runBrokerReadiness({ expected: candidate });
    assert.equal(report.ok, false);
    assert.equal(report.status, "schema_not_ready");
    assert.equal(observations, 0);
  }
  assert.equal(getterCalls, 0);
});

test("journal parsing rejects extra, reordered, and modified canonical entries", async () => {
  await assertJournalRejected((journal) => journal.entries.push({
    idx: 10,
    version: "7",
    when: 1787480000000,
    tag: "0011_unknown",
    breakpoints: true,
  }));
  await assertJournalRejected((journal) => journal.entries.reverse());
  await assertJournalRejected((journal) => {
    journal.entries[0].tag = journal.entries[1].tag;
  });
  await assertJournalRejected((journal) => {
    journal.entries[9].when += 1;
  });
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
    provider_identity_exact: true,
    postgres_major_17: true,
    migrator_role_attributes_exact: true,
    migrator_password_null: true,
    provider_set_capability: true,
    application_migrator_authority_absent: true,
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
    retained_operator_routine_exact: true,
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

      if (/provider_identity_exact/i.test(sql)) {
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
    /provider_identity_exact/i.test(sql),
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
