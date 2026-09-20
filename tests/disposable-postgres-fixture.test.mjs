import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { mock } from "node:test";
import { Client, Pool } from "pg";
import { inspect } from "node:util";

import {
  DisposablePostgresFixtureAdmissionError,
  admitDisposablePostgresConstructionTargets,
  admitDisposablePostgresFixture,
  admitDisposablePostgresFixtures,
  createAuthorizedDatabaseCreationPool,
  createAuthorizedProvisioningPool,
  createAdmittedMutationClient,
  createAdmittedMutationPool,
  deriveDisposablePostgresDatabaseCreationAuthority,
  deriveDisposablePostgresProvisioningAuthority,
  deriveDisposablePostgresTargetAuthority,
  invalidateDisposablePostgresAdmission,
  invalidateDisposablePostgresConstructionAdmission,
  parseDisposablePostgresUrl,
  requireDisposablePostgresAdmission,
  withDisposablePostgresFixtureMigration,
  withDisposablePostgresFixturesAdmitted,
} from "./support/disposable-postgres-fixture.mjs";

const baseFixture = Object.freeze({
  name: "primary",
  connectionString:
    "postgres://platform_app@127.0.0.1:5432/runtime_posture_test",
  expectedDatabase: "runtime_posture_test",
  expectedUser: "platform_app",
  expectedRuntimeRole: "platform_runtime",
  expectedObjects: {
    schemas: ["public", "drizzle"],
    relations: [
      { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
    ],
    sequences: [],
    routines: [],
  },
  transport: { kind: "loopback", phase: "initialization" },
});

const passingProbe = async ({ fixture } = {}) => ({
  databaseMatches: true,
  userMatches: true,
  postgres17: true,
  nonRecovery: true,
  catalogIdentityPresent: true,
  lifecycleIdentityPresent: true,
  runtimePosturePassed: true,
  ownershipAbsent: true,
  expectedObjectsPresent: true,
  targetDatabasePresent: true,
  catalogFingerprint: fixture?.connectionString ?? "catalog-1",
  lifecycleFingerprint: fixture?.connectionString ?? "lifecycle-1",
});

function createProbeClient(target) {
  const parsed = new URL(target.probeConnectionString ?? target.connectionString);
  let released = false;
  return {
    connectionParameters: {
      database: decodeURIComponent(parsed.pathname.slice(1)),
      host: parsed.hostname,
      port: parsed.port || "5432",
      user: decodeURIComponent(parsed.username),
    },
    async query(text) {
      const normalized = String(text).trim().toLowerCase();
      if (normalized === "show transaction_read_only") {
        return { rows: [{ transaction_read_only: "on" }] };
      }
      return { rows: [] };
    },
    release() {
      released = true;
    },
    wasReleased() {
      return released;
    },
  };
}

function createRealPasswordlessProbeClient(target) {
  const parsed = new URL(target.probeConnectionString ?? target.connectionString);
  const client = new Client({
    database: decodeURIComponent(parsed.pathname.slice(1)),
    host: parsed.hostname,
    port: Number(parsed.port || "5432"),
    user: decodeURIComponent(parsed.username),
  });
  const passwordDescriptor = Object.getOwnPropertyDescriptor(
    client.connectionParameters,
    "password",
  );
  assert.ok(passwordDescriptor);
  assert.equal(passwordDescriptor.enumerable, false);
  Object.defineProperty(client.connectionParameters, "password", {
    ...passwordDescriptor,
    value: null,
  });
  client.query = async (text) => {
    const normalized = String(text).trim().toLowerCase();
    if (normalized === "show transaction_read_only") {
      return { rows: [{ transaction_read_only: "on" }] };
    }
    if (normalized.includes("current_database()")) {
      return {
        rows: [{
          catalog_fingerprint: target.connectionString,
          database_matches: true,
          lifecycle_fingerprint: target.connectionString,
          non_recovery: true,
          postgres17: true,
          user_matches: true,
        }],
      };
    }
    return { rows: [] };
  };
  client.release = () => {};
  return client;
}

function createBoundaryClient({
  cleanupMethod = "release",
  readOnlyValue = "on",
  rejectCleanup = false,
  rejectQuery,
} = {}) {
  const calls = [];
  let released = false;
  const client = {
    calls,
    async query(text) {
      const normalized = String(text).trim().toLowerCase();
      calls.push(normalized);
      if (normalized === rejectQuery) throw new Error();
      if (normalized === "show transaction_read_only") {
        return { rows: [{ transaction_read_only: readOnlyValue }] };
      }
      return { rows: [] };
    },
    wasReleased() {
      return released;
    },
  };
  client[cleanupMethod] = () => {
    released = true;
    if (rejectCleanup) throw new Error();
  };
  return client;
}

const migrationTargetDefaults = Object.freeze({
  connectionString:
    "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test",
  expectedDatabase: "runtime_posture_test",
  expectedUser: "cloud_admin",
  migrationsFolder: "./drizzle/migrations",
  phase: "initialization",
});

const passingMigrationIdentity = Object.freeze({
  database_matches: true,
  user_matches: true,
  postgres17: true,
  non_recovery: true,
  catalog_fingerprint: "100",
  lifecycle_fingerprint: "200",
});

async function runMigrationPoolHarness({
  input = migrationTargetDefaults,
  operation = async () => ({ ok: true }),
  identityRows = [passingMigrationIdentity, passingMigrationIdentity],
  endError,
} = {}) {
  const state = {
    endCalls: 0,
    error: undefined,
    identityCalls: 0,
    migrationCalls: 0,
    poolCount: 0,
    poolOptions: [],
    returned: undefined,
  };
  const pools = new WeakMap();
  let nextPoolId = 0;

  const query = async function query(text) {
    const queryText = typeof text === "string" ? text : text?.text ?? "";
    if (!pools.has(this)) {
      nextPoolId += 1;
      pools.set(this, nextPoolId);
    }
    const options = this.options ?? {};
    state.poolOptions.push({
      database: options.database,
      hasConnectionString: Object.hasOwn(options, "connectionString"),
      hasPassword: Object.hasOwn(options, "password"),
      host: options.host,
      max: options.max,
      password: options.password,
      poolId: pools.get(this),
      port: options.port,
      user: options.user,
    });
    if (queryText.includes("current_database()")) {
      const row = identityRows[Math.min(
        state.identityCalls,
        identityRows.length - 1,
      )];
      state.identityCalls += 1;
      return { rows: [{ ...row }] };
    }
    state.migrationCalls += 1;
    return { rows: [] };
  };

  mock.method(Pool.prototype, "query", query);
  mock.method(Pool.prototype, "connect", async function connect() {
    return {
      query: query.bind(this),
      release() {},
    };
  });
  mock.method(Pool.prototype, "end", async function end() {
    state.endCalls += 1;
    if (endError) throw endError;
  });

  try {
    state.returned = await withDisposablePostgresFixtureMigration(
      input,
      operation,
    );
  } catch (error) {
    state.error = error;
  } finally {
    state.poolCount = nextPoolId;
    mock.restoreAll();
  }

  return state;
}

function sourceSection(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.equal(start >= 0 && end > start, true);
  return source.slice(start, end);
}

function publicErrorSurface(error) {
  const values = [
    error?.name,
    error?.message,
    error?.code,
    error?.stack,
  ];
  try {
    values.push(JSON.stringify(error));
  } catch {
    values.push("<unserializable>");
  }
  try {
    values.push(inspect(error));
  } catch {
    values.push("<uninspectable>");
  }
  return values.filter((value) => typeof value === "string").join("\n");
}

function assertPrivateAdmissionFailure(error, secrets = []) {
  const surface = publicErrorSurface(error);
  assert.equal(error instanceof DisposablePostgresFixtureAdmissionError, true);
  assert.equal(error?.name === "DisposablePostgresFixtureAdmissionError", true);
  assert.equal(error?.code === "disposable_fixture_admission_failed", true);
  assert.equal(error?.message === "Disposable fixture admission failed.", true);
  for (const secret of secrets) {
    assert.equal(surface.includes(secret), false);
  }
}

async function captureProcessSurfaces(operation) {
  const captured = { console: [], stderr: [], stdout: [] };
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  const originalStderrWrite = process.stderr.write;
  const originalStdoutWrite = process.stdout.write;
  const envBefore = Object.values(process.env).join("\n");
  console.error = (...values) => {
    captured.console.push(values.map((value) => String(value)).join(" "));
  };
  console.log = (...values) => {
    captured.console.push(values.map((value) => String(value)).join(" "));
  };
  process.stderr.write = (value) => {
    captured.stderr.push(String(value));
    return true;
  };
  process.stdout.write = (value) => {
    captured.stdout.push(String(value));
    return true;
  };
  let result;
  let error;
  try {
    result = await operation();
  } catch (caught) {
    error = caught;
  } finally {
    console.error = originalConsoleError;
    console.log = originalConsoleLog;
    process.stderr.write = originalStderrWrite;
    process.stdout.write = originalStdoutWrite;
  }
  captured.envBefore = envBefore;
  captured.envAfter = Object.values(process.env).join("\n");
  return { captured, error, result };
}

test("disposable fixture admission rejects ambiguous, remote, socket, and unattested targets", () => {
  const rejected = [
    [
      "postgres://platform_app@localhost:5432/runtime_posture_test",
      { kind: "loopback", phase: "initialization" },
    ],
    [
      "postgres://platform_app@10.0.0.9:5432/runtime_posture_test",
      { kind: "loopback", phase: "initialization" },
    ],
    [
      "postgres:///runtime_posture_test?host=%2Fvar%2Frun%2Fpostgresql",
      { kind: "loopback", phase: "initialization" },
    ],
    [
      "postgres://platform_app@unattested-postgres:5432/runtime_posture_test",
      { kind: "managed-container", phase: "initialization" },
    ],
  ];

  for (const [connectionString, transport] of rejected) {
    assert.throws(
      () =>
        parseDisposablePostgresUrl(connectionString, {
          expectedDatabase: "runtime_posture_test",
          expectedUser: "platform_app",
          phase: "initialization",
          transport,
        }),
      safeAdmissionError,
    );
  }
});

test("fixture migration scope rejects caller-supplied authority and transport", async () => {
  const baseMigrationTarget = {
    connectionString:
      "postgres://cloud_admin@127.0.0.1:5432/runtime_posture_test",
    expectedDatabase: "runtime_posture_test",
    expectedUser: "cloud_admin",
    migrationsFolder: "./drizzle",
    phase: "initialization",
  };

  for (const rejectedTarget of [
    { ...baseMigrationTarget, pool: Object.freeze({}) },
    { ...baseMigrationTarget, operatorUrl: "postgres://operator@127.0.0.1:5432/postgres" },
    { ...baseMigrationTarget, authority: Object.freeze({}) },
    { ...baseMigrationTarget, capability: Object.freeze({}) },
    { ...baseMigrationTarget, probe: async () => ({}) },
    { ...baseMigrationTarget, query: async () => ({}) },
    { ...baseMigrationTarget, connect: async () => ({}) },
    { ...baseMigrationTarget, clientFactory: async () => ({}) },
    { ...baseMigrationTarget, transport: Object.freeze({}) },
    { ...baseMigrationTarget, connectionString: "postgres://cloud_admin@remote:5432/runtime_posture_test" },
    { ...baseMigrationTarget, connectionString: "postgres://cloud_admin@localhost:5432/runtime_posture_test" },
    { ...baseMigrationTarget, connectionString: "postgres://cloud_admin:uri-secret@127.0.0.1:5432/runtime_posture_test" },
    { ...baseMigrationTarget, connectionString: "postgres://cloud_admin/runtime_posture_test" },
    { ...baseMigrationTarget, phase: "final_start" },
  ]) {
    await assert.rejects(
      () => withDisposablePostgresFixtureMigration(rejectedTarget, async () => {}),
      safeAdmissionError,
    );
  }
});

test("migration helper contract binds structured Pool construction and authority ordering", async () => {
  const helperSource = await readFile(
    "tests/support/disposable-postgres-fixture.mjs",
    "utf8",
  );
  const migrationSource = sourceSection(
    helperSource,
    "export async function withDisposablePostgresFixtureMigration(",
    "\nfunction normalizeMigrationTarget",
  );
  const targetSource = sourceSection(
    helperSource,
    "function normalizeMigrationTarget",
    "\nfunction readMigrationConnectionPassword",
  );
  const passwordSource = sourceSection(
    helperSource,
    "function readMigrationConnectionPassword",
    "\nasync function readMigrationAuthorityIdentity",
  );
  const identitySource = sourceSection(
    helperSource,
    "async function readMigrationAuthorityIdentity",
    "\nasync function runScopedFixtureMigration",
  );
  const scopedMigrationSource = sourceSection(
    helperSource,
    "async function runScopedFixtureMigration",
    "\nexport function parseDisposablePostgresUrl",
  );
  const authorityRecordSource = sourceSection(
    helperSource,
    "migrationAuthorityValues.set(authority, {",
    "});",
  );

  assert.equal(/import \{ Client, Pool \} from "pg";/u.test(helperSource), true);
  assert.equal(
    /const poolOptions = \{\s*host: target\.hostname,\s*port: Number\(target\.port\),\s*user: target\.expectedUser,\s*database: target\.expectedDatabase,\s*max: 1,\s*\};/su.test(migrationSource),
    true,
  );
  assert.equal(/pool = new Pool\(poolOptions\);/u.test(migrationSource), true);
  assert.equal(
    /if \(connectionPassword !== undefined\) \{\s*poolOptions\.password = connectionPassword;\s*\}/su.test(migrationSource),
    true,
  );
  assert.equal(
    !/(?:connectionString|pg-connection-string|new URL|Object\.assign|Object\.fromEntries|\.\.\.)/u.test(migrationSource),
    true,
  );
  const constructionStart = migrationSource.indexOf("const poolOptions");
  const constructionEnd = migrationSource.indexOf("pool = new Pool", constructionStart);
  assert.equal(constructionStart >= 0 && constructionEnd > constructionStart, true);
  assert.equal(
    !/(?:trim|encodeURIComponent|decodeURIComponent|String\()/u.test(
      migrationSource.slice(constructionStart, constructionEnd),
    ),
    true,
  );

  for (const pattern of [
    /\["postgres:", "postgresql:"\]\.includes\(parsed\.protocol\)/u,
    /parsed\.password\s*\|\|\s*parsed\.search\s*\|\|\s*parsed\.hash/su,
    /!loopbackHosts\.has\(hostname\)/u,
    /!port/u,
    /!validPort\(port\)/u,
    /username !== expectedUser/u,
    /database !== expectedDatabase/u,
    /parsed\.pathname !== `\/\$\{database\}`/u,
  ]) {
    assert.equal(pattern.test(targetSource), true);
  }
  assert.equal(/password !== undefined/u.test(passwordSource), true);
  assert.equal(/typeof password !== "string"/u.test(passwordSource), true);
  assert.equal(/password\.trim\(\)\.length === 0/u.test(passwordSource), true);

  for (const pattern of [
    /result\?\.rows\?\.length !== 1/u,
    /row\?\.database_matches !== true/u,
    /row\?\.user_matches !== true/u,
    /row\?\.postgres17 !== true/u,
    /row\?\.non_recovery !== true/u,
    /typeof row\.catalog_fingerprint !== "string"/u,
    /\/\^\\d\+\$\/u\.test\(row\.catalog_fingerprint\)/u,
    /typeof row\.lifecycle_fingerprint !== "string"/u,
    /\/\^\\d\+\$\/u\.test\(row\.lifecycle_fingerprint\)/u,
  ]) {
    assert.equal(pattern.test(identitySource), true);
  }

  const firstIdentity = migrationSource.indexOf(
    "const identity = await readMigrationAuthorityIdentity(pool, target);",
  );
  const authorityCreation = migrationSource.indexOf(
    "authority = Object.freeze({});",
  );
  const scopedMigration = migrationSource.indexOf(
    "await runScopedFixtureMigration(authority, pool, target.migrationsFolder, target);",
  );
  assert.equal(
    firstIdentity >= 0 && firstIdentity < authorityCreation &&
      authorityCreation < scopedMigration,
    true,
  );
  assert.equal(
    (scopedMigrationSource.match(/readMigrationAuthorityIdentity\(pool, target\)/gu) ?? []).length,
    1,
  );
  for (const pattern of [
    /value\.authority !== authority/u,
    /!value\.valid/u,
    /value\.pool !== pool/u,
    /value\.database !== target\.expectedDatabase/u,
    /value\.user !== target\.expectedUser/u,
    /identity\.catalogFingerprint !== value\.clusterFingerprint/u,
    /identity\.lifecycleFingerprint !== value\.lifecycleFingerprint/u,
    /await migrate\(drizzle\(pool\), \{ migrationsFolder \}\);/u,
  ]) {
    assert.equal(pattern.test(scopedMigrationSource), true);
  }
  assert.equal(/authority = Object\.freeze\(\{\}\)/u.test(migrationSource), true);
  assert.equal(/migrationAuthorityValues\.set\(authority, \{/u.test(helperSource), true);
  assert.equal(/value\.valid = false/u.test(migrationSource), true);
  assert.equal(/pool\.end\(\)\.catch\(\(\) => \{\}\)/u.test(migrationSource), true);
  assert.equal(/connectionPassword/u.test(authorityRecordSource), false);
  assert.equal(/return await operation\(\)/u.test(migrationSource), true);
  assert.equal(
    !/(?:process\.env|console\.|JSON\.stringify|writeFile|createWriteStream|createHash|createHmac)/u.test(
      `${migrationSource}\n${authorityRecordSource}`,
    ),
    true,
  );
});

test("migration connection credentials are optional, validated, and private", async () => {
  const baseMigrationTarget = {
    connectionString:
      "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test",
    expectedDatabase: "runtime_posture_test",
    expectedUser: "cloud_admin",
    migrationsFolder: "./drizzle",
    phase: "initialization",
  };
  const syntheticPassword = "Operator_A1!synthetic-only";

  await assert.rejects(
    () => withDisposablePostgresFixtureMigration(
      { ...baseMigrationTarget, connectionPassword: syntheticPassword },
      async () => {},
    ),
    (error) => {
      safeAdmissionError(error);
      assert.equal(
        !`${error.message}\n${error.stack ?? ""}`.includes("synthetic-only"),
        true,
      );
      return true;
    },
  );

  for (const connectionPassword of ["", "   ", null, 42, false, {}, [], () => {}]) {
    await assert.rejects(
      () => withDisposablePostgresFixtureMigration(
        { ...baseMigrationTarget, connectionPassword },
        async () => {},
      ),
      safeAdmissionError,
    );
  }
});

test("migration helper admits only undefined or nonblank credentials before transport", async () => {
  const invalidCredentials = ["", "   ", null, 42, false, {}, [], () => {}];
  for (const connectionPassword of invalidCredentials) {
    const state = await runMigrationPoolHarness({
      input: { ...migrationTargetDefaults, connectionPassword },
    });
    assertPrivateAdmissionFailure(state.error);
    assert.equal(state.poolCount === 0, true);
    assert.equal(state.identityCalls === 0, true);
    assert.equal(state.migrationCalls === 0, true);
    assert.equal(state.endCalls === 0, true);
  }

  const noCredential = await runMigrationPoolHarness({
    input: { ...migrationTargetDefaults, connectionPassword: undefined },
  });
  assert.equal(noCredential.error === undefined, true);
  assert.equal(noCredential.returned?.ok === true, true);
  assert.equal(noCredential.endCalls === 1, true);
  assert.equal(noCredential.identityCalls === 2, true);
  assert.equal(noCredential.migrationCalls > 0, true);
  assert.equal(noCredential.poolOptions[0]?.hasPassword === false, true);
  assert.equal(noCredential.poolOptions[0]?.hasConnectionString === false, true);

  const syntheticPassword = "  Operator_A1!synthetic-whitespace  ";
  const whitespaceCredential = await runMigrationPoolHarness({
    input: {
      ...migrationTargetDefaults,
      connectionPassword: syntheticPassword,
    },
  });
  assert.equal(whitespaceCredential.error === undefined, true);
  assert.equal(whitespaceCredential.poolCount === 1, true);
  assert.equal(whitespaceCredential.identityCalls === 2, true);
  assert.equal(whitespaceCredential.migrationCalls > 0, true);
  assert.equal(whitespaceCredential.endCalls === 1, true);
  assert.equal(
    whitespaceCredential.poolOptions.every((options) =>
      options.host === "127.0.0.1" &&
      options.port === 1 &&
      options.user === "cloud_admin" &&
      options.database === "runtime_posture_test" &&
      options.max === 1 &&
      options.hasConnectionString === false &&
      options.hasPassword === true &&
      options.password === syntheticPassword
    ),
    true,
  );
  assert.equal(
    new Set(whitespaceCredential.poolOptions.map((options) => options.poolId)).size === 1,
    true,
  );
});

test("migration URL identity boundary rejects the complete pre-authority matrix", async () => {
  const encodedPassword = "Encoded_A1!synthetic-url";
  const cases = [
    [
      "clear URL password",
      { connectionString: `postgres://cloud_admin:${encodedPassword}@127.0.0.1:1/runtime_posture_test` },
    ],
    [
      "encoded URL password",
      { connectionString: `postgres://cloud_admin:${encodeURIComponent(encodedPassword)}@127.0.0.1:1/runtime_posture_test` },
    ],
    [
      "query parameters",
      { connectionString: `${migrationTargetDefaults.connectionString}?sslmode=require` },
    ],
    [
      "fragment",
      { connectionString: `${migrationTargetDefaults.connectionString}#fragment` },
    ],
    [
      "missing port",
      { connectionString: "postgres://cloud_admin@127.0.0.1/runtime_posture_test" },
    ],
    [
      "zero port",
      { connectionString: "postgres://cloud_admin@127.0.0.1:0/runtime_posture_test" },
    ],
    [
      "out of range port",
      { connectionString: "postgres://cloud_admin@127.0.0.1:65536/runtime_posture_test" },
    ],
    [
      "nonnumeric port",
      { connectionString: "postgres://cloud_admin@127.0.0.1:not-a-port/runtime_posture_test" },
    ],
    [
      "localhost",
      { connectionString: "postgres://cloud_admin@localhost:1/runtime_posture_test" },
    ],
    [
      "forbidden host",
      { connectionString: "postgres://cloud_admin@remote.example:1/runtime_posture_test" },
    ],
    [
      "wrong user",
      { connectionString: "postgres://other_user@127.0.0.1:1/runtime_posture_test" },
    ],
    [
      "wrong database",
      { connectionString: "postgres://cloud_admin@127.0.0.1:1/other_database" },
    ],
    [
      "invalid database identifier",
      {
        connectionString: "postgres://cloud_admin@127.0.0.1:1/bad-database",
        expectedDatabase: "bad-database",
      },
    ],
    [
      "invalid user identifier",
      {
        connectionString: "postgres://bad-user@127.0.0.1:1/runtime_posture_test",
        expectedUser: "bad-user",
      },
    ],
    [
      "extra pathname",
      { connectionString: "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test/extra" },
    ],
    [
      "unsupported protocol",
      { connectionString: "mysql://cloud_admin@127.0.0.1:1/runtime_posture_test" },
    ],
  ];

  for (const [label, override] of cases) {
    const state = await runMigrationPoolHarness({
      input: { ...migrationTargetDefaults, ...override },
      operation: async () => {
        throw new Error("migration must not be reached");
      },
    });
    assertPrivateAdmissionFailure(state.error, [encodedPassword]);
    assert.equal(state.poolCount === 0, true, label);
    assert.equal(state.identityCalls === 0, true, label);
    assert.equal(state.migrationCalls === 0, true, label);
    assert.equal(state.endCalls === 0, true, label);
  }
});

test("migration helper gates identity and lifecycle drift before migration and cleans up", async () => {
  const invalidIdentities = [
    ["database", { ...passingMigrationIdentity, database_matches: false }],
    ["user", { ...passingMigrationIdentity, user_matches: false }],
    ["version", { ...passingMigrationIdentity, postgres17: false }],
    ["recovery", { ...passingMigrationIdentity, non_recovery: false }],
    ["catalog", { ...passingMigrationIdentity, catalog_fingerprint: "not-numeric" }],
    ["lifecycle", { ...passingMigrationIdentity, lifecycle_fingerprint: "" }],
  ];

  for (const [label, invalidIdentity] of invalidIdentities) {
    const firstFailure = await runMigrationPoolHarness({
      identityRows: [invalidIdentity],
    });
    assertPrivateAdmissionFailure(firstFailure.error);
    assert.equal(firstFailure.poolCount === 1, true, label);
    assert.equal(firstFailure.identityCalls === 1, true, label);
    assert.equal(firstFailure.migrationCalls === 0, true, label);
    assert.equal(firstFailure.endCalls === 1, true, label);

    const secondFailure = await runMigrationPoolHarness({
      identityRows: [passingMigrationIdentity, invalidIdentity],
    });
    assertPrivateAdmissionFailure(secondFailure.error);
    assert.equal(secondFailure.poolCount === 1, true, label);
    assert.equal(secondFailure.identityCalls === 2, true, label);
    assert.equal(secondFailure.migrationCalls === 0, true, label);
    assert.equal(secondFailure.endCalls === 1, true, label);
  }

  for (const [label, drift] of [
    ["catalog drift", { ...passingMigrationIdentity, catalog_fingerprint: "101" }],
    ["lifecycle drift", { ...passingMigrationIdentity, lifecycle_fingerprint: "201" }],
  ]) {
    const state = await runMigrationPoolHarness({
      identityRows: [passingMigrationIdentity, drift],
    });
    assertPrivateAdmissionFailure(state.error);
    assert.equal(state.identityCalls === 2, true, label);
    assert.equal(state.migrationCalls === 0, true, label);
    assert.equal(state.endCalls === 1, true, label);
  }

  let operationCalls = 0;
  const success = await runMigrationPoolHarness({
    operation: async () => {
      operationCalls += 1;
      return { migrated: true };
    },
  });
  assert.equal(success.error === undefined, true);
  assert.equal(success.returned?.migrated === true, true);
  assert.equal(operationCalls === 1, true);
  assert.equal(success.identityCalls === 2, true);
  assert.equal(success.migrationCalls > 0, true);
  assert.equal(success.endCalls === 1, true);
  assert.equal(success.poolCount === 1, true);
  assert.equal(
    new Set(success.poolOptions.map((options) => options.poolId)).size === 1,
    true,
  );
});

test("migration authority and cleanup failures never propagate synthetic secrets", async () => {
  const credential = "Operator_A1!synthetic-secret";
  const cleanupDiagnostic = "Cleanup_A1!synthetic-diagnostic";
  const successfulCleanupFailure = await runMigrationPoolHarness({
    input: { ...migrationTargetDefaults, connectionPassword: credential },
    endError: new Error(cleanupDiagnostic),
    operation: async () => ({ migrated: true }),
  });
  assert.equal(successfulCleanupFailure.error === undefined, true);
  assert.equal(successfulCleanupFailure.returned?.migrated === true, true);
  assert.equal(successfulCleanupFailure.endCalls === 1, true);

  const captured = await captureProcessSurfaces(() =>
    runMigrationPoolHarness({
      input: { ...migrationTargetDefaults, connectionPassword: credential },
      endError: new Error(cleanupDiagnostic),
      operation: async () => {
        throw new Error(credential);
      },
    }),
  );
  assert.equal(captured.error === undefined, true);
  const failed = captured.result;
  assertPrivateAdmissionFailure(failed.error, [credential, cleanupDiagnostic]);
  assert.equal(failed.endCalls === 1, true);
  const publicValues = [
    failed.returned,
    failed.error?.name,
    failed.error?.message,
    failed.error?.code,
    failed.error?.stack,
    publicErrorSurface(failed.error),
  ].map((value) => String(value ?? "")).join("\n");
  const capturedOutput = [
    ...captured.captured.console,
    ...captured.captured.stdout,
    ...captured.captured.stderr,
    captured.captured.envBefore,
    captured.captured.envAfter,
  ].join("\n");
  assert.equal(publicValues.includes(credential), false);
  assert.equal(publicValues.includes(cleanupDiagnostic), false);
  assert.equal(capturedOutput.includes(credential), false);
  assert.equal(capturedOutput.includes(cleanupDiagnostic), false);
});

test("structured migration Pool options preserve credentials without URL authority", async () => {
  const connectionString =
    "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test";
  const syntheticPassword = "Operator_A1!synthetic-only";
  const legacyPool = new Pool({
    connectionString,
    password: syntheticPassword,
    max: 1,
  });
  const structuredPool = new Pool({
    host: "127.0.0.1",
    port: 1,
    user: "cloud_admin",
    database: "runtime_posture_test",
    password: syntheticPassword,
    max: 1,
  });
  const legacyClient = new legacyPool.Client(legacyPool.options);
  const structuredClient = new structuredPool.Client(structuredPool.options);

  try {
    assert.equal(legacyClient.connectionParameters.password === syntheticPassword, false);
    assert.equal(structuredClient.connectionParameters.password === syntheticPassword, true);
    assert.equal(Object.hasOwn(structuredPool.options, "connectionString"), false);
    assert.equal(structuredPool.options.password === syntheticPassword, true);
    assert.equal(new URL(connectionString).password, "");
  } finally {
    await legacyClient.end().catch(() => {});
    await legacyPool.end();
    await structuredClient.end().catch(() => {});
    await structuredPool.end();
  }
});

test("migration helper rejects an injected pg Pool before transport or completion", async () => {
  const callerPool = new Pool({
    host: "127.0.0.1",
    port: 1,
    user: "cloud_admin",
    database: "runtime_posture_test",
  });
  assert.equal(callerPool instanceof Pool, true);
  const queryTexts = [];
  let connectCalls = 0;
  callerPool.query = async (text) => {
    queryTexts.push(String(text));
    return {
      rows: [{
        database_matches: true,
        user_matches: true,
        postgres17: true,
        non_recovery: true,
        catalog_fingerprint: "1",
        lifecycle_fingerprint: "2",
      }],
    };
  };
  callerPool.connect = async () => {
    connectCalls += 1;
    return {
      async query() {
        throw new Error("injected transport must not receive migration SQL");
      },
      release() {},
    };
  };
  let completionCalled = false;
  await assert.rejects(
    () =>
      withDisposablePostgresFixtureMigration(
        {
          pool: callerPool,
          connectionString:
            "postgres://cloud_admin@127.0.0.1:1/runtime_posture_test",
          expectedDatabase: "runtime_posture_test",
          expectedUser: "cloud_admin",
          migrationsFolder: "./drizzle",
          phase: "initialization",
        },
        async () => {
          completionCalled = true;
        },
      ),
    safeAdmissionError,
  );
  assert.deepEqual(queryTexts, []);
  assert.equal(connectCalls, 0);
  assert.equal(completionCalled, false);
  await callerPool.end();
});

test("migration authority stays runner-local and cannot cross disposable process boundaries", async () => {
  const [
    helperSource,
    roleRunnerSource,
    roleProofSource,
    durableRunnerSource,
    durableProofSource,
  ] = await Promise.all([
    readFile("tests/support/disposable-postgres-fixture.mjs", "utf8"),
    readFile("scripts/run-disposable-role-collapse-postgres-tests.mjs", "utf8"),
    readFile("tests/role-collapse-postgres.test.mjs", "utf8"),
    readFile("scripts/run-disposable-durable-db-operations-tests.mjs", "utf8"),
    readFile("tests/durable-database-operations-postgres.test.mjs", "utf8"),
  ]);

  assert.match(helperSource, /const migrationAuthorityBrand = Symbol/u);
  assert.match(helperSource, /const migrationAuthorityValues = new WeakMap/u);
  assert.match(helperSource, /authority = Object\.freeze\(\{\}\)/u);
  assert.match(helperSource, /migrationAuthorityValues\.get\(authority\)/u);
  assert.match(helperSource, /value\.authority !== authority/u);
  assert.match(helperSource, /value\.valid/u);
  assert.match(helperSource, /value\.valid = false/u);
  assert.match(helperSource, /poolOptions\.password = connectionPassword/u);
  const authorityStart = helperSource.indexOf(
    "migrationAuthorityValues.set(authority, {",
  );
  const authorityEnd = helperSource.indexOf("});", authorityStart);
  assert.ok(authorityStart >= 0 && authorityEnd > authorityStart);
  assert.doesNotMatch(
    helperSource.slice(authorityStart, authorityEnd),
    /connectionPassword/u,
  );
  assert.doesNotMatch(helperSource, /JSON\.stringify\(authority\)|process\.env/u);

  assert.match(roleRunnerSource, /withDisposablePostgresFixtureMigration/u);
  assert.match(roleRunnerSource, /runRoleCollapseProofs/u);
  assert.doesNotMatch(roleRunnerSource, /\["--test", "tests\/role-collapse-postgres\.test\.mjs"\]/u);
  assert.doesNotMatch(roleProofSource, /withDisposablePostgresFixtureMigration/u);
  assert.doesNotMatch(roleProofSource, /ROLE_COLLAPSE_TEST_/u);

  assert.match(durableRunnerSource, /withDisposablePostgresFixtureMigration/u);
  assert.match(durableRunnerSource, /applyFirstNine/u);
  assert.doesNotMatch(durableProofSource, /withDisposablePostgresFixtureMigration/u);
  assert.doesNotMatch(durableProofSource, /\bapplyFirstNine\b/u);
});

test("initialization and final-start transports are distinct admission phases", () => {
  assert.doesNotThrow(() =>
    parseDisposablePostgresUrl(baseFixture.connectionString, {
      expectedDatabase: baseFixture.expectedDatabase,
      expectedUser: baseFixture.expectedUser,
      phase: "initialization",
      transport: baseFixture.transport,
    }),
  );

  assert.throws(
    () =>
      parseDisposablePostgresUrl(baseFixture.connectionString, {
        expectedDatabase: baseFixture.expectedDatabase,
        expectedUser: baseFixture.expectedUser,
        phase: "final_start",
        transport: baseFixture.transport,
      }),
    safeAdmissionError,
  );

  assert.throws(() =>
    parseDisposablePostgresUrl(
      "postgres://platform_app@postgres-primary:5432/runtime_posture_test",
      {
        expectedDatabase: baseFixture.expectedDatabase,
        expectedUser: baseFixture.expectedUser,
        phase: "final_start",
        transport: {
          kind: "managed-container",
          phase: "final_start",
          attestation: Object.freeze({}),
        },
      },
    ),
    safeAdmissionError,
  );
});

test("every target is admitted before mutation and a secondary failure permits zero mutation", async () => {
  const admitted = [];
  let mutationCalls = 0;
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };

  await assert.rejects(
    () =>
      withDisposablePostgresFixturesAdmitted(
        [baseFixture, secondary],
        async () => {
          mutationCalls += 1;
        },
        {
          readOnlyProbe: async ({ fixture }) => {
            admitted.push(fixture.name);
            return {
              ...(await passingProbe({ fixture })),
              expectedObjectsPresent: fixture.name !== "secondary",
            };
          },
           clientFactory: createProbeClient,
        },
      ),
    safeAdmissionError,
  );

  assert.deepEqual(admitted, ["primary", "secondary"]);
  assert.equal(mutationCalls, 0);
  await assertClosedAdmissionEvidence();
  await assertCanonicalLocatorCollisions();
  await assertObservedPhysicalIdentityCollision();
  await assertSeparateAggregateTargets();
  await assertCustomProbeBoundary();
  await assertCustomProbeCleanup();
  await assertReadOnlyBoundaryFailures();
});

async function assertCanonicalLocatorCollisions() {
  const collisions = [
    {
      ...baseFixture,
      name: "secondary",
    },
    {
      ...baseFixture,
      name: "secondary",
      connectionString:
        "postgresql://alternate_app@127.0.0.1/runtime_posture_test",
      expectedUser: "alternate_app",
    },
  ];

  for (const collision of collisions) {
    const probed = [];
    await assert.rejects(
      () =>
        admitDisposablePostgresFixtures([baseFixture, collision], {
          readOnlyProbe: async ({ fixture }) => {
            probed.push(fixture.name);
            return passingProbe({ fixture });
          },
          clientFactory: createProbeClient,
        }),
      safeAdmissionError,
    );
    assert.deepEqual(probed, []);
  }
}

async function assertClosedAdmissionEvidence() {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  const stageCases = [
    ["IDENTITY", { databaseMatches: false }],
    ["POSTURE", { runtimePosturePassed: false }],
    ["OWNERSHIP", { ownershipAbsent: false }],
    ["EXPECTED_OBJECTS", { expectedObjectsPresent: false }],
  ];

  for (const [stage, override] of stageCases) {
    await assert.rejects(
      () => admitDisposablePostgresFixture(baseFixture, {
        readOnlyProbe: async ({ fixture }) => ({
          ...(await passingProbe({ fixture })),
          ...override,
        }),
        clientFactory: createProbeClient,
      }),
      admissionEvidence("PRIMARY", stage),
    );
  }

  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: passingProbe,
      clientFactory: () => {
        throw new Error("unsafe-internal-detail");
      },
    }),
    admissionEvidence("PRIMARY", "CONNECT"),
  );
  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: passingProbe,
      clientFactory: () => ({
        connectionParameters: {
          database: baseFixture.expectedDatabase,
          host: "127.0.0.1",
          port: "5433",
          user: baseFixture.expectedUser,
        },
        async query() {
          return { rows: [] };
        },
        release() {},
      }),
    }),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: passingProbe,
      clientFactory: () => createBoundaryClient({
        rejectQuery: "set transaction read only",
      }),
    }),
    admissionEvidence("PRIMARY", "READONLY"),
  );
  await assert.rejects(
    () => admitDisposablePostgresFixture(
      { ...baseFixture, expectedUser: "invalid-user" },
      {
        readOnlyProbe: passingProbe,
        clientFactory: createProbeClient,
      },
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await assert.rejects(
    () => admitDisposablePostgresConstructionTargets(
      [
        { ...constructionTarget("primary", "runtime_posture_test"), expectedUser: "invalid-user" },
        constructionTarget("secondary", "runtime_posture_test_secondary"),
      ],
      { readOnlyProbe: passingProbe, clientFactory: createProbeClient },
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await assert.rejects(
    () => admitDisposablePostgresFixtures([baseFixture, secondary], {
      readOnlyProbe: async ({ fixture }) => ({
        ...(await passingProbe({ fixture })),
        expectedObjectsPresent: fixture.name !== "secondary",
      }),
      clientFactory: createProbeClient,
    }),
    admissionEvidence("SECONDARY", "EXPECTED_OBJECTS"),
  );

  await assert.rejects(
    () => admitDisposablePostgresFixtures(
      [baseFixture, { ...baseFixture, name: "secondary" }],
      {
        readOnlyProbe: passingProbe,
        clientFactory: createProbeClient,
      },
    ),
    admissionEvidence("SECONDARY", "BINDING"),
  );
}

async function assertObservedPhysicalIdentityCollision() {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  let probeCalls = 0;
  let mutationCalls = 0;

  await assert.rejects(
    () =>
      withDisposablePostgresFixturesAdmitted(
        [baseFixture, secondary],
        async () => {
          mutationCalls += 1;
        },
        {
          readOnlyProbe: async () => {
            probeCalls += 1;
            return {
              ...(await passingProbe()),
              catalogFingerprint: "run45-cluster-1",
              lifecycleFingerprint: "run45-database-1",
            };
          },
          clientFactory: createProbeClient,
        },
      ),
    admissionEvidence("SECONDARY", "IDENTITY"),
  );

  assert.equal(probeCalls, 2);
  assert.equal(mutationCalls, 0);

  await assert.rejects(
    () => admitDisposablePostgresConstructionTargets(
      [
        constructionTarget("primary", "runtime_posture_test"),
        constructionTarget("secondary", "runtime_posture_test_secondary"),
      ],
      {
        readOnlyProbe: async () => ({
          ...(await passingProbe()),
          catalogFingerprint: "construction-cluster-1",
          lifecycleFingerprint: "construction-database-1",
        }),
        clientFactory: createProbeClient,
      },
    ),
    admissionEvidence("SECONDARY", "IDENTITY"),
  );

  const unclassified = {
    ...secondary,
    name: "tertiary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5434/runtime_posture_test",
  };
  await assert.rejects(
    () => admitDisposablePostgresFixtures([baseFixture, unclassified], {
      readOnlyProbe: async () => ({
        ...(await passingProbe()),
        catalogFingerprint: "run45-cluster-1",
        lifecycleFingerprint: "run45-database-1",
      }),
      clientFactory: createProbeClient,
    }),
    (error) => {
      safeAdmissionError(error);
      assert.equal("target" in error, false);
      assert.equal("stage" in error, false);
      return true;
    },
  );
}

async function assertSeparateAggregateTargets() {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  const probed = [];
  const admission = await admitDisposablePostgresFixtures(
    [baseFixture, secondary],
    {
      readOnlyProbe: async ({ fixture }) => {
        probed.push(fixture.name);
        return passingProbe({ fixture });
      },
      clientFactory: createProbeClient,
    },
  );

  assert.deepEqual(probed, ["primary", "secondary"]);
  assert.doesNotThrow(() => requireDisposablePostgresAdmission(admission));
}

async function assertCustomProbeBoundary() {
  const client = createBoundaryClient();
  await admitDisposablePostgresFixture(baseFixture, {
    readOnlyProbe: async ({ client: probeClient, fixture }) => {
      await probeClient.query("select 1");
      await assert.rejects(() => probeClient.query("commit"));
      await assert.rejects(() => probeClient.query({ text: "commit" }));
      await assert.rejects(() => probeClient.query("set transaction read write"));
      await assert.rejects(() =>
        probeClient.query("select set_config('transaction_read_only', 'off', false)"),
      );
      return passingProbe({ fixture });
    },
    clientFactory: () => client,
  });

  assert.deepEqual(client.calls, [
    "begin",
    "set transaction read only",
    "show transaction_read_only",
    "select 1",
    "rollback",
  ]);
  assert.equal(client.wasReleased(), true);
}

async function assertCustomProbeCleanup() {
  const cases = [
    ["callback throw", createBoundaryClient(), async () => {
      throw new Error();
    }],
    [
      "rejected query",
      createBoundaryClient({ rejectQuery: "select 1" }),
      async ({ client: probeClient }) => {
        await probeClient.query("select 1");
      },
    ],
    ["malformed result", createBoundaryClient(), async () => ({})],
  ];

  for (const [name, client, readOnlyProbe] of cases) {
    await assert.rejects(
      () =>
        admitDisposablePostgresFixture(baseFixture, {
          readOnlyProbe,
          clientFactory: () => client,
        }),
      safeAdmissionError,
      name,
    );
    assert.equal(client.calls.at(-1), "rollback", name);
    assert.equal(client.wasReleased(), true, name);
  }

  const genericThenCleanup = createBoundaryClient({
    rejectCleanup: true,
    rejectQuery: "rollback",
  });
  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: async () => {
        throw new Error();
      },
      clientFactory: () => genericThenCleanup,
    }),
    (error) => {
      safeAdmissionError(error);
      assert.equal("target" in error, false);
      assert.equal("stage" in error, false);
      return true;
    },
  );
  assert.equal(genericThenCleanup.wasReleased(), true);

  const identityThenCleanup = createBoundaryClient({
    rejectCleanup: true,
    rejectQuery: "rollback",
  });
  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: async ({ fixture }) => ({
        ...(await passingProbe({ fixture })),
        databaseMatches: false,
      }),
      clientFactory: () => identityThenCleanup,
    }),
    admissionEvidence("PRIMARY", "IDENTITY"),
  );
  assert.equal(identityThenCleanup.wasReleased(), true);

  for (const cleanupMethod of ["release", "end"]) {
    const cleanupOnly = createBoundaryClient({
      cleanupMethod,
      rejectCleanup: true,
    });
    await assert.rejects(
      () => admitDisposablePostgresFixture(baseFixture, {
        readOnlyProbe: passingProbe,
        clientFactory: () => cleanupOnly,
      }),
      admissionEvidence("PRIMARY", "CONNECT"),
    );
    assert.equal(cleanupOnly.wasReleased(), true, cleanupMethod);
  }

  const rollbackOnly = createBoundaryClient({ rejectQuery: "rollback" });
  await assert.rejects(
    () => admitDisposablePostgresFixture(baseFixture, {
      readOnlyProbe: passingProbe,
      clientFactory: () => rollbackOnly,
    }),
    admissionEvidence("PRIMARY", "READONLY"),
  );
  assert.equal(rollbackOnly.wasReleased(), true);
}

async function assertReadOnlyBoundaryFailures() {
  const cases = [
    ["begin failure", createBoundaryClient({ rejectQuery: "begin" })],
    ["establishment failure", createBoundaryClient({ rejectQuery: "set transaction read only" })],
    ["verification failure", createBoundaryClient({ readOnlyValue: "off" })],
  ];

  for (const [name, client] of cases) {
    let callbackCalled = false;
    await assert.rejects(
      () =>
        admitDisposablePostgresFixture(baseFixture, {
          readOnlyProbe: async () => {
            callbackCalled = true;
            return passingProbe({ fixture: baseFixture });
          },
          clientFactory: () => client,
        }),
      admissionEvidence("PRIMARY", "READONLY"),
      name,
    );
    assert.equal(callbackCalled, false, name);
    assert.equal(
      client.calls.at(-1),
      name === "begin failure" ? "begin" : "rollback",
      name,
    );
    assert.equal(client.wasReleased(), true, name);
  }
}

test("mutation clients require an opaque aggregate admission token", async () => {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  const admission = await admitDisposablePostgresFixtures(
    [baseFixture, secondary],
    {
      readOnlyProbe: ({ fixture }) => passingProbe({ fixture }),
      clientFactory: createProbeClient,
    },
  );
  assert.equal(Object.keys(admission).length, 0);
  assert.doesNotThrow(() => requireDisposablePostgresAdmission(admission));
  assert.throws(
    () => requireDisposablePostgresAdmission({}),
    safeAdmissionError,
  );

  const calls = [];
  const identity = {
    database_matches: true,
    user_matches: true,
    postgres17: true,
    non_recovery: true,
    catalog_fingerprint: baseFixture.connectionString,
    lifecycle_fingerprint: baseFixture.connectionString,
  };
  const pool = {
    options: { connectionString: baseFixture.connectionString },
    async connect() {
      return {
        release() {},
        async query() {
          return { rows: [] };
        },
      };
    },
  };
  const authority = deriveDisposablePostgresTargetAuthority(
    admission,
    "primary",
    pool,
    { revalidateMutationConnection: async () => {} },
  );
  const mutationClient = createAdmittedMutationClient(
    {
      connectionParameters: {
        host: "127.0.0.1",
        port: 5432,
        database: "runtime_posture_test",
        user: "platform_app",
      },
      async query(text, values) {
        if (text.includes("current_database()")) {
          return { rows: [identity] };
        }
        calls.push({ text, values });
        return { rows: [] };
      },
    },
    authority,
  );
  await mutationClient.query("grant select on table public.users to platform_runtime", []);
  assert.equal(calls.length, 1);
  assert.throws(
    () => createAdmittedMutationClient(
      {
        connectionParameters: {
          host: "127.0.0.1",
          port: 5433,
          database: "runtime_posture_test",
          user: "platform_app",
        },
        async query() {
          return { rows: [identity] };
        },
      },
      authority,
    ),
    safeAdmissionError,
  );
});

test("single-target configured admission cannot satisfy aggregate authority", async () => {
  const singleTarget = await admitDisposablePostgresFixture(baseFixture, {
    readOnlyProbe: passingProbe,
    clientFactory: createProbeClient,
  });
  assert.throws(
    () => requireDisposablePostgresAdmission(singleTarget),
    safeAdmissionError,
  );

  const construction = await admitDisposablePostgresConstructionTargets(
    [
      {
        name: "primary",
        connectionString:
          "postgres://postgres@127.0.0.1:5432/runtime_posture_test",
        expectedDatabase: "runtime_posture_test",
        expectedUser: "postgres",
        phase: "initialization",
        transport: { kind: "loopback", phase: "initialization" },
      },
      {
        name: "secondary",
        connectionString:
          "postgres://postgres@127.0.0.1:5433/runtime_posture_test",
        expectedDatabase: "runtime_posture_test",
        expectedUser: "postgres",
        phase: "initialization",
        transport: { kind: "loopback", phase: "initialization" },
      },
    ],
    {
      readOnlyProbe: ({ fixture }) => passingProbe({ fixture }),
      clientFactory: createProbeClient,
    },
  );
  const provisioning = deriveDisposablePostgresProvisioningAuthority(
    construction,
    "primary",
  );
  assert.throws(
    () => deriveDisposablePostgresProvisioningAuthority(singleTarget, "primary"),
    safeAdmissionError,
  );
  assert.equal(Object.keys(provisioning).length, 0);
  const creationSecondary = {
    name: "secondary",
    connectionString: "postgres://postgres@127.0.0.1:5432/runtime_posture_test_secondary",
    creationConnectionString: "postgres://postgres@127.0.0.1:5432/postgres",
    creationExpectedDatabase: "postgres",
    databaseMayBeAbsent: true,
    allowDatabaseCreation: true,
    expectedDatabase: "runtime_posture_test_secondary",
    expectedUser: "postgres",
    phase: "initialization",
    transport: { kind: "loopback", phase: "initialization" },
  };
  const creationConstruction = await admitDisposablePostgresConstructionTargets(
    [constructionTarget("primary", "runtime_posture_test"), creationSecondary],
    {
      readOnlyProbe: async ({ fixture }) => ({
        ...(await passingProbe({ fixture })),
        lifecycleFingerprint: fixture.name === "secondary"
          ? "absent:runtime_posture_test_secondary"
          : "lifecycle-1",
        targetDatabasePresent: fixture.name !== "secondary",
      }),
      clientFactory: createProbeClient,
    },
  );
  const authority = deriveDisposablePostgresDatabaseCreationAuthority(creationConstruction, "secondary");
  const provisioningAuthority = deriveDisposablePostgresProvisioningAuthority(
    creationConstruction,
    "secondary",
  );
  const queries = [];
  let created = false;
  const rootPool = {
    options: { connectionString: creationSecondary.creationConnectionString },
    async connect() {
      return {
        connectionParameters: {
          host: "127.0.0.1",
          port: 5432,
          database: "postgres",
          user: "postgres",
        },
        release() {},
        async query(text, values) {
          queries.push({ text, values });
          if (/^create database\b/iu.test(text)) {
            created = true;
            return { rows: [] };
          }
          if (text.includes("target_database_absent")) {
            return {
              rows: [{
                database_matches: true,
                user_matches: true,
                postgres17: true,
                non_recovery: true,
                catalog_fingerprint: creationSecondary.connectionString,
                lifecycle_fingerprint: created
                  ? "lifecycle-2"
                  : "absent:runtime_posture_test_secondary",
                target_database_absent: !created,
              }],
            };
          }
          return { rows: [] };
        },
      };
    },
    async end() {},
  };
  const authorized = createAuthorizedDatabaseCreationPool(rootPool, authority);
  await authorized.query("select 1 from pg_database where datname = $1", [
    "runtime_posture_test_secondary",
  ]);
  await authorized.query('create database "runtime_posture_test_secondary"');
  assert.equal(queries.length, 5);
  const targetPool = {
    options: { connectionString: creationSecondary.connectionString },
    async connect() {
      return {
        connectionParameters: {
          host: "127.0.0.1",
          port: 5432,
          database: "runtime_posture_test_secondary",
          user: "postgres",
        },
        release() {},
        async query(text) {
          if (text.includes("current_database()")) {
            return {
              rows: [{
                database_matches: true,
                user_matches: true,
                postgres17: true,
                non_recovery: true,
                catalog_fingerprint: creationSecondary.connectionString,
                lifecycle_fingerprint: "lifecycle-2",
              }],
            };
          }
          return { rows: [] };
        },
      };
    },
  };
  const authorizedProvisioning = createAuthorizedProvisioningPool(
    targetPool,
    provisioningAuthority,
  );
  await authorizedProvisioning.query(
    "grant connect on database runtime_posture_test_secondary to platform_app",
  );
  assert.throws(
    () => createAuthorizedDatabaseCreationPool(rootPool, authority),
    safeAdmissionError,
  );
  assert.throws(
    () => deriveDisposablePostgresDatabaseCreationAuthority(creationConstruction, "secondary"),
    safeAdmissionError,
  );
  invalidateDisposablePostgresConstructionAdmission(creationConstruction);
  assert.throws(
    () => createAuthorizedDatabaseCreationPool(rootPool, authority),
    safeAdmissionError,
  );
});

test("target authority rejects wrong pool, connection substitution, replay, stale, and vacuous evidence", async () => {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  const admission = await admitDisposablePostgresFixtures(
    [baseFixture, secondary],
    {
      readOnlyProbe: ({ fixture }) => passingProbe({ fixture }),
      clientFactory: createProbeClient,
    },
  );
  const pool = {
    options: { connectionString: baseFixture.connectionString },
    async connect() {
      return {
        release() {},
        async query() {
          return { rows: [] };
        },
      };
    },
  };
  const mutationPool = (connectionString) => ({
    options: { connectionString },
    async connect() {
      return {
        release() {},
        async query() {
          return { rows: [] };
        },
      };
    },
  });
  const authority = deriveDisposablePostgresTargetAuthority(
    admission,
    "primary",
    pool,
    { revalidateMutationConnection: async () => {} },
  );
  assert.throws(
    () => createAdmittedMutationPool(
      mutationPool(baseFixture.connectionString),
      admission,
      "secondary",
      { revalidateMutationConnection: async () => {} },
    ),
    safeAdmissionError,
  );
  assert.throws(
    () => deriveDisposablePostgresTargetAuthority(
      admission,
      "primary",
      pool,
      { revalidateMutationConnection: async () => {} },
    ),
    safeAdmissionError,
  );
  const secondaryPool = {
    options: { connectionString: secondary.connectionString },
    async connect() {
      return { release() {}, async query() { return { rows: [] }; } };
    },
  };
  const wrongAuthority = deriveDisposablePostgresTargetAuthority(
    admission,
    "secondary",
    secondaryPool,
    { revalidateMutationConnection: async () => {} },
  );
  assert.equal(Object.keys(wrongAuthority).length, 0);
  assert.doesNotThrow(() => wrongAuthority);
  assert.throws(
    () => createAdmittedMutationPool(
      mutationPool(secondary.connectionString),
      admission,
      "primary",
      { revalidateMutationConnection: async () => {} },
    ),
    safeAdmissionError,
  );
  invalidateDisposablePostgresAdmission(admission);
  assert.throws(
    () => createAdmittedMutationPool(
      secondaryPool,
      admission,
      "secondary",
      { revalidateMutationConnection: async () => {} },
    ),
    safeAdmissionError,
  );
  void authority;
});

test("pool binding matcher closes real pg, supported-shape, and matcher-reuse family", async () => {
  const password = "fixture-password";
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  const identity = {
    database_matches: true,
    user_matches: true,
    postgres17: true,
    non_recovery: true,
    catalog_fingerprint: baseFixture.connectionString,
    lifecycle_fingerprint: baseFixture.connectionString,
  };
  const matchingClient = ({ actual = false, clientPassword = password } = {}) => {
    const parameters = {
      user: baseFixture.expectedUser,
      host: "127.0.0.1",
      port: 5432,
      database: baseFixture.expectedDatabase,
      ...(actual ? { password: clientPassword } : {}),
    };
    const client = actual ? new Client(parameters) : { connectionParameters: parameters };
    client.release = () => {};
    client.query = async (text) =>
      String(text).includes("current_database()")
        ? { rows: [identity] }
        : { rows: [] };
    return client;
  };
  const admissionFor = () => admitDisposablePostgresFixtures(
    [baseFixture, secondary],
    { readOnlyProbe: passingProbe, clientFactory: createProbeClient },
  );
  const representationPools = [
    ["flat pg-pool options", () => {
      const pool = new Pool({
        user: baseFixture.expectedUser,
        host: "127.0.0.1",
        port: 5432,
        database: baseFixture.expectedDatabase,
        password,
        max: 1,
      });
      pool.connect = async () => matchingClient({ actual: true });
      return pool;
    }],
    ["connection string", () => ({
      options: { connectionString: baseFixture.connectionString },
      connect: async () => matchingClient(),
      async end() {},
    })],
    ["nested connection parameters", () => ({
      options: {
        connectionParameters: {
          user: baseFixture.expectedUser,
          host: "127.0.0.1",
          port: 5432,
          database: baseFixture.expectedDatabase,
        },
      },
      connect: async () => matchingClient(),
      async end() {},
    })],
  ];

  for (const [name, createPool] of representationPools) {
    const admission = await admissionFor();
    const pool = createPool();
    const authorized = createAdmittedMutationPool(pool, admission, "primary");
    await assert.doesNotReject(() => authorized.query("select 1"), name);
    await pool.end();
  }

  const wrongIdentityAdmission = await admissionFor();
  const wrongIdentityPool = new Pool({
    user: "alternate_app",
    host: "127.0.0.1",
    port: 5432,
    database: baseFixture.expectedDatabase,
    password,
  });
  assert.throws(
    () => createAdmittedMutationPool(
      wrongIdentityPool,
      wrongIdentityAdmission,
      "primary",
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await wrongIdentityPool.end();

  const wrongTransportAdmission = await admissionFor();
  const wrongTransportPool = new Pool({
    user: baseFixture.expectedUser,
    host: "::1",
    port: 5432,
    database: baseFixture.expectedDatabase,
    password,
  });
  assert.throws(
    () => createAdmittedMutationPool(
      wrongTransportPool,
      wrongTransportAdmission,
      "primary",
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await wrongTransportPool.end();

  const wrongTargetAdmission = await admissionFor();
  assert.throws(
    () => createAdmittedMutationPool(
      {
        options: { connectionString: secondary.connectionString },
        async connect() {},
      },
      wrongTargetAdmission,
      "primary",
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );

  const wrongPasswordAdmission = await admissionFor();
  const wrongPasswordPool = new Pool({
    user: baseFixture.expectedUser,
    host: "127.0.0.1",
    port: 5432,
    database: baseFixture.expectedDatabase,
    password,
  });
  wrongPasswordPool.connect = async () => matchingClient({
    actual: true,
    clientPassword: "different-fixture-password",
  });
  const wrongPasswordAuthorized = createAdmittedMutationPool(
    wrongPasswordPool,
    wrongPasswordAdmission,
    "primary",
  );
  await assert.rejects(
    () => wrongPasswordAuthorized.query("select 1"),
    admissionEvidence("PRIMARY", "BINDING"),
  );
  await wrongPasswordPool.end();

  for (const hostilePool of [
    {
      options: {
        user: baseFixture.expectedUser,
        host: "127.0.0.1",
        port: 5432,
        database: baseFixture.expectedDatabase,
        password,
      },
      async connect() {},
    },
    {
      options: {
        connectionString:
          "postgres://platform_app:incorrect@127.0.0.1:5432/runtime_posture_test",
      },
      async connect() {},
    },
  ]) {
    const admission = await admissionFor();
    assert.throws(
      () => createAdmittedMutationPool(hostilePool, admission, "primary"),
      (error) => {
        safeAdmissionError(error);
        assert.equal("target" in error, false);
        assert.equal("stage" in error, false);
        return true;
      },
    );
  }

  const creationSecondary = {
    ...constructionTarget("secondary", "runtime_posture_test_secondary"),
    creationConnectionString: "postgres://postgres@127.0.0.1:5432/postgres",
    creationExpectedDatabase: "postgres",
    databaseMayBeAbsent: true,
    allowDatabaseCreation: true,
  };
  const construction = await admitDisposablePostgresConstructionTargets(
    [constructionTarget("primary", "runtime_posture_test"), creationSecondary],
    {
      readOnlyProbe: ({ fixture }) => passingProbe({ fixture }).then((result) => ({
        ...result,
        targetDatabasePresent: fixture.databaseMayBeAbsent ? false : true,
        lifecycleFingerprint: fixture.databaseMayBeAbsent
          ? `absent:${fixture.expectedDatabase}`
          : result.lifecycleFingerprint,
      })),
      clientFactory: createProbeClient,
    },
  );
  const creationAuthority = deriveDisposablePostgresDatabaseCreationAuthority(
    construction,
    "secondary",
  );
  const creationPool = new Pool({
    user: "postgres",
    host: "127.0.0.1",
    port: 5432,
    database: "postgres",
    password,
  });
  assert.doesNotThrow(() =>
    createAuthorizedDatabaseCreationPool(creationPool, creationAuthority),
  );
  await creationPool.end();

  const provisioningAuthority = deriveDisposablePostgresProvisioningAuthority(
    construction,
    "primary",
  );
  const provisioningPool = new Pool({
    user: "postgres",
    host: "127.0.0.1",
    port: 5432,
    database: "runtime_posture_test",
    password,
  });
  assert.doesNotThrow(() =>
    createAuthorizedProvisioningPool(provisioningPool, provisioningAuthority),
  );
  await provisioningPool.end();
});

test("real passwordless pg clients preserve binding across aggregate admission paths", async () => {
  const secondaryConstruction = {
    ...constructionTarget("secondary", "runtime_posture_test_secondary"),
    allowDatabaseCreation: true,
    creationConnectionString: "postgres://postgres@127.0.0.1:5432/postgres",
    creationExpectedDatabase: "postgres",
    databaseMayBeAbsent: true,
  };
  await assert.doesNotReject(() =>
    admitDisposablePostgresConstructionTargets(
      [constructionTarget("primary", "runtime_posture_test"), secondaryConstruction],
      {
        readOnlyProbe: async ({ fixture }) => ({
          ...await passingProbe({ fixture }),
          lifecycleFingerprint: fixture.name === "secondary"
            ? "absent:runtime_posture_test_secondary"
            : fixture.connectionString,
          targetDatabasePresent: fixture.name !== "secondary",
        }),
        clientFactory: createRealPasswordlessProbeClient,
      },
    ),
  );

  const secondaryConfigured = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test_secondary",
    expectedDatabase: "runtime_posture_test_secondary",
  };
  let configuredAdmission;
  await assert.doesNotReject(async () => {
    configuredAdmission = await admitDisposablePostgresFixtures(
      [baseFixture, secondaryConfigured],
      {
        readOnlyProbe: passingProbe,
        clientFactory: createRealPasswordlessProbeClient,
      },
    );
  });

  const passwordlessPool = {
    options: { connectionString: baseFixture.connectionString },
    connect: async () => createRealPasswordlessProbeClient(baseFixture),
    async end() {},
  };
  const admittedPasswordlessPool = createAdmittedMutationPool(
    passwordlessPool,
    configuredAdmission,
    "primary",
  );
  await assert.doesNotReject(() => admittedPasswordlessPool.query("select 1"));

  const ambiguousClient = createProbeClient(baseFixture);
  Object.defineProperty(ambiguousClient.connectionParameters, "password", {
    configurable: true,
    enumerable: false,
    value: null,
    writable: true,
  });
  await assert.rejects(
    () => admitDisposablePostgresFixtures(
      [baseFixture, secondaryConfigured],
      {
        readOnlyProbe: passingProbe,
        clientFactory: () => ambiguousClient,
      },
    ),
    admissionEvidence("PRIMARY", "BINDING"),
  );
});

test("managed transport and non-vacuous fingerprints cannot be caller-spoofed", async () => {
  assert.throws(
    () =>
      parseDisposablePostgresUrl(
        "postgres://platform_app@postgres-primary:5432/runtime_posture_test",
        {
          expectedDatabase: "runtime_posture_test",
          expectedUser: "platform_app",
          phase: "final_start",
          transport: {
            kind: "managed-container",
            phase: "final_start",
            attestation: {
              alias: "postgres-primary",
              image: "postgres:17",
              phase: "final_start",
            },
          },
        },
      ),
    safeAdmissionError,
  );
  for (const field of ["catalogFingerprint", "lifecycleFingerprint"]) {
    await assert.rejects(
      () =>
        admitDisposablePostgresFixtures(
          [baseFixture, { ...baseFixture, name: "secondary" }],
          {
            readOnlyProbe: async () => ({
              ...(await passingProbe()),
              [field]: "0",
            }),
            clientFactory: createProbeClient,
          },
        ),
      safeAdmissionError,
    );
  }
});

test("fixture probes cannot mutate before aggregate admission", async () => {
  const secondary = {
    ...baseFixture,
    name: "secondary",
    connectionString:
      "postgres://platform_app@127.0.0.1:5433/runtime_posture_test",
  };
  await assert.rejects(
    () =>
      admitDisposablePostgresFixtures([baseFixture, secondary], {
        readOnlyProbe: async ({ client }) => {
          await client.query("grant select on table public.users to platform_runtime");
          return passingProbe({ fixture: baseFixture });
        },
        clientFactory: createProbeClient,
      }),
    safeAdmissionError,
  );
});

function safeAdmissionError(error) {
  assert.equal(error instanceof DisposablePostgresFixtureAdmissionError, true);
  assert.equal(error?.code === "disposable_fixture_admission_failed", true);
  assert.equal(error?.message === "Disposable fixture admission failed.", true);
  assert.equal(
    !/postgres|platform_|runtime_|127|5432|localhost/iu.test(error?.message ?? ""),
    true,
  );
  return true;
}

function admissionEvidence(target, stage) {
  return (error) => {
    safeAdmissionError(error);
    assert.equal(error.target, target);
    assert.equal(error.stage, stage);
    assert.equal(/^(?:PRIMARY|SECONDARY)$/u.test(error.target), true);
    assert.equal(
      /^(?:CONNECT|BINDING|READONLY|IDENTITY|POSTURE|OWNERSHIP|EXPECTED_OBJECTS)$/u.test(
        error.stage,
      ),
      true,
    );
    const publicError = JSON.stringify(error);
    assert.equal(
      !/unsafe|internal|detail|password|token|postgres(?:ql)?:|127\.0\.0\.1|5432|select|runtime_posture_test/iu.test(
        publicError,
      ),
      true,
    );
    assert.equal(
      !/unsafe-internal-detail|password|token|postgres(?:ql)?:/iu.test(
        String(error.stack),
      ),
      true,
    );
    assert.equal("cause" in error, false);
    return true;
  };
}

function constructionTarget(name, database) {
  return {
    name,
    connectionString: `postgres://postgres@127.0.0.1:5432/${database}`,
    expectedDatabase: database,
    expectedUser: "postgres",
    phase: "initialization",
    transport: { kind: "loopback", phase: "initialization" },
  };
}
