import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Client, Pool } from "pg";

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
      assert.doesNotMatch(
        `${error.message}\n${error.stack ?? ""}`,
        /synthetic-only/u,
      );
      return true;
    },
  );

  for (const connectionPassword of ["", "   ", null, 42, false, {}]) {
    await assert.rejects(
      () => withDisposablePostgresFixtureMigration(
        { ...baseMigrationTarget, connectionPassword },
        async () => {},
      ),
      safeAdmissionError,
    );
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
  assert.equal(error.code, "disposable_fixture_admission_failed");
  assert.equal(
    error.message,
    "Disposable fixture admission failed.",
  );
  assert.doesNotMatch(error.message, /postgres|platform_|runtime_|127|5432|localhost/i);
  return true;
}

function admissionEvidence(target, stage) {
  return (error) => {
    safeAdmissionError(error);
    assert.equal(error.target, target);
    assert.equal(error.stage, stage);
    assert.match(error.target, /^(?:PRIMARY|SECONDARY)$/u);
    assert.match(
      error.stage,
      /^(?:CONNECT|BINDING|READONLY|IDENTITY|POSTURE|OWNERSHIP|EXPECTED_OBJECTS)$/u,
    );
    const publicError = JSON.stringify(error);
    assert.doesNotMatch(
      publicError,
      /unsafe|internal|detail|password|token|postgres(?:ql)?:|127\.0\.0\.1|5432|select|runtime_posture_test/iu,
    );
    assert.doesNotMatch(
      String(error.stack),
      /unsafe-internal-detail|password|token|postgres(?:ql)?:/iu,
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
