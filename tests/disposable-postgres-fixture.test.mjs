import assert from "node:assert/strict";
import test from "node:test";

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

function createBoundaryClient({ readOnlyValue = "on", rejectQuery } = {}) {
  const calls = [];
  let released = false;
  return {
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
    release() {
      released = true;
    },
    wasReleased() {
      return released;
    },
  };
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
    safeAdmissionError,
  );

  assert.equal(probeCalls, 2);
  assert.equal(mutationCalls, 0);
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
}

async function assertReadOnlyBoundaryFailures() {
  const cases = [
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
      safeAdmissionError,
      name,
    );
    assert.equal(callbackCalled, false, name);
    assert.equal(client.calls.at(-1), "rollback", name);
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
