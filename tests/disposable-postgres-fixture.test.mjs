import assert from "node:assert/strict";
import test from "node:test";

import {
  DisposablePostgresFixtureAdmissionError,
  admitDisposablePostgresFixtures,
  createAdmittedMutationClient,
  createManagedContainerTransportAttestation,
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

const passingProbe = async () => ({
  databaseMatches: true,
  userMatches: true,
  postgres17: true,
  nonRecovery: true,
  catalogIdentityPresent: true,
  lifecycleIdentityPresent: true,
  runtimePosturePassed: true,
  ownershipAbsent: true,
  expectedObjectsPresent: true,
});

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

  const attestation = createManagedContainerTransportAttestation({
    alias: "postgres-primary",
    image: "postgres:17",
    phase: "final_start",
  });
  assert.doesNotThrow(() =>
    parseDisposablePostgresUrl(
      "postgres://platform_app@postgres-primary:5432/runtime_posture_test",
      {
        expectedDatabase: baseFixture.expectedDatabase,
        expectedUser: baseFixture.expectedUser,
        phase: "final_start",
        transport: {
          kind: "managed-container",
          phase: "final_start",
          attestation,
        },
      },
    ),
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
              ...(await passingProbe()),
              expectedObjectsPresent: fixture.name !== "secondary",
            };
          },
        },
      ),
    safeAdmissionError,
  );

  assert.deepEqual(admitted, ["primary", "secondary"]);
  assert.equal(mutationCalls, 0);
});

test("mutation clients require an opaque aggregate admission token", async () => {
  const admission = await admitDisposablePostgresFixtures([baseFixture], {
    readOnlyProbe: passingProbe,
  });
  assert.equal(Object.keys(admission).length, 0);
  assert.doesNotThrow(() => requireDisposablePostgresAdmission(admission));
  assert.throws(
    () => requireDisposablePostgresAdmission({}),
    safeAdmissionError,
  );

  const calls = [];
  const mutationClient = createAdmittedMutationClient(
    {
      async query(text, values) {
        calls.push({ text, values });
        return { rows: [] };
      },
    },
    admission,
  );
  await mutationClient.query("grant select on table public.users to platform_runtime", []);
  assert.equal(calls.length, 1);
});

test("fixture probes cannot mutate before aggregate admission", async () => {
  await assert.rejects(
    () =>
      admitDisposablePostgresFixtures([baseFixture], {
        readOnlyProbe: async ({ client }) => {
          await client.query("grant select on table public.users to platform_runtime");
          return passingProbe();
        },
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
