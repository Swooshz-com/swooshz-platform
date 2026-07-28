import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { Pool } from "pg";

import {
  PlatformRuntimeActivationError,
  PlatformRuntimeActivationMutationTracker,
  PlatformRuntimeActivationPhaseJournal,
  assertMatchingPostgresFixtureIdentities,
  assertRuntimeIdentity,
  buildRuntimeDatabaseUrl,
  buildRuntimeRoleStatement,
  createNeonProviderAttestation,
  createRuntimeActivationTarget,
  installRuntimePasswordWithDocker,
  readDockerPostgresFixtureIdentity,
  readPostgresFixtureIdentity,
  runtimeActivationMutationMayHaveBegun,
  runtimeActivationRole,
} from "../scripts/platform-runtime-activation-contract.mjs";
import {
  assertRuntimeDatabasePosture,
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../dist/db/runtime-posture.js";
import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";

const operatorUrl = process.env.RUNTIME_ACTIVATION_TEST_OPERATOR_URL;
const secondOperatorUrl =
  process.env.RUNTIME_ACTIVATION_TEST_SECOND_OPERATOR_URL;
const dockerNetwork =
  process.env.RUNTIME_ACTIVATION_TEST_DOCKER_NETWORK;
const secondDockerNetwork =
  process.env.RUNTIME_ACTIVATION_TEST_SECOND_DOCKER_NETWORK;
const disposableConfirmed =
  process.env.RUNTIME_ACTIVATION_TEST_CONFIRM === "disposable-only";
const skipReason =
  operatorUrl && dockerNetwork && disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable activation fixture";
const twoClusterSkipReason =
  !skipReason &&
  secondOperatorUrl && secondDockerNetwork
    ? false
    : "requires two explicitly confirmed disposable PostgreSQL fixtures";
const primaryDockerSpawn = dockerSpawnOnNetwork(dockerNetwork);
const secondaryDockerSpawn = dockerSpawnOnNetwork(secondDockerNetwork);
const syntheticRuntimePassword =
  "SyntheticRuntime_2026!éΩ漢字_ExtraLength";
const providerNow = Date.now();
const disposableEndpointId = "ep-disposable-primary-001";
const disposableProxyHost = "us-east-2.aws.neon.tech";
const disposableRegionId = "aws-us-east-2";
const disposableDirectHost =
  `${disposableEndpointId}.${disposableProxyHost}`;
const disposablePooledHost =
  `${disposableEndpointId}-pooler.${disposableProxyHost}`;
const boundDirectOperatorUrl =
  `postgresql://platform_app:synthetic@${disposableDirectHost}/runtime_posture_test`;
const boundDockerOperatorUrl =
  `postgresql://platform_app:synthetic@${disposablePooledHost}/runtime_posture_test`;
const planningAttestation = createNeonProviderAttestation(
  {
    branchId: "br-disposable-local-001",
    database: "runtime_posture_test",
    endpoints: [
      {
        branchId: "br-disposable-local-001",
        currentState: "active",
        database: "runtime_posture_test",
        disabled: false,
        host: disposableDirectHost,
        id: disposableEndpointId,
        port: 5432,
        projectId: "disposable-local-123456",
        proxyHost: disposableProxyHost,
        regionId: disposableRegionId,
        type: "read_write",
      },
    ],
    expiresAt: new Date(providerNow + 10 * 60_000).toISOString(),
    observedAt: new Date(providerNow - 60_000).toISOString(),
    projectId: "disposable-local-123456",
    provider: "neon",
  },
  { now: providerNow },
);
const target = createRuntimeActivationTarget(
  "platform_runtime",
  {
    providerAttestation: planningAttestation,
    directEndpointId: disposableEndpointId,
    directOperatorUrl: boundDirectOperatorUrl,
    dockerEndpointId: disposableEndpointId,
    dockerEndpointKind: "pooled",
    dockerOperatorUrl: boundDockerOperatorUrl,
    expectedDatabase: "runtime_posture_test",
  },
  { now: providerNow },
);
const boundSecondDockerOperatorUrl = boundDockerOperatorUrl;
const twoClusterPlanningAttestation = createNeonProviderAttestation(
  {
    branchId: "br-disposable-local-001",
    database: "runtime_posture_test",
    endpoints: [
      {
        branchId: "br-disposable-local-001",
        currentState: "active",
        database: "runtime_posture_test",
        disabled: false,
        host: disposableDirectHost,
        id: disposableEndpointId,
        port: 5432,
        projectId: "disposable-local-123456",
        proxyHost: disposableProxyHost,
        regionId: disposableRegionId,
        type: "read_write",
      },
    ],
    expiresAt: new Date(providerNow + 10 * 60_000).toISOString(),
    observedAt: new Date(providerNow - 60_000).toISOString(),
    projectId: "disposable-local-123456",
    provider: "neon",
  },
  { now: providerNow },
);
const twoClusterTarget = createRuntimeActivationTarget(
  "platform_runtime",
  {
    providerAttestation: twoClusterPlanningAttestation,
    directEndpointId: disposableEndpointId,
    directOperatorUrl: boundDirectOperatorUrl,
    dockerEndpointId: disposableEndpointId,
    dockerEndpointKind: "pooled",
    dockerOperatorUrl: boundSecondDockerOperatorUrl,
    expectedDatabase: "runtime_posture_test",
  },
  { now: providerNow },
);
const expectedPublicTables = Object.freeze(
  [
    ...new Set(
      RUNTIME_TABLE_GRANT_CONTRACT.map((record) => record.objectName),
    ),
  ].sort(),
);
const expectedGrantMatrix = Object.freeze(
  RUNTIME_TABLE_GRANT_CONTRACT
    .map((record) => [
      "platform_runtime",
      record.schema,
      record.objectName,
      record.privilege,
      record.grantOption ? "YES" : "NO",
    ])
    .sort((left, right) =>
      left.join("\u0000").localeCompare(right.join("\u0000")),
    ),
);

test.before(async () => {
  if (skipReason) {
    return;
  }
  const primaryPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    await configureContractDerivedGrantFixture(primaryPool);
  } finally {
    await primaryPool.end();
  }
  if (!twoClusterSkipReason) {
    const secondaryPool = new Pool({
      connectionString: secondOperatorUrl,
      max: 1,
    });
    try {
      await configureContractDerivedGrantFixture(secondaryPool);
    } finally {
      await secondaryPool.end();
    }
  }
});

test(
  "PostgreSQL 17 completes every activation phase with secret-safe reporting",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 2 });
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    let runtimePool;
    let successFinalised = false;

    try {
      const pre = await assertCompleteDormantPreflight(adminPool, target);
      const directIdentity = await readPostgresFixtureIdentity(adminPool);
      const dockerIdentity = await readDockerPostgresFixtureIdentity({
        operatorUrl: boundDockerOperatorUrl,
        spawnImpl: primaryDockerSpawn,
        target,
      });
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        dockerIdentity,
      );
      mutation.fixtureValidated(
        target,
        directIdentity,
        dockerIdentity,
        planningAttestation,
        { now: providerNow },
      );

      const journal = new PlatformRuntimeActivationPhaseJournal();
      journal.start("dormant_role_preflight");
      journal.pass();

      journal.start("password_installation");
      const passwordPermit = mutation.authorisePasswordInstallation(
        target,
        providerPhaseAttestation(-50_000),
        { now: providerNow },
      );
      try {
        await installRuntimePasswordWithDocker({
          operatorUrl: boundDockerOperatorUrl,
          spawnImpl: primaryDockerSpawn,
          target,
          runtimePassword: syntheticRuntimePassword,
          expectedFixtureIdentity: directIdentity,
          phasePermit: passwordPermit,
          now: providerNow,
        });
      } catch (error) {
        mutation.passwordInstallationFailed(target, error);
        throw error;
      }
      const passwordState = await inspectFixture(adminPool, target);
      assert.equal(passwordState.login, false);
      assert.equal(passwordState.password_null, false);
      assert.deepEqual(invariants(passwordState), invariants(pre.state));
      journal.pass();

      journal.start("login_enablement");
      const loginPermit = mutation.authoriseLoginEnablement(
        target,
        providerPhaseAttestation(-40_000),
        { now: providerNow },
      );
      await adminPool.query(
        buildRuntimeRoleStatement(target, "enable_login", {
          phasePermit: loginPermit,
          now: providerNow,
        }),
      );
      const loginState = await inspectFixture(adminPool, target);
      assert.equal(loginState.login, true);
      assert.equal(loginState.password_null, false);
      assert.deepEqual(invariants(loginState), invariants(pre.state));
      journal.pass();

      journal.start("runtime_connection_construction");
      assert.throws(
        () =>
          buildRuntimeDatabaseUrl(
            boundDirectOperatorUrl,
            target,
            syntheticRuntimePassword,
            { now: providerNow },
          ),
        PlatformRuntimeActivationError,
      );
      const runtimeUrl = buildRuntimeDatabaseUrl(
        boundDockerOperatorUrl,
        target,
        syntheticRuntimePassword,
        { now: providerNow },
      );
      const providerShapedRuntimeUrl = new URL(runtimeUrl);
      assert.equal(
        providerShapedRuntimeUrl.hostname,
        disposablePooledHost,
      );
      assert.equal(effectiveTestPort(providerShapedRuntimeUrl), 5432);
      assert.equal(
        providerShapedRuntimeUrl.pathname,
        "/runtime_posture_test",
      );
      journal.pass();

      journal.start("runtime_connection_establishment");
      runtimePool = new Pool({
        connectionString: loopbackRuntimeTransport(
          runtimeUrl,
          operatorUrl,
        ),
        max: 1,
      });
      const runtimeClient = await runtimePool.connect();
      journal.pass();

      try {
        journal.start("runtime_identity");
        const identity = await runtimeClient.query(
          "select current_database(), current_user, session_user",
        );
        assert.equal(identity.rows.length, 1);
        assertRuntimeIdentity(
          identity.rows[0],
          target,
          "runtime_posture_test",
        );
        const runtimeFixtureIdentity =
          await readPostgresFixtureIdentity(runtimeClient);
        assertMatchingPostgresFixtureIdentities(
          directIdentity,
          runtimeFixtureIdentity,
        );
        journal.pass();

        journal.start("recursive_set_role_posture");
        const report = await assertRuntimeDatabasePosture(
          runtimeClient,
          runtimeActivationRole(target),
        );
        assert.equal(report.runtimePosture, "passed");
        journal.pass();
      } finally {
        runtimeClient.release(true);
      }

      journal.start("grants_and_ownership_verification");
      const post = await inspectFixture(adminPool, target);
      assert.deepEqual(invariants(post), invariants(pre.state));
      journal.pass();

      journal.start("success_finalisation");
      const successPermit = mutation.authoriseSuccessFinalisation(
        target,
        providerPhaseAttestation(-30_000),
        { now: providerNow },
      );
      mutation.successFinalised(target, successPermit, {
        now: providerNow,
      });
      successFinalised = true;
      journal.pass();
      journal.notRequired("mandatory_rollback");

      const safeReport = journal.safeReport();
      assert.equal(safeReport.failedPhase, null);
      assert.equal(safeReport.rollbackTriggered, false);
      assert.equal(safeReport.phases.success_finalisation, "passed");
      assert.equal(safeReport.phases.mandatory_rollback, "not_required");
    } finally {
      await runtimePool?.end().catch(() => {});
      if (successFinalised) {
        await adminPool.query(
          `alter role ${identifier(
            runtimeActivationRole(target),
          )} nologin password null`,
        );
      } else {
        await cleanupIfRequired(adminPool, mutation, target);
      }
      const dormant = await inspectFixture(adminPool, target);
      assertDormantFixture(dormant);
      await adminPool.end();
    }
  },
);

test(
  "PostgreSQL 17 preserves the failed phase and verifies mandatory rollback",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    const journal = new PlatformRuntimeActivationPhaseJournal();

    try {
      const pre = await assertCompleteDormantPreflight(adminPool, target);
      const directIdentity = await readPostgresFixtureIdentity(adminPool);
      const dockerIdentity = await readDockerPostgresFixtureIdentity({
        operatorUrl: boundDockerOperatorUrl,
        spawnImpl: primaryDockerSpawn,
        target,
      });
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        dockerIdentity,
      );
      mutation.fixtureValidated(
        target,
        directIdentity,
        dockerIdentity,
        planningAttestation,
        { now: providerNow },
      );

      journal.start("dormant_role_preflight");
      journal.pass();
      journal.start("password_installation");
      const passwordPermit = mutation.authorisePasswordInstallation(
        target,
        providerPhaseAttestation(-50_000),
        { now: providerNow },
      );
      try {
        await installRuntimePasswordWithDocker({
          operatorUrl: boundDockerOperatorUrl,
          spawnImpl: primaryDockerSpawn,
          target,
          runtimePassword: syntheticRuntimePassword,
          expectedFixtureIdentity: directIdentity,
          phasePermit: passwordPermit,
          now: providerNow,
        });
      } catch (error) {
        mutation.passwordInstallationFailed(target, error);
        throw error;
      }
      journal.pass();

      journal.start("login_enablement");
      const loginPermit = mutation.authoriseLoginEnablement(
        target,
        providerPhaseAttestation(-40_000),
        { now: providerNow },
      );
      await adminPool.query(
        buildRuntimeRoleStatement(target, "enable_login", {
          phasePermit: loginPermit,
          now: providerNow,
        }),
      );
      journal.pass();
      journal.start("runtime_connection_construction");
      const runtimeUrl = buildRuntimeDatabaseUrl(
        boundDockerOperatorUrl,
        target,
        syntheticRuntimePassword,
        { now: providerNow },
      );
      assert.equal(new URL(runtimeUrl).hostname, disposablePooledHost);
      journal.pass();
      journal.start("runtime_connection_establishment");
      journal.pass();
      journal.start("runtime_identity");
      journal.pass();
      journal.start("recursive_set_role_posture");
      journal.pass();
      journal.start("grants_and_ownership_verification");
      journal.fail();

      journal.start("mandatory_rollback");
      await cleanupIfRequired(adminPool, mutation, target);
      const rollbackState = await inspectFixture(adminPool, target);
      assertDormantFixture(rollbackState);
      assert.deepEqual(invariants(rollbackState), invariants(pre.state));
      journal.pass();

      const safeReport = journal.safeReport();
      assert.equal(
        safeReport.failedPhase,
        "grants_and_ownership_verification",
      );
      assert.equal(safeReport.rollbackTriggered, true);
      assert.equal(safeReport.rollbackVerified, true);
      assert.doesNotMatch(
        JSON.stringify(safeReport),
        /SyntheticRuntime|postgresql:\/\//,
      );
    } finally {
      await cleanupIfRequired(adminPool, mutation, target);
      await adminPool.end();
    }
  },
);

test(
  "failed initial fixture validation causes zero activation or cleanup mutation",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    let fixtureValidated = false;
    let installationCalls = 0;
    let cleanupCalls = 0;

    try {
      await assertDisposableFixtureIdentity(
        adminPool,
        target,
        boundDockerOperatorUrl,
        primaryDockerSpawn,
      );
      fixtureValidated = true;
      await adminPool.query(
        `alter role ${identifier(runtimeActivationRole(target))} login`,
      );
      await assert.rejects(
        () => assertCompleteDormantPreflight(adminPool, target),
        assert.AssertionError,
      );
      if (mutation.rollbackRequired(target)) {
        cleanupCalls += 1;
      }
      installationCalls += 0;

      const unchangedUnsafeState = await inspectFixture(adminPool, target);
      assert.equal(unchangedUnsafeState.login, true);
      assert.equal(unchangedUnsafeState.password_null, true);
      assert.equal(installationCalls, 0);
      assert.equal(cleanupCalls, 0);
    } finally {
      if (fixtureValidated) {
        await adminPool.query(
          `alter role ${identifier(
            runtimeActivationRole(target),
          )} nologin password null`,
        );
      }
      await adminPool.end();
    }
  },
);

test(
  "same SQL fixture fingerprint with a different Neon branch blocks before mutation",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    const wrongBranchBinding = providerPhaseAttestation(-50_000, {
      branchId: "br-disposable-recovery-002",
    });
    let installationCalls = 0;
    let cleanupCalls = 0;

    try {
      const before = await assertCompleteDormantPreflight(
        adminPool,
        target,
      );
      const directIdentity = await readPostgresFixtureIdentity(adminPool);
      const dockerIdentity = await readDockerPostgresFixtureIdentity({
        operatorUrl: boundDockerOperatorUrl,
        spawnImpl: primaryDockerSpawn,
        target,
      });
      assert.doesNotThrow(() =>
        assertMatchingPostgresFixtureIdentities(
          directIdentity,
          dockerIdentity,
        ),
      );
      assert.throws(
        () =>
          mutation.fixtureValidated(
            target,
            directIdentity,
            dockerIdentity,
            wrongBranchBinding,
          ),
        /Runtime activation failed/,
      );
      assert.throws(
        () =>
          mutation.authorisePasswordInstallation(
            target,
            providerPhaseAttestation(-50_000),
            { now: providerNow },
          ),
        /Runtime activation failed/,
      );
      if (mutation.rollbackRequired(target)) {
        cleanupCalls += 1;
      }
      installationCalls += 0;

      assert.equal(installationCalls, 0);
      assert.equal(cleanupCalls, 0);
      assert.deepEqual(await inspectFixture(adminPool, target), before.state);
    } finally {
      await adminPool.end();
    }
  },
);

test(
  "two-cluster fixture mismatch blocks before password installation and leaves both unchanged",
  { skip: twoClusterSkipReason },
  async () => {
    const firstPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const secondPool = new Pool({
      connectionString: secondOperatorUrl,
      max: 1,
    });
    const mutation = new PlatformRuntimeActivationMutationTracker(
      twoClusterTarget,
    );
    let installationCalls = 0;
    let cleanupCalls = 0;

    try {
      const firstBefore = await assertCompleteDormantPreflight(
        firstPool,
        twoClusterTarget,
      );
      const secondBefore = await assertCompleteDormantPreflight(
        secondPool,
        twoClusterTarget,
      );
      const firstIdentity = await readPostgresFixtureIdentity(firstPool);
      const wrongDockerIdentity =
        await readDockerPostgresFixtureIdentity({
          operatorUrl: boundSecondDockerOperatorUrl,
          spawnImpl: secondaryDockerSpawn,
          target: twoClusterTarget,
        });

      assert.throws(
        () =>
          mutation.fixtureValidated(
            twoClusterTarget,
            firstIdentity,
            wrongDockerIdentity,
            twoClusterPlanningAttestation,
          ),
        /Runtime activation failed/,
      );
      if (mutation.rollbackRequired(twoClusterTarget)) {
        cleanupCalls += 1;
      }

      assert.equal(installationCalls, 0);
      assert.equal(cleanupCalls, 0);
      assert.deepEqual(
        await inspectFixture(firstPool, twoClusterTarget),
        firstBefore.state,
      );
      assert.deepEqual(
        await inspectFixture(secondPool, twoClusterTarget),
        secondBefore.state,
      );
    } finally {
      await firstPool.end();
      await secondPool.end();
    }
  },
);

test(
  "read-only identity timeout confirms exact daemon-side container cleanup",
  { skip: skipReason },
  async () => {
    let containerName;
    const terminationArguments = [];

    await assert.rejects(
      () =>
        readDockerPostgresFixtureIdentity({
          operatorUrl: boundDockerOperatorUrl,
          target,
          timeoutMs: 2_000,
          terminationGraceMs: 500,
          terminationRetryMs: 500,
          terminationAttempts: 5,
          spawnImpl(command, args, options) {
            const delayedArgs = dockerArgsOnNetwork(args, dockerNetwork);
            containerName = delayedArgs[delayedArgs.indexOf("--name") + 1];
            delayedArgs[delayedArgs.length - 1] =
              `sleep 30; ${delayedArgs[delayedArgs.length - 1]}`;
            assert.equal(delayedArgs.includes(boundDockerOperatorUrl), false);
            return spawn(command, delayedArgs, options);
          },
          terminationSpawnImpl(command, args, options) {
            terminationArguments.push([...args]);
            assert.equal(args.includes(boundDockerOperatorUrl), false);
            return spawn(command, args, options);
          },
        }),
      /Runtime activation failed/,
    );

    assert.match(
      containerName,
      /^swooshz-runtime-identity-[0-9a-f-]{36}$/u,
    );
    assert.equal(
      terminationArguments.some(
        (args) =>
          args[0] === "rm" &&
          args[1] === "--force" &&
          args[2] === containerName,
      ),
      true,
    );
    assert.equal(
      terminationArguments.some(
        (args) =>
          args[0] === "ps" &&
          args[1] === "--all" &&
          args[2] === "--quiet" &&
          args[3] === "--filter" &&
          args[4] === `name=^/${containerName}$`,
      ),
      true,
    );
    assert.equal(
      await readDockerOutput([
        "ps",
        "--all",
        "--quiet",
        "--filter",
        `name=^/${containerName}$`,
      ]),
      "",
    );
  },
);

test(
  "dormant preflight rejects prohibited attributes and SET-assumable authority before password installation",
  { skip: skipReason },
  async (context) => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 2 });
    const createdRoles = [];
    let fixtureValidated = false;
    const suffix = randomUUID().replaceAll("-", "").slice(0, 8);
    let roleSequence = 0;
    const role = (label) => {
      roleSequence += 1;
      const name = `activation_${label}_${roleSequence}_${suffix}`;
      createdRoles.push(name);
      return name;
    };

    const assertUnsafeBeforeInstall = async () => {
      let installationCalls = 0;
      await assert.rejects(async () => {
        const result = await assertCompleteDormantPreflight(
          adminPool,
          target,
        );
        installationCalls += 1;
        return result;
      });
      assert.equal(installationCalls, 0);
    };

    try {
      await assertDisposableFixtureIdentity(
        adminPool,
        target,
        boundDockerOperatorUrl,
        primaryDockerSpawn,
      );
      fixtureValidated = true;
      for (const attribute of [
        "superuser",
        "createdb",
        "createrole",
        "replication",
        "bypassrls",
      ]) {
        await context.test(`${attribute} fails before password installation`, async () => {
          await adminPool.query(
            `alter role ${identifier(runtimeActivationRole(target))} ${attribute}`,
          );
          try {
            await assertUnsafeBeforeInstall();
          } finally {
            await adminPool.query(
              `alter role ${identifier(runtimeActivationRole(target))} no${attribute}`,
            );
          }
        });
      }

      await context.test("direct unsafe SET membership fails", async () => {
        const dangerous = role("direct_createdb");
        await createRole(adminPool, dangerous, "createdb");
        try {
          await grantRole(
            adminPool,
            dangerous,
            runtimeActivationRole(target),
            true,
            false,
          );
          await assertUnsafeBeforeInstall();
        } finally {
          await dropRole(adminPool, dangerous);
        }
      });

      await context.test("indirect unsafe SET membership fails", async () => {
        const middle = role("middle");
        const dangerous = role("indirect_bypassrls");
        await createRole(adminPool, middle);
        await createRole(adminPool, dangerous, "bypassrls");
        try {
          await grantRole(
            adminPool,
            middle,
            runtimeActivationRole(target),
            true,
            false,
          );
          await grantRole(adminPool, dangerous, middle, true, false);
          await assertUnsafeBeforeInstall();
        } finally {
          await dropRole(adminPool, dangerous);
          await dropRole(adminPool, middle);
        }
      });

      await context.test(
        "PostgreSQL rejects membership cycles and preflight rejects the remaining membership",
        async () => {
          const first = role("cycle_first");
          const second = role("cycle_second");
          await createRole(adminPool, first);
          await createRole(adminPool, second);
          try {
            await grantRole(
              adminPool,
              first,
              runtimeActivationRole(target),
              true,
              false,
            );
            await grantRole(adminPool, second, first, true, false);
            await assert.rejects(
              grantRole(adminPool, first, second, true, false),
              (error) => error?.code === "0LP01",
            );
            await assertUnsafeBeforeInstall();
          } finally {
            await dropRole(adminPool, second);
            await dropRole(adminPool, first);
          }
        },
      );

      await context.test("SET-disabled membership remains prohibited", async () => {
        const blocked = role("set_disabled_createdb");
        await createRole(adminPool, blocked, "createdb");
        try {
          await grantRole(
            adminPool,
            blocked,
            runtimeActivationRole(target),
            false,
            false,
          );
          await assertUnsafeBeforeInstall();
        } finally {
          await dropRole(adminPool, blocked);
        }
      });

      await context.test("reachable ADMIN OPTION fails", async () => {
        const blocked = role("admin_createdb");
        await createRole(adminPool, blocked, "createdb");
        try {
          await grantRole(
            adminPool,
            blocked,
            runtimeActivationRole(target),
            false,
            true,
          );
          await assertUnsafeBeforeInstall();
        } finally {
          await dropRole(adminPool, blocked);
        }
      });

      await context.test("prohibited neon membership fails", async () => {
        await ensureRole(adminPool, "neon_superuser");
        try {
          await grantRole(
            adminPool,
            "neon_superuser",
            runtimeActivationRole(target),
            false,
            false,
          );
          await assertUnsafeBeforeInstall();
        } finally {
          await adminPool.query(
            `revoke ${identifier("neon_superuser")} from ${identifier(
              runtimeActivationRole(target),
            )}`,
          );
        }
      });
    } finally {
      if (fixtureValidated) {
        await adminPool.query(
          `alter role ${identifier(
            runtimeActivationRole(target),
          )} nologin password null`,
        );
        for (const createdRole of createdRoles.reverse()) {
          await adminPool.query(
            `drop role if exists ${identifier(createdRole)}`,
          );
        }
        await adminPool
          .query(
            `revoke ${identifier("neon_superuser")} from ${identifier(
              runtimeActivationRole(target),
            )}`,
          )
          .catch(() => {});
      }
      await adminPool.end();
    }
  },
);

test(
  "PostgreSQL 17 detects missing, extra, and grant-option table drift and restores the fixture",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const roleName = runtimeActivationRole(target);
    try {
      await assertCompleteDormantPreflight(adminPool, target);

      await withRolledBackGrantMutation(adminPool, async () => {
        await adminPool.query(
          `revoke select on table public.access_validation_grants from ${identifier(roleName)}`,
        );
        const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
          adminPool,
          roleName,
        );
        assert.equal(report.runtimeTableGrantsExact, "failed");
        assert.equal(report.runtimeRoleAuthorityPosture, "failed");
      });

      await withRolledBackGrantMutation(adminPool, async () => {
        await adminPool.query(
          `grant update on table public.users to ${identifier(roleName)}`,
        );
        const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
          adminPool,
          roleName,
        );
        assert.equal(report.runtimeTableGrantsExact, "failed");
        assert.equal(report.runtimeRoleAuthorityPosture, "failed");
      });

      await withRolledBackGrantMutation(adminPool, async () => {
        await adminPool.query(
          `grant select on table public.access_validation_grants to ${identifier(roleName)} with grant option`,
        );
        const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
          adminPool,
          roleName,
        );
        assert.equal(report.runtimeTableGrantsExact, "failed");
        assert.equal(report.runtimeRoleAuthorityPosture, "failed");
      });

      await assertCompleteDormantPreflight(adminPool, target);
    } finally {
      await adminPool.end();
    }
  },
);

test(
  "PostgreSQL 17 rejects complete relation, column, default, routine, and sequence authority drift",
  { skip: skipReason },
  async (context) => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const roleName = runtimeActivationRole(target);
    const unrelatedRole =
      `rt_unrelated_${randomUUID().replaceAll("-", "").slice(0, 12)}`;

    try {
      await assertCompleteDormantPreflight(adminPool, target);

      const relationCases = [
        [
          "runtime SELECT on an unexpected public view",
          [
            "create view public.runtime_unexpected_view as select id from public.users",
            `grant select on public.runtime_unexpected_view to ${identifier(roleName)}`,
          ],
        ],
        [
          "runtime SELECT on an unexpected public materialized view",
          [
            "create materialized view public.runtime_unexpected_matview as select id from public.users with no data",
            `grant select on public.runtime_unexpected_matview to ${identifier(roleName)}`,
          ],
        ],
        [
          "runtime SELECT on an unexpected synthetic foreign table",
          [
            "create foreign data wrapper runtime_synthetic_fdw no handler",
            "create server runtime_synthetic_server foreign data wrapper runtime_synthetic_fdw",
            "create foreign table public.runtime_unexpected_foreign (id integer) server runtime_synthetic_server",
            `grant select on public.runtime_unexpected_foreign to ${identifier(roleName)}`,
          ],
        ],
        [
          "PUBLIC authority on a view-like relation",
          [
            "create view public.runtime_public_view as select id from public.users",
            "grant select on public.runtime_public_view to public",
          ],
        ],
        [
          "runtime direct authority in another non-system schema",
          [
            "create schema runtime_extra_schema",
            "create table runtime_extra_schema.runtime_extra_table (id integer)",
            `grant usage on schema runtime_extra_schema to ${identifier(roleName)}`,
            `grant select on runtime_extra_schema.runtime_extra_table to ${identifier(roleName)}`,
          ],
        ],
        [
          "correct relation and privilege in the wrong schema",
          [
            "create schema runtime_wrong_schema",
            "create table runtime_wrong_schema.access_validation_grants (id integer)",
            `grant select on runtime_wrong_schema.access_validation_grants to ${identifier(roleName)}`,
          ],
        ],
      ];

      for (const [name, statements] of relationCases) {
        await context.test(name, async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            for (const statement of statements) {
              await adminPool.query(statement);
            }
            await assertAuthorityCategoryFails(
              adminPool,
              roleName,
              "runtimeTableGrantsExact",
            );
          });
        });
      }

      await context.test(
        "runtime ownership of an unexpected view is denied outside direct ACL equality",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              "create view public.runtime_owned_view as select id from public.users",
            );
            await adminPool.query(
              `alter view public.runtime_owned_view owner to ${identifier(roleName)}`,
            );
            const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
              adminPool,
              roleName,
            );
            assert.equal(report.applicationTableOwnershipAbsent, "failed");
            assert.equal(report.runtimeTableGrantsExact, "passed");
            assert.equal(report.runtimeRoleAuthorityPosture, "failed");
          });
        },
      );

      await context.test(
        "schema authority and relation authority remain separate posture categories",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              `grant create on schema public to ${identifier(roleName)}`,
            );
            const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
              adminPool,
              roleName,
            );
            assert.equal(report.databaseAndSchemaCreateAbsent, "failed");
            assert.equal(report.runtimeTableGrantsExact, "passed");
            assert.equal(report.runtimeRoleAuthorityPosture, "failed");
          });
        },
      );

      const columnCases = [
        [
          "runtime column SELECT",
          `grant select (id) on public.users to ${identifier(roleName)}`,
        ],
        [
          "runtime column UPDATE",
          `grant update (id) on public.users to ${identifier(roleName)}`,
        ],
        [
          "runtime column REFERENCES",
          `grant references (id) on public.users to ${identifier(roleName)}`,
        ],
        [
          "runtime column grant option",
          `grant select (id) on public.users to ${identifier(roleName)} with grant option`,
        ],
        [
          "PUBLIC column authority",
          "grant select (id) on public.users to public",
        ],
      ];

      for (const [name, statement] of columnCases) {
        await context.test(name, async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(statement);
            await assertAuthorityCategoryFails(
              adminPool,
              roleName,
              "runtimeColumnAuthorityAbsent",
            );
          });
        });
      }

      await context.test(
        "column authority on a supported view-like object",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              "create view public.runtime_column_view as select id from public.users",
            );
            await adminPool.query(
              `grant select (id) on public.runtime_column_view to ${identifier(roleName)}`,
            );
            await assertAuthorityCategoryFails(
              adminPool,
              roleName,
              "runtimeColumnAuthorityAbsent",
            );
          });
        },
      );

      await context.test(
        "unrelated non-member role column authority does not falsely fail",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await createRole(adminPool, unrelatedRole);
            await adminPool.query(
              `grant select (id) on public.users to ${identifier(unrelatedRole)}`,
            );
            await assertCompleteDormantPreflight(adminPool, target);
          });
        },
      );

      const defaultAclCases = [
        [
          "owner global default SELECT to runtime",
          `alter default privileges grant select on tables to ${identifier(roleName)}`,
        ],
        [
          "owner global default UPDATE to runtime",
          `alter default privileges grant update on tables to ${identifier(roleName)}`,
        ],
        [
          "default relation privilege with grant option",
          `alter default privileges grant select on tables to ${identifier(roleName)} with grant option`,
        ],
        [
          "global default relation privilege to PUBLIC",
          "alter default privileges grant select on tables to public",
        ],
        [
          "schema-specific default ACL",
          `alter default privileges in schema public grant select on tables to ${identifier(roleName)}`,
        ],
      ];

      for (const [name, statement] of defaultAclCases) {
        await context.test(name, async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(statement);
            await assertAuthorityCategoryFails(
              adminPool,
              roleName,
              "runtimeDefaultRelationAuthorityAbsent",
            );
          });
        });
      }

      await context.test(
        "unrelated default ACL to a non-member role does not falsely fail",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await createRole(adminPool, unrelatedRole);
            await adminPool.query(
              `alter default privileges grant select on tables to ${identifier(unrelatedRole)}`,
            );
            await assertCompleteDormantPreflight(adminPool, target);
          });
        },
      );

      await context.test(
        "runtime routine and sequence authority remain separate denied categories",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              "create function public.runtime_unexpected_function() returns integer language sql as 'select 1'",
            );
            await adminPool.query(
              "revoke all on function public.runtime_unexpected_function() from public",
            );
            await adminPool.query(
              `grant execute on function public.runtime_unexpected_function() to ${identifier(roleName)}`,
            );
            await adminPool.query(
              "create sequence public.runtime_unexpected_sequence",
            );
            await adminPool.query(
              `grant usage on sequence public.runtime_unexpected_sequence to ${identifier(roleName)}`,
            );
            const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
              adminPool,
              roleName,
            );
            assert.equal(report.runtimeRoutineAuthorityAbsent, "failed");
            assert.equal(report.runtimeSequenceAuthorityAbsent, "failed");
            assert.equal(report.runtimeRoleAuthorityPosture, "failed");
          });
        },
      );

      await context.test(
        "runtime routine and sequence ownership remain separate denied categories",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              "create function public.runtime_owned_function() returns integer language sql as 'select 1'",
            );
            await adminPool.query(
              "revoke all on function public.runtime_owned_function() from public",
            );
            await adminPool.query(
              `alter function public.runtime_owned_function() owner to ${identifier(roleName)}`,
            );
            await adminPool.query(
              "create sequence public.runtime_owned_sequence",
            );
            await adminPool.query(
              `alter sequence public.runtime_owned_sequence owner to ${identifier(roleName)}`,
            );
            const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
              adminPool,
              roleName,
            );
            assert.equal(report.runtimeRoutineAuthorityAbsent, "failed");
            assert.equal(report.runtimeSequenceAuthorityAbsent, "failed");
            assert.equal(report.runtimeRoleAuthorityPosture, "failed");
          });
        },
      );

      await context.test(
        "provider-like object defaults are not misclassified as explicit application ACL drift",
        async () => {
          await withRolledBackAuthorityMutation(adminPool, async () => {
            await adminPool.query(
              "create schema runtime_provider_defaults",
            );
            await adminPool.query(
              `grant usage on schema runtime_provider_defaults to ${identifier(roleName)}`,
            );
            await adminPool.query(
              "create table runtime_provider_defaults.provider_table (id integer)",
            );
            await adminPool.query(
              "create view runtime_provider_defaults.provider_view as select id from runtime_provider_defaults.provider_table",
            );
            await adminPool.query(
              "create function runtime_provider_defaults.provider_function() returns integer language sql as 'select 1'",
            );
            await assertCompleteDormantPreflight(adminPool, target);
          });
        },
      );

      await assertCompleteDormantPreflight(adminPool, target);
      const cleanup = await adminPool.query(
        `
          select
            not exists (
              select 1 from pg_roles
              where rolname = $2
            ) as unrelated_role_absent,
            not exists (
              select 1 from pg_namespace
              where nspname like 'runtime_%schema'
            ) as synthetic_schemas_absent,
            not exists (
              select 1
              from pg_class
              where relname like 'runtime_unexpected_%'
                 or relname = 'runtime_public_view'
                 or relname = 'runtime_column_view'
                 or relname = 'runtime_owned_view'
                 or relname = 'runtime_owned_sequence'
            ) as synthetic_relations_absent,
            not exists (
              select 1
              from pg_default_acl default_acl
              cross join lateral aclexplode(default_acl.defaclacl) grant_record
              join pg_roles runtime_role on runtime_role.rolname = $1
              where default_acl.defaclobjtype = 'r'
                and grant_record.grantee in (0, runtime_role.oid)
            ) as prohibited_default_acls_absent
        `,
        [roleName, unrelatedRole],
      );
      assert.deepEqual(cleanup.rows, [
        {
          unrelated_role_absent: true,
          synthetic_schemas_absent: true,
          synthetic_relations_absent: true,
          prohibited_default_acls_absent: true,
        },
      ]);
    } finally {
      await adminPool.end();
    }
  },
);

async function configureContractDerivedGrantFixture(pool) {
  const roleName = runtimeActivationRole(target);
  const guard = await pool.query(
    `
      select
        current_database() = 'runtime_posture_test' as database_is_disposable,
        current_setting('server_version_num')::integer / 10000 = 17
          as server_is_postgresql_17,
        (select count(*) = 1 from pg_roles where rolname = $1)
          as runtime_role_exists
    `,
    [roleName],
  );
  assert.deepEqual(guard.rows, [
    {
      database_is_disposable: true,
      server_is_postgresql_17: true,
      runtime_role_exists: true,
    },
  ]);

  await pool.query(
    `revoke all privileges on all tables in schema public from ${identifier(roleName)}`,
  );
  const privilegesByTable = new Map();
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    const privileges = privilegesByTable.get(record.objectName) ?? [];
    privileges.push(record.privilege);
    privilegesByTable.set(record.objectName, privileges);
  }
  for (const [tableName, privileges] of privilegesByTable) {
    await pool.query(
      `grant ${privileges.join(", ")} on table public.${identifier(tableName)} to ${identifier(roleName)}`,
    );
  }
}

async function withRolledBackAuthorityMutation(pool, operation) {
  await pool.query("begin");
  try {
    await operation();
  } finally {
    await pool.query("rollback");
  }
}

const withRolledBackGrantMutation = withRolledBackAuthorityMutation;

async function assertAuthorityCategoryFails(pool, roleName, category) {
  const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
    pool,
    roleName,
  );
  assert.equal(report[category], "failed");
  assert.equal(report.runtimeRoleAuthorityPosture, "failed");
}

async function assertDisposableFixtureIdentity(
  pool,
  activationTarget,
  dockerUrl,
  dockerSpawn,
) {
  await assertCompleteDormantPreflight(pool, activationTarget);
  const directIdentity = await readPostgresFixtureIdentity(pool);
  const dockerIdentity = await readDockerPostgresFixtureIdentity({
    operatorUrl: dockerUrl,
    spawnImpl: dockerSpawn,
    target: activationTarget,
  });
  assertMatchingPostgresFixtureIdentities(
    directIdentity,
    dockerIdentity,
  );
}

async function assertCompleteDormantPreflight(pool, activationTarget) {
  const state = await inspectFixture(pool, activationTarget);
  assertDormantFixture(state);
  const authority = await inspectRuntimeDatabaseRoleAuthorityPosture(
    pool,
    runtimeActivationRole(activationTarget),
  );
  assert.deepEqual(authority, {
    roleIdentityConclusive: "passed",
    administrativeAttributesAbsent: "passed",
    databaseAndSchemaCreateAbsent: "passed",
    migrationLedgerAccessDenied: "passed",
    databaseAndSchemaOwnershipAbsent: "passed",
    applicationTableOwnershipAbsent: "passed",
    runtimeTableGrantsExact: "passed",
    runtimeColumnAuthorityAbsent: "passed",
    runtimeDefaultRelationAuthorityAbsent: "passed",
    runtimeRoutineAuthorityAbsent: "passed",
    runtimeSequenceAuthorityAbsent: "passed",
    runtimeRoleAuthorityPosture: "passed",
  });
  return { authority, state };
}

async function inspectFixture(pool, activationTarget) {
  const roleName = runtimeActivationRole(activationTarget);
  const result = await pool.query(
    `
      select json_build_object(
        'database', current_database(),
        'operator', current_user,
        'session_operator', session_user,
        'postgres_major',
          current_setting('server_version_num')::integer / 10000,
        'role_count', (
          select count(*) from pg_authid where rolname = $1
        ),
        'login', (
          select rolcanlogin from pg_authid where rolname = $1
        ),
        'password_null', (
          select rolpassword is null from pg_authid where rolname = $1
        ),
        'grant_matrix', coalesce((
          select json_agg(
            json_build_array(
              grantor,
              grantee,
              table_schema,
              table_name,
              privilege_type,
              is_grantable
            )
            order by
              grantor,
              grantee,
              table_schema,
              table_name,
              privilege_type,
              is_grantable
          )
          from information_schema.role_table_grants
          where grantee = $1 and table_schema = 'public'
        ), '[]'::json),
        'owned_databases', (
          select count(*)
          from pg_database database_record
          join pg_roles role_record
            on role_record.oid = database_record.datdba
          where role_record.rolname = $1
        ),
        'owned_schemas', (
          select count(*)
          from pg_namespace schema_record
          join pg_roles role_record
            on role_record.oid = schema_record.nspowner
          where role_record.rolname = $1
        ),
        'owned_relations', (
          select count(*)
          from pg_class relation_record
          join pg_roles role_record
            on role_record.oid = relation_record.relowner
          where role_record.rolname = $1
        ),
        'owned_routines', (
          select count(*)
          from pg_proc routine_record
          join pg_roles role_record
            on role_record.oid = routine_record.proowner
          where role_record.rolname = $1
        ),
        'owned_types', (
          select count(*)
          from pg_type type_record
          join pg_roles role_record
            on role_record.oid = type_record.typowner
          where role_record.rolname = $1
        ),
        'ledger_rows', (
          select count(*) from drizzle.__drizzle_migrations
        ),
        'public_tables', (
          select count(*)
          from pg_class relation_record
          join pg_namespace schema_record
            on schema_record.oid = relation_record.relnamespace
          where schema_record.nspname = 'public'
            and relation_record.relkind in ('r', 'p')
        ),
        'public_table_names', (
          select json_agg(
            relation_record.relname order by relation_record.relname
          )
          from pg_class relation_record
          join pg_namespace schema_record
            on schema_record.oid = relation_record.relnamespace
          where schema_record.nspname = 'public'
            and relation_record.relkind in ('r', 'p')
        ),
        'public_indexes', (
          select count(*) from pg_indexes where schemaname = 'public'
        )
      ) as state
    `,
    [roleName],
  );
  assert.equal(result.rows.length, 1);
  return result.rows[0].state;
}

function assertDormantFixture(state) {
  assert.equal(state.database, "runtime_posture_test");
  assert.equal(state.operator, "platform_app");
  assert.equal(state.session_operator, "platform_app");
  assert.equal(state.postgres_major, 17);
  assert.equal(state.role_count, 1);
  assert.equal(state.login, false);
  assert.equal(state.password_null, true);
  assert.equal(state.grant_matrix.length, 39);
  assert.deepEqual(
    state.grant_matrix
      .map((row) => row.slice(1))
      .sort((left, right) =>
        left.join("\u0000").localeCompare(right.join("\u0000")),
      ),
    expectedGrantMatrix,
  );
  assert.equal(state.owned_databases, 0);
  assert.equal(state.owned_schemas, 0);
  assert.equal(state.owned_relations, 0);
  assert.equal(state.owned_routines, 0);
  assert.equal(state.owned_types, 0);
  assert.equal(state.ledger_rows, 9);
  assert.equal(state.public_tables, 14);
  assert.deepEqual(state.public_table_names, expectedPublicTables);
  assert.equal(state.public_indexes, 59);
}

function invariants(state) {
  return {
    role_count: state.role_count,
    grant_matrix: state.grant_matrix,
    owned_databases: state.owned_databases,
    owned_schemas: state.owned_schemas,
    owned_relations: state.owned_relations,
    owned_routines: state.owned_routines,
    owned_types: state.owned_types,
    ledger_rows: state.ledger_rows,
    public_tables: state.public_tables,
    public_table_names: state.public_table_names,
    public_indexes: state.public_indexes,
  };
}

function providerPhaseAttestation(
  observedOffsetMs,
  {
    branchId = "br-disposable-local-001",
  } = {},
) {
  return createNeonProviderAttestation(
    {
      branchId,
      database: "runtime_posture_test",
      endpoints: [
        {
          branchId,
          currentState: "active",
          database: "runtime_posture_test",
          disabled: false,
          host: disposableDirectHost,
          id: disposableEndpointId,
          port: 5432,
          projectId: "disposable-local-123456",
          proxyHost: disposableProxyHost,
          regionId: disposableRegionId,
          type: "read_write",
        },
      ],
      expiresAt: new Date(providerNow + 10 * 60_000).toISOString(),
      observedAt: new Date(
        providerNow + observedOffsetMs,
      ).toISOString(),
      projectId: "disposable-local-123456",
      provider: "neon",
    },
    { now: providerNow },
  );
}

async function cleanupIfRequired(pool, mutation, activationTarget) {
  if (!mutation.rollbackRequired(activationTarget)) {
    return;
  }
  const currentIdentity = await readPostgresFixtureIdentity(pool);
  const rollbackPermit = mutation.assertRollbackFixture(
    activationTarget,
    currentIdentity,
    providerPhaseAttestation(-10_000),
    { now: providerNow },
  );
  await pool.query(
    buildRuntimeRoleStatement(activationTarget, "rollback", {
      phasePermit: rollbackPermit,
      now: providerNow,
    }),
  );
  mutation.rollbackCompleted(activationTarget);
}

async function createRole(pool, roleName, attributes = "") {
  await pool.query(
    `create role ${identifier(roleName)} noinherit nologin ${attributes}`,
  );
}

async function ensureRole(pool, roleName) {
  const exists = await pool.query(
    "select 1 from pg_roles where rolname = $1",
    [roleName],
  );
  if (exists.rows.length === 0) {
    await createRole(pool, roleName);
  }
}

async function grantRole(
  pool,
  grantedRole,
  memberRole,
  setOption,
  adminOption,
) {
  await pool.query(
    `grant ${identifier(grantedRole)} to ${identifier(memberRole)}
      with inherit false, set ${setOption ? "true" : "false"},
      admin ${adminOption ? "true" : "false"}`,
  );
}

async function dropRole(pool, roleName) {
  await pool.query(`drop role if exists ${identifier(roleName)}`);
}

function identifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function readDockerOutput(args) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    const output = [];
    let outputLength = 0;
    child.once("error", () => reject(new Error("Docker query failed.")));
    child.once("close", (code, signal) => {
      if (code !== 0 || signal !== null || outputLength > 256) {
        reject(new Error("Docker query failed."));
        return;
      }
      resolve(Buffer.concat(output).toString("utf8").trim());
    });
    child.stdout.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= 256) {
        output.push(Buffer.from(chunk));
      }
    });
  });
}

function dockerSpawnOnNetwork(network) {
  return (command, args, options) =>
    spawn(command, dockerArgsOnNetwork(args, network), options);
}

function dockerArgsOnNetwork(args, network) {
  if (
    !network ||
    args[0] !== "run" ||
    args.includes("--network")
  ) {
    throw new Error("Disposable Docker network is not configured.");
  }
  return ["run", "--network", network, ...args.slice(1)];
}

function loopbackRuntimeTransport(runtimeUrl, fixtureUrl) {
  const logical = new URL(runtimeUrl);
  const fixture = new URL(fixtureUrl);
  if (
    logical.hostname !== disposablePooledHost ||
    effectiveTestPort(logical) !== 5432 ||
    fixture.hostname !== "127.0.0.1" ||
    !fixture.port
  ) {
    throw new Error("Disposable loopback transport is not configured.");
  }
  logical.hostname = fixture.hostname;
  logical.port = fixture.port;
  return logical.toString();
}

function effectiveTestPort(parsed) {
  return parsed.port ? Number(parsed.port) : 5432;
}
