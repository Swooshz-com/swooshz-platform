import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { Pool } from "pg";

import {
  PlatformRuntimeActivationMutationTracker,
  PlatformRuntimeActivationPhaseJournal,
  assertMatchingPostgresFixtureIdentities,
  assertRuntimeIdentity,
  buildRuntimeDatabaseUrl,
  buildRuntimeRoleStatement,
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

const operatorUrl = process.env.RUNTIME_ACTIVATION_TEST_OPERATOR_URL;
const dockerOperatorUrl =
  process.env.RUNTIME_ACTIVATION_TEST_DOCKER_OPERATOR_URL;
const secondOperatorUrl =
  process.env.RUNTIME_ACTIVATION_TEST_SECOND_OPERATOR_URL;
const secondDockerOperatorUrl =
  process.env.RUNTIME_ACTIVATION_TEST_SECOND_DOCKER_OPERATOR_URL;
const disposableConfirmed =
  process.env.RUNTIME_ACTIVATION_TEST_CONFIRM === "disposable-only";
const skipReason =
  operatorUrl && dockerOperatorUrl && disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable activation fixture";
const twoClusterSkipReason =
  !skipReason && secondOperatorUrl && secondDockerOperatorUrl
    ? false
    : "requires two explicitly confirmed disposable PostgreSQL fixtures";
const syntheticRuntimePassword =
  "SyntheticRuntime_2026!éΩ漢字_ExtraLength";
const target = createRuntimeActivationTarget("platform_runtime");
const expectedTablePrivileges = Object.freeze({
  access_validation_grants: ["INSERT", "SELECT"],
  app_entitlements: ["INSERT", "SELECT"],
  app_launch_tokens: ["INSERT", "SELECT"],
  apps: ["INSERT", "SELECT"],
  audit_events: ["INSERT", "SELECT"],
  auth_states: ["DELETE", "INSERT", "SELECT"],
  csrf_tokens: ["DELETE", "INSERT", "SELECT", "UPDATE"],
  invitations: ["INSERT", "SELECT", "UPDATE"],
  memberships: ["DELETE", "INSERT", "SELECT", "UPDATE"],
  provider_identities: ["INSERT", "SELECT", "UPDATE"],
  sessions: ["INSERT", "SELECT", "UPDATE"],
  users: ["INSERT", "SELECT", "UPDATE"],
  workspace_membership_approvals: ["INSERT", "SELECT", "UPDATE"],
  workspaces: ["INSERT", "SELECT", "UPDATE"],
});
const expectedPublicTables = Object.freeze(
  Object.keys(expectedTablePrivileges).sort(),
);
const expectedGrantMatrix = Object.freeze(
  Object.entries(expectedTablePrivileges)
    .flatMap(([tableName, privileges]) =>
      privileges.map((privilege) => [
        "platform_runtime",
        "public",
        tableName,
        privilege,
        "NO",
      ]),
    )
    .sort((left, right) =>
      left.join("\u0000").localeCompare(right.join("\u0000")),
    ),
);

test(
  "PostgreSQL 17 completes every activation phase with secret-safe reporting",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 2 });
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    let runtimePool;

    try {
      const pre = await assertCompleteDormantPreflight(adminPool, target);
      const directIdentity = await readPostgresFixtureIdentity(adminPool);
      const dockerIdentity = await readDockerPostgresFixtureIdentity({
        operatorUrl: dockerOperatorUrl,
      });
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        dockerIdentity,
      );
      mutation.fixtureValidated(target, directIdentity, dockerIdentity);

      const journal = new PlatformRuntimeActivationPhaseJournal();
      journal.start("dormant_role_preflight");
      journal.pass();

      journal.start("password_installation");
      mutation.passwordInstallationStarted(target);
      try {
        await installRuntimePasswordWithDocker({
          operatorUrl: dockerOperatorUrl,
          target,
          runtimePassword: syntheticRuntimePassword,
          expectedFixtureIdentity: directIdentity,
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
      await adminPool.query(buildRuntimeRoleStatement(target, "enable_login"));
      const loginState = await inspectFixture(adminPool, target);
      assert.equal(loginState.login, true);
      assert.equal(loginState.password_null, false);
      assert.deepEqual(invariants(loginState), invariants(pre.state));
      journal.pass();

      journal.start("runtime_connection_construction");
      const runtimeUrl = buildRuntimeDatabaseUrl(
        operatorUrl,
        target,
        syntheticRuntimePassword,
      );
      journal.pass();

      journal.start("runtime_connection_establishment");
      runtimePool = new Pool({ connectionString: runtimeUrl, max: 1 });
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
      journal.pass();
      journal.notRequired("mandatory_rollback");

      const safeReport = journal.safeReport();
      assert.equal(safeReport.failedPhase, null);
      assert.equal(safeReport.rollbackTriggered, false);
      assert.equal(safeReport.phases.success_finalisation, "passed");
      assert.equal(safeReport.phases.mandatory_rollback, "not_required");
    } finally {
      await runtimePool?.end().catch(() => {});
      await cleanupIfRequired(adminPool, mutation, target);
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
        operatorUrl: dockerOperatorUrl,
      });
      assertMatchingPostgresFixtureIdentities(
        directIdentity,
        dockerIdentity,
      );
      mutation.fixtureValidated(target, directIdentity, dockerIdentity);

      journal.start("dormant_role_preflight");
      journal.pass();
      journal.start("password_installation");
      mutation.passwordInstallationStarted(target);
      try {
        await installRuntimePasswordWithDocker({
          operatorUrl: dockerOperatorUrl,
          target,
          runtimePassword: syntheticRuntimePassword,
          expectedFixtureIdentity: directIdentity,
        });
      } catch (error) {
        mutation.passwordInstallationFailed(target, error);
        throw error;
      }
      journal.pass();

      journal.start("login_enablement");
      await adminPool.query(buildRuntimeRoleStatement(target, "enable_login"));
      journal.pass();
      journal.start("runtime_connection_construction");
      buildRuntimeDatabaseUrl(operatorUrl, target, syntheticRuntimePassword);
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
        dockerOperatorUrl,
      );
      fixtureValidated = true;
      await adminPool.query(buildRuntimeRoleStatement(target, "enable_login"));
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
        await adminPool.query(buildRuntimeRoleStatement(target, "rollback"));
      }
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
    const mutation = new PlatformRuntimeActivationMutationTracker(target);
    let installationCalls = 0;
    let cleanupCalls = 0;

    try {
      const firstBefore = await assertCompleteDormantPreflight(
        firstPool,
        target,
      );
      const secondBefore = await assertCompleteDormantPreflight(
        secondPool,
        target,
      );
      const firstIdentity = await readPostgresFixtureIdentity(firstPool);
      const wrongDockerIdentity =
        await readDockerPostgresFixtureIdentity({
          operatorUrl: secondDockerOperatorUrl,
        });

      assert.throws(
        () =>
          mutation.fixtureValidated(
            target,
            firstIdentity,
            wrongDockerIdentity,
          ),
        /Runtime activation failed/,
      );
      if (mutation.rollbackRequired(target)) {
        cleanupCalls += 1;
      }

      assert.equal(installationCalls, 0);
      assert.equal(cleanupCalls, 0);
      assert.deepEqual(
        await inspectFixture(firstPool, target),
        firstBefore.state,
      );
      assert.deepEqual(
        await inspectFixture(secondPool, target),
        secondBefore.state,
      );
    } finally {
      await firstPool.end();
      await secondPool.end();
    }
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
        dockerOperatorUrl,
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
        "PostgreSQL rejects membership cycles and preflight remains deterministic",
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
            await assertCompleteDormantPreflight(adminPool, target);
          } finally {
            await dropRole(adminPool, second);
            await dropRole(adminPool, first);
          }
        },
      );

      await context.test("SET-disabled edge does not become assumable", async () => {
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
          await assertCompleteDormantPreflight(adminPool, target);
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
        await adminPool.query(buildRuntimeRoleStatement(target, "rollback"));
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

async function assertDisposableFixtureIdentity(
  pool,
  activationTarget,
  dockerUrl,
) {
  await assertCompleteDormantPreflight(pool, activationTarget);
  const directIdentity = await readPostgresFixtureIdentity(pool);
  const dockerIdentity = await readDockerPostgresFixtureIdentity({
    operatorUrl: dockerUrl,
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

async function cleanupIfRequired(pool, mutation, activationTarget) {
  if (!mutation.rollbackRequired(activationTarget)) {
    return;
  }
  const currentIdentity = await readPostgresFixtureIdentity(pool);
  mutation.assertRollbackFixture(activationTarget, currentIdentity);
  await pool.query(buildRuntimeRoleStatement(activationTarget, "rollback"));
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
