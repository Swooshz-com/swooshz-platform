import assert from "node:assert/strict";
import test from "node:test";

import { Pool } from "pg";

import {
  PlatformRuntimeActivationPhaseJournal,
  buildRuntimeDatabaseUrl,
  installRuntimePasswordWithDocker,
} from "../scripts/platform-runtime-activation-contract.mjs";
import { assertRuntimeDatabasePosture } from "../dist/db/runtime-posture.js";

const operatorUrl = process.env.RUNTIME_ACTIVATION_TEST_OPERATOR_URL;
const dockerOperatorUrl =
  process.env.RUNTIME_ACTIVATION_TEST_DOCKER_OPERATOR_URL;
const disposableConfirmed =
  process.env.RUNTIME_ACTIVATION_TEST_CONFIRM === "disposable-only";
const skipReason =
  operatorUrl && dockerOperatorUrl && disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable activation fixture";
const syntheticRuntimePassword =
  "SyntheticRuntime_2026!éΩ漢字_ExtraLength";

test(
  "PostgreSQL 17 completes every activation phase with secret-safe reporting",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 2 });
    let runtimePool;

    try {
      const pre = await inspectFixture(adminPool);
      assertDormantFixture(pre);

      const journal = new PlatformRuntimeActivationPhaseJournal();
      journal.start("dormant_role_preflight");
      journal.pass();

      journal.start("password_installation");
      await installRuntimePasswordWithDocker({
        operatorUrl: dockerOperatorUrl,
        runtimeRole: "platform_runtime",
        runtimePassword: syntheticRuntimePassword,
      });
      const passwordState = await inspectFixture(adminPool);
      assert.equal(passwordState.login, false);
      assert.equal(passwordState.password_null, false);
      assert.deepEqual(invariants(passwordState), invariants(pre));
      journal.pass();

      journal.start("login_enablement");
      await adminPool.query("alter role platform_runtime login");
      const loginState = await inspectFixture(adminPool);
      assert.equal(loginState.login, true);
      assert.equal(loginState.password_null, false);
      assert.deepEqual(invariants(loginState), invariants(pre));
      journal.pass();

      journal.start("runtime_connection_construction");
      const runtimeUrl = buildRuntimeDatabaseUrl(
        operatorUrl,
        "platform_runtime",
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
        assert.deepEqual(identity.rows, [
          {
            current_database: "runtime_posture_test",
            current_user: "platform_runtime",
            session_user: "platform_runtime",
          },
        ]);
        journal.pass();

        journal.start("recursive_set_role_posture");
        const report = await assertRuntimeDatabasePosture(
          runtimeClient,
          "platform_runtime",
        );
        assert.equal(report.runtimePosture, "passed");
        journal.pass();
      } finally {
        runtimeClient.release(true);
      }

      journal.start("grants_and_ownership_verification");
      const post = await inspectFixture(adminPool);
      assert.deepEqual(invariants(post), invariants(pre));
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
      await rollback(adminPool);
      await adminPool.end();
    }
  },
);

test(
  "PostgreSQL 17 preserves the failed phase and verifies mandatory rollback",
  { skip: skipReason },
  async () => {
    const adminPool = new Pool({ connectionString: operatorUrl, max: 1 });
    const journal = new PlatformRuntimeActivationPhaseJournal();
    let runtimePool;

    try {
      const pre = await inspectFixture(adminPool);
      assertDormantFixture(pre);

      journal.start("dormant_role_preflight");
      journal.pass();
      journal.start("password_installation");
      await installRuntimePasswordWithDocker({
        operatorUrl: dockerOperatorUrl,
        runtimeRole: "platform_runtime",
        runtimePassword: syntheticRuntimePassword,
      });
      journal.pass();
      journal.start("login_enablement");
      await adminPool.query("alter role platform_runtime login");
      journal.pass();

      journal.start("runtime_connection_construction");
      const runtimeUrl = buildRuntimeDatabaseUrl(
        operatorUrl,
        "platform_runtime",
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
        assert.deepEqual(identity.rows, [
          {
            current_database: "runtime_posture_test",
            current_user: "platform_runtime",
            session_user: "platform_runtime",
          },
        ]);
        journal.pass();

        journal.start("recursive_set_role_posture");
        const report = await assertRuntimeDatabasePosture(
          runtimeClient,
          "platform_runtime",
        );
        assert.equal(report.runtimePosture, "passed");
        journal.pass();
      } finally {
        runtimeClient.release(true);
      }

      journal.start("grants_and_ownership_verification");
      journal.fail();

      journal.start("mandatory_rollback");
      await rollback(adminPool);
      const rollbackState = await inspectFixture(adminPool);
      assertDormantFixture(rollbackState);
      assert.deepEqual(invariants(rollbackState), invariants(pre));
      journal.pass();

      const safeReport = journal.safeReport();
      assert.equal(
        safeReport.failedPhase,
        "grants_and_ownership_verification",
      );
      assert.equal(safeReport.rollbackTriggered, true);
      assert.equal(safeReport.rollbackVerified, true);
      assert.equal(
        safeReport.phases.grants_and_ownership_verification,
        "failed",
      );
      assert.equal(safeReport.phases.mandatory_rollback, "passed");
      assert.doesNotMatch(
        JSON.stringify(safeReport),
        /SyntheticRuntime|postgresql:\/\//,
      );
    } finally {
      await runtimePool?.end().catch(() => {});
      await rollback(adminPool);
      await adminPool.end();
    }
  },
);

async function inspectFixture(pool) {
  const result = await pool.query(`
    select json_build_object(
      'database', current_database(),
      'operator', current_user,
      'session_operator', session_user,
      'postgres_major', current_setting('server_version_num')::integer / 10000,
      'login', (
        select rolcanlogin from pg_authid where rolname = 'platform_runtime'
      ),
      'password_null', (
        select rolpassword is null
        from pg_authid
        where rolname = 'platform_runtime'
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
        where grantee = 'platform_runtime' and table_schema = 'public'
      ), '[]'::json),
      'owned_databases', (
        select count(*)
        from pg_database database_record
        join pg_roles role_record
          on role_record.oid = database_record.datdba
        where role_record.rolname = 'platform_runtime'
      ),
      'owned_schemas', (
        select count(*)
        from pg_namespace schema_record
        join pg_roles role_record
          on role_record.oid = schema_record.nspowner
        where role_record.rolname = 'platform_runtime'
      ),
      'owned_relations', (
        select count(*)
        from pg_class relation_record
        join pg_roles role_record
          on role_record.oid = relation_record.relowner
        where role_record.rolname = 'platform_runtime'
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
      'public_indexes', (
        select count(*) from pg_indexes where schemaname = 'public'
      )
    ) as state
  `);
  assert.equal(result.rows.length, 1);
  return result.rows[0].state;
}

function assertDormantFixture(state) {
  assert.equal(state.database, "runtime_posture_test");
  assert.equal(state.operator, "platform_app");
  assert.equal(state.session_operator, "platform_app");
  assert.equal(state.postgres_major, 17);
  assert.equal(state.login, false);
  assert.equal(state.password_null, true);
  assert.equal(state.grant_matrix.length, 39);
  assert.equal(state.owned_databases, 0);
  assert.equal(state.owned_schemas, 0);
  assert.equal(state.owned_relations, 0);
  assert.equal(state.ledger_rows, 9);
  assert.equal(state.public_tables, 14);
  assert.equal(state.public_indexes, 59);
}

function invariants(state) {
  return {
    grant_matrix: state.grant_matrix,
    owned_databases: state.owned_databases,
    owned_schemas: state.owned_schemas,
    owned_relations: state.owned_relations,
    ledger_rows: state.ledger_rows,
    public_tables: state.public_tables,
    public_indexes: state.public_indexes,
  };
}

async function rollback(pool) {
  await pool.query("alter role platform_runtime nologin password null");
}
