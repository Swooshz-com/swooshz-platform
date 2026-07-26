import assert from "node:assert/strict";
import test from "node:test";

import {
  RuntimeDatabasePostureError,
  assertRuntimeDatabasePosture,
  inspectRuntimeDatabasePosture,
  inspectRuntimeDatabaseRoleAuthorityPosture,
  readExpectedRuntimeRole,
} from "../dist/db/runtime-posture.js";

const expectedRole = "platform_runtime";

const passingRow = Object.freeze({
  expected_role_match: true,
  role_assumption_state_conclusive: true,
  role_membership_admin_absent: true,
  neon_superuser_membership_absent: true,
  superuser_absent: true,
  createdb_absent: true,
  createrole_absent: true,
  replication_absent: true,
  bypassrls_absent: true,
  database_create_absent: true,
  public_schema_create_absent: true,
  drizzle_schema_usage_absent: true,
  migration_ledger_select_absent: true,
  database_ownership_absent: true,
  schema_ownership_absent: true,
  application_table_ownership_absent: true,
});

test("expected runtime role is required only in production", () => {
  assert.throws(
    () => readExpectedRuntimeRole({ NODE_ENV: "production" }),
    safePostureError,
  );
  assert.equal(readExpectedRuntimeRole({ NODE_ENV: "development" }), null);
  assert.equal(readExpectedRuntimeRole({ NODE_ENV: "test" }), null);
  assert.equal(
    readExpectedRuntimeRole({
      NODE_ENV: "production",
      DATABASE_EXPECTED_RUNTIME_ROLE: `  ${expectedRole}  `,
    }),
    expectedRole,
  );
});

test("expected runtime role rejects unsafe PostgreSQL identifiers", () => {
  for (const role of [
    "Platform_Runtime",
    "9runtime",
    "runtime-role",
    "runtime role",
    "runtime;select",
    "a".repeat(64),
  ]) {
    assert.throws(
      () =>
        readExpectedRuntimeRole({
          NODE_ENV: "production",
          DATABASE_EXPECTED_RUNTIME_ROLE: role,
        }),
      safePostureError,
    );
  }
});

test("restricted runtime posture returns aggregate states only", async () => {
  const calls = [];
  const report = await inspectRuntimeDatabasePosture(
    {
      async query(sql, values) {
        calls.push({ sql, values });
        return { rows: [{ ...passingRow }] };
      },
    },
    expectedRole,
  );

  assert.deepEqual(report, {
    expectedRoleMatch: "passed",
    administrativeAttributesAbsent: "passed",
    databaseAndSchemaCreateAbsent: "passed",
    migrationLedgerAccessDenied: "passed",
    databaseAndSchemaOwnershipAbsent: "passed",
    applicationTableOwnershipAbsent: "passed",
    runtimePosture: "passed",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].values[0], expectedRole);
  assert.ok(calls[0].values[1].includes("access_validation_grants"));
  assert.match(calls[0].sql, /current_user = \$1 and session_user = \$1/);
  assert.match(
    calls[0].sql,
    /pg_has_role\(assumable_role\.role_oid, table_record\.relowner, 'USAGE'\)/,
  );
  assert.match(
    calls[0].sql,
    /migration_record\.relnamespace = schema_record\.oid/,
  );
  assert.match(calls[0].sql, /migration_record\.relname = '__drizzle_migrations'/);
  assert.match(
    calls[0].sql,
    /migration_record\.relkind as migration_ledger_relkind/,
  );
  assert.doesNotMatch(
    calls[0].sql,
    /migration_record\.relname = '__drizzle_migrations'[\s\S]*?and migration_record\.relkind/,
  );
  assert.match(
    calls[0].sql,
    /has_table_privilege\(\s*assumable_role\.role_oid,\s*\(select migration_ledger_oid from drizzle_state\)/,
  );
  assert.doesNotMatch(calls[0].sql, /to_regclass\('drizzle\.__drizzle_migrations'\)/);
  assert.doesNotMatch(
    calls[0].sql,
    /has_table_privilege\(\s*current_user,\s*'drizzle\.__drizzle_migrations'/,
  );
  assert.doesNotMatch(calls[0].sql, new RegExp(expectedRole));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(expectedRole));
});

test("runtime posture traverses every SET-assumable role by catalog OID", async () => {
  let postureSql = "";
  await inspectRuntimeDatabasePosture(
    {
      async query(sql) {
        postureSql = sql;
        return { rows: [{ ...passingRow }] };
      },
    },
    expectedRole,
  );

  assert.match(postureSql, /with recursive/i);
  assert.match(
    postureSql,
    /pg_roles[\s\S]*?rolname = \$1/,
  );
  assert.match(
    postureSql,
    /pg_auth_members[\s\S]*?member = [a-z_.]+role_oid[\s\S]*?set_option/,
  );
  assert.match(postureSql, /set_assumable_roles\(role_oid\)[\s\S]*?union\s+select membership\.roleid/);
  assert.doesNotMatch(postureSql, /union all/i);
  assert.match(postureSql, /role_assumption_state_conclusive/);
  assert.match(
    postureSql,
    /pg_auth_members membership[\s\S]*?membership\.member = [a-z_.]+role_oid[\s\S]*?membership\.admin_option[\s\S]*?role_membership_admin_absent/,
  );
  assert.match(
    postureSql,
    /has_database_privilege\(\s*[a-z_.]+role_oid,/,
  );
  assert.match(
    postureSql,
    /has_schema_privilege\(\s*[a-z_.]+role_oid,/,
  );
  assert.match(
    postureSql,
    /has_table_privilege\(\s*[a-z_.]+role_oid,/,
  );
  assert.doesNotMatch(
    postureSql,
    /from pg_roles\s+where rolname = current_user/,
  );
});

test("operator-side dormant authority inspection reuses the exact recursive posture query", async () => {
  let postureSql = "";
  const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
    {
      async query(sql, values) {
        postureSql = sql;
        assert.deepEqual(values[0], expectedRole);
        return { rows: [{ ...passingRow, expected_role_match: false }] };
      },
    },
    expectedRole,
  );

  assert.match(postureSql, /with recursive/i);
  assert.match(postureSql, /pg_roles[\s\S]*?rolname = \$1/);
  assert.match(postureSql, /membership\.set_option/);
  assert.match(postureSql, /membership\.admin_option/);
  assert.deepEqual(report, {
    roleIdentityConclusive: "passed",
    administrativeAttributesAbsent: "passed",
    databaseAndSchemaCreateAbsent: "passed",
    migrationLedgerAccessDenied: "passed",
    databaseAndSchemaOwnershipAbsent: "passed",
    applicationTableOwnershipAbsent: "passed",
    runtimeRoleAuthorityPosture: "passed",
  });
});

test("migration ledger relation kinds are inspected or rejected fail closed", async (context) => {
  let postureSql = "";
  await inspectRuntimeDatabasePosture(
    {
      async query(sql) {
        postureSql = sql;
        return { rows: [{ ...passingRow }] };
      },
    },
    expectedRole,
  );

  const supportedRelationKinds = [
    ["ordinary table", "r"],
    ["partitioned table", "p"],
    ["view", "v"],
    ["materialized view", "m"],
    ["foreign table", "f"],
  ];

  for (const [name, relkind] of supportedRelationKinds) {
    await context.test(`${name} uses the OID privilege check`, () => {
      assert.match(
        postureSql,
        new RegExp(`migration_ledger_relkind[\\s\\S]*?in \\([^)]*'${relkind}'`),
      );
    });
  }

  await context.test("genuine relation absence remains safe", () => {
    assert.match(
      postureSql,
      /when \(select migration_ledger_oid from drizzle_state\) is null then true/,
    );
  });

  await context.test("unsupported exact-name relation kinds fail posture", () => {
    assert.match(
      postureSql,
      /when \(select migration_ledger_relkind from drizzle_state\)[\s\S]*?then not exists \([\s\S]*?has_table_privilege\([\s\S]*?else false\s+end as migration_ledger_select_absent/,
    );
  });
});

test("every prohibited runtime posture fails closed", async (context) => {
  const cases = [
    ["wrong connected role", "expected_role_match"],
    ["inconclusive SET-role catalog state", "role_assumption_state_conclusive"],
    ["administrative membership authority", "role_membership_admin_absent"],
    ["neon_superuser membership", "neon_superuser_membership_absent"],
    ["superuser", "superuser_absent"],
    ["createdb", "createdb_absent"],
    ["createrole", "createrole_absent"],
    ["replication", "replication_absent"],
    ["bypassrls", "bypassrls_absent"],
    ["database create", "database_create_absent"],
    ["public schema create", "public_schema_create_absent"],
    ["drizzle schema usage", "drizzle_schema_usage_absent"],
    ["migration ledger select", "migration_ledger_select_absent"],
    ["database ownership", "database_ownership_absent"],
    ["schema ownership", "schema_ownership_absent"],
    ["application table ownership", "application_table_ownership_absent"],
  ];

  for (const [name, field] of cases) {
    await context.test(name, async () => {
      await assert.rejects(
        () =>
          assertRuntimeDatabasePosture(
            {
              async query() {
                return { rows: [{ ...passingRow, [field]: false }] };
              },
            },
            expectedRole,
          ),
        safePostureError,
      );
    });
  }
});

test("database posture query failure and inconclusive rows fail closed", async () => {
  await assert.rejects(
    () =>
      assertRuntimeDatabasePosture(
        {
          async query() {
            throw new Error("synthetic private database failure");
          },
        },
        expectedRole,
      ),
    safePostureError,
  );
  await assert.rejects(
    () =>
      assertRuntimeDatabasePosture(
        {
          async query() {
            return { rows: [] };
          },
        },
        expectedRole,
      ),
    safePostureError,
  );
  await assert.rejects(
    () =>
      assertRuntimeDatabasePosture(
        {
          async query() {
            return {
              rows: [
                { ...passingRow },
                { ...passingRow, opaque_catalog_detail: "must-not-leak" },
              ],
            };
          },
        },
        expectedRole,
      ),
    safePostureError,
  );
});

function safePostureError(error) {
  assert.equal(error instanceof RuntimeDatabasePostureError, true);
  assert.equal(error.code, "database_posture_failed");
  assert.equal(error.publicMessage, "Runtime database posture validation failed.");
  assert.doesNotMatch(String(error.message), /platform_runtime|postgres|private/i);
  return true;
}
