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
  runtime_creator_admin_edge_exact: true,
  neon_superuser_membership_absent: true,
  superuser_absent: true,
  createdb_absent: true,
  createrole_absent: true,
  replication_absent: true,
  bypassrls_absent: true,
  database_create_absent: true,
  all_non_system_schema_create_absent: true,
  public_schema_create_absent: true,
  drizzle_schema_usage_absent: true,
  migration_ledger_select_absent: true,
  database_ownership_absent: true,
  schema_ownership_absent: true,
  application_table_ownership_absent: true,
  role_membership_absent: true,
  runtime_table_grant_option_absent: true,
  runtime_table_grant_set_exact: true,
  public_table_authority_absent: true,
  runtime_column_authority_absent: true,
  runtime_column_grant_option_absent: true,
  public_column_authority_absent: true,
  runtime_default_relation_authority_absent: true,
  runtime_default_relation_grant_option_absent: true,
  public_default_relation_authority_absent: true,
  runtime_default_sequence_authority_absent: true,
  public_default_sequence_authority_absent: true,
  runtime_default_routine_authority_absent: true,
  public_default_routine_authority_absent: true,
  default_acl_grant_option_absent: true,
  runtime_routine_authority_absent: true,
  public_routine_authority_absent: true,
  runtime_routine_ownership_absent: true,
  runtime_sequence_authority_absent: true,
  public_sequence_authority_absent: true,
  runtime_sequence_ownership_absent: true,
});

test("expected runtime role is fixed in code", () => {
  assert.equal(readExpectedRuntimeRole(), expectedRole);
  assert.equal(readExpectedRuntimeRole({ NODE_ENV: "development" }), expectedRole);
  assert.equal(
    readExpectedRuntimeRole({
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

test("caller-selected runtime roles are rejected", () => {
  for (const role of ["platform_app", "platform_migrator"]) {
    assert.throws(
      () =>
        readExpectedRuntimeRole({
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
    runtimeTableGrantsExact: "passed",
    runtimeColumnAuthorityAbsent: "passed",
    runtimeDefaultRelationAuthorityAbsent: "passed",
    runtimeRoutineAuthorityAbsent: "passed",
    runtimeSequenceAuthorityAbsent: "passed",
    runtimePosture: "passed",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].values[0], expectedRole);
  const expectedGrants = JSON.parse(calls[0].values[1]);
  assert.equal(expectedGrants.length, 39);
  assert.ok(
    expectedGrants.some(
      (record) =>
        record.table_name === "access_validation_grants" &&
        record.privilege_type === "UPDATE",
    ),
  );
  assert.equal(
    expectedGrants.some(
      (record) =>
        record.table_name === "csrf_tokens" &&
        record.privilege_type === "UPDATE",
    ),
    false,
  );
  assert.match(calls[0].sql, /current_user = \$1 and session_user = \$1/);
  assert.match(
    calls[0].sql,
    /pg_has_role\(effective_role\.role_oid, table_record\.relowner, 'USAGE'\)/,
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
    /has_table_privilege\(\s*effective_role\.role_oid,\s*\(select migration_ledger_oid from drizzle_state\)/,
  );
  assert.doesNotMatch(calls[0].sql, /to_regclass\('drizzle\.__drizzle_migrations'\)/);
  assert.doesNotMatch(
    calls[0].sql,
    /has_table_privilege\(\s*current_user,\s*'drizzle\.__drizzle_migrations'/,
  );
  assert.doesNotMatch(calls[0].sql, new RegExp(expectedRole));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(expectedRole));
  assert.match(calls[0].sql, /jsonb_to_recordset\(\$2::jsonb\)/);
  assert.match(calls[0].sql, /aclexplode\(/);
  assert.match(calls[0].sql, /runtime_table_grant_set_exact/);
  assert.match(calls[0].sql, /runtime_table_grant_option_absent/);
  assert.match(calls[0].sql, /public_table_authority_absent/);
  assert.match(calls[0].sql, /pg_attribute/);
  assert.match(calls[0].sql, /attnum > 0/);
  assert.match(calls[0].sql, /not column_record\.attisdropped/);
  assert.match(calls[0].sql, /pg_default_acl/);
  assert.match(calls[0].sql, /defaclobjtype in \('r', 'S', 'f'\)/);
  assert.match(calls[0].sql, /pg_proc/);
  assert.match(calls[0].sql, /relkind = 'S'/);
  assert.match(calls[0].sql, /relkind in \('r', 'p', 'v', 'm', 'f'\)/);
  assert.match(calls[0].sql, /runtime_column_authority_absent/);
  assert.match(calls[0].sql, /public_column_authority_absent/);
  assert.match(calls[0].sql, /runtime_default_relation_authority_absent/);
  assert.match(calls[0].sql, /public_default_relation_authority_absent/);
  assert.match(calls[0].sql, /runtime_routine_authority_absent/);
  assert.match(calls[0].sql, /runtime_sequence_authority_absent/);
  assert.match(calls[0].sql, /runtime_routine_ownership_absent/);
  assert.match(calls[0].sql, /runtime_sequence_ownership_absent/);
  assert.match(
    calls[0].sql,
    /nspname not in \('pg_catalog', 'information_schema'\)/,
  );
  assert.match(calls[0].sql, /nspname !~ '\^pg_\(\?:toast\|temp\)/);
  const publicRoutineInventory = calls[0].sql.match(
    /public_routine_grants as \(([\s\S]*?)\n\),\nruntime_sequence_grants/,
  )?.[1];
  assert.equal(typeof publicRoutineInventory, "string");
  assert.doesNotMatch(publicRoutineInventory, /acldefault/);
  const directRelationInventory = calls[0].sql.match(
    /direct_runtime_table_grants as \(([\s\S]*?)\n\),\nruntime_column_grants/,
  )?.[1];
  assert.equal(typeof directRelationInventory, "string");
  assert.doesNotMatch(
    directRelationInventory,
    /table_schema\.nspname = 'public'/,
  );
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

test("runtime posture rejects CREATE on every non-system schema and both membership directions", async () => {
  let postureSql = "";
  const report = await inspectRuntimeDatabasePosture(
    {
      async query(sql) {
        postureSql = sql;
        return {
          rows: [
            {
              ...passingRow,
              all_non_system_schema_create_absent: false,
              role_membership_absent: false,
            },
          ],
        };
      },
    },
    expectedRole,
  );

  assert.equal(report.databaseAndSchemaCreateAbsent, "failed");
  assert.equal(report.administrativeAttributesAbsent, "failed");
  assert.match(
    postureSql,
    /schema_record\.nspname <> 'information_schema'[\s\S]*?schema_record\.nspname !~ '\^pg_'/,
  );
  assert.match(
    postureSql,
    /has_schema_privilege\(\s*[a-z_.]+role_oid,\s*schema_record\.oid,\s*'CREATE'\s*\)/,
  );
  assert.match(postureSql, /schema_record\.nspowner/);
  assert.match(
    postureSql,
    /membership\.member = runtime_role\.oid[\s\S]*?or membership\.roleid = runtime_role\.oid[\s\S]*?or membership\.grantor = runtime_role\.oid/,
  );
});

test("runtime posture models hard-wired, global replacement, and per-schema additive defaults for relations, sequences, and routines", async () => {
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

  assert.match(postureSql, /acldefault\(/);
  assert.match(postureSql, /defaclnamespace = 0/);
  assert.match(postureSql, /defaclobjtype in \('r', 'S', 'f'\)/);
  assert.match(postureSql, /defaclacl[\s\S]*?\|\|/);
  assert.match(postureSql, /aclexplode\(/);
  assert.match(postureSql, /grantee_oid = 0/);
  assert.match(postureSql, /is_grantable/);
  assert.match(postureSql, /default_creator\.role_oid/);
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
    runtimeTableGrantsExact: "passed",
    runtimeColumnAuthorityAbsent: "passed",
    runtimeDefaultRelationAuthorityAbsent: "passed",
    runtimeRoutineAuthorityAbsent: "passed",
    runtimeSequenceAuthorityAbsent: "passed",
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
    ["direct role membership", "role_membership_absent"],
    ["missing or drifted provider creator edge", "runtime_creator_admin_edge_exact"],
    ["neon_superuser membership", "neon_superuser_membership_absent"],
    ["superuser", "superuser_absent"],
    ["createdb", "createdb_absent"],
    ["createrole", "createrole_absent"],
    ["replication", "replication_absent"],
    ["bypassrls", "bypassrls_absent"],
    ["database create", "database_create_absent"],
    ["all non-system schema create", "all_non_system_schema_create_absent"],
    ["public schema create", "public_schema_create_absent"],
    ["drizzle schema usage", "drizzle_schema_usage_absent"],
    ["migration ledger select", "migration_ledger_select_absent"],
    ["database ownership", "database_ownership_absent"],
    ["schema ownership", "schema_ownership_absent"],
    ["application table ownership", "application_table_ownership_absent"],
    ["missing or extra runtime table grant", "runtime_table_grant_set_exact"],
    ["runtime table grant option", "runtime_table_grant_option_absent"],
    ["PUBLIC table authority", "public_table_authority_absent"],
    ["runtime column authority", "runtime_column_authority_absent"],
    ["runtime column grant option", "runtime_column_grant_option_absent"],
    ["PUBLIC column authority", "public_column_authority_absent"],
    [
      "runtime default relation authority",
      "runtime_default_relation_authority_absent",
    ],
    [
      "runtime default relation grant option",
      "runtime_default_relation_grant_option_absent",
    ],
    [
      "PUBLIC default relation authority",
      "public_default_relation_authority_absent",
    ],
    [
      "runtime default sequence authority",
      "runtime_default_sequence_authority_absent",
    ],
    [
      "PUBLIC default sequence authority",
      "public_default_sequence_authority_absent",
    ],
    [
      "runtime default routine authority",
      "runtime_default_routine_authority_absent",
    ],
    [
      "PUBLIC default routine authority",
      "public_default_routine_authority_absent",
    ],
    ["default ACL grant option", "default_acl_grant_option_absent"],
    ["runtime routine authority", "runtime_routine_authority_absent"],
    ["PUBLIC routine authority", "public_routine_authority_absent"],
    ["runtime routine ownership", "runtime_routine_ownership_absent"],
    ["runtime sequence authority", "runtime_sequence_authority_absent"],
    ["PUBLIC sequence authority", "public_sequence_authority_absent"],
    ["runtime sequence ownership", "runtime_sequence_ownership_absent"],
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
