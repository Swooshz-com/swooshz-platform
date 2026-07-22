import assert from "node:assert/strict";
import test from "node:test";

import {
  RuntimeDatabasePostureError,
  assertRuntimeDatabasePosture,
  inspectRuntimeDatabasePosture,
  readExpectedRuntimeRole,
} from "../dist/db/runtime-posture.js";

const expectedRole = "platform_runtime";

const passingRow = Object.freeze({
  expected_role_match: true,
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
  assert.match(calls[0].sql, /pg_has_role\(current_user, table_record\.relowner, 'MEMBER'\)/);
  assert.doesNotMatch(calls[0].sql, new RegExp(expectedRole));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(expectedRole));
});

test("every prohibited runtime posture fails closed", async (context) => {
  const cases = [
    ["wrong connected role", "expected_role_match"],
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
});

function safePostureError(error) {
  assert.equal(error instanceof RuntimeDatabasePostureError, true);
  assert.equal(error.code, "database_posture_failed");
  assert.equal(error.publicMessage, "Runtime database posture validation failed.");
  assert.doesNotMatch(String(error.message), /platform_runtime|postgres|private/i);
  return true;
}
