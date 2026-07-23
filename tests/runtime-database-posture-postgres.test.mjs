import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { Pool } from "pg";

import {
  RuntimeDatabasePostureError,
  assertRuntimeDatabasePosture,
  inspectRuntimeDatabasePosture,
} from "../dist/db/runtime-posture.js";

const databaseUrl = process.env.RUNTIME_POSTURE_TEST_DATABASE_URL;
const disposableConfirmed =
  process.env.RUNTIME_POSTURE_TEST_CONFIRM === "disposable-only";
const skipReason =
  databaseUrl && disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable PostgreSQL fixture";

test(
  "PostgreSQL 17 rejects authority reachable through SET ROLE",
  { skip: skipReason },
  async (context) => {
    const adminPool = new Pool({ connectionString: databaseUrl, max: 4 });
    const roles = [];
    const suffix = randomUUID().replaceAll("-", "").slice(0, 10);
    let sequence = 0;
    let neonSuperuserCreated = false;

    const role = (label) => {
      sequence += 1;
      const value = `rt_${label}_${sequence}_${suffix}`;
      roles.push(value);
      return value;
    };

    try {
      const guard = await adminPool.query(`
        select
          current_database() = 'runtime_posture_test' as database_is_disposable,
          current_setting('server_version_num')::integer / 10000 = 17
            as server_is_postgresql_17
      `);
      assert.deepEqual(guard.rows, [
        {
          database_is_disposable: true,
          server_is_postgresql_17: true,
        },
      ]);

      await adminPool.query("revoke create on schema public from public");
      await adminPool.query("drop schema if exists drizzle cascade");
      await adminPool.query("drop table if exists public.users cascade");
      await adminPool.query("create schema drizzle authorization postgres");
      await adminPool.query(
        "create table drizzle.__drizzle_migrations (id integer primary key)",
      );
      await adminPool.query("create table public.users (id integer primary key)");
      neonSuperuserCreated = await ensureRole(adminPool, "neon_superuser");

      await context.test("direct SET-capable CREATEDB membership fails", async () => {
        const runtime = role("direct_runtime");
        const dangerous = role("createdb");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous, "createdb");
        await grantRole(adminPool, dangerous, runtime, true, false);
        await assertSetRole(adminPool, runtime, dangerous, true);
        await assertPostureFails(adminPool, runtime, "administrativeAttributesAbsent");
      });

      await context.test("indirect SET-capable BYPASSRLS chain fails", async () => {
        const runtime = role("indirect_runtime");
        const middle = role("middle");
        const dangerous = role("bypassrls");
        await createRole(adminPool, runtime);
        await createRole(adminPool, middle);
        await createRole(adminPool, dangerous, "bypassrls");
        await grantRole(adminPool, middle, runtime, true, false);
        await grantRole(adminPool, dangerous, middle, true, false);
        await assertSetRole(adminPool, runtime, dangerous, true);
        await assertPostureFails(adminPool, runtime, "administrativeAttributesAbsent");
      });

      await context.test("NOINHERIT does not hide SET-capable CREATEROLE", async () => {
        const runtime = role("noinherit_runtime");
        const dangerous = role("createrole");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous, "createrole");
        await grantRole(adminPool, dangerous, runtime, true, false);
        await assertSetRole(adminPool, runtime, dangerous, true);
        await assertPostureFails(adminPool, runtime, "administrativeAttributesAbsent");
      });

      await context.test("database CREATE on an assumable role fails", async () => {
        const runtime = role("database_create_runtime");
        const dangerous = role("database_create");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(
          `grant create on database runtime_posture_test to ${identifier(dangerous)}`,
        );
        await assertPostureFails(adminPool, runtime, "databaseAndSchemaCreateAbsent");
        await adminPool.query(
          `revoke create on database runtime_posture_test from ${identifier(dangerous)}`,
        );
      });

      await context.test("public-schema CREATE on an assumable role fails", async () => {
        const runtime = role("public_create_runtime");
        const dangerous = role("public_create");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(`grant create on schema public to ${identifier(dangerous)}`);
        await assertPostureFails(adminPool, runtime, "databaseAndSchemaCreateAbsent");
        await adminPool.query(`revoke create on schema public from ${identifier(dangerous)}`);
      });

      await context.test("Drizzle USAGE on an assumable role fails", async () => {
        const runtime = role("drizzle_usage_runtime");
        const dangerous = role("drizzle_usage");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(`grant usage on schema drizzle to ${identifier(dangerous)}`);
        await assertPostureFails(adminPool, runtime, "databaseAndSchemaCreateAbsent");
        await adminPool.query(`revoke usage on schema drizzle from ${identifier(dangerous)}`);
      });

      await context.test("migration-ledger SELECT on an assumable role fails", async () => {
        const runtime = role("ledger_runtime");
        const dangerous = role("ledger_select");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(
          `grant select on drizzle.__drizzle_migrations to ${identifier(dangerous)}`,
        );
        await assertPostureFails(adminPool, runtime, "migrationLedgerAccessDenied");
        await adminPool.query(
          `revoke select on drizzle.__drizzle_migrations from ${identifier(dangerous)}`,
        );
      });

      await context.test("database ownership through an assumable role fails", async () => {
        const runtime = role("database_owner_runtime");
        const dangerous = role("database_owner");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(
          `alter database runtime_posture_test owner to ${identifier(dangerous)}`,
        );
        await assertPostureFails(adminPool, runtime, "databaseAndSchemaOwnershipAbsent");
        await adminPool.query("alter database runtime_posture_test owner to postgres");
      });

      await context.test("schema ownership through an assumable role fails", async () => {
        const runtime = role("schema_owner_runtime");
        const dangerous = role("schema_owner");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(`alter schema drizzle owner to ${identifier(dangerous)}`);
        await assertPostureFails(adminPool, runtime, "databaseAndSchemaOwnershipAbsent");
        await adminPool.query("alter schema drizzle owner to postgres");
      });

      await context.test("required-table ownership through an assumable role fails", async () => {
        const runtime = role("table_owner_runtime");
        const dangerous = role("table_owner");
        await createRole(adminPool, runtime);
        await createRole(adminPool, dangerous);
        await grantRole(adminPool, dangerous, runtime, true, false);
        await adminPool.query(`alter table public.users owner to ${identifier(dangerous)}`);
        await assertPostureFails(adminPool, runtime, "applicationTableOwnershipAbsent");
        await adminPool.query("alter table public.users owner to postgres");
      });

      await context.test("indirect neon_superuser membership fails", async () => {
        const runtime = role("neon_runtime");
        const middle = role("neon_middle");
        await createRole(adminPool, runtime);
        await createRole(adminPool, middle);
        await grantRole(adminPool, middle, runtime, true, false);
        await grantRole(adminPool, "neon_superuser", middle, true, false);
        await assertSetRole(adminPool, runtime, "neon_superuser", true);
        await assertPostureFails(adminPool, runtime, "administrativeAttributesAbsent");
      });

      await context.test("SET false membership is not treated as assumable", async () => {
        const runtime = role("set_false_runtime");
        const blocked = role("set_false_createdb");
        await createRole(adminPool, runtime);
        await createRole(adminPool, blocked, "createdb");
        await grantRole(adminPool, blocked, runtime, false, false);
        await assertSetRole(adminPool, runtime, blocked, false);
        await assertPosturePasses(adminPool, runtime);
      });

      await context.test(
        "SET false membership with ADMIN authority fails before it can enable SET",
        async () => {
          const runtime = role("admin_option_runtime");
          const dangerous = role("admin_option_createdb");
          await createRole(adminPool, runtime);
          await createRole(adminPool, dangerous, "createdb");
          await grantRole(adminPool, dangerous, runtime, false, false, true);
          await assertSetRole(adminPool, runtime, dangerous, false);
          await assertPostureFails(
            adminPool,
            runtime,
            "administrativeAttributesAbsent",
          );
          await assertCanEnableSetOption(adminPool, runtime, dangerous);
        },
      );

      await context.test("one SET false edge blocks a mixed chain", async () => {
        const runtime = role("mixed_runtime");
        const middle = role("mixed_middle");
        const blocked = role("mixed_bypassrls");
        await createRole(adminPool, runtime);
        await createRole(adminPool, middle);
        await createRole(adminPool, blocked, "bypassrls");
        await grantRole(adminPool, middle, runtime, true, false);
        await grantRole(adminPool, blocked, middle, false, false);
        await assertSetRole(adminPool, runtime, middle, true);
        await assertSetRole(adminPool, runtime, blocked, false);
        await assertPosturePasses(adminPool, runtime);
      });

      await context.test("cycle guard terminates and de-duplicates deterministically", async () => {
        const result = await adminPool.query(`
          with recursive membership_edges(member, roleid, set_option) as (
            values (1, 2, true), (2, 3, true), (3, 1, true), (3, 4, false)
          ), reachable(role_oid) as (
            values (1)
            union
            select edge.roleid
            from reachable
            join membership_edges edge on edge.member = reachable.role_oid
            where edge.set_option
          )
          select array_agg(role_oid order by role_oid) as role_oids
          from reachable
        `);
        assert.deepEqual(result.rows, [{ role_oids: [1, 2, 3] }]);
      });

      await context.test("a safe SET-assumable role passes", async () => {
        const runtime = role("safe_runtime");
        const safe = role("safe_role");
        await createRole(adminPool, runtime);
        await createRole(adminPool, safe);
        await grantRole(adminPool, safe, runtime, true, false);
        await assertSetRole(adminPool, runtime, safe, true);
        await assertPosturePasses(adminPool, runtime);
      });
    } finally {
      await adminPool.query("alter database runtime_posture_test owner to postgres").catch(() => {});
      await adminPool.query("alter schema drizzle owner to postgres").catch(() => {});
      await adminPool.query("alter table public.users owner to postgres").catch(() => {});
      await adminPool.query("drop schema if exists drizzle cascade").catch(() => {});
      await adminPool.query("drop table if exists public.users cascade").catch(() => {});
      for (const roleName of roles.reverse()) {
        await adminPool.query(`drop role if exists ${identifier(roleName)}`).catch(() => {});
      }
      if (neonSuperuserCreated) {
        await adminPool.query("drop role if exists neon_superuser").catch(() => {});
      }
      await adminPool.end();
    }
  },
);

async function createRole(pool, roleName, attribute = "") {
  const supportedAttributes = new Set(["", "createdb", "createrole", "bypassrls"]);
  assert.equal(supportedAttributes.has(attribute), true);
  const createdb = attribute === "createdb" ? "createdb" : "nocreatedb";
  const createrole = attribute === "createrole" ? "createrole" : "nocreaterole";
  const bypassrls = attribute === "bypassrls" ? "bypassrls" : "nobypassrls";
  await pool.query(
    `create role ${identifier(roleName)} nologin noinherit nosuperuser ` +
      `${createdb} ${createrole} noreplication ${bypassrls}`,
  );
}

async function ensureRole(pool, roleName) {
  const result = await pool.query("select 1 from pg_roles where rolname = $1", [roleName]);
  if (result.rowCount === 0) {
    await createRole(pool, roleName);
    return true;
  }
  return false;
}

async function grantRole(
  pool,
  grantedRole,
  memberRole,
  setOption,
  inheritOption,
  adminOption = false,
) {
  await pool.query(
    `grant ${identifier(grantedRole)} to ${identifier(memberRole)} ` +
      `with admin ${adminOption}, set ${setOption}, inherit ${inheritOption}`,
  );
}

async function assertCanEnableSetOption(pool, sessionRole, targetRole) {
  const client = await pool.connect();
  try {
    await client.query(`set session authorization ${identifier(sessionRole)}`);
    await client.query(
      `grant ${identifier(targetRole)} to ${identifier(sessionRole)} with set true`,
    );
    await client.query(`set role ${identifier(targetRole)}`);
    const identity = await client.query("select current_user, session_user");
    assert.deepEqual(identity.rows, [
      { current_user: targetRole, session_user: sessionRole },
    ]);
  } finally {
    client.release(true);
  }
}

async function assertSetRole(pool, sessionRole, targetRole, shouldSucceed) {
  const client = await pool.connect();
  try {
    await client.query(`set session authorization ${identifier(sessionRole)}`);
    if (shouldSucceed) {
      await client.query(`set role ${identifier(targetRole)}`);
      const identity = await client.query("select current_user, session_user");
      assert.deepEqual(identity.rows, [
        { current_user: targetRole, session_user: sessionRole },
      ]);
    } else {
      await assert.rejects(() => client.query(`set role ${identifier(targetRole)}`));
    }
  } finally {
    client.release(true);
  }
}

async function postureReport(pool, sessionRole) {
  const client = await pool.connect();
  try {
    await client.query(`set session authorization ${identifier(sessionRole)}`);
    return await inspectRuntimeDatabasePosture(client, sessionRole);
  } finally {
    client.release(true);
  }
}

async function assertPostureFails(pool, sessionRole, failedField) {
  const report = await postureReport(pool, sessionRole);
  assert.equal(report[failedField], "failed");
  assert.equal(report.runtimePosture, "failed");

  const client = await pool.connect();
  try {
    await client.query(`set session authorization ${identifier(sessionRole)}`);
    await assert.rejects(
      () => assertRuntimeDatabasePosture(client, sessionRole),
      safePostureError,
    );
  } finally {
    client.release(true);
  }
}

async function assertPosturePasses(pool, sessionRole) {
  const report = await postureReport(pool, sessionRole);
  assert.equal(report.runtimePosture, "passed");
}

function safePostureError(error) {
  assert.equal(error instanceof RuntimeDatabasePostureError, true);
  assert.equal(error.code, "database_posture_failed");
  assert.equal(error.publicMessage, "Runtime database posture validation failed.");
  assert.equal(error.message, "Runtime database posture validation failed.");
  assert.doesNotMatch(String(error), /rt_|pg_auth|acl|oid|roleid/i);
  return true;
}

function identifier(value) {
  assert.match(value, /^[a-z_][a-z0-9_]{0,62}$/);
  return `"${value.replaceAll('"', '""')}"`;
}
