import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { Pool } from "pg";

import {
  RuntimeDatabasePostureError,
  assertRuntimeDatabasePosture,
  inspectRuntimeDatabasePosture,
} from "../dist/db/runtime-posture.js";
import {
  admitDisposablePostgresFixtures,
  createAdmittedMutationPool,
} from "./support/disposable-postgres-fixture.mjs";

const databaseUrl = process.env.RUNTIME_POSTURE_TEST_DATABASE_URL;
const operatorUrl = process.env.RUNTIME_POSTURE_TEST_OPERATOR_URL;
const secondaryDatabaseUrl = process.env.RUNTIME_POSTURE_TEST_SECONDARY_DATABASE_URL;
const secondaryOperatorUrl = process.env.RUNTIME_POSTURE_TEST_SECONDARY_OPERATOR_URL;
const disposableConfirmed =
  process.env.RUNTIME_POSTURE_TEST_CONFIRM === "disposable-only";
const skipReason =
  databaseUrl &&
  operatorUrl &&
  secondaryDatabaseUrl &&
  secondaryOperatorUrl &&
  disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable PostgreSQL fixture";

test(
  "PostgreSQL 17 rejects authority reachable through SET ROLE",
  { skip: skipReason },
  async (context) => {
    const rawAdminPool = new Pool({ connectionString: operatorUrl, max: 4 });
    const admission = await admitDisposablePostgresFixtures([
      fixtureDefinition("primary", databaseUrl, operatorUrl),
      fixtureDefinition("secondary", secondaryDatabaseUrl, secondaryOperatorUrl),
    ]);
    const adminPool = createAdmittedMutationPool(
      rawAdminPool,
      admission,
      "primary",
    );
    const roles = [];
    const schemas = [];
    const relations = [];
    const sequences = [];
    const routines = [];
    const extensions = [];
    const suffix = randomUUID().replaceAll("-", "").slice(0, 10);
    let sequence = 0;
    let neonSuperuserCreated = false;

    const role = (label) => {
      sequence += 1;
      const value = `rt_${label}_${sequence}_${suffix}`;
      roles.push(value);
      return value;
    };

    const schema = (label) => {
      const value = `rt_${label}_${suffix}`;
      schemas.push(value);
      return value;
    };

    const relation = (label) => {
      const value = `rt_${label}_${suffix}`;
      relations.push(value);
      return value;
    };

    const sequenceName = (label) => {
      const value = `rt_${label}_${suffix}`;
      sequences.push(value);
      return value;
    };

    const routine = (label) => {
      const value = `rt_${label}_${suffix}`;
      routines.push(value);
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

      neonSuperuserCreated = await ensureRole(adminPool, "neon_superuser");

      await context.test(
        "extension-managed non-system schema CREATE is denied",
        async () => {
          const runtime = role("extension_runtime");
          const extensionSchema = schema("extension_schema");
          await createRole(adminPool, runtime);
          await adminPool.query(
            `create schema ${identifier(extensionSchema)} authorization postgres`,
          );
          await adminPool.query(
            `create extension hstore schema ${identifier(extensionSchema)}`,
          );
          extensions.push("hstore");
          await adminPool.query(
            `grant create on schema ${identifier(extensionSchema)} to ${identifier(runtime)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "databaseAndSchemaCreateAbsent",
          );
          await adminPool.query(
            `revoke create on schema ${identifier(extensionSchema)} from ${identifier(runtime)}`,
          );
        },
      );

      await context.test("direct schema CREATE is denied", async () => {
        const runtime = role("direct_schema_runtime");
        const targetSchema = schema("direct_schema");
        await createRole(adminPool, runtime);
        await adminPool.query(
          `create schema ${identifier(targetSchema)} authorization postgres`,
        );
        await adminPool.query(
          `grant create on schema ${identifier(targetSchema)} to ${identifier(runtime)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "databaseAndSchemaCreateAbsent",
        );
      });

      await context.test("PUBLIC schema CREATE is denied", async () => {
        const runtime = role("public_schema_runtime");
        await createRole(adminPool, runtime);
        await adminPool.query(
          `grant create on schema public to ${identifier(runtime)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "databaseAndSchemaCreateAbsent",
        );
        await adminPool.query(
          `revoke create on schema public from ${identifier(runtime)}`,
        );
      });

      await context.test("inherited-role schema CREATE is denied", async () => {
        const runtime = role("inherited_schema_runtime");
        const inherited = role("inherited_schema_role");
        const targetSchema = schema("inherited_schema");
        await createRole(adminPool, runtime);
        await createRole(adminPool, inherited);
        await grantRole(adminPool, inherited, runtime, false, true);
        await adminPool.query(
          `create schema ${identifier(targetSchema)} authorization postgres`,
        );
        await adminPool.query(
          `grant create on schema ${identifier(targetSchema)} to ${identifier(inherited)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "databaseAndSchemaCreateAbsent",
        );
      });

      await context.test("SET-assumable schema CREATE is denied", async () => {
        const runtime = role("set_schema_runtime");
        const assumable = role("set_schema_role");
        const targetSchema = schema("set_schema");
        await createRole(adminPool, runtime);
        await createRole(adminPool, assumable);
        await grantRole(adminPool, assumable, runtime, true, false);
        await adminPool.query(
          `create schema ${identifier(targetSchema)} authorization postgres`,
        );
        await adminPool.query(
          `grant create on schema ${identifier(targetSchema)} to ${identifier(assumable)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "databaseAndSchemaCreateAbsent",
        );
      });

      await context.test("schema-owner authority is denied", async () => {
        const runtime = role("owner_schema_runtime");
        const owner = role("owner_schema_role");
        const targetSchema = schema("owner_schema");
        await createRole(adminPool, runtime);
        await createRole(adminPool, owner);
        await grantRole(adminPool, owner, runtime, false, true);
        await adminPool.query(
          `create schema ${identifier(targetSchema)} authorization ${identifier(owner)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "databaseAndSchemaCreateAbsent",
        );
      });

      await context.test(
        "inherited-role default-ACL grantee is denied",
        async () => {
          const runtime = role("inherited_default_runtime");
          const grantee = role("inherited_default_grantee");
          const creator = role("inherited_default_creator");
          await createRole(adminPool, runtime);
          await createRole(adminPool, grantee);
          await createRole(adminPool, creator);
          await adminPool.query(`alter role ${identifier(runtime)} inherit`);
          await grantRole(adminPool, grantee, runtime, false, true);
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant select on tables to ${identifier(grantee)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeDefaultRelationAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke select on tables from ${identifier(grantee)}`,
          );
        },
      );

      await context.test(
        "SET-assumable default-ACL grantee is denied",
        async () => {
          const runtime = role("set_default_runtime");
          const grantee = role("set_default_grantee");
          const creator = role("set_default_creator");
          await createRole(adminPool, runtime);
          await createRole(adminPool, grantee);
          await createRole(adminPool, creator);
          await grantRole(adminPool, grantee, runtime, true, false);
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant usage on sequences to ${identifier(grantee)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeSequenceAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke usage on sequences from ${identifier(grantee)}`,
          );
        },
      );

      await context.test("PUBLIC relation defaults are denied", async () => {
        const runtime = role("public_relation_default_runtime");
        const creator = role("public_relation_default_creator");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} grant select on tables to public`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeDefaultRelationAuthorityAbsent",
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} revoke select on tables from public`,
        );
      });

      await context.test("PUBLIC sequence defaults are denied", async () => {
        const runtime = role("public_sequence_default_runtime");
        const creator = role("public_sequence_default_creator");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} grant usage on sequences to public`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeSequenceAuthorityAbsent",
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} revoke usage on sequences from public`,
        );
      });

      await context.test("PUBLIC routine defaults are denied", async () => {
        const runtime = role("public_routine_default_runtime");
        const creator = role("public_routine_default_creator");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} grant execute on functions to public`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeRoutineAuthorityAbsent",
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} revoke execute on functions from public`,
        );
      });

      await context.test("relation grant options are denied", async () => {
        const runtime = role("relation_grant_option_runtime");
        const tableName = relation("relation_grant_option");
        await createRole(adminPool, runtime);
        await adminPool.query(
          `create table public.${identifier(tableName)} (id integer)`,
        );
        await adminPool.query(
          `grant select on table public.${identifier(tableName)} to ${identifier(runtime)} with grant option`,
        );
        await assertPostureFails(adminPool, runtime, "runtimeTableGrantsExact");
      });

      await context.test("sequence grant options are denied", async () => {
        const runtime = role("sequence_grant_option_runtime");
        const sequence = sequenceName("sequence_grant_option");
        await createRole(adminPool, runtime);
        await adminPool.query(`create sequence public.${identifier(sequence)}`);
        await adminPool.query(
          `grant usage on sequence public.${identifier(sequence)} to ${identifier(runtime)} with grant option`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeSequenceAuthorityAbsent",
        );
      });

      await context.test("routine grant options are denied", async () => {
        const runtime = role("routine_grant_option_runtime");
        const routineName = routine("routine_grant_option");
        await createRole(adminPool, runtime);
        await adminPool.query(
          `create function public.${identifier(routineName)}() returns integer language sql immutable as $$ select 1 $$`,
        );
        await adminPool.query(
          `grant execute on function public.${identifier(routineName)}() to ${identifier(runtime)} with grant option`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeRoutineAuthorityAbsent",
        );
      });

      await context.test("global default replacement is enforced", async () => {
        const runtime = role("global_default_runtime");
        const creator = role("global_default_creator");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} revoke select on tables from public`,
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} grant select on tables to ${identifier(runtime)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeDefaultRelationAuthorityAbsent",
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} revoke select on tables from ${identifier(runtime)}`,
        );
      });

      await context.test("per-schema default additions are enforced", async () => {
        const runtime = role("schema_default_runtime");
        const creator = role("schema_default_creator");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} in schema drizzle grant select on tables to ${identifier(runtime)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeDefaultRelationAuthorityAbsent",
        );
        await adminPool.query(
          `alter default privileges for role ${identifier(creator)} in schema drizzle revoke select on tables from ${identifier(runtime)}`,
        );
      });

      await context.test("hard-wired default behavior is enforced", async () => {
        const runtime = role("hardwired_runtime");
        const creator = role("hardwired_creator");
        const targetSchema = schema("hardwired_schema");
        await createRole(adminPool, runtime);
        await createRole(adminPool, creator);
        await adminPool.query(
          `create schema ${identifier(targetSchema)} authorization postgres`,
        );
        await adminPool.query(
          `grant create on schema ${identifier(targetSchema)} to ${identifier(creator)}`,
        );
        await assertPostureFails(
          adminPool,
          runtime,
          "runtimeRoutineAuthorityAbsent",
        );
        await adminPool.query(
          `revoke create on schema ${identifier(targetSchema)} from ${identifier(creator)}`,
        );
      });

      await context.test(
        "direct, PUBLIC, inherited, SET-role, and owner CREATE fail for every non-system schema",
        async () => {
          const directRuntime = role("schema_direct_runtime");
          const directSchema = schema("direct_create");
          await createRole(adminPool, directRuntime);
          await adminPool.query(
            `create schema ${identifier(directSchema)} authorization postgres`,
          );
          await adminPool.query(
            `grant create on schema ${identifier(directSchema)} to ${identifier(directRuntime)}`,
          );
          await assertPostureFails(
            adminPool,
            directRuntime,
            "databaseAndSchemaCreateAbsent",
          );
          await adminPool.query(
            `revoke create on schema ${identifier(directSchema)} from ${identifier(directRuntime)}`,
          );

          const publicRuntime = role("schema_public_runtime");
          await createRole(adminPool, publicRuntime);
          await adminPool.query(
            `grant create on schema ${identifier(directSchema)} to public`,
          );
          await assertPostureFails(
            adminPool,
            publicRuntime,
            "databaseAndSchemaCreateAbsent",
          );
          await adminPool.query(
            `revoke create on schema ${identifier(directSchema)} from public`,
          );

          const inheritedRuntime = role("schema_inherited_runtime");
          const inheritedRole = role("schema_inherited_role");
          await createRole(adminPool, inheritedRuntime);
          await createRole(adminPool, inheritedRole);
          await grantRole(adminPool, inheritedRole, inheritedRuntime, false, true);
          await adminPool.query(
            `grant create on schema ${identifier(directSchema)} to ${identifier(inheritedRole)}`,
          );
          await assertPostureFails(
            adminPool,
            inheritedRuntime,
            "databaseAndSchemaCreateAbsent",
          );
          await adminPool.query(
            `revoke create on schema ${identifier(directSchema)} from ${identifier(inheritedRole)}`,
          );

          const setRuntime = role("schema_set_runtime");
          const setRole = role("schema_set_role");
          await createRole(adminPool, setRuntime);
          await createRole(adminPool, setRole);
          await grantRole(adminPool, setRole, setRuntime, true, false);
          await adminPool.query(
            `grant create on schema ${identifier(directSchema)} to ${identifier(setRole)}`,
          );
          await assertPostureFails(
            adminPool,
            setRuntime,
            "databaseAndSchemaCreateAbsent",
          );
          await adminPool.query(
            `revoke create on schema ${identifier(directSchema)} from ${identifier(setRole)}`,
          );

          const ownerRuntime = role("schema_owner_runtime");
          const ownerRole = role("schema_owner_role");
          const ownedSchema = schema("owned_schema");
          await createRole(adminPool, ownerRuntime);
          await createRole(adminPool, ownerRole);
          await grantRole(adminPool, ownerRole, ownerRuntime, false, true);
          await adminPool.query(
            `create schema ${identifier(ownedSchema)} authorization ${identifier(ownerRole)}`,
          );
          await assertPostureFails(
            adminPool,
            ownerRuntime,
            "databaseAndSchemaCreateAbsent",
          );
        },
      );

      await context.test(
        "global and per-schema relation defaults reject runtime and PUBLIC authority",
        async () => {
          const runtime = role("default_relation_runtime");
          const creator = role("default_relation_creator");
          await createRole(adminPool, runtime);
          await createRole(adminPool, creator);

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant select on tables to ${identifier(runtime)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeDefaultRelationAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke select on tables from ${identifier(runtime)}`,
          );

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} in schema drizzle grant select on tables to ${identifier(runtime)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeDefaultRelationAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} in schema drizzle revoke select on tables from ${identifier(runtime)}`,
          );

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant select on tables to public`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeDefaultRelationAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke select on tables from public`,
          );
        },
      );

      await context.test(
        "sequence, routine, and grant-option defaults are rejected",
        async () => {
          const runtime = role("default_object_runtime");
          const creator = role("default_object_creator");
          await createRole(adminPool, runtime);
          await createRole(adminPool, creator);

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant usage on sequences to ${identifier(runtime)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeSequenceAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke usage on sequences from ${identifier(runtime)}`,
          );

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant execute on functions to ${identifier(runtime)}`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeRoutineAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke execute on functions from ${identifier(runtime)}`,
          );

          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} grant select on tables to ${identifier(runtime)} with grant option`,
          );
          await assertPostureFails(
            adminPool,
            runtime,
            "runtimeDefaultRelationAuthorityAbsent",
          );
          await adminPool.query(
            `alter default privileges for role ${identifier(creator)} revoke select on tables from ${identifier(runtime)}`,
          );
        },
      );

      await context.test(
        "every membership edge is prohibited in both directions for all option combinations",
        async () => {
          for (const [setOption, inheritOption, adminOption] of [
            [false, false, false],
            [false, false, true],
            [false, true, false],
            [false, true, true],
            [true, false, false],
            [true, false, true],
            [true, true, false],
            [true, true, true],
          ]) {
            const first = role("membership_first");
            const second = role("membership_second");
            await createRole(adminPool, first);
            await createRole(adminPool, second);
            await grantRole(
              adminPool,
              second,
              first,
              setOption,
              inheritOption,
              adminOption,
            );
            await assertPostureFails(
              adminPool,
              first,
              "administrativeAttributesAbsent",
            );
            await adminPool.query(
              `revoke ${identifier(second)} from ${identifier(first)}`,
            );

            await grantRole(
              adminPool,
              first,
              second,
              setOption,
              inheritOption,
              adminOption,
            );
            await assertPostureFails(
              adminPool,
              first,
              "administrativeAttributesAbsent",
            );
            await adminPool.query(
              `revoke ${identifier(first)} from ${identifier(second)}`,
            );
          }
        },
      );

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

      await context.test("SET false membership is still prohibited", async () => {
        const runtime = role("set_false_runtime");
        const blocked = role("set_false_createdb");
        await createRole(adminPool, runtime);
        await createRole(adminPool, blocked, "createdb");
        await grantRole(adminPool, blocked, runtime, false, false);
        await assertSetRole(adminPool, runtime, blocked, false);
        await assertPostureFails(
          adminPool,
          runtime,
          "administrativeAttributesAbsent",
        );
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

      await context.test("a mixed membership chain remains prohibited", async () => {
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
        await assertPostureFails(
          adminPool,
          runtime,
          "administrativeAttributesAbsent",
        );
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

      await context.test("even a non-administrative SET membership is prohibited", async () => {
        const runtime = role("safe_runtime");
        const safe = role("safe_role");
        await createRole(adminPool, runtime);
        await createRole(adminPool, safe);
        await grantRole(adminPool, safe, runtime, true, false);
        await assertSetRole(adminPool, runtime, safe, true);
        await assertPostureFails(
          adminPool,
          runtime,
          "administrativeAttributesAbsent",
        );
      });
    } finally {
      await adminPool.query("alter database runtime_posture_test owner to postgres").catch(() => {});
      await adminPool.query("alter schema drizzle owner to postgres").catch(() => {});
      await adminPool.query("alter table public.users owner to postgres").catch(() => {});
      for (const extension of extensions.reverse()) {
        await adminPool.query(`drop extension if exists ${identifier(extension)} cascade`).catch(() => {});
      }
      for (const routineName of routines.reverse()) {
        await adminPool.query(`drop function if exists public.${identifier(routineName)}() cascade`).catch(() => {});
      }
      for (const sequence of sequences.reverse()) {
        await adminPool.query(`drop sequence if exists public.${identifier(sequence)} cascade`).catch(() => {});
      }
      for (const relationName of relations.reverse()) {
        await adminPool.query(`drop table if exists public.${identifier(relationName)} cascade`).catch(() => {});
      }
      for (const schemaName of schemas.reverse()) {
        await adminPool.query(`drop schema if exists ${identifier(schemaName)} cascade`).catch(() => {});
      }
      await adminPool.query("drop schema if exists drizzle cascade").catch(() => {});
      await adminPool.query("drop table if exists public.users cascade").catch(() => {});
      for (const roleName of roles.reverse()) {
        await adminPool.query(`drop role if exists ${identifier(roleName)}`).catch(() => {});
      }
      if (neonSuperuserCreated) {
        await adminPool.query("drop role if exists neon_superuser").catch(() => {});
      }
      await rawAdminPool.end();
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

function fixtureDefinition(name, connectionString, operatorConnectionString) {
  const expectedDatabase = name === "primary"
    ? "runtime_posture_test"
    : "runtime_posture_test_secondary";
  return {
    name,
    connectionString,
    expectedDatabase,
    expectedUser: "platform_app",
    expectedMutationUser: "postgres",
    operatorUrl: operatorConnectionString,
    expectedRuntimeRole: "platform_runtime",
    expectedObjects: {
      schemas: ["public", "drizzle"],
      relations: [
        { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
        { schema: "public", name: "users", kind: "r" },
      ],
      sequences: [],
      routines: [],
    },
    operatorTransport: { kind: "loopback", phase: "final_start" },
    transport: { kind: "loopback", phase: "final_start" },
  };
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
