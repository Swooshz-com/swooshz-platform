import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

import {
  JOURNAL_PREFIX_DOMAIN_SEPARATOR,
  captureNormalizedPrestate,
  canonicalDigest,
  computeTargetBindingDigest,
  createDurableInverse,
  createDurablePlan,
  executeDurablePlan,
  loadCanonicalMigrationJournal,
  runCanonicalMigrationPrimitive,
} from "../dist/db/durable-operations.js";
import { RUNTIME_TABLE_GRANT_CONTRACT } from "../dist/db/runtime-grant-contract.js";

const testDatabaseUrl = process.env.DURABLE_OPERATIONS_TEST_DATABASE_URL;
const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const migrationsFolder = resolve(rootDir, "drizzle", "migrations");
const databaseName = "durable_operations_test";
const expectedGitSha = "9ce40dce85484ef5fd8c849951527572e95afa24";
const contractDigest = "a".repeat(64);

if (!testDatabaseUrl) {
  test("durable PostgreSQL 17 proofs require the disposable runner", { skip: "runner-owned local fixture not supplied" }, () => {});
} else {
  test("Run-185 durable database operations on disposable PostgreSQL 17", async () => {
    const connection = readConnectionTarget(testDatabaseUrl);
    const adminPool = new Pool({ ...connection, user: "cloud_admin" });
    const cloudAdminPool = new Pool({ ...connection, user: "cloud_admin" });
    const migratorPool = new Pool({ ...connection, user: "platform_migrator" });
    const runtimePool = new Pool({ ...connection, user: "platform_runtime" });
    const appPool = new Pool({ ...connection, user: "platform_app" });

    try {
      await createRoles(adminPool);
      await cloudAdminPool.query("select 1");
      const migration = await provisionCanonicalFixture(cloudAdminPool);
      assert.equal(migration.after.length, 10);
      assert.equal(migration.applied_entries.length, 10);
      assert.equal(migration.applied_entries.at(-1).tag, "0010_admin_operator_viewer_role_collapse");

      const binding = {
        version: "target-binding-v1",
        logicalDatabaseName: databaseName,
        expectedCurrentUser: "platform_migrator",
        expectedSessionUser: "platform_migrator",
        expectedPostgresMajor: 17,
        connect: () => migratorPool.connect(),
      };
      const journal = await loadCanonicalMigrationJournal(rootDir);
      const baseline = await captureNormalizedPrestate(binding, journal);
      assert.equal(baseline.prestate.target.current_user, "platform_migrator");
      assert.equal(baseline.prestate.target.session_user, "platform_migrator");
      assert.equal(baseline.prestate.migration_journal.applied_rows.length, 10);
      assert.equal(
        baseline.prestate.migration_journal.applied_prefix_digest,
        canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, baseline.prestate.migration_journal.applied_rows),
      );
      assertCanonicalReadiness(baseline.prestate);

      await assertReadOnlyWriteRejected(migratorPool);
      await assertRuntimeAndAppSeparation(runtimePool, appPool);

      await cloudAdminPool.query(`grant select on table "public"."users" to "platform_app"`);
      const aclDrift = await captureNormalizedPrestate(binding, journal);
      assert.ok(aclDrift.prestate.privileges.direct.some((row) => row.grantee === "platform_app" && row.privilege === "select"));
      await cloudAdminPool.query(`revoke select on table "public"."users" from "platform_app"`);

      await cloudAdminPool.query(`alter default privileges for role "cloud_admin" in schema "public" grant select on tables to "platform_app"`);
      const defaultAclDrift = await captureNormalizedPrestate(binding, journal);
      assert.ok(defaultAclDrift.prestate.default_acls.creator.includes("cloud_admin"));
      await cloudAdminPool.query(`alter default privileges for role "cloud_admin" in schema "public" revoke select on tables from "platform_app"`);

      await cloudAdminPool.query(`create table "public"."run185_unknown_drift" ("id" integer)`);
      await assert.rejects(
        () => captureNormalizedPrestate(binding, journal),
        (error) => error?.semanticCode === "UNKNOWN_DRIFT",
      );
      await cloudAdminPool.query(`drop table "public"."run185_unknown_drift"`);

      const prewriteBaseline = await captureNormalizedPrestate(binding, journal);
      await cloudAdminPool.query(`grant select on table "public"."users" to "platform_app"`);
      const appRole = prewriteBaseline.prestate.roles.accepted_role_states.find((role) => role.rolname === "platform_app");
      const prewriteOperation = {
        kind: "role_posture",
        role: "platform_app",
        attributes: roleAttributes(appRole),
        previous_attributes: roleAttributes(appRole),
      };
      const prewritePlan = makePlan(binding, prewriteBaseline, [prewriteOperation]);
      await assert.rejects(
        () => executeDurablePlan({
          plan: prewritePlan,
          binding,
          expectedPrestate: prewriteBaseline.prestate,
          expectedContractDigest: contractDigest,
          journal,
        }),
        (error) => error?.semanticCode === "PREWRITE_DRIFT",
      );
      await cloudAdminPool.query(`revoke select on table "public"."users" from "platform_app"`);
      await assert.rejects(
        () => executeDurablePlan({
          plan: prewritePlan,
          binding,
          expectedPrestate: {},
          expectedContractDigest: contractDigest,
          journal,
        }),
        (error) => error?.semanticCode === "PRESTATE_INVALID",
      );

      const successBaseline = await captureNormalizedPrestate(binding, journal);
      const privilegeOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const successPlan = makePlan(binding, successBaseline, [privilegeOperation]);
      const successReceipt = await executeDurablePlan({
        plan: successPlan,
        binding,
        expectedPrestate: successBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(successReceipt.outcome, "PASS");
      assert.equal(successReceipt.mutation_started, true);
      assert.equal(successReceipt.final_readiness_state, "PASS");
      assert.equal(successReceipt.counts.inverse_steps, 1);

      const afterSuccess = await captureNormalizedPrestate(binding, journal);
      const inverse = createDurableInverse(successPlan);
      assert.equal(inverse.steps[0].operation.action, "revoke");
      const inversePlan = makePlan(binding, afterSuccess, [inverse.steps[0].operation]);
      const inverseReceipt = await executeDurablePlan({
        plan: inversePlan,
        binding,
        expectedPrestate: afterSuccess.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(inverseReceipt.outcome, "PASS");
      const restored = await captureNormalizedPrestate(binding, journal);
      assert.equal(restored.prestate_digest, successBaseline.prestate_digest);

      const partialBaseline = await captureNormalizedPrestate(binding, journal);
      const partialOperations = [
        {
          kind: "default_acl",
          action: "grant",
          creator: "platform_migrator",
          schema: "drizzle",
          object_type: "table",
          principal: "platform_app",
          privilege: "SELECT",
          grant_option: false,
          previous_grant_option: false,
        },
        {
          kind: "default_acl",
          action: "grant",
          creator: "platform_app",
          schema: "public",
          object_type: "table",
          principal: "platform_app",
          privilege: "SELECT",
          grant_option: false,
          previous_grant_option: false,
        },
      ];
      const partialPlan = makePlan(binding, partialBaseline, partialOperations);
      const partialReceipt = await executeDurablePlan({
        plan: partialPlan,
        binding,
        expectedPrestate: partialBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(partialReceipt.outcome, "FAIL");
      assert.equal(partialReceipt.mutation_started, true);
      assert.equal(partialReceipt.rollback_attempted, true);
      assert.equal(partialReceipt.rollback_verified, true);
      assert.equal(partialReceipt.restoration_state, "VERIFIED");
      const afterPartial = await captureNormalizedPrestate(binding, journal);
      assert.equal(afterPartial.prestate_digest, partialBaseline.prestate_digest);
    } finally {
      await Promise.all([
        appPool.end(),
        runtimePool.end(),
        migratorPool.end(),
        cloudAdminPool.end(),
        adminPool.end(),
      ]);
    }
  });
}

function readConnectionTarget(value) {
  const parsed = new URL(value);
  const port = Number(parsed.port);
  const database = decodeURIComponent(parsed.pathname.replace(/^\//u, ""));
  if ((parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") || parsed.hostname !== "127.0.0.1" || !Number.isInteger(port) || database !== databaseName) throw new Error("disposable fixture target rejected");
  return { host: parsed.hostname, port, database, max: 4, connectionTimeoutMillis: 4_000 };
}

function quoteIdentifier(value) {
  if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(value)) throw new Error("fixture identifier rejected");
  return `"${value}"`;
}

async function createRoles(adminPool) {
  await adminPool.query(`revoke "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables" from "pg_monitor"`);
  await adminPool.query(`create role "platform_migrator" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await adminPool.query(`create role "platform_runtime" login inherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await adminPool.query(`create role "platform_app" login inherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
}

async function provisionCanonicalFixture(cloudAdminPool) {
  const migration = await runCanonicalMigrationPrimitive({ pool: cloudAdminPool, migrationsFolder });
  const database = quoteIdentifier(databaseName);
  const migrator = quoteIdentifier("platform_migrator");
  const runtime = quoteIdentifier("platform_runtime");
  const app = quoteIdentifier("platform_app");
  await cloudAdminPool.query(`alter database ${database} owner to ${app}`);
  await cloudAdminPool.query(`revoke temporary on database ${database} from public`);
  await cloudAdminPool.query(`grant connect on database ${database} to ${migrator}`);
  await cloudAdminPool.query(`revoke create on schema public from public`);
  await cloudAdminPool.query(`grant usage, create on schema public to ${migrator}`);
  await cloudAdminPool.query(`alter schema drizzle owner to ${migrator}`);
  await cloudAdminPool.query(`revoke all on schema drizzle from public`);
  await cloudAdminPool.query(`grant usage, create on schema drizzle to ${migrator}`);
  await cloudAdminPool.query(`grant ${migrator} to ${app} with admin true, inherit false, set false granted by "cloud_admin"`);
  await cloudAdminPool.query(`alter default privileges for role "cloud_admin" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role "platform_app" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role "pg_database_owner" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke all privileges on tables from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke all privileges on sequences from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke execute on functions from public`);

  const relations = await cloudAdminPool.query(`
    select namespace_record.nspname as schema_name,
           relation_record.relname as object_name,
           relation_record.relkind
    from pg_class relation_record
    join pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace
    where namespace_record.nspname in ('public', 'drizzle')
      and relation_record.relkind in ('r', 'p', 'S', 'i', 'I')
    order by namespace_record.nspname, relation_record.relname
  `);
  for (const row of relations.rows) {
    const object = `${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.object_name)}`;
    const command = row.relkind === "S"
      ? `alter sequence ${object} owner to ${migrator}`
      : row.relkind === "i" || row.relkind === "I"
        ? `alter index ${object} owner to ${migrator}`
        : `alter table ${object} owner to ${migrator}`;
    await cloudAdminPool.query(command);
  }
  const enumTypes = await cloudAdminPool.query(`
    select namespace_record.nspname as schema_name, type_record.typname as type_name
    from pg_type type_record
    join pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace
    where namespace_record.nspname = 'public' and type_record.typtype = 'e' and type_record.typisdefined
    order by type_record.typname
  `);
  for (const row of enumTypes.rows) {
    await cloudAdminPool.query(`alter type ${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.type_name)} owner to ${migrator}`);
  }
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    await cloudAdminPool.query(`grant ${record.privilege} on table ${quoteIdentifier(record.schema)}.${quoteIdentifier(record.objectName)} to ${runtime}`);
  }
  return migration;
}

function roleAttributes(role) {
  assert.ok(role);
  return {
    rolcanlogin: role.rolcanlogin,
    rolinherit: role.rolinherit,
    rolsuper: role.rolsuper,
    rolcreatedb: role.rolcreatedb,
    rolcreaterole: role.rolcreaterole,
    rolreplication: role.rolreplication,
    rolbypassrls: role.rolbypassrls,
  };
}

function makePlan(binding, captured, operations) {
  return createDurablePlan({
    expected_git_sha: expectedGitSha,
    contract_digest: contractDigest,
    target_binding_digest: computeTargetBindingDigest(binding),
    prestate_digest: captured.prestate_digest,
    operation_kind: operations[0].kind,
    operations,
  });
}

function assertCanonicalReadiness(prestate) {
  assert.deepEqual(prestate.canonical_checks.readiness_checks, {
    config: "present",
    reachability: "passed",
    schema: "passed",
    migrations: "passed",
    migratorPosture: "passed",
  });
  assert.ok(Object.values(prestate.canonical_checks.runtime_posture_fields).every((value) => value === "passed"));
}

async function assertReadOnlyWriteRejected(migratorPool) {
  const client = await migratorPool.connect();
  try {
    await client.query("begin");
    await client.query("set transaction read only");
    await assert.rejects(
      () => client.query(`create temp table "run185_read_only_forbidden" ("id" integer)`),
      /read-only transaction/i,
    );
  } finally {
    await client.query("rollback").catch(() => {});
    client.release();
  }
}

async function assertRuntimeAndAppSeparation(runtimePool, appPool) {
  await assert.rejects(
    () => runtimePool.query(`create table "public"."run185_runtime_forbidden" ("id" integer)`),
    /permission denied/i,
  );
  await assert.rejects(
    () => appPool.query(`select count(*) from "public"."users"`),
    /permission denied/i,
  );
}
