import assert from "node:assert/strict";
import test from "node:test";

import { Pool } from "pg";

import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../dist/db/runtime-posture.js";
import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresFixtures,
  createAdmittedMutationPool,
  invalidateDisposablePostgresAdmission,
} from "./support/disposable-postgres-fixture.mjs";

const primaryDatabaseUrl = process.env.MIGRATOR_ALIGNMENT_TEST_DATABASE_URL;
const primaryOperatorUrl = process.env.MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL;
const secondaryDatabaseUrl = process.env.MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL;
const secondaryOperatorUrl = process.env.MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL;
const disposableConfirmed =
  process.env.MIGRATOR_ALIGNMENT_TEST_CONFIRM === "disposable-only";
const skipReason =
  primaryDatabaseUrl &&
  primaryOperatorUrl &&
  secondaryDatabaseUrl &&
  secondaryOperatorUrl &&
  disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable migrator alignment fixture";

const primaryDatabaseName = "migrator_alignment_test";
const secondaryDatabaseName = "migrator_alignment_test_secondary";
const ownedPort = 56432;
const fixtureRoleNames = [
  "platform_app",
  "platform_migrator",
  "platform_runtime",
  "provider_owner",
];
const allowedAclRoles = new Set([
  ...fixtureRoleNames,
  "postgres",
  "PUBLIC",
]);
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const syntheticMigratorPassword = "synthetic-migrator-password";

test(
  "PostgreSQL 17 protects the bootstrap creator edge created for platform_migrator",
  { skip: skipReason },
  async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      const baseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(baseline);

      await createMigratorRoleAsLegacyOwner(primary.appPool);

      await assertExactProtectedEdge(primary.adminPool);
      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /permission denied to set role|must be able to SET ROLE/i,
      );

      await primary.appPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await assertMigratorRoleAttribute(
        primary.adminPool,
        "rolcreatedb",
        false,
      );

      await primary.adminPool.query(`drop role platform_migrator`);
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "bounded supplemental SET edge, credential-before-transfer login admission and one-transaction ownership transfer",
  { skip: skipReason },
  async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      const baseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(baseline);

      await createMigratorRoleAsLegacyOwner(primary.appPool);
      await primary.appPool.query(
        `grant connect on database ${identifier(primary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(primary.adminPool);
      await assertExactProtectedEdge(primary.adminPool);

      await assertQueryRejected(
        primary.migratorPool,
        `select 1`,
        /not permitted to log in/i,
      );
      assertOwnershipFieldsUnchanged(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );

      await primary.adminPool.query(
        `alter role platform_migrator login password '${syntheticMigratorPassword}'`,
      );
      await assertMigratorRoleAttribute(primary.adminPool, "rolcanlogin", true);
      await validateMigratorLoginAdmission(primary.migratorPool);

      await primary.appPool.query(
        `grant platform_migrator to platform_app with set true, inherit false`,
      );
      assertExactTransferWindowEdges(await readMembershipEdges(primary.adminPool));

      await primary.adminPool.query(
        `grant create, usage on schema public to platform_migrator`,
      );
      await primary.adminPool.query(
        `grant create on schema drizzle to platform_migrator`,
      );
      await primary.adminPool.query(
        `grant create on schema appdata to platform_migrator`,
      );

      await forwardTransferInOneTransaction(primary);

      await assertMigratorRoleAttribute(primary.adminPool, "rolcreatedb", false);
      await assertMigratorFinalAttributes(primary.adminPool);

      await primary.appPool.query(
        `revoke platform_migrator from platform_app granted by platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      const forwardFingerprint = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(forwardFingerprint.databaseOwner, "platform_migrator");
      assert.deepEqual(forwardFingerprint.schemaOwners, [
        "appdata=platform_migrator",
        "drizzle=platform_migrator",
        "public=provider_owner",
      ]);
      for (const objectName of [
        "widgets",
        "widgets_label_uidx",
        "counter_seq",
        "__drizzle_migrations",
        "users",
        ...contractTableNames(),
      ]) {
        assert.ok(
          forwardFingerprint.objectOwners.includes(
            `${objectName}=platform_migrator`,
          ),
          `expected ${objectName} owned by platform_migrator`,
        );
      }
      assert.ok(forwardFingerprint.enumOwners.includes("widget_status=platform_migrator"));
      assert.ok(forwardFingerprint.routineOwners.includes("widget_summary=platform_migrator"));

      const ledgerBefore = await primary.adminPool.query(
        "select count(*)::int as c from drizzle.__drizzle_migrations",
      );
      const migrationClient = await primary.migratorPool.connect();
      try {
        await migrationClient.query("begin");
        await migrationClient.query(
          "insert into drizzle.__drizzle_migrations (id, hash) select coalesce(max(id), 0) + 1, 'bounded-migration-proof' from drizzle.__drizzle_migrations",
        );
        await migrationClient.query("rollback");
      } finally {
        migrationClient.release();
      }
      const ledgerAfter = await primary.adminPool.query(
        "select count(*)::int as c from drizzle.__drizzle_migrations",
      );
      assert.equal(ledgerAfter.rows[0].c, ledgerBefore.rows[0].c);

      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "provider_owner",
      );
      const publicPrivileges = await schemaPrivileges(
        primary.adminPool,
        "platform_migrator",
        "public",
      );
      assert.equal(publicPrivileges.can_create, true);
      assert.equal(publicPrivileges.can_usage, true);
      await assertRuntimeGrantSetExact(primary.adminPool);
      await assertRuntimePosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "exact reverse rollback via the provider/bootstrap authority restores the complete baseline",
  { skip: skipReason },
  async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      const migratedState = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(migratedState.databaseOwner, "platform_migrator");
      await assertExactProtectedEdge(primary.adminPool);

      await reverseTransferViaProviderAuthority(primary);

      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await dropMigratorRole(primary.adminPool);

      const restored = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(restored);
      assert.equal(restored.databaseOwner, "platform_app");
      assert.equal(restored.memberships.length, 0);
      assert.equal(
        restored.attributes.some((row) => row.rolname === "platform_migrator"),
        false,
      );
      await assertRuntimePosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "platform_runtime edge revocation and provider-managed public bounded migrator transaction",
  { skip: skipReason },
  async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      const secondary = fixture.secondary;
      const primaryBaseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(primaryBaseline);
      const secondaryBaseline = await readOwnershipFingerprint(
        secondary.adminPool,
        secondary.databaseName,
      );
      assertBaselineFingerprint(secondaryBaseline);

      await primary.adminPool.query(
        `grant platform_runtime to platform_app with admin true, inherit false, set false`,
      );
      const runtimeEdge = (await readMembershipEdges(primary.adminPool))
        .filter((edge) => edge.granted_role === "platform_runtime");
      assert.equal(runtimeEdge.length, 1);
      assert.equal(runtimeEdge[0].granted_role, "platform_runtime");
      assert.equal(runtimeEdge[0].member, "platform_app");
      assert.equal(runtimeEdge[0].grantor, "postgres");
      assert.equal(runtimeEdge[0].admin_option, true);
      assert.equal(runtimeEdge[0].inherit_option, false);
      assert.equal(runtimeEdge[0].set_option, false);
      const edgesWhereRuntimeIsMember = (await readMembershipEdges(primary.adminPool))
        .filter((edge) => edge.member === "platform_runtime");
      assert.equal(edgesWhereRuntimeIsMember.length, 0);
      await assertRuntimeGrantSetExact(primary.adminPool);
      const runtimeOwns = await runtimeOwnershipCounts(primary.adminPool);
      assert.deepEqual(runtimeOwns, {
        dbs: 0,
        relations: 0,
        routines: 0,
        schemas: 0,
        types: 0,
      });

      await primary.adminPool.query(
        `revoke platform_runtime from platform_app`,
      );
      assert.equal(
        (await readMembershipEdges(primary.adminPool))
          .filter((edge) => edge.granted_role === "platform_runtime").length,
        0,
      );
      await assertRuntimePosture(primary.adminPool);
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        primaryBaseline,
      );

      await createMigratorRoleAsLegacyOwner(secondary.appPool);
      await secondary.appPool.query(
        `grant connect on database ${identifier(secondary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(secondary.adminPool);
      await assertExactProtectedEdge(secondary.adminPool);
      await secondary.adminPool.query(
        `grant create, usage on schema public to platform_migrator`,
      );
      await secondary.adminPool.query(
        `alter role platform_migrator login password '${syntheticMigratorPassword}'`,
      );
      await validateMigratorLoginAdmission(secondary.migratorPool);
      const boundedClient = await secondary.migratorPool.connect();
      try {
        await boundedClient.query("begin");
        await boundedClient.query(
          `create table public.__migrator_bounded_probe (id integer primary key)`,
        );
        await boundedClient.query(
          `insert into public.__migrator_bounded_probe (id) values (1)`,
        );
        const probe = await boundedClient.query(
          `select count(*)::int as c from public.__migrator_bounded_probe`,
        );
        assert.equal(probe.rows[0].c, 1);
        await boundedClient.query("rollback");
      } finally {
        boundedClient.release();
      }
      const probeResidue = await secondary.adminPool.query(
        `
          select count(*)::int as c
            from pg_class probe_record
            join pg_namespace probe_schema
              on probe_schema.oid = probe_record.relnamespace
           where probe_schema.nspname = 'public'
             and probe_record.relname = '__migrator_bounded_probe'
        `,
      );
      assert.equal(probeResidue.rows[0].c, 0);
      assert.equal(
        await schemaOwner(secondary.adminPool, secondary.databaseName, "public"),
        "provider_owner",
      );
      await assertRuntimePosture(secondary.adminPool);

      await secondary.adminPool.query(
        `revoke create, usage on schema public from platform_migrator`,
      );
      await secondary.adminPool.query(
        `revoke connect on database ${identifier(secondary.databaseName)} from platform_migrator`,
      );
      await secondary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await dropMigratorRole(secondary.adminPool);
      assert.deepEqual(
        await readOwnershipFingerprint(
          secondary.adminPool,
          secondary.databaseName,
        ),
        secondaryBaseline,
      );
    } finally {
      await closeFixtures(fixture);
    }
  },
);

async function createMigratorRoleAsLegacyOwner(appPool) {
  await appPool.query(
    `create role platform_migrator nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls`,
  );
}

async function installMigratorDefaultPrivileges(adminPool) {
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke all privileges on tables from public",
  );
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke all privileges on sequences from public",
  );
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke execute on functions from public",
  );
}

async function dropMigratorRole(adminPool) {
  await adminPool.query(`drop owned by platform_migrator`);
  await adminPool.query(`drop role platform_migrator`);
}

async function validateMigratorLoginAdmission(migratorPool) {
  const client = await migratorPool.connect();
  try {
    const result = await client.query(
      `select current_user::text as cu, session_user::text as su`,
    );
    assert.equal(result.rows[0].cu, "platform_migrator");
    assert.equal(result.rows[0].su, "platform_migrator");
  } finally {
    client.release();
  }
}

async function forwardTransferInOneTransaction(primary) {
  const { appPool } = primary;
  const databaseName = primary.databaseName;

  const statements = [
    `alter table drizzle.__drizzle_migrations owner to platform_migrator`,
    `alter table appdata.widgets owner to platform_migrator`,
    `alter sequence appdata.counter_seq owner to platform_migrator`,
    `alter type appdata.widget_status owner to platform_migrator`,
    `alter function appdata.widget_summary() owner to platform_migrator`,
    ...[...new Set(["users", ...contractTableNames()])].map(
      (tableName) =>
        `alter table public.${identifier(tableName)} owner to platform_migrator`,
    ),
    `alter schema drizzle owner to platform_migrator`,
    `alter schema appdata owner to platform_migrator`,
    `alter database ${identifier(databaseName)} owner to platform_migrator`,
  ];
  const client = await appPool.connect();
  try {
    await client.query("begin");
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function reverseTransferViaProviderAuthority(primary) {
  const { adminPool } = primary;
  const databaseName = primary.databaseName;

  const statements = [
    `alter database ${identifier(databaseName)} owner to platform_app`,
    `alter schema drizzle owner to platform_app`,
    `alter schema appdata owner to platform_app`,
    `alter table drizzle.__drizzle_migrations owner to platform_app`,
    `alter table appdata.widgets owner to platform_app`,
    `alter sequence appdata.counter_seq owner to platform_app`,
    `alter type appdata.widget_status owner to platform_app`,
    `alter function appdata.widget_summary() owner to platform_app`,
    ...[...new Set(["users", ...contractTableNames()])].map(
      (tableName) =>
        `alter table public.${identifier(tableName)} owner to platform_app`,
    ),
    `revoke create on schema drizzle from platform_migrator`,
    `revoke create on schema appdata from platform_migrator`,
    `revoke create, usage on schema public from platform_migrator`,
    `revoke connect on database ${identifier(databaseName)} from platform_migrator`,
  ];
  const client = await adminPool.connect();
  try {
    await client.query("begin");
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function readMembershipEdges(adminPool) {
  const result = await adminPool.query(
    `
      select roleid_role.rolname as granted_role,
             member_role.rolname as member,
             grantor_role.rolname as grantor,
             membership.admin_option,
             membership.inherit_option,
             membership.set_option
        from pg_auth_members membership
        join pg_roles roleid_role on roleid_role.oid = membership.roleid
        join pg_roles member_role on member_role.oid = membership.member
        left join pg_roles grantor_role on grantor_role.oid = membership.grantor
       where member_role.rolname = any($1::text[])
          or roleid_role.rolname = any($1::text[])
       order by granted_role, member, grantor
    `,
    [fixtureRoleNames],
  );
  return result.rows.map((row) => ({
    admin_option: row.admin_option,
    granted_role: row.granted_role,
    grantor: row.grantor,
    inherit_option: row.inherit_option,
    member: row.member,
    set_option: row.set_option,
  }));
}

async function assertExactProtectedEdge(adminPool) {
  const migratorEdges = (await readMembershipEdges(adminPool))
    .filter((edge) => edge.granted_role === "platform_migrator");
  assert.equal(migratorEdges.length, 1);
  const edge = migratorEdges[0];
  assert.equal(edge.granted_role, "platform_migrator");
  assert.equal(edge.member, "platform_app");
  assert.equal(edge.grantor, "postgres");
  assert.equal(edge.admin_option, true);
  assert.equal(edge.inherit_option, false);
  assert.equal(edge.set_option, false);
}

function assertExactTransferWindowEdges(edges) {
  const migratorEdges = edges.filter((edge) => edge.granted_role === "platform_migrator");
  assert.equal(migratorEdges.length, 2);
  const protectedEdge = migratorEdges.find((edge) => edge.grantor === "postgres");
  assert.ok(protectedEdge);
  assert.equal(protectedEdge.member, "platform_app");
  assert.equal(protectedEdge.admin_option, true);
  assert.equal(protectedEdge.inherit_option, false);
  assert.equal(protectedEdge.set_option, false);
  const supplementalEdge = migratorEdges.find((edge) => edge.grantor === "platform_app");
  assert.ok(supplementalEdge);
  assert.equal(supplementalEdge.member, "platform_app");
  assert.equal(supplementalEdge.admin_option, false);
  assert.equal(supplementalEdge.inherit_option, false);
  assert.equal(supplementalEdge.set_option, true);
}

async function assertMigratorRoleAttribute(adminPool, field, expected) {
  const result = await adminPool.query(
    `select ${field} from pg_roles where rolname = 'platform_migrator'`,
  );
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0][field], expected);
}

async function assertMigratorFinalAttributes(adminPool) {
  const result = await adminPool.query(
    `
      select rolsuper, rolcreatedb, rolcreaterole, rolreplication,
             rolbypassrls, rolcanlogin
        from pg_roles
       where rolname = 'platform_migrator'
    `,
  );
  assert.equal(result.rows.length, 1);
  const row = result.rows[0];
  assert.deepEqual(
    {
      bypassrls: row.rolbypassrls,
      createdb: row.rolcreatedb,
      createrole: row.rolcreaterole,
      login: row.rolcanlogin,
      replication: row.rolreplication,
      super: row.rolsuper,
    },
    {
      bypassrls: false,
      createdb: false,
      createrole: false,
      login: true,
      replication: false,
      super: false,
    },
  );
}

async function runtimeOwnershipCounts(adminPool) {
  const result = await adminPool.query(
    `
      select
        (select count(*)::int from pg_database d where d.datdba = (select oid from pg_roles where rolname='platform_runtime')) as dbs,
        (select count(*)::int from pg_namespace s where s.nspowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as schemas,
        (select count(*)::int from pg_class c join pg_namespace s on s.oid=c.relnamespace where c.relowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as relations,
        (select count(*)::int from pg_proc p join pg_namespace s on s.oid=p.pronamespace where p.proowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as routines,
        (select count(*)::int from pg_type t join pg_namespace s on s.oid=t.typnamespace where t.typowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as types
    `,
  );
  return result.rows[0];
}

function assertOwnershipFieldsUnchanged(fingerprint, baseline) {
  assert.equal(fingerprint.databaseOwner, baseline.databaseOwner);
  assert.deepEqual(fingerprint.schemaOwners, baseline.schemaOwners);
  assert.deepEqual(fingerprint.objectOwners, baseline.objectOwners);
  assert.deepEqual(fingerprint.enumOwners, baseline.enumOwners);
  assert.deepEqual(fingerprint.routineOwners, baseline.routineOwners);
}

async function openFixtures() {
  assertFixtureUrl(primaryDatabaseUrl, {
    expectedUser: "platform_app",
    expectedDatabase: primaryDatabaseName,
  });
  assertFixtureUrl(primaryOperatorUrl, {
    expectedUser: "postgres",
    expectedDatabase: primaryDatabaseName,
  });
  assertFixtureUrl(secondaryDatabaseUrl, {
    expectedUser: "platform_app",
    expectedDatabase: secondaryDatabaseName,
  });
  assertFixtureUrl(secondaryOperatorUrl, {
    expectedUser: "postgres",
    expectedDatabase: secondaryDatabaseName,
  });

  const primaryOperatorPool = new Pool({
    connectionString: primaryOperatorUrl,
    max: 4,
  });
  const secondaryOperatorPool = new Pool({
    connectionString: secondaryOperatorUrl,
    max: 4,
  });
  const admission = await admitDisposablePostgresFixtures([
    fixtureDefinition(
      "primary",
      primaryDatabaseUrl,
      primaryOperatorUrl,
      primaryDatabaseName,
    ),
    fixtureDefinition(
      "secondary",
      secondaryDatabaseUrl,
      secondaryOperatorUrl,
      secondaryDatabaseName,
    ),
  ]);
  const primaryAdmin = createAdmittedMutationPool(
    primaryOperatorPool,
    admission,
    "primary",
  );
  const secondaryAdmin = createAdmittedMutationPool(
    secondaryOperatorPool,
    admission,
    "secondary",
  );
  const primaryApp = new Pool({
    connectionString: roleUrl("platform_app", primaryDatabaseName),
    max: 2,
  });
  const primaryMigrator = new Pool({
    connectionString: roleUrl("platform_migrator", primaryDatabaseName),
    max: 2,
  });
  const secondaryApp = new Pool({
    connectionString: roleUrl("platform_app", secondaryDatabaseName),
    max: 2,
  });
  const secondaryMigrator = new Pool({
    connectionString: roleUrl("platform_migrator", secondaryDatabaseName),
    max: 2,
  });

  return {
    admission,
    pools: [
      primaryOperatorPool,
      secondaryOperatorPool,
      primaryApp,
      primaryMigrator,
      secondaryApp,
      secondaryMigrator,
    ],
    primary: {
      adminPool: primaryAdmin,
      appPool: primaryApp,
      databaseName: primaryDatabaseName,
      migratorPool: primaryMigrator,
    },
    secondary: {
      adminPool: secondaryAdmin,
      appPool: secondaryApp,
      databaseName: secondaryDatabaseName,
      migratorPool: secondaryMigrator,
    },
  };
}

async function closeFixtures(fixture) {
  invalidateDisposablePostgresAdmission(fixture.admission);
  for (const pool of fixture.pools) {
    await pool.end().catch(() => {});
  }
}

function fixtureDefinition(name, databaseUrl, operatorUrl, expectedDatabase) {
  return {
    name,
    connectionString: databaseUrl,
    expectedDatabase,
    expectedUser: "platform_app",
    expectedRuntimeRole: "platform_runtime",
    expectedMutationUser: "postgres",
    operatorUrl,
    expectedObjects: {
      schemas: ["public", "appdata", "drizzle"],
      relations: [
        { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
        { schema: "public", name: "users", kind: "r" },
        { schema: "appdata", name: "widgets", kind: "r" },
        ...contractTableNames().map((name) => ({
          schema: "public",
          name,
          kind: "r",
        })),
      ],
      sequences: [{ schema: "appdata", name: "counter_seq" }],
      routines: [{ schema: "appdata", name: "widget_summary", kind: "f" }],
    },
    transport: { kind: "loopback", phase: "final_start" },
    operatorTransport: { kind: "loopback", phase: "final_start" },
  };
}

async function readOwnershipFingerprint(adminPool, databaseName) {
  const ownership = await adminPool.query(
    `
      select
        (select rolname
           from pg_database database_record
           join pg_roles role_record on role_record.oid = database_record.datdba
          where database_record.datname = $1) as database_owner,
        (select array_agg(schema_record.nspname || '=' || role_record.rolname
                order by schema_record.nspname)
           from pg_namespace schema_record
           join pg_roles role_record on role_record.oid = schema_record.nspowner
          where schema_record.nspname in ('public', 'appdata', 'drizzle')) as schema_owners,
        (select array_agg(relation_record.relname || '=' || role_record.rolname
                order by relation_record.relname)
           from pg_class relation_record
           join pg_namespace schema_record
             on schema_record.oid = relation_record.relnamespace
           join pg_roles role_record on role_record.oid = relation_record.relowner
          where relation_record.relkind in ('r', 'S', 'i')
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as object_owners,
        (select array_agg(type_record.typname || '=' || role_record.rolname
                order by type_record.typname)
           from pg_type type_record
           join pg_namespace schema_record
             on schema_record.oid = type_record.typnamespace
           join pg_roles role_record on role_record.oid = type_record.typowner
          where type_record.typtype = 'e'
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as enum_owners,
        (select array_agg(routine_record.proname || '=' || role_record.rolname
                order by routine_record.proname)
           from pg_proc routine_record
           join pg_namespace schema_record
             on schema_record.oid = routine_record.pronamespace
           join pg_roles role_record on role_record.oid = routine_record.proowner
          where routine_record.prokind = 'f'
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as routine_owners
    `,
    [databaseName],
  );
  assert.equal(ownership.rows.length, 1);

  const aclRecords = await adminPool.query(
    `
      select 'database' as surface,
             $1::text as object_name,
             coalesce(grantor_role.rolname, 'PUBLIC') as grantor,
             coalesce(grantee_role.rolname, 'PUBLIC') as grantee,
             grant_record.privilege_type as privilege_type,
             grant_record.is_grantable as is_grantable
        from pg_database database_record
        join lateral aclexplode(
          coalesce(
            database_record.datacl,
            acldefault('d', database_record.datdba)
          )
        ) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where database_record.datname = $1
      union all
      select 'schema', schema_record.nspname,
             coalesce(grantor_role.rolname, 'PUBLIC'),
             coalesce(grantee_role.rolname, 'PUBLIC'),
             grant_record.privilege_type,
             grant_record.is_grantable
        from pg_namespace schema_record
        join lateral aclexplode(
          coalesce(
            schema_record.nspacl,
            acldefault('n', schema_record.nspowner)
          )
        ) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where schema_record.nspname in ('public', 'appdata', 'drizzle')
      union all
      select 'default', coalesce(namespace_record.nspname, '<global>')
             || ':' || default_record.defaclobjtype::text,
             coalesce(grantor_role.rolname, 'PUBLIC'),
             coalesce(grantee_role.rolname, 'PUBLIC'),
             grant_record.privilege_type,
             grant_record.is_grantable
        from pg_default_acl default_record
        left join pg_namespace namespace_record
          on namespace_record.oid = default_record.defaclnamespace
        join lateral aclexplode(default_record.defaclacl) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where default_record.defaclrole in (
         select oid from pg_roles where rolname = any($2::text[])
       )
      order by surface, object_name, grantor, grantee, privilege_type
    `,
    [databaseName, fixtureRoleNames],
  );

  const attributes = await adminPool.query(
    `
      select rolname, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
             rolreplication, rolbypassrls, rolcanlogin
        from pg_roles
       where rolname = any($1::text[])
       order by rolname
    `,
    [fixtureRoleNames],
  );

  const memberships = await readMembershipEdges(adminPool);

  const aclSurfaces = {
    database: [],
    "default": [],
    schema: [],
  };
  for (const row of aclRecords.rows) {
    if (
      typeof row.surface !== "string" ||
      typeof row.object_name !== "string" ||
      typeof row.grantor !== "string" ||
      typeof row.grantee !== "string" ||
      typeof row.privilege_type !== "string" ||
      typeof row.is_grantable !== "boolean"
    ) {
      throw new Error();
    }
    if (!aclSurfaces[row.surface]) throw new Error();
    aclSurfaces[row.surface].push(
      `${row.object_name}\u0000${row.grantor}\u0000${row.grantee}\u0000${row.privilege_type}\u0000${row.is_grantable}`,
    );
  }

  return {
    attributes: attributes.rows,
    databaseAcl: [...new Set(aclSurfaces.database)].sort(),
    databaseOwner: ownership.rows[0].database_owner,
    defaultAcl: [...new Set(aclSurfaces.default)].sort(),
    enumOwners: ownership.rows[0].enum_owners ?? [],
    memberships,
    objectOwners: ownership.rows[0].object_owners ?? [],
    routineOwners: ownership.rows[0].routine_owners ?? [],
    schemaAcls: [...new Set(aclSurfaces.schema)].sort(),
    schemaOwners: ownership.rows[0].schema_owners ?? [],
  };
}

function assertBaselineFingerprint(fingerprint) {
  assert.equal(fingerprint.databaseOwner, "platform_app");
  assert.deepEqual(fingerprint.schemaOwners, [
    "appdata=platform_app",
    "drizzle=platform_app",
    "public=provider_owner",
  ]);
  for (const objectName of [
    "widgets",
    "widgets_label_uidx",
    "counter_seq",
    "__drizzle_migrations",
    "users",
    ...contractTableNames(),
  ]) {
    assert.ok(
      fingerprint.objectOwners.includes(`${objectName}=platform_app`),
      `expected baseline ${objectName} owned by platform_app`,
    );
  }
  assert.ok(fingerprint.enumOwners.includes("widget_status=platform_app"));
  assert.ok(fingerprint.routineOwners.includes("widget_summary=platform_app"));
  assert.equal(fingerprint.memberships.length, 0);

  const attributes = new Map(
    fingerprint.attributes.map((row) => [row.rolname, row]),
  );
  assert.equal(attributes.has("platform_migrator"), false);
  const app = attributes.get("platform_app");
  assert.equal(app.rolcanlogin, true);
  assert.equal(app.rolcreatedb, true);
  assert.equal(app.rolcreaterole, true);
  assert.equal(app.rolsuper, false);
  const runtime = attributes.get("platform_runtime");
  assert.equal(runtime.rolcanlogin, false);
  assert.equal(runtime.rolsuper, false);
  assert.equal(runtime.rolcreatedb, false);
  const provider = attributes.get("provider_owner");
  assert.equal(provider.rolcanlogin, false);
  assert.equal(provider.rolsuper, false);

  assertAclSurfaceBounded(fingerprint.databaseAcl, "database");
  assertAclSurfaceBounded(fingerprint.schemaAcls, "schema");
  assertAclSurfaceBounded(fingerprint.defaultAcl, "default");
  assert.ok(fingerprint.databaseAcl.length > 0);
  assert.ok(fingerprint.schemaAcls.length > 0);
  assert.ok(fingerprint.defaultAcl.length > 0);
}

function assertAclSurfaceBounded(records, surface) {
  assert.ok(Array.isArray(records));
  for (const record of records) {
    const fields = record.split("\u0000");
    assert.equal(fields.length, 5);
    const objectName = fields[0];
    const grantor = fields[1];
    const grantee = fields[2];
    const privilegeType = fields[3];
    const isGrantable = fields[4];
    assert.ok(
      allowedAclRoles.has(grantor),
      `unexpected ${surface} grantor ${grantor}`,
    );
    assert.ok(
      allowedAclRoles.has(grantee),
      `unexpected ${surface} grantee ${grantee}`,
    );
    assert.match(privilegeType, /^[A-Z_]+$/);
    assert.ok(isGrantable === "true" || isGrantable === "false");
    assert.ok(objectName.length > 0);
  }
}

async function assertRuntimePosture(adminPool) {
  const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
    adminPool,
    "platform_runtime",
  );
  assert.equal(report.runtimeRoleAuthorityPosture, "passed");
}

async function assertRuntimeGrantSetExact(adminPool) {
  const runtimeGrantSet = await adminPool.query(
    `
      select case c.relkind
               when 'r' then 'table'
               when 'p' then 'table'
               when 'v' then 'view'
               when 'm' then 'materialized_view'
               when 'f' then 'foreign_table'
               else 'unsupported_relation'
             end::text as object_class,
             s.nspname::text as schema_name,
             c.relname::text as object_name,
             upper(acl.privilege_type)::text as privilege_type,
             acl.is_grantable as is_grantable
        from pg_class c
        join pg_namespace s on s.oid = c.relnamespace
        join pg_roles runtime_role on runtime_role.rolname = 'platform_runtime'
        cross join lateral aclexplode(c.relacl) acl
       where s.nspname = 'public'
         and c.relkind in ('r','p','v','m','f')
         and acl.grantee = runtime_role.oid
       order by object_class, schema_name, object_name, privilege_type
    `,
  );
  const expectedKeys = new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map(
      (record) =>
        [
          record.objectClass,
          record.schema,
          record.objectName,
          record.privilege,
          record.authoritySource,
          record.grantOption ? "YES" : "NO",
        ].join("\u0000"),
    ),
  );
  const observed = runtimeGrantSet.rows.map((row) =>
    [
      row.object_class,
      row.schema_name,
      row.object_name,
      row.privilege_type,
      "direct",
      row.is_grantable ? "YES" : "NO",
    ].join("\u0000"),
  );
  const observedSet = new Set(observed);
  const missing = RUNTIME_TABLE_GRANT_CONTRACT.filter(
    (record) =>
      !observedSet.has(
        [
          record.objectClass,
          record.schema,
          record.objectName,
          record.privilege,
          record.authoritySource,
          record.grantOption ? "YES" : "NO",
        ].join("\u0000"),
      ),
  );
  const extra = observed.filter((key) => !expectedKeys.has(key));
  assert.equal(observed.length, RUNTIME_TABLE_GRANT_CONTRACT.length);
  assert.equal(missing.length, 0);
  assert.equal(extra.length, 0);
}

async function schemaOwner(adminPool, databaseName, schemaName) {
  const result = await adminPool.query(
    `
      select role_record.rolname
        from pg_namespace schema_record
        join pg_roles role_record on role_record.oid = schema_record.nspowner
       where schema_record.nspname = $1
    `,
    [schemaName],
  );
  assert.equal(result.rows.length, 1);
  void databaseName;
  return result.rows[0].rolname;
}

async function schemaPrivileges(adminPool, roleName, schemaName) {
  const result = await adminPool.query(
    `
      select
        has_schema_privilege($1, $2, 'CREATE') as can_create,
        has_schema_privilege($1, $2, 'USAGE') as can_usage
    `,
    [roleName, schemaName],
  );
  assert.equal(result.rows.length, 1);
  return result.rows[0];
}

async function assertQueryRejected(pool, sql, pattern) {
  await assert.rejects(
    () => pool.query(sql),
    (error) => pattern.test(String(error?.message ?? error)),
  );
}

function assertFixtureUrl(url, { expectedUser, expectedDatabase }) {
  const parsed = new URL(url);
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new Error();
  }
  if (parsed.password || parsed.search || parsed.hash) {
    throw new Error();
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  const port = parsed.port || "5432";
  if (hostname !== "127.0.0.1" && hostname !== "::1") {
    throw new Error();
  }
  if (port !== String(ownedPort)) {
    throw new Error();
  }
  const user = decodeURIComponent(parsed.username);
  const database = decodeURIComponent(parsed.pathname.slice(1));
  if (user !== expectedUser || database !== expectedDatabase) {
    throw new Error();
  }
}

function roleUrl(user, databaseName) {
  if (!safeIdentifier.test(user) || !safeIdentifier.test(databaseName)) {
    throw new Error();
  }
  return `postgres://${user}@127.0.0.1:${ownedPort}/${databaseName}`;
}

function contractTableNames() {
  return [...new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map((record) => record.objectName),
  )];
}

function identifier(value) {
  assert.match(value, /^[a-z_][a-z0-9_$]{0,62}$/);
  return `"${value.replaceAll('"', '""')}"`;
}
