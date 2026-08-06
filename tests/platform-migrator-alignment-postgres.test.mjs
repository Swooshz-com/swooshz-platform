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

test(
  "PostgreSQL 17 rejects the bare target-only CREATEDB owner-transfer model without persistent mutation",
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

      await primary.adminPool.query(`alter role platform_migrator createdb`);

      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /must be able to SET ROLE|permission denied to set role/i,
      );
      await assertQueryRejected(
        primary.appPool,
        `alter database ${identifier(primary.databaseName)} owner to platform_migrator`,
        /must be able to SET ROLE|must be member of role/i,
      );

      await primary.adminPool.query(`alter role platform_migrator nocreatedb`);
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );
      await assertMigratorFinalState(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "bounded temporary SET-capable membership completes the ownership transfer with immediate revocation, bounded migration proof, reverse rollback and fingerprint restore",
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
      await assertMigratorFinalState(primary.adminPool);

      await forwardTransfer(primary);

      await assertZeroFixtureMemberships(primary.adminPool);
      await assertMigratorFinalState(primary.adminPool);

      const forwardFingerprint = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(forwardFingerprint.databaseOwner, "platform_migrator");
      assert.deepEqual(forwardFingerprint.schemaOwners, [
        "appdata=platform_migrator",
        "drizzle=platform_migrator",
        "public=platform_migrator",
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

      await assertRuntimePosture(primary.adminPool);

      await reverseTransfer(primary);
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );
      await assertRuntimePosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "restricted runtime contract is preserved and legacy retirement is blocked until replacement proof passes",
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
      await assertRuntimePosture(primary.adminPool);

      await assertQueryRejected(
        primary.adminPool,
        `drop role platform_app`,
        /depends on it|cannot be dropped/i,
      );

      await primary.adminPool.query(`alter role platform_migrator createdb`);
      await primary.adminPool.query(
        `grant platform_migrator to platform_app with inherit false, set true`,
      );
      await assertSoleTemporaryMembership(
        primary.adminPool,
        "platform_app",
        "platform_migrator",
      );
      await primary.adminPool.query(
        `grant create on schema appdata to platform_migrator`,
      );
      await primary.adminPool.query(
        `grant create on schema drizzle to platform_migrator`,
      );
      await primary.appPool.query(
        `alter table appdata.widgets owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter sequence appdata.counter_seq owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter type appdata.widget_status owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter function appdata.widget_summary() owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter table drizzle.__drizzle_migrations owner to platform_migrator`,
      );

      await assertQueryRejected(
        primary.adminPool,
        `drop role platform_app`,
        /depends on it|cannot be dropped/i,
      );
      await assertAppLegacyStateUnchanged(primary.adminPool);

      await primary.adminPool.query(
        `grant create on schema public to platform_migrator`,
      );
      for (const tableName of [...new Set(["users", ...contractTableNames()])]) {
        await primary.appPool.query(
          `alter table public.${identifier(tableName)} owner to platform_migrator`,
        );
      }
      await primary.appPool.query(
        `alter schema public owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter schema appdata owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter schema drizzle owner to platform_migrator`,
      );
      await primary.appPool.query(
        `alter database ${identifier(primary.databaseName)} owner to platform_migrator`,
      );
      await primary.adminPool.query(
        `revoke create on schema public from platform_migrator`,
      );
      await primary.adminPool.query(
        `revoke create on schema appdata from platform_migrator`,
      );
      await primary.adminPool.query(
        `revoke create on schema drizzle from platform_migrator`,
      );
      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await primary.adminPool.query(
        `alter role platform_migrator nocreatedb`,
      );

      await assertRuntimePosture(primary.adminPool);
      await assertZeroFixtureMemberships(primary.adminPool);

      await reverseTransfer(primary);
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );
      await assertRuntimePosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
  },
);

test(
  "both public ownership variants are covered without widening runtime authority",
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
      assertBaselineFingerprint(secondaryBaseline, {
        providerManagedPublic: true,
      });

      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "platform_app",
      );
      await primary.adminPool.query(
        `grant platform_migrator to platform_app with inherit false, set true`,
      );
      await primary.adminPool.query(
        `grant create on schema public to platform_migrator`,
      );
      await primary.appPool.query(
        `alter schema public owner to platform_migrator`,
      );
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "platform_migrator",
      );
      await assertRuntimePosture(primary.adminPool);

      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await primary.adminPool.query(
        `grant platform_app to platform_migrator with inherit false, set true`,
      );
      await primary.adminPool.query(
        `grant create on schema public to platform_app`,
      );
      await primary.adminPool.query(
        `grant create on database ${identifier(primary.databaseName)} to platform_migrator`,
      );
      await primary.migratorPool.query(
        `alter schema public owner to platform_app`,
      );
      await primary.adminPool.query(
        `revoke create on database ${identifier(primary.databaseName)} from platform_migrator`,
      );
      await primary.adminPool.query(
        `revoke platform_app from platform_migrator`,
      );
      assert.deepEqual(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        primaryBaseline,
      );

      assert.equal(
        await schemaOwner(secondary.adminPool, secondary.databaseName, "public"),
        "provider_owner",
      );
      const privileges = await schemaPrivileges(
        secondary.adminPool,
        "platform_migrator",
        "public",
      );
      assert.equal(privileges.can_create, true);
      assert.equal(privileges.can_usage, true);
      await assertQueryRejected(
        secondary.appPool,
        `alter schema public owner to platform_migrator`,
        /permission denied|must be member|must be owner|must own|not owner/i,
      );

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

async function forwardTransfer(primary) {
  const { adminPool, appPool } = primary;
  const databaseName = primary.databaseName;

  await adminPool.query(`alter role platform_migrator createdb`);
  await adminPool.query(
    `grant platform_migrator to platform_app with inherit false, set true`,
  );
  await assertSoleTemporaryMembership(
    adminPool,
    "platform_app",
    "platform_migrator",
  );

  const assumedClient = await appPool.connect();
  try {
    await assumedClient.query(`set role platform_migrator`);
    const assumed = await assumedClient.query(
      `select current_user as cu, session_user as su`,
    );
    assert.equal(assumed.rows[0].cu, "platform_migrator");
    assert.equal(assumed.rows[0].su, "platform_app");
    await assumedClient.query(`reset role`);
  } finally {
    assumedClient.release();
  }

  await adminPool.query(`grant create on schema public to platform_migrator`);
  await adminPool.query(`grant create on schema appdata to platform_migrator`);
  await adminPool.query(`grant create on schema drizzle to platform_migrator`);

  for (const tableName of [...new Set(["users", ...contractTableNames()])]) {
    await appPool.query(
      `alter table public.${identifier(tableName)} owner to platform_migrator`,
    );
  }
  await appPool.query(`alter table appdata.widgets owner to platform_migrator`);
  await appPool.query(
    `alter sequence appdata.counter_seq owner to platform_migrator`,
  );
  await appPool.query(
    `alter type appdata.widget_status owner to platform_migrator`,
  );
  await appPool.query(
    `alter function appdata.widget_summary() owner to platform_migrator`,
  );
  await appPool.query(
    `alter table drizzle.__drizzle_migrations owner to platform_migrator`,
  );

  await appPool.query(`alter schema public owner to platform_migrator`);
  await appPool.query(`alter schema appdata owner to platform_migrator`);
  await appPool.query(`alter schema drizzle owner to platform_migrator`);

  await appPool.query(
    `alter database ${identifier(databaseName)} owner to platform_migrator`,
  );

  await adminPool.query(
    `revoke create on schema public from platform_migrator`,
  );
  await adminPool.query(
    `revoke create on schema appdata from platform_migrator`,
  );
  await adminPool.query(
    `revoke create on schema drizzle from platform_migrator`,
  );
  await adminPool.query(`revoke platform_migrator from platform_app`);
  await adminPool.query(`alter role platform_migrator nocreatedb`);
}

async function reverseTransfer(primary) {
  const { adminPool, migratorPool } = primary;
  const databaseName = primary.databaseName;

  await adminPool.query(`alter role platform_migrator createdb`);
  await adminPool.query(
    `grant platform_app to platform_migrator with inherit false, set true`,
  );
  await assertSoleTemporaryMembership(
    adminPool,
    "platform_migrator",
    "platform_app",
  );

  await adminPool.query(`grant create on schema public to platform_app`);
  await adminPool.query(`grant create on schema appdata to platform_app`);
  await adminPool.query(`grant create on schema drizzle to platform_app`);

  for (const tableName of [...new Set(["users", ...contractTableNames()])]) {
    await migratorPool.query(
      `alter table public.${identifier(tableName)} owner to platform_app`,
    );
  }
  await migratorPool.query(
    `alter table appdata.widgets owner to platform_app`,
  );
  await migratorPool.query(
    `alter sequence appdata.counter_seq owner to platform_app`,
  );
  await migratorPool.query(
    `alter type appdata.widget_status owner to platform_app`,
  );
  await migratorPool.query(
    `alter function appdata.widget_summary() owner to platform_app`,
  );
  await migratorPool.query(
    `alter table drizzle.__drizzle_migrations owner to platform_app`,
  );

  await migratorPool.query(`alter schema public owner to platform_app`);
  await migratorPool.query(`alter schema appdata owner to platform_app`);
  await migratorPool.query(`alter schema drizzle owner to platform_app`);

  await migratorPool.query(
    `alter database ${identifier(databaseName)} owner to platform_app`,
  );

  await adminPool.query(
    `grant connect on database ${identifier(databaseName)} to platform_migrator`,
  );
  await adminPool.query(`revoke platform_app from platform_migrator`);
  await adminPool.query(`alter role platform_migrator nocreatedb`);
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

  const memberships = await adminPool.query(
    `
      select member_role.rolname as member_role,
             roleid_role.rolname as roleid_role,
             membership.admin_option,
             membership.inherit_option,
             membership.set_option
        from pg_auth_members membership
        join pg_roles member_role on member_role.oid = membership.member
        join pg_roles roleid_role on roleid_role.oid = membership.roleid
       where member_role.rolname = any($1::text[])
          or roleid_role.rolname = any($1::text[])
       order by member_role, roleid_role
    `,
    [fixtureRoleNames],
  );

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
    memberships: memberships.rows,
    objectOwners: ownership.rows[0].object_owners ?? [],
    routineOwners: ownership.rows[0].routine_owners ?? [],
    schemaAcls: [...new Set(aclSurfaces.schema)].sort(),
    schemaOwners: ownership.rows[0].schema_owners ?? [],
  };
}

function assertBaselineFingerprint(fingerprint, { providerManagedPublic = false } = {}) {
  assert.equal(fingerprint.databaseOwner, "platform_app");
  assert.deepEqual(fingerprint.schemaOwners, [
    "appdata=platform_app",
    "drizzle=platform_app",
    `public=${providerManagedPublic ? "provider_owner" : "platform_app"}`,
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
  const app = attributes.get("platform_app");
  assert.equal(app.rolcanlogin, true);
  assert.equal(app.rolcreatedb, true);
  assert.equal(app.rolsuper, false);
  const migrator = attributes.get("platform_migrator");
  assert.equal(migrator.rolcanlogin, true);
  assert.equal(migrator.rolcreatedb, false);
  assert.equal(migrator.rolsuper, false);
  const runtime = attributes.get("platform_runtime");
  assert.equal(runtime.rolcanlogin, false);
  assert.equal(runtime.rolsuper, false);
  assert.equal(runtime.rolcreatedb, false);
  if (providerManagedPublic) {
    const provider = attributes.get("provider_owner");
    assert.equal(provider.rolcanlogin, false);
    assert.equal(provider.rolsuper, false);
  }

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

async function assertMigratorFinalState(adminPool) {
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
  await assertZeroFixtureMemberships(adminPool);
}

async function assertAppLegacyStateUnchanged(adminPool) {
  const result = await adminPool.query(
    `
      select rolcanlogin, rolcreatedb, rolsuper, rolcreaterole,
             rolreplication, rolbypassrls
        from pg_roles
       where rolname = 'platform_app'
    `,
  );
  assert.equal(result.rows.length, 1);
  const row = result.rows[0];
  assert.equal(row.rolcanlogin, true);
  assert.equal(row.rolcreatedb, true);
  assert.equal(row.rolsuper, false);
  assert.equal(row.rolcreaterole, false);
  assert.equal(row.rolreplication, false);
  assert.equal(row.rolbypassrls, false);
}

async function assertZeroFixtureMemberships(adminPool) {
  const result = await adminPool.query(
    `
      select count(*)::int as c
        from pg_auth_members membership
        join pg_roles member_role on member_role.oid = membership.member
        join pg_roles roleid_role on roleid_role.oid = membership.roleid
       where member_role.rolname = any($1::text[])
          or roleid_role.rolname = any($1::text[])
    `,
    [fixtureRoleNames],
  );
  assert.equal(result.rows[0].c, 0);
}

async function assertSoleTemporaryMembership(adminPool, memberRole, roleidRole) {
  const result = await adminPool.query(
    `
      select member_role.rolname as member_role,
             roleid_role.rolname as roleid_role,
             membership.admin_option,
             membership.inherit_option,
             membership.set_option
        from pg_auth_members membership
        join pg_roles member_role on member_role.oid = membership.member
        join pg_roles roleid_role on roleid_role.oid = membership.roleid
       where member_role.rolname = any($1::text[])
          or roleid_role.rolname = any($1::text[])
    `,
    [fixtureRoleNames],
  );
  assert.equal(result.rows.length, 1);
  const edge = result.rows[0];
  assert.equal(edge.member_role, memberRole);
  assert.equal(edge.roleid_role, roleidRole);
  assert.equal(edge.admin_option, false);
  assert.equal(edge.inherit_option, false);
  assert.equal(edge.set_option, true);
}

async function assertRuntimePosture(adminPool) {
  const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
    adminPool,
    "platform_runtime",
  );
  assert.equal(report.runtimeRoleAuthorityPosture, "passed");
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
