import { REQUIRED_PLATFORM_TABLES } from "./readiness.js";

export type RuntimeDatabasePostureCheckState = "passed" | "failed";

export interface RuntimeDatabasePostureReport {
  expectedRoleMatch: RuntimeDatabasePostureCheckState;
  administrativeAttributesAbsent: RuntimeDatabasePostureCheckState;
  databaseAndSchemaCreateAbsent: RuntimeDatabasePostureCheckState;
  migrationLedgerAccessDenied: RuntimeDatabasePostureCheckState;
  databaseAndSchemaOwnershipAbsent: RuntimeDatabasePostureCheckState;
  applicationTableOwnershipAbsent: RuntimeDatabasePostureCheckState;
  runtimePosture: RuntimeDatabasePostureCheckState;
}

export interface RuntimeDatabasePostureClient {
  query(
    text: string,
    values: readonly unknown[],
  ): Promise<{ rows: Array<Record<string, unknown>> }>;
}

export interface RuntimeDatabasePostureEnvironment {
  NODE_ENV?: string;
  DATABASE_EXPECTED_RUNTIME_ROLE?: string;
}

export class RuntimeDatabasePostureError extends Error {
  readonly code = "database_posture_failed";
  readonly publicMessage = "Runtime database posture validation failed.";

  constructor() {
    super("Runtime database posture validation failed.");
    this.name = "RuntimeDatabasePostureError";
  }
}

const safePostgresRoleIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/;

const runtimeDatabasePostureSql = `
with recursive login_role_state as (
  select oid
  from pg_roles
  where rolname = session_user
),
set_assumable_roles(role_oid) as (
  select login_role.oid
  from login_role_state login_role

  union

  select membership.roleid
  from set_assumable_roles assumable_role
  join pg_auth_members membership on membership.member = assumable_role.role_oid
  where membership.set_option
),
current_database_state as (
  select oid, datdba
  from pg_database
  where datname = current_database()
),
public_schema_state as (
  select oid, nspowner
  from pg_namespace
  where nspname = 'public'
),
drizzle_state as (
  select
    schema_record.oid as schema_oid,
    migration_record.oid as migration_ledger_oid,
    migration_record.relkind as migration_ledger_relkind
  from pg_namespace schema_record
  left join pg_class migration_record
    on migration_record.relnamespace = schema_record.oid
    and migration_record.relname = '__drizzle_migrations'
  where schema_record.nspname = 'drizzle'
)
select
  current_user = $1 and session_user = $1 as expected_role_match,
  (select count(*) = 1 from login_role_state)
    and not exists (
      select 1
      from set_assumable_roles assumable_role
      left join pg_roles role_record on role_record.oid = assumable_role.role_oid
      where role_record.oid is null
    ) as role_assumption_state_conclusive,
  not exists (
    select 1
    from set_assumable_roles assumable_role
    join pg_roles prohibited_role on prohibited_role.rolname = 'neon_superuser'
    where pg_has_role(assumable_role.role_oid, prohibited_role.oid, 'MEMBER')
  ) as neon_superuser_membership_absent,
  not exists (
    select 1 from set_assumable_roles assumable_role
    join pg_roles role_record on role_record.oid = assumable_role.role_oid
    where role_record.rolsuper
  ) as superuser_absent,
  not exists (
    select 1 from set_assumable_roles assumable_role
    join pg_roles role_record on role_record.oid = assumable_role.role_oid
    where role_record.rolcreatedb
  ) as createdb_absent,
  not exists (
    select 1 from set_assumable_roles assumable_role
    join pg_roles role_record on role_record.oid = assumable_role.role_oid
    where role_record.rolcreaterole
  ) as createrole_absent,
  not exists (
    select 1 from set_assumable_roles assumable_role
    join pg_roles role_record on role_record.oid = assumable_role.role_oid
    where role_record.rolreplication
  ) as replication_absent,
  not exists (
    select 1 from set_assumable_roles assumable_role
    join pg_roles role_record on role_record.oid = assumable_role.role_oid
    where role_record.rolbypassrls
  ) as bypassrls_absent,
  not exists (
    select 1
    from set_assumable_roles assumable_role
    cross join current_database_state database_record
    where has_database_privilege(
      assumable_role.role_oid,
      database_record.oid,
      'CREATE'
    )
  ) as database_create_absent,
  case when (select oid from public_schema_state) is null then false
    else not exists (
      select 1
      from set_assumable_roles assumable_role
      where has_schema_privilege(
        assumable_role.role_oid,
        (select oid from public_schema_state),
        'CREATE'
      )
    )
  end as public_schema_create_absent,
  case when (select schema_oid from drizzle_state) is null then true
    else not exists (
      select 1
      from set_assumable_roles assumable_role
      where has_schema_privilege(
        assumable_role.role_oid,
        (select schema_oid from drizzle_state),
        'USAGE'
      )
    )
  end as drizzle_schema_usage_absent,
  case
    when (select migration_ledger_oid from drizzle_state) is null then true
    when (select migration_ledger_relkind from drizzle_state)
      in ('r', 'p', 'v', 'm', 'f') then not exists (
      select 1
      from set_assumable_roles assumable_role
      where has_table_privilege(
        assumable_role.role_oid,
        (select migration_ledger_oid from drizzle_state),
        'SELECT'
      )
    )
    else false
  end as migration_ledger_select_absent,
  not exists (
    select 1
    from current_database_state database_record
    cross join set_assumable_roles assumable_role
    where pg_has_role(assumable_role.role_oid, database_record.datdba, 'USAGE')
  ) as database_ownership_absent,
  not exists (
    select 1
    from pg_namespace schema_record
    cross join set_assumable_roles assumable_role
    where schema_record.nspname = any(array['public', 'drizzle']::name[])
      and pg_has_role(assumable_role.role_oid, schema_record.nspowner, 'USAGE')
  ) as schema_ownership_absent,
  not exists (
    select 1
    from pg_class table_record
    join pg_namespace table_schema on table_schema.oid = table_record.relnamespace
    cross join set_assumable_roles assumable_role
    where table_schema.nspname = 'public'
      and table_record.relkind in ('r', 'p')
      and table_record.relname = any($2::name[])
      and pg_has_role(assumable_role.role_oid, table_record.relowner, 'USAGE')
  ) as application_table_ownership_absent
`;

export function readExpectedRuntimeRole(
  env: RuntimeDatabasePostureEnvironment,
): string | null {
  const expectedRole = env.DATABASE_EXPECTED_RUNTIME_ROLE?.trim();

  if (!expectedRole) {
    if (env.NODE_ENV?.trim() === "production") {
      throw new RuntimeDatabasePostureError();
    }
    return null;
  }
  if (!safePostgresRoleIdentifier.test(expectedRole)) {
    throw new RuntimeDatabasePostureError();
  }
  return expectedRole;
}

export async function inspectRuntimeDatabasePosture(
  client: RuntimeDatabasePostureClient,
  expectedRole: string,
): Promise<RuntimeDatabasePostureReport> {
  let row: Record<string, unknown>;
  try {
    const result = await client.query(runtimeDatabasePostureSql, [
      expectedRole,
      [...REQUIRED_PLATFORM_TABLES],
    ]);
    if (result.rows.length !== 1) {
      throw new RuntimeDatabasePostureError();
    }
    row = result.rows[0];
  } catch {
    throw new RuntimeDatabasePostureError();
  }

  const expectedRoleMatch = boolean(row, "expected_role_match");
  const administrativeAttributesAbsent = all(row, [
    "role_assumption_state_conclusive",
    "neon_superuser_membership_absent",
    "superuser_absent",
    "createdb_absent",
    "createrole_absent",
    "replication_absent",
    "bypassrls_absent",
  ]);
  const databaseAndSchemaCreateAbsent = all(row, [
    "database_create_absent",
    "public_schema_create_absent",
    "drizzle_schema_usage_absent",
  ]);
  const migrationLedgerAccessDenied = boolean(
    row,
    "migration_ledger_select_absent",
  );
  const databaseAndSchemaOwnershipAbsent = all(row, [
    "database_ownership_absent",
    "schema_ownership_absent",
  ]);
  const applicationTableOwnershipAbsent = boolean(
    row,
    "application_table_ownership_absent",
  );
  const passed = [
    expectedRoleMatch,
    administrativeAttributesAbsent,
    databaseAndSchemaCreateAbsent,
    migrationLedgerAccessDenied,
    databaseAndSchemaOwnershipAbsent,
    applicationTableOwnershipAbsent,
  ].every(Boolean);

  return {
    expectedRoleMatch: state(expectedRoleMatch),
    administrativeAttributesAbsent: state(administrativeAttributesAbsent),
    databaseAndSchemaCreateAbsent: state(databaseAndSchemaCreateAbsent),
    migrationLedgerAccessDenied: state(migrationLedgerAccessDenied),
    databaseAndSchemaOwnershipAbsent: state(databaseAndSchemaOwnershipAbsent),
    applicationTableOwnershipAbsent: state(applicationTableOwnershipAbsent),
    runtimePosture: state(passed),
  };
}

export async function assertRuntimeDatabasePosture(
  client: RuntimeDatabasePostureClient,
  expectedRole: string,
): Promise<RuntimeDatabasePostureReport> {
  const report = await inspectRuntimeDatabasePosture(client, expectedRole);
  if (report.runtimePosture !== "passed") {
    throw new RuntimeDatabasePostureError();
  }
  return report;
}

function all(row: Record<string, unknown>, fields: readonly string[]): boolean {
  return fields.map((field) => boolean(row, field)).every(Boolean);
}

function boolean(row: Record<string, unknown>, field: string): boolean {
  const value = row[field];
  if (typeof value !== "boolean") {
    throw new RuntimeDatabasePostureError();
  }
  return value;
}

function state(value: boolean): RuntimeDatabasePostureCheckState {
  return value ? "passed" : "failed";
}
