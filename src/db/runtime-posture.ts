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
with current_role_state as (
  select oid, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
  from pg_roles
  where rolname = current_user
),
drizzle_state as (
  select
    schema_record.oid as schema_oid,
    migration_record.oid as migration_ledger_oid
  from pg_namespace schema_record
  left join pg_class migration_record
    on migration_record.relnamespace = schema_record.oid
    and migration_record.relname = '__drizzle_migrations'
    and migration_record.relkind in ('r', 'p')
  where schema_record.nspname = 'drizzle'
)
select
  current_user = $1 and session_user = $1 as expected_role_match,
  not pg_has_role(current_user, 'neon_superuser', 'MEMBER')
    as neon_superuser_membership_absent,
  not coalesce((select rolsuper from current_role_state), true) as superuser_absent,
  not coalesce((select rolcreatedb from current_role_state), true) as createdb_absent,
  not coalesce((select rolcreaterole from current_role_state), true) as createrole_absent,
  not coalesce((select rolreplication from current_role_state), true) as replication_absent,
  not coalesce((select rolbypassrls from current_role_state), true) as bypassrls_absent,
  not has_database_privilege(current_user, current_database(), 'CREATE')
    as database_create_absent,
  not has_schema_privilege(current_user, 'public', 'CREATE')
    as public_schema_create_absent,
  case when (select schema_oid from drizzle_state) is null then true
    else not has_schema_privilege(
      current_user,
      (select schema_oid from drizzle_state),
      'USAGE'
    )
  end as drizzle_schema_usage_absent,
  case when (select migration_ledger_oid from drizzle_state) is null then true
    else not has_table_privilege(
      current_user,
      (select migration_ledger_oid from drizzle_state),
      'SELECT'
    )
  end as migration_ledger_select_absent,
  not exists (
    select 1 from pg_database database_record
    where database_record.datname = current_database()
      and pg_has_role(current_user, database_record.datdba, 'MEMBER')
  ) as database_ownership_absent,
  not exists (
    select 1 from pg_namespace schema_record
    where schema_record.nspname = any(array['public', 'drizzle']::name[])
      and pg_has_role(current_user, schema_record.nspowner, 'MEMBER')
  ) as schema_ownership_absent,
  not exists (
    select 1
    from pg_class table_record
    join pg_namespace table_schema on table_schema.oid = table_record.relnamespace
    where table_schema.nspname = 'public'
      and table_record.relkind in ('r', 'p')
      and table_record.relname = any($2::name[])
      and pg_has_role(current_user, table_record.relowner, 'MEMBER')
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
    row = result.rows[0] ?? {};
  } catch {
    throw new RuntimeDatabasePostureError();
  }

  const expectedRoleMatch = boolean(row, "expected_role_match");
  const administrativeAttributesAbsent = all(row, [
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
