import { RUNTIME_TABLE_GRANT_CONTRACT } from "./runtime-grant-contract.js";

export type RuntimeDatabasePostureCheckState = "passed" | "failed";

export interface RuntimeDatabasePostureReport {
  expectedRoleMatch: RuntimeDatabasePostureCheckState;
  administrativeAttributesAbsent: RuntimeDatabasePostureCheckState;
  databaseAndSchemaCreateAbsent: RuntimeDatabasePostureCheckState;
  migrationLedgerAccessDenied: RuntimeDatabasePostureCheckState;
  databaseAndSchemaOwnershipAbsent: RuntimeDatabasePostureCheckState;
  applicationTableOwnershipAbsent: RuntimeDatabasePostureCheckState;
  runtimeTableGrantsExact: RuntimeDatabasePostureCheckState;
  runtimeColumnAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeDefaultRelationAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeRoutineAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeSequenceAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimePosture: RuntimeDatabasePostureCheckState;
}

export interface RuntimeDatabaseRoleAuthorityPostureReport {
  roleIdentityConclusive: RuntimeDatabasePostureCheckState;
  administrativeAttributesAbsent: RuntimeDatabasePostureCheckState;
  databaseAndSchemaCreateAbsent: RuntimeDatabasePostureCheckState;
  migrationLedgerAccessDenied: RuntimeDatabasePostureCheckState;
  databaseAndSchemaOwnershipAbsent: RuntimeDatabasePostureCheckState;
  applicationTableOwnershipAbsent: RuntimeDatabasePostureCheckState;
  runtimeTableGrantsExact: RuntimeDatabasePostureCheckState;
  runtimeColumnAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeDefaultRelationAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeRoutineAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeSequenceAuthorityAbsent: RuntimeDatabasePostureCheckState;
  runtimeRoleAuthorityPosture: RuntimeDatabasePostureCheckState;
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
const runtimeTableGrantExpectationJson = JSON.stringify(
  RUNTIME_TABLE_GRANT_CONTRACT.map((record) => ({
    object_class: record.objectClass,
    schema_name: record.schema,
    table_name: record.objectName,
    privilege_type: record.privilege,
    authority_source: record.authoritySource,
    grant_option: record.grantOption,
  })),
);

const runtimeDatabasePostureSql = `
with recursive login_role_state as (
  select oid
  from pg_roles
  where rolname = $1
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
inherited_roles(role_oid) as (
  select login_role.oid
  from login_role_state login_role

  union

  select membership.roleid
  from inherited_roles inherited_role
  join pg_roles member_role
    on member_role.oid = inherited_role.role_oid
  join pg_auth_members membership
    on membership.member = inherited_role.role_oid
  where member_role.rolinherit
    and membership.inherit_option
),
effective_runtime_roles(role_oid) as (
  select login_role.oid
  from login_role_state login_role

  union

  select membership.roleid
  from effective_runtime_roles effective_member
  join pg_roles member_role
    on member_role.oid = effective_member.role_oid
  join pg_auth_members membership
    on membership.member = effective_member.role_oid
  where membership.set_option
    or (member_role.rolinherit and membership.inherit_option)
),
non_system_schemas as (
  select
    schema_record.oid,
    schema_record.nspname,
    schema_record.nspowner
  from pg_namespace schema_record
  where schema_record.nspname <> 'information_schema'
    and schema_record.nspname !~ '^pg_'
),
expected_runtime_table_grants as (
  select
    expected.object_class,
    expected.schema_name,
    expected.table_name,
    expected.privilege_type,
    expected.authority_source,
    expected.grant_option
  from jsonb_to_recordset($2::jsonb) as expected(
    object_class text,
    schema_name text,
    table_name text,
    privilege_type text,
    authority_source text,
    grant_option boolean
  )
),
application_acl_schemas as (
  select schema_record.oid
  from pg_namespace schema_record
  cross join login_role_state runtime_role
  where schema_record.nspname in ('public', 'drizzle')
    or (
      schema_record.nspname not in ('pg_catalog', 'information_schema')
      and schema_record.nspname !~ '^pg_(?:toast|temp)(?:_|$)'
      and has_schema_privilege(
        runtime_role.oid,
        schema_record.oid,
        'USAGE'
      )
    )
),
direct_runtime_table_grants as (
  select
    case table_record.relkind
      when 'r' then 'table'
      when 'p' then 'table'
      when 'v' then 'view'
      when 'm' then 'materialized_view'
      when 'f' then 'foreign_table'
      else 'unsupported_relation'
    end::text as object_class,
    table_schema.nspname::text as schema_name,
    table_record.relname::text as table_name,
    upper(grant_record.privilege_type)::text as privilege_type,
    'direct'::text as authority_source,
    grant_record.is_grantable as grant_option
  from login_role_state runtime_role
  join pg_class table_record
    on table_record.relkind in ('r', 'p', 'v', 'm', 'f')
  join pg_namespace table_schema
    on table_schema.oid = table_record.relnamespace
  cross join lateral aclexplode(table_record.relacl) grant_record
  where grant_record.grantee = runtime_role.oid
),
runtime_column_grants as (
  select
    column_schema.oid as schema_oid,
    column_schema.nspname::text as schema_name,
    column_relation.relname::text as relation_name,
    column_record.attname::text as column_name,
    upper(grant_record.privilege_type)::text as privilege_type,
    grant_record.is_grantable
  from login_role_state runtime_role
  join pg_attribute column_record
    on column_record.attnum > 0
    and not column_record.attisdropped
  join pg_class column_relation
    on column_relation.oid = column_record.attrelid
    and column_relation.relkind in ('r', 'p', 'v', 'm', 'f')
  join pg_namespace column_schema
    on column_schema.oid = column_relation.relnamespace
  cross join lateral aclexplode(column_record.attacl) grant_record
  where grant_record.grantee = runtime_role.oid
),
public_column_grants as (
  select
    column_schema.oid as schema_oid,
    column_schema.nspname::text as schema_name,
    column_relation.relname::text as relation_name,
    column_record.attname::text as column_name,
    upper(grant_record.privilege_type)::text as privilege_type,
    grant_record.is_grantable
  from pg_attribute column_record
  join pg_class column_relation
    on column_relation.oid = column_record.attrelid
    and column_relation.relkind in ('r', 'p', 'v', 'm', 'f')
  join pg_namespace column_schema
    on column_schema.oid = column_relation.relnamespace
  join application_acl_schemas application_schema
    on application_schema.oid = column_schema.oid
  cross join lateral aclexplode(column_record.attacl) grant_record
  where column_record.attnum > 0
    and not column_record.attisdropped
    and grant_record.grantee = 0
),
default_acl_object_types(object_type) as (
  values ('r'::"char"), ('S'::"char"), ('f'::"char")
),
default_acl_creators(role_oid) as (
  select role_record.oid
  from pg_roles role_record
  cross join non_system_schemas schema_record
  where has_schema_privilege(
    role_record.oid,
    schema_record.oid,
    'CREATE'
  )

  union

  select nspowner from non_system_schemas

  union

  select relation_record.relowner
  from pg_class relation_record
  join non_system_schemas schema_record
    on schema_record.oid = relation_record.relnamespace
  where relation_record.relkind in ('r', 'p', 'v', 'm', 'f', 'S')

  union

  select routine_record.proowner
  from pg_proc routine_record
  join non_system_schemas schema_record
    on schema_record.oid = routine_record.pronamespace

  union

  select default_acl.defaclrole
  from pg_default_acl default_acl
  where default_acl.defaclobjtype in ('r', 'S', 'f')
),
default_acl_context as (
  select
    default_creator.role_oid as creator_oid,
    schema_record.oid as schema_oid,
    schema_record.nspname::text as schema_name,
    object_type.object_type,
    coalesce(
      global_default.defaclacl,
      acldefault(object_type.object_type, default_creator.role_oid)
    ) || coalesce(
      schema_default.defaclacl,
      '{}'::aclitem[]
    ) as effective_acl
  from default_acl_creators default_creator
  cross join non_system_schemas schema_record
  cross join default_acl_object_types object_type
  left join pg_default_acl global_default
    on global_default.defaclrole = default_creator.role_oid
    and global_default.defaclnamespace = 0
    and global_default.defaclobjtype in ('r', 'S', 'f')
    and global_default.defaclobjtype = object_type.object_type
  left join pg_default_acl schema_default
    on schema_default.defaclrole = default_creator.role_oid
    and schema_default.defaclnamespace = schema_record.oid
    and schema_default.defaclobjtype in ('r', 'S', 'f')
    and schema_default.defaclobjtype = object_type.object_type
),
default_acl_grants as (
  select
    default_context.creator_oid,
    default_context.schema_oid,
    default_context.schema_name,
    default_context.object_type,
    grant_record.grantee as grantee_oid,
    case
      when grant_record.grantee = 0 then 'PUBLIC'
      else grantee_role.rolname::text
    end as grantee_name,
    upper(grant_record.privilege_type)::text as privilege_type,
    grant_record.is_grantable
  from default_acl_context default_context
  cross join lateral aclexplode(default_context.effective_acl) grant_record
  left join pg_roles grantee_role
    on grantee_role.oid = grant_record.grantee
),
prohibited_default_acl_grants as (
  select default_grant.*
  from default_acl_grants default_grant
  where default_grant.grantee_oid = 0
    or exists (
      select 1
      from effective_runtime_roles effective_role
      where effective_role.role_oid = default_grant.grantee_oid
    )
),
runtime_routine_grants as (
  select
    routine_schema.oid as schema_oid,
    routine_record.oid as routine_oid,
    grant_record.is_grantable
  from login_role_state runtime_role
  join pg_proc routine_record on true
  join pg_namespace routine_schema
    on routine_schema.oid = routine_record.pronamespace
  cross join lateral aclexplode(routine_record.proacl) grant_record
  where grant_record.grantee = runtime_role.oid
),
public_routine_grants as (
  select
    routine_schema.oid as schema_oid,
    routine_record.oid as routine_oid,
    grant_record.is_grantable
  from pg_proc routine_record
  join pg_namespace routine_schema
    on routine_schema.oid = routine_record.pronamespace
  join application_acl_schemas application_schema
    on application_schema.oid = routine_schema.oid
  cross join lateral aclexplode(routine_record.proacl) grant_record
  where grant_record.grantee = 0
),
runtime_sequence_grants as (
  select
    sequence_schema.oid as schema_oid,
    sequence_record.oid as sequence_oid,
    grant_record.is_grantable
  from login_role_state runtime_role
  join pg_class sequence_record
    on sequence_record.relkind = 'S'
  join pg_namespace sequence_schema
    on sequence_schema.oid = sequence_record.relnamespace
  cross join lateral aclexplode(sequence_record.relacl) grant_record
  where grant_record.grantee = runtime_role.oid
),
public_sequence_grants as (
  select
    sequence_schema.oid as schema_oid,
    sequence_record.oid as sequence_oid,
    grant_record.is_grantable
  from pg_class sequence_record
  join pg_namespace sequence_schema
    on sequence_schema.oid = sequence_record.relnamespace
  join application_acl_schemas application_schema
    on application_schema.oid = sequence_schema.oid
  cross join lateral aclexplode(sequence_record.relacl) grant_record
  where sequence_record.relkind = 'S'
    and grant_record.grantee = 0
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
    from login_role_state runtime_role
    join pg_auth_members membership
      on membership.member = runtime_role.oid
      or membership.roleid = runtime_role.oid
  ) as role_membership_absent,
  not exists (
    select 1
    from set_assumable_roles assumable_role
    join pg_auth_members membership
      on membership.member = assumable_role.role_oid
    where membership.admin_option
  ) as role_membership_admin_absent,
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
    from effective_runtime_roles effective_role
    where has_database_privilege(
      effective_role.role_oid,
      (select oid from current_database_state),
      'CREATE'
    )
  ) as database_create_absent,
  not exists (
    select 1
    from effective_runtime_roles effective_role
    cross join non_system_schemas schema_record
    where has_schema_privilege(
      effective_role.role_oid,
      schema_record.oid,
      'CREATE'
    )
    or pg_has_role(
      effective_role.role_oid,
      schema_record.nspowner,
      'USAGE'
    )
  ) as all_non_system_schema_create_absent,
  case when (select oid from public_schema_state) is null then false
    else not exists (
      select 1
      from effective_runtime_roles effective_role
      where has_schema_privilege(
        effective_role.role_oid,
        (select oid from public_schema_state),
        'CREATE'
      )
    )
  end as public_schema_create_absent,
  case when (select schema_oid from drizzle_state) is null then true
    else not exists (
      select 1
      from effective_runtime_roles effective_role
      where has_schema_privilege(
        effective_role.role_oid,
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
      from effective_runtime_roles effective_role
      where has_table_privilege(
        effective_role.role_oid,
        (select migration_ledger_oid from drizzle_state),
        'SELECT'
      )
    )
    else false
  end as migration_ledger_select_absent,
  not exists (
    select 1
    from current_database_state database_record
    cross join effective_runtime_roles effective_role
    where pg_has_role(effective_role.role_oid, database_record.datdba, 'USAGE')
  ) as database_ownership_absent,
  not exists (
    select 1
    from non_system_schemas schema_record
    cross join effective_runtime_roles effective_role
    where pg_has_role(
      effective_role.role_oid,
      schema_record.nspowner,
      'USAGE'
    )
  ) as schema_ownership_absent,
  not exists (
    select 1
    from pg_class table_record
    join non_system_schemas table_schema
      on table_schema.oid = table_record.relnamespace
    cross join effective_runtime_roles effective_role
    where table_record.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
      and pg_has_role(effective_role.role_oid, table_record.relowner, 'USAGE')
  ) as application_table_ownership_absent
  ,
  not exists (
    select 1
    from direct_runtime_table_grants
    where grant_option
  ) as runtime_table_grant_option_absent,
  (
    (select count(*) from expected_runtime_table_grants)
      = (select count(*) from direct_runtime_table_grants)
    and
    (select count(*) from direct_runtime_table_grants)
      = (
        select count(distinct (
          object_class,
          schema_name,
          table_name,
          privilege_type,
          authority_source,
          grant_option
        ))
        from direct_runtime_table_grants
      )
    and not exists (
    (
      select
        object_class,
        schema_name,
        table_name,
        privilege_type,
        authority_source,
        grant_option
      from expected_runtime_table_grants
      except
      select
        object_class,
        schema_name,
        table_name,
        privilege_type,
        authority_source,
        grant_option
      from direct_runtime_table_grants
    )
    union
    (
      select
        object_class,
        schema_name,
        table_name,
        privilege_type,
        authority_source,
        grant_option
      from direct_runtime_table_grants
      except
      select
        object_class,
        schema_name,
        table_name,
        privilege_type,
        authority_source,
        grant_option
      from expected_runtime_table_grants
    )
    )
  ) as runtime_table_grant_set_exact,
  not exists (
    select 1
    from pg_class table_record
    join pg_namespace table_schema
      on table_schema.oid = table_record.relnamespace
    join application_acl_schemas application_schema
      on application_schema.oid = table_schema.oid
    cross join lateral aclexplode(table_record.relacl) grant_record
    where table_record.relkind in ('r', 'p', 'v', 'm', 'f')
      and grant_record.grantee = 0
  ) as public_table_authority_absent,
  not exists (
    select 1 from runtime_column_grants
  ) as runtime_column_authority_absent,
  not exists (
    select 1 from runtime_column_grants
    where is_grantable
  ) as runtime_column_grant_option_absent,
  not exists (
    select 1 from public_column_grants
  ) as public_column_authority_absent,
  not exists (
    select 1
    from prohibited_default_acl_grants default_grant
    where default_grant.object_type = 'r'
  ) as runtime_default_relation_authority_absent,
  not exists (
    select 1
    from default_acl_grants default_grant
    where default_grant.object_type = 'r'
      and default_grant.is_grantable
  ) as runtime_default_relation_grant_option_absent,
  not exists (
    select 1
    from default_acl_grants
    where object_type = 'r'
      and grantee_oid = 0
  ) as public_default_relation_authority_absent,
  not exists (
    select 1
    from prohibited_default_acl_grants
    where object_type = 'S'
  ) as runtime_default_sequence_authority_absent,
  not exists (
    select 1
    from default_acl_grants
    where object_type = 'S'
      and grantee_oid = 0
  ) as public_default_sequence_authority_absent,
  not exists (
    select 1
    from prohibited_default_acl_grants
    where object_type = 'f'
  ) as runtime_default_routine_authority_absent,
  not exists (
    select 1
    from default_acl_grants
    where object_type = 'f'
      and grantee_oid = 0
  ) as public_default_routine_authority_absent,
  not exists (
    select 1
    from default_acl_grants
    where is_grantable
  ) as default_acl_grant_option_absent,
  not exists (
    select 1 from runtime_routine_grants
  ) as runtime_routine_authority_absent,
  not exists (
    select 1 from public_routine_grants
  ) as public_routine_authority_absent,
  not exists (
    select 1
    from pg_proc routine_record
    join non_system_schemas routine_schema
      on routine_schema.oid = routine_record.pronamespace
    cross join effective_runtime_roles effective_role
    where pg_has_role(
      effective_role.role_oid,
      routine_record.proowner,
      'USAGE'
    )
  ) as runtime_routine_ownership_absent,
  not exists (
    select 1 from runtime_sequence_grants
  ) as runtime_sequence_authority_absent,
  not exists (
    select 1 from public_sequence_grants
  ) as public_sequence_authority_absent,
  not exists (
    select 1
    from pg_class sequence_record
    join non_system_schemas sequence_schema
      on sequence_schema.oid = sequence_record.relnamespace
    cross join effective_runtime_roles effective_role
    where sequence_record.relkind = 'S'
      and pg_has_role(
        effective_role.role_oid,
        sequence_record.relowner,
        'USAGE'
      )
  ) as runtime_sequence_ownership_absent
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
  const row = await inspectRuntimeDatabasePostureRow(client, expectedRole);
  const expectedRoleMatch = boolean(row, "expected_role_match");
  const checks = postureChecks(row);
  const passed = [
    expectedRoleMatch,
    checks.roleIdentityConclusive,
    checks.administrativeAttributesAbsent,
    checks.databaseAndSchemaCreateAbsent,
    checks.migrationLedgerAccessDenied,
    checks.databaseAndSchemaOwnershipAbsent,
    checks.applicationTableOwnershipAbsent,
    checks.runtimeTableGrantsExact,
    checks.runtimeColumnAuthorityAbsent,
    checks.runtimeDefaultRelationAuthorityAbsent,
    checks.runtimeRoutineAuthorityAbsent,
    checks.runtimeSequenceAuthorityAbsent,
  ].every(Boolean);

  return {
    expectedRoleMatch: state(expectedRoleMatch),
    administrativeAttributesAbsent: state(
      checks.roleIdentityConclusive &&
        checks.administrativeAttributesAbsent,
    ),
    databaseAndSchemaCreateAbsent: state(
      checks.databaseAndSchemaCreateAbsent,
    ),
    migrationLedgerAccessDenied: state(checks.migrationLedgerAccessDenied),
    databaseAndSchemaOwnershipAbsent: state(
      checks.databaseAndSchemaOwnershipAbsent,
    ),
    applicationTableOwnershipAbsent: state(
      checks.applicationTableOwnershipAbsent,
    ),
    runtimeTableGrantsExact: state(checks.runtimeTableGrantsExact),
    runtimeColumnAuthorityAbsent: state(
      checks.runtimeColumnAuthorityAbsent,
    ),
    runtimeDefaultRelationAuthorityAbsent: state(
      checks.runtimeDefaultRelationAuthorityAbsent,
    ),
    runtimeRoutineAuthorityAbsent: state(
      checks.runtimeRoutineAuthorityAbsent,
    ),
    runtimeSequenceAuthorityAbsent: state(
      checks.runtimeSequenceAuthorityAbsent,
    ),
    runtimePosture: state(passed),
  };
}

export async function inspectRuntimeDatabaseRoleAuthorityPosture(
  client: RuntimeDatabasePostureClient,
  expectedRole: string,
): Promise<RuntimeDatabaseRoleAuthorityPostureReport> {
  const row = await inspectRuntimeDatabasePostureRow(client, expectedRole);
  const checks = postureChecks(row);
  const passed = Object.values(checks).every(Boolean);

  return {
    roleIdentityConclusive: state(checks.roleIdentityConclusive),
    administrativeAttributesAbsent: state(
      checks.administrativeAttributesAbsent,
    ),
    databaseAndSchemaCreateAbsent: state(
      checks.databaseAndSchemaCreateAbsent,
    ),
    migrationLedgerAccessDenied: state(checks.migrationLedgerAccessDenied),
    databaseAndSchemaOwnershipAbsent: state(
      checks.databaseAndSchemaOwnershipAbsent,
    ),
    applicationTableOwnershipAbsent: state(
      checks.applicationTableOwnershipAbsent,
    ),
    runtimeTableGrantsExact: state(checks.runtimeTableGrantsExact),
    runtimeColumnAuthorityAbsent: state(
      checks.runtimeColumnAuthorityAbsent,
    ),
    runtimeDefaultRelationAuthorityAbsent: state(
      checks.runtimeDefaultRelationAuthorityAbsent,
    ),
    runtimeRoutineAuthorityAbsent: state(
      checks.runtimeRoutineAuthorityAbsent,
    ),
    runtimeSequenceAuthorityAbsent: state(
      checks.runtimeSequenceAuthorityAbsent,
    ),
    runtimeRoleAuthorityPosture: state(passed),
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

async function inspectRuntimeDatabasePostureRow(
  client: RuntimeDatabasePostureClient,
  expectedRole: string,
): Promise<Record<string, unknown>> {
  if (!safePostgresRoleIdentifier.test(expectedRole)) {
    throw new RuntimeDatabasePostureError();
  }
  try {
    const result = await client.query(runtimeDatabasePostureSql, [
      expectedRole,
      runtimeTableGrantExpectationJson,
    ]);
    if (result.rows.length !== 1) {
      throw new RuntimeDatabasePostureError();
    }
    return result.rows[0];
  } catch {
    throw new RuntimeDatabasePostureError();
  }
}

function postureChecks(row: Record<string, unknown>) {
  return {
    roleIdentityConclusive: boolean(
      row,
      "role_assumption_state_conclusive",
    ),
    administrativeAttributesAbsent: all(row, [
      "role_membership_absent",
      "role_membership_admin_absent",
      "neon_superuser_membership_absent",
      "superuser_absent",
      "createdb_absent",
      "createrole_absent",
      "replication_absent",
      "bypassrls_absent",
    ]),
    databaseAndSchemaCreateAbsent: all(row, [
      "database_create_absent",
      "all_non_system_schema_create_absent",
      "public_schema_create_absent",
      "drizzle_schema_usage_absent",
    ]),
    migrationLedgerAccessDenied: boolean(
      row,
      "migration_ledger_select_absent",
    ),
    databaseAndSchemaOwnershipAbsent: all(row, [
      "database_ownership_absent",
      "schema_ownership_absent",
    ]),
    applicationTableOwnershipAbsent: boolean(
      row,
      "application_table_ownership_absent",
    ),
    runtimeTableGrantsExact: all(row, [
      "runtime_table_grant_option_absent",
      "runtime_table_grant_set_exact",
      "public_table_authority_absent",
    ]),
    runtimeColumnAuthorityAbsent: all(row, [
      "runtime_column_authority_absent",
      "runtime_column_grant_option_absent",
      "public_column_authority_absent",
    ]),
    runtimeDefaultRelationAuthorityAbsent: all(row, [
      "runtime_default_relation_authority_absent",
      "runtime_default_relation_grant_option_absent",
      "public_default_relation_authority_absent",
      "default_acl_grant_option_absent",
    ]),
    runtimeRoutineAuthorityAbsent: all(row, [
      "runtime_routine_authority_absent",
      "public_routine_authority_absent",
      "runtime_routine_ownership_absent",
      "runtime_default_routine_authority_absent",
      "public_default_routine_authority_absent",
      "default_acl_grant_option_absent",
    ]),
    runtimeSequenceAuthorityAbsent: all(row, [
      "runtime_sequence_authority_absent",
      "public_sequence_authority_absent",
      "runtime_sequence_ownership_absent",
      "runtime_default_sequence_authority_absent",
      "public_default_sequence_authority_absent",
      "default_acl_grant_option_absent",
    ]),
  };
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
