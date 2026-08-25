import {
  createDatabasePool,
  DatabaseConfigError,
  readOperatorDatabaseConfig,
  type DatabaseConfig,
  type DatabaseEnvironment,
} from "./client.js";

export const REQUIRED_PLATFORM_TABLES = [
  "users",
  "provider_identities",
  "workspaces",
  "memberships",
  "workspace_membership_approvals",
  "invitations",
  "sessions",
  "csrf_tokens",
  "auth_states",
  "audit_events",
  "apps",
  "app_launch_tokens",
  "app_entitlements",
  "access_validation_grants",
] as const;
const CANONICAL_PLATFORM_TABLES = REQUIRED_PLATFORM_TABLES;

const CANONICAL_PLATFORM_ENUM_TYPES = [
  "app_status",
  "entitlement_status",
  "invitation_status",
  "membership_status",
  "role",
  "user_status",
  "workspace_membership_approval_status",
  "workspace_status",
  "csrf_token_purpose",
] as const;

const CANONICAL_PLATFORM_ROUTINES = [] as const;
export type DatabaseReadinessStatus =
  | "db_config_missing"
  | "db_config_invalid"
  | "db_unreachable"
  | "schema_not_ready"
  | "ready";

export type DatabaseReadinessCheckState =
  | "missing"
  | "invalid"
  | "present"
  | "not_checked"
  | "passed"
  | "failed";

export interface ExpectedMigrationState {
  latestTag: string;
  latestCreatedAt: number;
  migrationCount: number;
}

export interface DatabaseReadinessChecks {
  config: DatabaseReadinessCheckState;
  reachability: DatabaseReadinessCheckState;
  schema: DatabaseReadinessCheckState;
  migrations: DatabaseReadinessCheckState;
  migratorPosture: DatabaseReadinessCheckState;
}

export interface DatabaseReadinessReport {
  ok: boolean;
  status: DatabaseReadinessStatus;
  checks: DatabaseReadinessChecks;
  requiredTables: readonly string[];
  missingTables: string[];
  expectedMigrationState?: ExpectedMigrationState;
}

export interface DatabaseReadinessQueryResult {
  rows: Array<Record<string, unknown>>;
}

export interface DatabaseReadinessClient {
  query(
    text: string,
    values?: readonly unknown[],
  ): Promise<DatabaseReadinessQueryResult>;
  end?(): Promise<void> | void;
}

export interface DatabaseReadinessInput {
  env: DatabaseEnvironment;
  expectedMigrationState?: ExpectedMigrationState;
  requiredTables?: readonly string[];
  clientFactory?: (
    config: DatabaseConfig,
  ) => DatabaseReadinessClient | Promise<DatabaseReadinessClient>;
}

const reachabilitySql = "select 1 as readiness_ok";
const requiredTablesSql = `
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name = any($1::text[])
`;
const migrationStateSql = `
select count(*)::int as applied_count, max(created_at)::bigint as latest_created_at
from drizzle.__drizzle_migrations
`;
const migratorPostureSql = `
with recursive
migrator_role as (
  select oid, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
    rolreplication, rolbypassrls
  from pg_roles
  where rolname = 'platform_migrator'
),
app_role as (
  select oid
  from pg_roles
  where rolname = 'platform_app'
),
runtime_role as (
  select oid
  from pg_roles
  where rolname = 'platform_runtime'
),
database_state as (
  select oid, datdba
  from pg_database
  where datname = current_database()
),
schema_state as (
  select oid, nspname, nspowner, nspacl
  from pg_namespace
  where nspname in ('public', 'drizzle')
),
extension_owned_objects as (
  select classid, objid
  from pg_depend
  where refclassid = 'pg_extension'::regclass
    and deptype = 'e'
),
extension_dependency_objects as (
  select classid, objid
  from extension_owned_objects

  union

  select dependency_record.classid, dependency_record.objid
  from pg_depend dependency_record
  join extension_dependency_objects extension_record
    on dependency_record.refclassid = extension_record.classid
   and dependency_record.refobjid = extension_record.objid
  where dependency_record.deptype in ('a', 'i', 'P', 'S')
    and dependency_record.classid in (
      'pg_class'::regclass,
      'pg_type'::regclass,
      'pg_proc'::regclass,
      'pg_constraint'::regclass
    )
    and dependency_record.refclassid in (
      'pg_class'::regclass,
      'pg_type'::regclass,
      'pg_proc'::regclass,
      'pg_constraint'::regclass
    )
),
extension_dependent_relations as (
  select
    relation_record.oid,
    relation_record.relname,
    relation_record.relkind,
    relation_record.relowner,
    relation_record.relnamespace,
    relation_record.relacl
  from pg_class relation_record
  join pg_namespace relation_schema
    on relation_schema.oid = relation_record.relnamespace
  where relation_schema.nspname in ('public', 'drizzle')
    and relation_record.relkind in ('r', 'p', 'S', 'i', 'I')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
    and exists (
      select 1
      from extension_dependency_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
),
extension_dependent_types as (
  select extension_record.objid as oid
  from extension_dependency_objects extension_record
  where extension_record.classid = 'pg_type'::regclass

  union

  select type_record.oid
  from pg_type type_record
  where type_record.typisdefined
    and type_record.typelem in (
      select extension_record.objid
      from extension_dependency_objects extension_record
      where extension_record.classid = 'pg_type'::regclass
    )
    and exists (
      select 1
      from pg_depend dependency_record
      where dependency_record.classid = 'pg_type'::regclass
        and dependency_record.objid = type_record.oid
        and dependency_record.refclassid = 'pg_type'::regclass
        and dependency_record.refobjid = type_record.typelem
        and dependency_record.deptype in ('a', 'i', 'P', 'S')
    )
),
ledger_state as (
  select
    schema_record.oid as schema_oid,
    migration_record.oid as ledger_oid,
    migration_record.relowner as ledger_owner
  from pg_namespace schema_record
  left join pg_class migration_record
    on migration_record.relnamespace = schema_record.oid
    and migration_record.relname = '__drizzle_migrations'
  where schema_record.nspname = 'drizzle'
),
canonical_table_relations as (
  select
    relation_record.oid,
    relation_record.relname,
    relation_record.relkind,
    relation_record.relowner,
    relation_record.relnamespace,
    relation_record.relacl
  from pg_class relation_record
  join pg_namespace relation_schema
    on relation_schema.oid = relation_record.relnamespace
  where relation_schema.nspname = 'public'
    and relation_record.relname = any($2::text[])
    and relation_record.relkind in ('r', 'p')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
),
canonical_drizzle_relations as (
  select
    relation_record.oid,
    relation_record.relname,
    relation_record.relkind,
    relation_record.relowner,
    relation_record.relnamespace,
    relation_record.relacl
  from pg_class relation_record
  join pg_namespace relation_schema
    on relation_schema.oid = relation_record.relnamespace
  where relation_schema.nspname = 'drizzle'
    and relation_record.relname = '__drizzle_migrations'
    and relation_record.relkind in ('r', 'p')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
),
canonical_base_relations as (
  select
    oid,
    relname,
    relkind,
    relowner,
    relnamespace,
    relacl
  from canonical_table_relations
  union all
  select
    oid,
    relname,
    relkind,
    relowner,
    relnamespace,
    relacl
  from canonical_drizzle_relations
),
canonical_dependent_relations as (
  select
    relation_record.oid,
    relation_record.relname,
    relation_record.relkind,
    relation_record.relowner,
    relation_record.relnamespace,
    relation_record.relacl
  from pg_class relation_record
  join pg_namespace relation_schema
    on relation_schema.oid = relation_record.relnamespace
  where relation_schema.nspname in ('public', 'drizzle')
    and relation_record.relkind in ('S', 'i', 'I')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
    and (
      (
        relation_record.relkind in ('i', 'I')
        and exists (
          select 1
          from pg_index index_record
          where index_record.indexrelid = relation_record.oid
            and index_record.indrelid in (
              select oid
              from canonical_base_relations
            )
        )
      )
      or (
        relation_record.relkind = 'S'
        and exists (
          select 1
          from pg_depend dependency_record
          where dependency_record.classid = 'pg_class'::regclass
            and dependency_record.objid = relation_record.oid
            and dependency_record.refclassid = 'pg_class'::regclass
            and dependency_record.refobjid in (
              select oid
              from canonical_base_relations
            )
            and dependency_record.deptype in ('a', 'i')
        )
      )
    )
),
application_relations as (
  select
    oid,
    relname,
    relkind,
    relowner,
    relnamespace,
    relacl
  from canonical_base_relations
  union all
  select
    oid,
    relname,
    relkind,
    relowner,
    relnamespace,
    relacl
  from canonical_dependent_relations
),
canonical_enum_types as (
  select type_record.oid, type_record.typname, type_record.typowner
  from pg_type type_record
  join pg_namespace type_schema
    on type_schema.oid = type_record.typnamespace
  where type_schema.nspname = 'public'
    and type_record.typname = any($3::text[])
    and type_record.typtype = 'e'
    and type_record.typisdefined
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_type'::regclass
        and extension_record.objid = type_record.oid
    )
),
canonical_table_row_types as (
  select type_record.oid
  from pg_type type_record
  where type_record.typisdefined
    and type_record.typrelid in (
      select oid
      from canonical_base_relations
    )
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_type'::regclass
        and extension_record.objid = type_record.oid
    )
),
application_types as (
  select type_record.oid, type_record.typowner
  from pg_type type_record
  join pg_namespace type_schema
    on type_schema.oid = type_record.typnamespace
  where type_schema.nspname in ('public', 'drizzle')
    and type_record.typisdefined
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_type'::regclass
        and extension_record.objid = type_record.oid
    )
    and (
      type_record.oid in (
        select oid
        from canonical_enum_types
      )
      or type_record.oid in (
        select oid
        from canonical_table_row_types
      )
      or type_record.typelem in (
        select oid
        from canonical_enum_types
        union all
        select oid
        from canonical_table_row_types
      )
    )
),
application_routines as (
  select routine_record.oid, routine_record.proowner, routine_record.proacl
  from pg_proc routine_record
  join pg_namespace routine_schema
    on routine_schema.oid = routine_record.pronamespace
  where routine_schema.nspname in ('public', 'drizzle')
    and routine_record.proname = any($4::text[])
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_proc'::regclass
        and extension_record.objid = routine_record.oid
    )
),
unknown_application_relations as (
  select relation_record.oid
  from pg_class relation_record
  join pg_namespace relation_schema
    on relation_schema.oid = relation_record.relnamespace
  where relation_schema.nspname in ('public', 'drizzle')
    and relation_record.relkind in ('r', 'p', 'v', 'm', 'f', 'S', 'i', 'I')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_class'::regclass
        and extension_record.objid = relation_record.oid
    )
    and not exists (
      select 1
      from extension_dependent_relations extension_record
      where extension_record.oid = relation_record.oid
    )
    and not exists (
      select 1
      from application_relations application_record
      where application_record.oid = relation_record.oid
    )
),
unknown_application_types as (
  select type_record.oid
  from pg_type type_record
  join pg_namespace type_schema
    on type_schema.oid = type_record.typnamespace
  where type_schema.nspname in ('public', 'drizzle')
    and type_record.typisdefined
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_type'::regclass
        and extension_record.objid = type_record.oid
    )
    and not exists (
      select 1
      from extension_dependent_types extension_record
      where extension_record.oid = type_record.oid
    )
    and not exists (
      select 1
      from application_types application_record
      where application_record.oid = type_record.oid
    )
),
unknown_application_routines as (
  select routine_record.oid
  from pg_proc routine_record
  join pg_namespace routine_schema
    on routine_schema.oid = routine_record.pronamespace
  where routine_schema.nspname in ('public', 'drizzle')
    and not exists (
      select 1
      from extension_owned_objects extension_record
      where extension_record.classid = 'pg_proc'::regclass
        and extension_record.objid = routine_record.oid
    )
    and not exists (
      select 1
      from extension_dependency_objects extension_record
      where extension_record.classid = 'pg_proc'::regclass
        and extension_record.objid = routine_record.oid
    )
    and not exists (
      select 1
      from application_routines application_record
      where application_record.oid = routine_record.oid
    )
),
migrator_memberships as (
  select
    membership.roleid,
    membership.member,
    membership.grantor,
    membership.admin_option,
    membership.inherit_option,
    membership.set_option,
    member_role.rolname as member_name,
    grantor_role.rolname as grantor_name
  from pg_auth_members membership
  join migrator_role
    on membership.roleid = migrator_role.oid
    or membership.member = migrator_role.oid
    or membership.grantor = migrator_role.oid
  left join pg_roles member_role
    on member_role.oid = membership.member
  left join pg_roles grantor_role
    on grantor_role.oid = membership.grantor
)
select
  current_user = 'platform_migrator'
    and session_user = 'platform_migrator' as migrator_identity_exact,
  current_setting('server_version_num')::integer between 170000 and 179999
    as postgres_major_17,
  coalesce((
    select rolcanlogin
      and not rolinherit
      and not rolsuper
      and not rolcreatedb
      and not rolcreaterole
      and not rolreplication
      and not rolbypassrls
    from migrator_role
  ), false) as migrator_role_attributes_exact,
  coalesce((
    select count(*) = 1
      and bool_and(
        membership.roleid = migrator_role.oid
        and membership.member_name = 'platform_app'
        and membership.grantor_name = 'cloud_admin'
        and membership.admin_option
        and not membership.inherit_option
        and not membership.set_option
      )
    from migrator_memberships membership
    cross join migrator_role
  ), false) as migrator_creator_admin_edge_exact,
  coalesce((
    select has_database_privilege(
      migrator_role.oid,
      database_state.oid,
      'CONNECT'
    )
    from migrator_role
    cross join database_state
  ), false) as migrator_database_connect_exact,
  coalesce((
    select not has_database_privilege(
      migrator_role.oid,
      database_state.oid,
      'CREATE'
    )
    from migrator_role
    cross join database_state
  ), false) as migrator_database_create_absent,
  coalesce((
    select not has_database_privilege(
      migrator_role.oid,
      database_state.oid,
      'TEMPORARY'
    )
    from migrator_role
    cross join database_state
  ), false) as migrator_database_temporary_absent,
  coalesce((
    select database_state.datdba = app_role.oid
    from database_state
    cross join app_role
  ), false) as database_owner_platform_app,
  coalesce((
    select schema_state.nspowner = pg_database_owner.oid
    from schema_state
    join pg_roles pg_database_owner
      on pg_database_owner.rolname = 'pg_database_owner'
    where schema_state.nspname = 'public'
  ), false) as public_schema_owner_pg_database_owner,
  coalesce((
    select has_schema_privilege(migrator_role.oid, schema_state.oid, 'USAGE')
      and has_schema_privilege(migrator_role.oid, schema_state.oid, 'CREATE')
    from schema_state
    cross join migrator_role
    where schema_state.nspname = 'public'
  ), false) as migrator_public_schema_authority,
  coalesce((
    select schema_state.nspowner = migrator_role.oid
      and has_schema_privilege(migrator_role.oid, schema_state.oid, 'USAGE')
      and has_schema_privilege(migrator_role.oid, schema_state.oid, 'CREATE')
    from schema_state
    cross join migrator_role
    where schema_state.nspname = 'drizzle'
  ), false) as drizzle_schema_migrator_authority,
  coalesce((
    select count(*) = 1
      and coalesce(bool_and(
        schema_record.nspowner = migrator_role.oid
        and has_schema_privilege(migrator_role.oid, schema_record.oid, 'USAGE')
        and has_schema_privilege(migrator_role.oid, schema_record.oid, 'CREATE')
      ), true)
    from schema_state schema_record
    cross join migrator_role
    where schema_record.nspname = 'drizzle'
  ), false) as application_schema_authority_exact,
  coalesce((
    select ledger_state.ledger_owner = migrator_role.oid
    from ledger_state
    cross join migrator_role
    where ledger_state.ledger_oid is not null
  ), false) as migration_ledger_owner_migrator,
  coalesce((
    select not exists (
      select 1
      from application_relations relation_record
      where relation_record.relowner <> migrator_role.oid
    )
    from migrator_role
  ), false) as application_namespace_relation_owner_exact,
  coalesce((
    select count(*) = cardinality($1::text[])
      and coalesce(bool_and(relation_record.relowner = migrator_role.oid), true)
    from canonical_table_relations relation_record
    cross join migrator_role
    where relation_record.relname = any($1::text[])
  ), false) as required_application_table_owner_exact,
  coalesce((
    select count(*) = cardinality($3::text[])
      and coalesce(bool_and(type_record.typowner = migrator_role.oid), false)
    from canonical_enum_types type_record
    cross join migrator_role
  ), false) as canonical_enum_presence_exact,
  coalesce((
    select not exists (
      select 1
      from application_types type_record
      where type_record.typowner <> migrator_role.oid
    )
    from migrator_role
  ), false) as application_type_owner_exact,
  coalesce((
    select not exists (
      select 1
      from application_routines routine_record
      where routine_record.proowner <> migrator_role.oid
    )
    from migrator_role
  ), false) as application_routine_owner_exact,
  coalesce((
    select not exists (
      select 1
      from unknown_application_relations
    )
  ), false) as unknown_application_relation_drift_absent,
  coalesce((
    select not exists (
      select 1
      from unknown_application_types
    )
  ), false) as unknown_application_type_drift_absent,
  coalesce((
    select not exists (
      select 1
      from unknown_application_routines
    )
  ), false) as unknown_application_routine_drift_absent,
  coalesce((
    select not exists (
      select 1
      from application_relations relation_record
      where relation_record.relowner <> migrator_role.oid
    )
    from migrator_role
  ), false) as application_relation_owner_exact,
  coalesce((
    select not exists (
      select 1
      from application_relations relation_record
      cross join lateral aclexplode(
        coalesce(
          relation_record.relacl,
          acldefault(
            case when relation_record.relkind = 'S' then 'S'::"char" else 'r'::"char" end,
            relation_record.relowner
          )
        )
      ) acl_record
      where relation_record.relkind not in ('i', 'I')
        and acl_record.grantee = 0
    )
  ), false) as public_relation_authority_absent,
  coalesce((
    select not exists (
      select 1
      from application_routines routine_record
      cross join lateral aclexplode(
        coalesce(
          routine_record.proacl,
          acldefault('f'::"char", routine_record.proowner)
        )
      ) acl_record
      where acl_record.grantee = 0
    )
  ), false) as public_routine_authority_absent,
  not exists (
    select 1
    from pg_default_acl default_acl
    cross join lateral aclexplode(default_acl.defaclacl) acl_record
    where default_acl.defaclobjtype in ('r', 'S', 'f')
      and acl_record.grantee = 0
  ) as public_default_acl_authority_absent,
  coalesce((
    select not exists (
      select 1
      from application_relations relation_record
      cross join lateral aclexplode(
        coalesce(
          relation_record.relacl,
          acldefault('r'::"char", relation_record.relowner)
        )
      ) acl_record
      where relation_record.relkind not in ('i', 'I')
        and acl_record.grantee = migrator_role.oid
        and acl_record.is_grantable
    )
    and not exists (
      select 1
      from application_routines routine_record
      cross join lateral aclexplode(
        coalesce(
          routine_record.proacl,
          acldefault('f'::"char", routine_record.proowner)
        )
      ) acl_record
      where acl_record.grantee = migrator_role.oid
        and acl_record.is_grantable
    )
    from migrator_role
  ), false) as migrator_grant_option_absent,
  coalesce((
    select not exists (
      select 1
      from schema_state
      cross join lateral aclexplode(
        coalesce(schema_state.nspacl, acldefault('n'::"char", schema_state.nspowner))
      ) acl_record
      where (schema_state.nspname = 'drizzle' and acl_record.grantee = 0)
        or (
          schema_state.nspname = 'public'
          and acl_record.grantee = 0
          and acl_record.privilege_type = 'CREATE'
        )
    )
  ), false) as public_schema_acl_least_privilege,
  coalesce((
    select not exists (
      select 1
      from runtime_role
      cross join ledger_state
      where ledger_state.ledger_oid is not null
        and (
          has_schema_privilege(runtime_role.oid, ledger_state.schema_oid, 'USAGE')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'SELECT')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'INSERT')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'UPDATE')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'DELETE')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'TRUNCATE')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'REFERENCES')
          or has_table_privilege(runtime_role.oid, ledger_state.ledger_oid, 'TRIGGER')
        )
    )
  ), false) as runtime_migration_ledger_access_absent,
  coalesce((
    select not exists (
      select 1
      from application_relations relation_record
      join runtime_role
        on relation_record.relowner = runtime_role.oid
    )
    and not exists (
      select 1
      from application_types type_record
      join runtime_role
        on type_record.typowner = runtime_role.oid
    )
    and not exists (
      select 1
      from application_routines routine_record
      join runtime_role
        on routine_record.proowner = runtime_role.oid
    )
    from runtime_role
  ), false) as runtime_application_ownership_zero

`;

export async function createDatabaseReadinessReport(
  input: DatabaseReadinessInput,
): Promise<DatabaseReadinessReport> {
  const requiredTables = input.requiredTables ?? REQUIRED_PLATFORM_TABLES;
  const checks: DatabaseReadinessChecks = {
    config: "not_checked",
    reachability: "not_checked",
    schema: "not_checked",
    migratorPosture: "not_checked",
    migrations: "not_checked",
  };
  let config: DatabaseConfig;
  let client: DatabaseReadinessClient | null = null;

  try {
    config = readOperatorDatabaseConfig(input.env);
    checks.config = "present";
  } catch (error) {
    checks.config = readConfigFailureState(error);
    return report({
      status: checks.config === "missing" ? "db_config_missing" : "db_config_invalid",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  }

  try {
    const clientFactory = input.clientFactory ?? createDatabaseReadinessClient;
    client = await clientFactory(config);
    await client.query(reachabilitySql);
    checks.reachability = "passed";
  } catch {
    checks.reachability = "failed";
    return report({
      status: "db_unreachable",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } finally {
    if (checks.reachability === "failed") {
      await closeClientQuietly(client);
    }
  }

  let missingTables: string[] | undefined;

  try {
    missingTables = await readMissingRequiredTables(client, requiredTables);
    checks.schema = missingTables.length === 0 ? "passed" : "failed";

    const migrationReady = await readMigrationReadiness(
      client,
      input.expectedMigrationState,
    );

    checks.migrations = migrationReady ? "passed" : "failed";
    const migratorReady = await readMigratorReadiness(
      client,
      requiredTables,
    );
    checks.migratorPosture = migratorReady ? "passed" : "failed";

    if (
      checks.schema !== "passed" ||
      checks.migrations !== "passed" ||
      checks.migratorPosture !== "passed"
    ) {
      return report({
        status: "schema_not_ready",
        checks,
        requiredTables,
        missingTables,
        expectedMigrationState: input.expectedMigrationState,
      });
    }

    return report({
      status: "ready",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } catch {
    checks.schema =
      typeof missingTables === "undefined"
        ? "failed"
        : missingTables.length === 0
          ? "passed"
          : "failed";
    checks.migrations =
      input.expectedMigrationState && checks.migrations === "not_checked"
        ? "failed"
        : checks.migrations;
    if (
      checks.migratorPosture === "not_checked" &&
      checks.schema === "passed" &&
      checks.migrations === "passed"
    ) {
      checks.migratorPosture = "failed";
    }
    return report({
      status: "schema_not_ready",
      checks,
      requiredTables,
      missingTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } finally {
    await closeClientQuietly(client);
  }
}

export function createDatabaseReadinessClient(
  config: DatabaseConfig,
): DatabaseReadinessClient {
  const pool = createDatabasePool(config);

  return {
    query(text, values) {
      return values ? pool.query(text, [...values]) : pool.query(text);
    },
    end() {
      return pool.end();
    },
  };
}

export function formatDatabaseReadinessReport(
  readinessReport: DatabaseReadinessReport,
): string[] {
  const lines = [
    `Swooshz Platform database readiness_check=${readinessReport.ok ? "pass" : "fail"}`,
    `status=${readinessReport.status}`,
    `database_config=${readinessReport.checks.config}`,
    `database_reachability=${readinessReport.checks.reachability}`,
    `schema_state=${readinessReport.checks.schema}`,
    `migrator_posture=${readinessReport.checks.migratorPosture}`,
  ];

  if (shouldReportRequiredTables(readinessReport)) {
    lines.push(
      `required_tables_present=${
        readinessReport.requiredTables.length - readinessReport.missingTables.length
      }/${readinessReport.requiredTables.length}`,
    );
  }

  if (readinessReport.missingTables.length > 0) {
    lines.push(`missing_tables=${readinessReport.missingTables.join(",")}`);
  }

  if (readinessReport.expectedMigrationState) {
    lines.push(`migration_state=${formatMigrationState(readinessReport)}`);
    lines.push(
      `expected_latest_migration=${readinessReport.expectedMigrationState.latestTag}`,
    );
  }

  return lines;
}

function shouldReportRequiredTables(
  readinessReport: DatabaseReadinessReport,
): boolean {
  if (readinessReport.requiredTables.length === 0) {
    return false;
  }

  return (
    readinessReport.checks.schema === "passed" ||
    readinessReport.missingTables.length > 0
  );
}

async function readMissingRequiredTables(
  client: DatabaseReadinessClient,
  requiredTables: readonly string[],
): Promise<string[]> {
  const result = await client.query(requiredTablesSql, [requiredTables]);
  const existingTables = new Set(
    result.rows
      .map((row) => row.table_name)
      .filter((value): value is string => typeof value === "string"),
  );

  return requiredTables.filter((tableName) => !existingTables.has(tableName));
}

const MIGRATOR_READINESS_FIELDS = [
  "migrator_identity_exact",
  "postgres_major_17",
  "migrator_role_attributes_exact",
  "migrator_creator_admin_edge_exact",
  "migrator_database_connect_exact",
  "migrator_database_create_absent",
  "migrator_database_temporary_absent",
  "database_owner_platform_app",
  "public_schema_owner_pg_database_owner",
  "migrator_public_schema_authority",
  "drizzle_schema_migrator_authority",
  "application_schema_authority_exact",
  "migration_ledger_owner_migrator",
  "application_namespace_relation_owner_exact",
  "required_application_table_owner_exact",
  "canonical_enum_presence_exact",
  "application_type_owner_exact",
  "application_routine_owner_exact",
  "unknown_application_relation_drift_absent",
  "unknown_application_type_drift_absent",
  "unknown_application_routine_drift_absent",
  "public_relation_authority_absent",
  "public_routine_authority_absent",
  "public_default_acl_authority_absent",
  "migrator_grant_option_absent",
  "public_schema_acl_least_privilege",
  "runtime_migration_ledger_access_absent",
  "runtime_application_ownership_zero",
] as const;

async function readMigratorReadiness(
  client: DatabaseReadinessClient,
  requiredTables: readonly string[],
): Promise<boolean> {
  const result = await client.query(migratorPostureSql, [
    requiredTables,
    CANONICAL_PLATFORM_TABLES,
    CANONICAL_PLATFORM_ENUM_TYPES,
    CANONICAL_PLATFORM_ROUTINES,
  ]);
  if (result.rows.length !== 1) {
    return false;
  }

  const row = result.rows[0];
  return MIGRATOR_READINESS_FIELDS.every((field) => row[field] === true);
}
async function readMigrationReadiness(
  client: DatabaseReadinessClient,
  expectedMigrationState: ExpectedMigrationState | undefined,
): Promise<boolean> {
  if (!expectedMigrationState) {
    return true;
  }

  const result = await client.query(migrationStateSql);
  const row = result.rows[0] ?? {};
  const appliedCount = Number(row.applied_count ?? 0);
  const latestCreatedAt = Number(row.latest_created_at ?? 0);

  return (
    Number.isFinite(appliedCount) &&
    Number.isFinite(latestCreatedAt) &&
    appliedCount >= expectedMigrationState.migrationCount &&
    latestCreatedAt >= expectedMigrationState.latestCreatedAt
  );
}

function readConfigFailureState(error: unknown): "missing" | "invalid" {
  if (
    error instanceof DatabaseConfigError &&
    ["missing_database_url", "missing_database_operator_url"].includes(error.code)
  ) {
    return "missing";
  }

  return "invalid";
}

function formatMigrationState(readinessReport: DatabaseReadinessReport): string {
  if (readinessReport.checks.migrations === "passed") {
    return "ready";
  }

  if (readinessReport.checks.migrations === "failed") {
    return "behind";
  }

  return "not_checked";
}

function report({
  status,
  checks,
  requiredTables,
  missingTables = [],
  expectedMigrationState,
}: {
  status: DatabaseReadinessStatus;
  checks: DatabaseReadinessChecks;
  requiredTables: readonly string[];
  missingTables?: string[];
  expectedMigrationState?: ExpectedMigrationState;
}): DatabaseReadinessReport {
  return {
    ok: status === "ready",
    status,
    checks: { ...checks },
    requiredTables,
    missingTables,
    ...(expectedMigrationState ? { expectedMigrationState } : {}),
  };
}

async function closeClientQuietly(
  client: DatabaseReadinessClient | null,
): Promise<void> {
  try {
    await client?.end?.();
  } catch {
    // Readiness output stays category-only; close errors may include connection details.
  }
}
