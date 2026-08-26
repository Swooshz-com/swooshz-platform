import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { readMigrationFiles } from "drizzle-orm/migrator";

import * as schema from "./schema.js";
import {
  CANONICAL_PLATFORM_ENUM_TYPES,
  CANONICAL_PLATFORM_ROUTINES,
  CANONICAL_PLATFORM_TABLES,
  MIGRATOR_READINESS_FIELDS,
  REQUIRED_PLATFORM_TABLES,
  verifyCanonicalPlatformDatabase,
  type CanonicalDatabaseVerification,
  type DatabaseReadinessClient,
} from "./readiness.js";
import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
  PLATFORM_RUNTIME_ROLE,
  type RuntimeDatabaseRoleAuthorityPostureReport,
} from "./runtime-posture.js";
import {
  RUNTIME_TABLE_GRANT_CONTRACT,
  RUNTIME_TABLE_GRANT_DIGEST,
  assertRuntimeTableGrantSet,
  type ObservedRuntimeTableGrantRecord,
} from "./runtime-grant-contract.js";

export const PRESTATE_VERSION = "platform-db-prestate-v1" as const;
export const PLAN_VERSION = "platform-db-plan-v1" as const;
export const INVERSE_VERSION = "platform-db-inverse-v1" as const;
export const RESTORE_CAPABILITY_VERSION = "restore-capability-v1" as const;

export const PRESTATE_DOMAIN_SEPARATOR =
  "swooshz-platform:platform-db-prestate-v1\0" as const;
export const PLAN_DOMAIN_SEPARATOR =
  "Swooshz-platform:platform-db-plan-v1\0" as const;
export const CONTRACT_DOMAIN_SEPARATOR =
  "Swooshz-platform:platform-db-contract-v1\0" as const;
const INVERSE_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-inverse-v1\0";
export const JOURNAL_PREFIX_DOMAIN_SEPARATOR =
  "Swooshz-platform:platform-db-journal-prefix-v1\0";

export const APPROVED_ROLE_NAMES = [
  "platform_runtime",
  "platform_migrator",
  "platform_app",
  "cloud_admin",
] as const;
export type ApprovedRoleName = (typeof APPROVED_ROLE_NAMES)[number];

export const APPROVED_RECEIPT_ROLE_NAMES = [
  ...APPROVED_ROLE_NAMES,
  "pg_database_owner",
] as const;
export type ApprovedReceiptRoleName =
  (typeof APPROVED_RECEIPT_ROLE_NAMES)[number];
export type ApprovedPrincipal = ApprovedRoleName | "PUBLIC" | "pg_database_owner";

export const OBSERVATION_QUERY_IDS = [
  "target_identity",
  "role_state",
  "membership_state",
  "ownership_state",
  "privilege_state",
  "default_acl_state",
  "runtime_grant_state",
  "migration_journal_state",
  "readiness_state",
  "runtime_posture_state",
  "unknown_drift_state",
] as const;
export type ObservationQueryId = (typeof OBSERVATION_QUERY_IDS)[number];

export const OPERATION_KINDS = [
  "ownership",
  "privilege",
  "membership",
  "default_acl",
  "role_posture",
  "migration",
] as const;
export type OperationKind = (typeof OPERATION_KINDS)[number];

export const RECEIPT_PHASES = [
  "ADMISSION",
  "OBSERVE",
  "PLAN",
  "PRESTATE",
  "INVERSE",
  "PREWRITE",
  "FORWARD",
  "COMMIT",
  "ROLLBACK",
  "RESTORE",
  "RESTORE_VERIFY",
  "FINAL_VERIFY",
  "RECEIPT",
] as const;
export type ReceiptPhase = (typeof RECEIPT_PHASES)[number];

export const SEMANTIC_CODES = [
  "SUCCESS",
  "ADMISSION_FAILED",
  "REVISION_UNAVAILABLE",
  "REVISION_MISMATCH",
  "DIRTY_CHECKOUT",
  "CONTRACT_DIGEST_MISMATCH",
  "TARGET_IDENTITY_UNAVAILABLE",
  "TARGET_MISMATCH",
  "POSTGRES_VERSION_UNSUPPORTED",
  "SESSION_IDENTITY_MISMATCH",
  "RECOVERY_STATE_UNSUPPORTED",
  "READ_ONLY_ASSERTION_FAILED",
  "OBSERVATION_FAILED",
  "PRESTATE_INVALID",
  "PRESTATE_MISMATCH",
  "UNKNOWN_DRIFT",
  "OPERATION_UNSUPPORTED",
  "ARBITRARY_INPUT_REJECTED",
  "MIGRATION_IDENTITY_MISMATCH",
  "INVERSE_INCOMPLETE",
  "RESTORE_CAPABILITY_REQUIRED",
  "RESTORE_EXECUTION_FAILED",
  "PREWRITE_DRIFT",
  "MUTATION_FAILED",
  "WRITE_INDETERMINATE",
  "COMMIT_FAILED",
  "COMMIT_INDETERMINATE",
  "ROLLBACK_FAILED",
  "RESTORATION_FAILED",
  "RESTORATION_AMBIGUOUS",
  "FINAL_VERIFICATION_FAILED",
  "RECEIPT_REJECTED",
  "UNEXPECTED_FAILURE",
] as const;
export type SemanticCode = (typeof SEMANTIC_CODES)[number];

export class DurableOperationError extends Error {
  readonly semanticCode: SemanticCode;
  readonly publicMessage = "Platform database operation failed.";
  mutationStarted = false;

  constructor(semanticCode: SemanticCode, message?: string) {
    super(message ?? publicMessageFor(semanticCode));
    this.name = "DurableOperationError";
    this.semanticCode = semanticCode;
  }
}

function publicMessageFor(code: SemanticCode): string {
  switch (code) {
    case "ARBITRARY_INPUT_REJECTED":
      return "Platform durable operation input is unsupported.";
    case "PRESTATE_INVALID":
      return "Platform database prestate is invalid.";
    case "READ_ONLY_ASSERTION_FAILED":
      return "Platform database observation is not read-only.";
    case "UNKNOWN_DRIFT":
      return "Platform database contains unknown drift.";
    case "RECEIPT_REJECTED":
      return "Platform database receipt is invalid.";
    default:
      return "Platform database operation failed.";
  }
}

function fail(code: SemanticCode, message?: string): never {
  throw new DurableOperationError(code, message);
}

function failCanonical(message: string): never {
  return fail("ARBITRARY_INPUT_REJECTED", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertRecord(value: unknown, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  asserts value is Record<string, unknown> {
  if (!isRecord(value)) fail(code);
}

function assertExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  code: SemanticCode = "ARBITRARY_INPUT_REJECTED",
): void {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== expected.size || actual.some((key) => !expected.has(key))) {
    fail(code);
  }
}

function stringValue(value: unknown, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  string {
  if (typeof value !== "string" || value.length === 0) fail(code);
  return value;
}

function stringAllowEmpty(value: unknown, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  string {
  if (typeof value !== "string") fail(code);
  return value;
}

function booleanValue(value: unknown, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  boolean {
  if (typeof value !== "boolean") fail(code);
  return value;
}

function safeIdentifier(value: unknown, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  string {
  const identifier = stringValue(value, code);
  if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(identifier)) fail(code);
  return identifier;
}

function hex(value: unknown, length: 40 | 64, code: SemanticCode = "ARBITRARY_INPUT_REJECTED"):
  string {
  const text = stringValue(value, code);
  if (!new RegExp(`^[0-9a-f]{${length}}$`, "u").test(text)) fail(code);
  return text;
}

function nonnegativeInteger(value: unknown, code: SemanticCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail(code);
  return value as number;
}

function targetNumericIdentifier(value: unknown, code: SemanticCode): string {
  const text = typeof value === "bigint"
    ? value.toString(10)
    : typeof value === "number" && Number.isSafeInteger(value) && value >= 0
      ? String(value)
      : value;
  if (typeof text !== "string" || !/^[1-9]\d{0,19}$/u.test(text)) fail(code);
  return text;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}

function compareTuple(left: readonly unknown[], right: readonly unknown[]): number {
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const a = String(left[index] ?? "");
    const b = String(right[index] ?? "");
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

export function canonicalSerialize(value: unknown): string {
  const normalized = canonicalValue(value);
  const serialized = JSON.stringify(normalized);
  if (typeof serialized !== "string") fail("ARBITRARY_INPUT_REJECTED");
  return serialized;
}

function canonicalValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("ARBITRARY_INPUT_REJECTED");
    if (!Number.isInteger(value)) failCanonical("Floating point values are unsupported.");
    if (!Number.isSafeInteger(value)) failCanonical("Unsafe numeric values are unsupported.");
    return value;
  }
  if (typeof value === "bigint" || typeof value === "undefined") {
    fail("ARBITRARY_INPUT_REJECTED");
  }
  if (typeof value === "function" || typeof value === "symbol") {
    fail("ARBITRARY_INPUT_REJECTED");
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  assertRecord(value);
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    result[key] = canonicalValue(value[key]);
  }
  return result;
}

export function canonicalDigest(domainSeparator: string, value: unknown): string {
  if (
    ![
      PRESTATE_DOMAIN_SEPARATOR,
      PLAN_DOMAIN_SEPARATOR,
      CONTRACT_DOMAIN_SEPARATOR,
      INVERSE_DOMAIN_SEPARATOR,
      JOURNAL_PREFIX_DOMAIN_SEPARATOR,
    ].includes(domainSeparator as never)
  ) {
    fail("ARBITRARY_INPUT_REJECTED");
  }
  return createHash("sha256")
    .update(Buffer.from(domainSeparator + canonicalSerialize(value), "utf8"))
    .digest("hex");
}

class StrictJsonParser {
  private index = 0;

  constructor(private readonly source: string) {}

  parse(): unknown {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.source.length) fail("ARBITRARY_INPUT_REJECTED");
    return value;
  }

  private parseValue(): unknown {
    this.skipWhitespace();
    const character = this.source[this.index];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (this.source.startsWith("true", this.index)) {
      this.index += 4;
      return true;
    }
    if (this.source.startsWith("false", this.index)) {
      this.index += 5;
      return false;
    }
    if (this.source.startsWith("null", this.index)) {
      this.index += 4;
      return null;
    }
    const match = this.source.slice(this.index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (!match) fail("ARBITRARY_INPUT_REJECTED");
    this.index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isSafeInteger(number) || !/^-?(?:0|[1-9]\d*)$/u.test(match[0])) {
      fail("ARBITRARY_INPUT_REJECTED");
    }
    return number;
  }

  private parseObject(): Record<string, unknown> {
    this.index += 1;
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (this.index < this.source.length) {
      this.skipWhitespace();
      if (this.source[this.index] !== '"') fail("ARBITRARY_INPUT_REJECTED");
      const key = this.parseString();
      if (keys.has(key)) fail("ARBITRARY_INPUT_REJECTED", "Duplicate JSON object key is unsupported.");
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.index] !== ":") fail("ARBITRARY_INPUT_REJECTED");
      this.index += 1;
      result[key] = this.parseValue();
      this.skipWhitespace();
      if (this.source[this.index] === "}") {
        this.index += 1;
        return result;
      }
      if (this.source[this.index] !== ",") fail("ARBITRARY_INPUT_REJECTED");
      this.index += 1;
    }
    fail("ARBITRARY_INPUT_REJECTED");
  }

  private parseArray(): unknown[] {
    this.index += 1;
    const result: unknown[] = [];
    this.skipWhitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (this.index < this.source.length) {
      result.push(this.parseValue());
      this.skipWhitespace();
      if (this.source[this.index] === "]") {
        this.index += 1;
        return result;
      }
      if (this.source[this.index] !== ",") fail("ARBITRARY_INPUT_REJECTED");
      this.index += 1;
    }
    fail("ARBITRARY_INPUT_REJECTED");
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const character = this.source[this.index];
      if (character === "\\") {
        this.index += 2;
        continue;
      }
      if (character === '"') {
        const raw = this.source.slice(start, this.index + 1);
        this.index += 1;
        try {
          const value = JSON.parse(raw);
          if (typeof value !== "string") fail("ARBITRARY_INPUT_REJECTED");
          return value;
        } catch {
          fail("ARBITRARY_INPUT_REJECTED");
        }
      }
      this.index += 1;
    }
    fail("ARBITRARY_INPUT_REJECTED");
  }

  private skipWhitespace(): void {
    while (/\s/u.test(this.source[this.index] ?? "")) this.index += 1;
  }
}

export function parseCanonicalJson(value: string): unknown {
  if (typeof value !== "string") fail("ARBITRARY_INPUT_REJECTED");
  return new StrictJsonParser(value).parse();
}

export interface DurableQueryResult {
  rows: Array<Record<string, unknown>>;
}

export type DurableQueryInput = string | Record<string, unknown>;

export interface DurableConnection {
  query(text: DurableQueryInput, values?: readonly unknown[]): Promise<DurableQueryResult>;
  release?(): Promise<void> | void;
}

export interface DurablePool {
  connect(): Promise<DurableConnection>;
  query?(text: DurableQueryInput, values?: readonly unknown[]): Promise<DurableQueryResult>;
}

export interface DurableTargetBinding {
  readonly version: "target-binding-v1";
  readonly logicalDatabaseName: string;
  readonly expectedClusterSystemIdentifier: string;
  readonly expectedDatabaseOid: string;
  readonly expectedCurrentUser: ApprovedRoleName;
  readonly expectedSessionUser: ApprovedRoleName;
  readonly expectedPostgresMajor: 17;
  readonly connect: () => Promise<DurableConnection>;
}

const TARGET_IDENTITY_SQL = `
/* platform durable:target_identity */
select control_state.system_identifier::text as cluster_system_identifier,
       database_record.oid::text as database_oid,
       current_database() as logical_database_name,
       current_user as current_user,
       session_user as session_user,
       (current_setting('server_version_num')::int / 10000)::int as postgres_major,
       pg_is_in_recovery() as in_recovery,
       (current_setting('transaction_read_only') = 'on') as transaction_read_only
from pg_catalog.pg_control_system() as control_state
cross join pg_catalog.pg_database as database_record
where database_record.datname = current_database()
`;
const ROLE_STATE_SQL = `
/* platform durable:role_state */
select rolname, oid::text as role_oid, rolcanlogin, rolinherit, rolsuper,
       rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
       rolconnlimit
from pg_roles
where rolname = any($1::text[])
order by rolname
`;
const MEMBERSHIP_STATE_SQL = `
/* platform durable:membership_state */
select granted_role.rolname as granted_role,
       member_role.rolname as member,
       grantor_role.rolname as grantor,
       membership.admin_option,
       membership.inherit_option,
       membership.set_option
from pg_auth_members membership
left join pg_roles granted_role on granted_role.oid = membership.roleid
left join pg_roles member_role on member_role.oid = membership.member
left join pg_roles grantor_role on grantor_role.oid = membership.grantor
where granted_role.rolname = any($1::text[])
   or member_role.rolname = any($1::text[])
   or grantor_role.rolname = any($1::text[])
order by granted_role.rolname, member_role.rolname, grantor_role.rolname,
         membership.admin_option, membership.inherit_option, membership.set_option
`;
const OWNERSHIP_STATE_SQL = `
/* platform durable:ownership_state */
with namespace_state as (
  select oid, nspname
  from pg_namespace
  where nspname in ('public', 'drizzle')
),
extension_members as (
  select classid, objid
  from pg_depend
  where refclassid = 'pg_extension'::regclass and deptype = 'e'
)
select 'database' as object_class,
       current_database() as qualified_name,
       database_record.oid::text as object_oid,
       owner_role.rolname as owner,
       false as is_extension_member,
       '' as object_kind
from pg_database database_record
join pg_roles owner_role on owner_role.oid = database_record.datdba
where database_record.datname = current_database()
union all
select 'schema', namespace_record.nspname, namespace_record.oid::text, owner_role.rolname, false, ''
from namespace_state namespace_record
join pg_namespace namespace_owner on namespace_owner.oid = namespace_record.oid
join pg_roles owner_role on owner_role.oid = namespace_owner.nspowner
union all
select case when relation_record.relkind in ('i', 'I') then 'index'
            when relation_record.relkind = 'S' then 'sequence'
            else 'relation' end,
       namespace_record.nspname || '.' || relation_record.relname,
       relation_record.oid::text,
       owner_role.rolname,
       exists (
         select 1 from extension_members extension_record
         where extension_record.classid = 'pg_class'::regclass
           and extension_record.objid = relation_record.oid
       ),
       relation_record.relkind::text
from pg_class relation_record
join namespace_state namespace_record on namespace_record.oid = relation_record.relnamespace
join pg_roles owner_role on owner_role.oid = relation_record.relowner
where relation_record.relkind in ('r', 'p', 'S', 'i', 'I')
union all
select 'type', namespace_record.nspname || '.' || type_record.typname,
       type_record.oid::text,
       owner_role.rolname,
       exists (
         select 1 from extension_members extension_record
         where extension_record.classid = 'pg_type'::regclass
           and extension_record.objid = type_record.oid
       ),
       type_record.typtype::text
from pg_type type_record
join namespace_state namespace_record on namespace_record.oid = type_record.typnamespace
join pg_roles owner_role on owner_role.oid = type_record.typowner
where type_record.typtype = 'e' and type_record.typisdefined
union all
select 'routine', namespace_record.nspname || '.' || routine_record.proname || '('
       || pg_get_function_identity_arguments(routine_record.oid) || ')',
       routine_record.oid::text,
       owner_role.rolname,
       exists (
         select 1 from extension_members extension_record
         where extension_record.classid = 'pg_proc'::regclass
           and extension_record.objid = routine_record.oid
       ),
       routine_record.prokind::text
from pg_proc routine_record
join namespace_state namespace_record on namespace_record.oid = routine_record.pronamespace
join pg_roles owner_role on owner_role.oid = routine_record.proowner
where routine_record.prokind in ('f', 'p', 'a', 'w')
order by object_class, qualified_name, owner
`;
const PRIVILEGE_STATE_SQL = `
/* platform durable:privilege_state */
with object_state as (
  select 'database' as object_class,
         database_record.datname as qualified_name,
         database_record.oid::text as object_oid,
         database_record.datacl as acl
  from pg_catalog.pg_database database_record
  where database_record.datname = current_database()
  union all
  select 'schema',
         namespace_record.nspname,
         namespace_record.oid::text,
         namespace_record.nspacl
  from pg_catalog.pg_namespace namespace_record
  where namespace_record.nspname in ('public', 'drizzle')
  union all
  select case when relation_record.relkind in ('i', 'I') then 'index'
              when relation_record.relkind = 'S' then 'sequence'
              else 'relation' end,
         namespace_record.nspname || '.' || relation_record.relname,
         relation_record.oid::text,
         relation_record.relacl
  from pg_catalog.pg_class relation_record
  join pg_catalog.pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace
  where namespace_record.nspname in ('public', 'drizzle')
    and relation_record.relkind in ('r', 'p', 'S', 'i', 'I')
  union all
  select 'type',
         namespace_record.nspname || '.' || type_record.typname,
         type_record.oid::text,
         type_record.typacl
  from pg_catalog.pg_type type_record
  join pg_catalog.pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace
  where namespace_record.nspname = 'public'
    and type_record.typtype = 'e'
    and type_record.typisdefined
),
expanded as (
  select object_state.object_class,
         object_state.qualified_name,
         object_state.object_oid,
         object_state.acl is null as acl_is_null,
         grantor_role.rolname as grantor,
         coalesce(grantee_role.rolname, 'PUBLIC') as grantee,
         grant_record.privilege_type as privilege,
         grant_record.is_grantable as grant_option
  from object_state
  left join lateral aclexplode(object_state.acl) grant_record on true
  left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
  left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
)
select * from expanded
order by object_class, qualified_name, object_oid, acl_is_null, grantor, grantee, privilege, grant_option
`;
const DEFAULT_ACL_STATE_SQL = `
/* platform durable:default_acl_state */
with default_state as (
  select default_record.oid::text as default_acl_oid,
         creator_role.rolname as creator,
         coalesce(namespace_record.nspname, '') as schema,
         case default_record.defaclobjtype
           when 'r' then 'table'
           when 'S' then 'sequence'
           when 'f' then 'routine'
           when 'T' then 'type'
           when 'n' then 'schema'
           else default_record.defaclobjtype::text
         end as object_type,
         default_record.defaclacl as acl
  from pg_catalog.pg_default_acl default_record
  join pg_catalog.pg_roles creator_role on creator_role.oid = default_record.defaclrole
  left join pg_catalog.pg_namespace namespace_record on namespace_record.oid = default_record.defaclnamespace
  where creator_role.rolname = any($1::text[])
),
expanded as (
  select default_state.default_acl_oid,
         true as row_present,
         default_state.creator,
         default_state.schema,
         default_state.object_type,
         default_state.acl is null as acl_is_null,
         coalesce(grantee_role.rolname, 'PUBLIC') as grantee,
         grantor_role.rolname as grantor,
         grant_record.privilege_type as privilege,
         grant_record.is_grantable as grant_option
  from default_state
  left join lateral aclexplode(default_state.acl) grant_record on true
  left join pg_catalog.pg_roles grantee_role on grantee_role.oid = grant_record.grantee
  left join pg_catalog.pg_roles grantor_role on grantor_role.oid = grant_record.grantor
)
select *
from expanded
order by creator, schema, object_type, grantee, grantor, privilege, grant_option
`;
const RUNTIME_GRANT_STATE_SQL = `
/* platform durable:runtime_grant_state */
select 'table' as object_class,
       namespace_record.nspname as schema,
       relation_record.relname as object_name,
       grant_record.privilege_type as privilege,
       'direct' as authority_source,
       grant_record.is_grantable as grant_option
from pg_class relation_record
join pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace
cross join lateral aclexplode(relation_record.relacl) grant_record
join pg_roles runtime_role on runtime_role.rolname = 'platform_runtime'
  and grant_record.grantee = runtime_role.oid
where namespace_record.nspname = 'public'
  and relation_record.relkind in ('r', 'p')
order by object_name, privilege
`;
const MIGRATION_LEDGER_EXISTS_SQL = `
/* platform durable:migration_journal_state */
select exists (
  select 1
  from pg_class relation_record
  join pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace
  where namespace_record.nspname = 'drizzle'
    and relation_record.relname = '__drizzle_migrations'
    and relation_record.relkind in ('r', 'p')
) as ledger_present
`;
const MIGRATION_LEDGER_ROWS_SQL = `
/* platform durable:migration_journal_state */
select hash as sql_sha256, created_at::text as when
from drizzle.__drizzle_migrations
order by created_at, hash
`;

export const FIXED_OBSERVATION_SQL = Object.freeze({
  target_identity: TARGET_IDENTITY_SQL,
  role_state: ROLE_STATE_SQL,
  membership_state: MEMBERSHIP_STATE_SQL,
  ownership_state: OWNERSHIP_STATE_SQL,
  privilege_state: PRIVILEGE_STATE_SQL,
  default_acl_state: DEFAULT_ACL_STATE_SQL,
  runtime_grant_state: RUNTIME_GRANT_STATE_SQL,
  migration_journal_state: MIGRATION_LEDGER_ROWS_SQL,
  readiness_state: "/* platform durable:readiness_state */ canonical readiness adapter",
  runtime_posture_state: "/* platform durable:runtime_posture_state */ canonical runtime posture adapter",
  unknown_drift_state: "/* platform durable:unknown_drift_state */ canonical unknown-drift adapter",
} satisfies Readonly<Record<string, string>>);

export interface ReadOnlyObservation {
  read(queryId: ObservationQueryId): Promise<{ rows: Array<Record<string, unknown>> }>;
  close(): Promise<void>;
}

function assertObservationBinding(binding: DurableTargetBinding): void {
  assertRecord(binding);
  assertExactKeys(binding, [
    "version",
    "logicalDatabaseName",
    "expectedClusterSystemIdentifier",
    "expectedDatabaseOid",
    "expectedCurrentUser",
    "expectedSessionUser",
    "expectedPostgresMajor",
    "connect",
  ]);
  if (binding.version !== "target-binding-v1") fail("TARGET_MISMATCH");
  safeIdentifier(binding.logicalDatabaseName, "TARGET_MISMATCH");
  targetNumericIdentifier(binding.expectedClusterSystemIdentifier, "TARGET_MISMATCH");
  targetNumericIdentifier(binding.expectedDatabaseOid, "TARGET_MISMATCH");
  if (!APPROVED_ROLE_NAMES.includes(binding.expectedCurrentUser)) fail("TARGET_MISMATCH");
  if (!APPROVED_ROLE_NAMES.includes(binding.expectedSessionUser)) fail("TARGET_MISMATCH");
  if (binding.expectedPostgresMajor !== 17 || typeof binding.connect !== "function") {
    fail("TARGET_MISMATCH");
  }
}

export function computeTargetBindingDigest(binding: DurableTargetBinding): string {
  assertObservationBinding(binding);
  return canonicalDigest(CONTRACT_DOMAIN_SEPARATOR, {
    version: binding.version,
    expected_target: {
      cluster_system_identifier: binding.expectedClusterSystemIdentifier,
      database_oid: binding.expectedDatabaseOid,
      logical_database_name: binding.logicalDatabaseName,
      current_user: binding.expectedCurrentUser,
      session_user: binding.expectedSessionUser,
      postgres_major: binding.expectedPostgresMajor,
      in_recovery: false,
      transaction_read_only: true,
    },
  });
}

async function closeConnection(connection: DurableConnection): Promise<void> {
  try {
    await connection.release?.();
  } catch {
    // A close failure never exposes driver details; the original semantic state wins.
  }
}

export async function beginReadOnlyObservation(
  binding: DurableTargetBinding,
): Promise<ReadOnlyObservation> {
  assertObservationBinding(binding);
  let connection: DurableConnection;
  try {
    connection = await binding.connect();
    await connection.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    let result: DurableQueryResult;
    try {
      result = await connection.query(TARGET_IDENTITY_SQL);
    } catch {
      fail("TARGET_IDENTITY_UNAVAILABLE");
    }
    const row = result.rows[0];
    if (!row || result.rows.length !== 1) fail("TARGET_IDENTITY_UNAVAILABLE");
    const identity = normalizeTargetIdentity(row);
    if (
      identity.cluster_system_identifier !== binding.expectedClusterSystemIdentifier ||
      identity.database_oid !== binding.expectedDatabaseOid ||
      identity.logical_database_name !== binding.logicalDatabaseName
    ) fail("TARGET_MISMATCH");
    if (
      identity.current_user !== binding.expectedCurrentUser ||
      identity.session_user !== binding.expectedSessionUser
    ) {
      fail("SESSION_IDENTITY_MISMATCH");
    }
    if (identity.postgres_major !== 17) fail("POSTGRES_VERSION_UNSUPPORTED");
    if (identity.in_recovery) fail("RECOVERY_STATE_UNSUPPORTED");
    if (!identity.transaction_read_only) fail("READ_ONLY_ASSERTION_FAILED");

    let closed = false;
    const close = async (): Promise<void> => {
      if (closed) return;
      closed = true;
      try {
        await connection.query("ROLLBACK");
      } finally {
        await closeConnection(connection);
      }
    };
    return {
      async read(queryId) {
        if (closed) fail("OBSERVATION_FAILED");
        if (!OBSERVATION_QUERY_IDS.includes(queryId)) fail("ARBITRARY_INPUT_REJECTED");
        if (queryId === "target_identity") return { rows: [identity] };
        try {
          switch (queryId) {
            case "role_state":
              return await connection.query(ROLE_STATE_SQL, [APPROVED_ROLE_NAMES]);
            case "membership_state":
              return await connection.query(MEMBERSHIP_STATE_SQL, [APPROVED_ROLE_NAMES]);
            case "ownership_state":
              return await connection.query(OWNERSHIP_STATE_SQL);
            case "privilege_state":
              return await connection.query(PRIVILEGE_STATE_SQL);
            case "default_acl_state":
              return await connection.query(DEFAULT_ACL_STATE_SQL, [APPROVED_ROLE_NAMES]);
            case "runtime_grant_state":
              return await connection.query(RUNTIME_GRANT_STATE_SQL);
            case "migration_journal_state": {
              const exists = await connection.query(MIGRATION_LEDGER_EXISTS_SQL);
              if (exists.rows[0]?.ledger_present !== true) fail("MIGRATION_IDENTITY_MISMATCH");
              return await connection.query(MIGRATION_LEDGER_ROWS_SQL);
            }
            case "readiness_state":
              return { rows: [await readCanonicalVerification(connection) as unknown as Record<string, unknown>] };
            case "runtime_posture_state":
              return { rows: [await readRuntimePosture(connection, identity.current_user) as unknown as Record<string, unknown>] };
            case "unknown_drift_state":
              return { rows: [classifyUnknownDrift((await connection.query(OWNERSHIP_STATE_SQL)).rows)] };
          }
        } catch (error) {
          await close();
          if (error instanceof DurableOperationError) throw error;
          fail("OBSERVATION_FAILED");
        }
      },
      close,
    };
  } catch (error) {
    if (connection!) {
      try {
        await connection.query("ROLLBACK");
      } catch {
        // Keep the safe semantic code below.
      }
      await closeConnection(connection);
    }
    if (error instanceof DurableOperationError) throw error;
    fail("OBSERVATION_FAILED");
  }
}

async function readObservationQuery(
  connection: DurableConnection,
  identity: ReturnType<typeof normalizeTargetIdentity>,
  queryId: ObservationQueryId,
): Promise<{ rows: Array<Record<string, unknown>> }> {
  if (!OBSERVATION_QUERY_IDS.includes(queryId)) fail("ARBITRARY_INPUT_REJECTED");
  try {
    if (queryId === "target_identity") return { rows: [identity] };
    switch (queryId) {
      case "role_state":
        return await connection.query(ROLE_STATE_SQL, [APPROVED_ROLE_NAMES]);
      case "membership_state":
        return await connection.query(MEMBERSHIP_STATE_SQL, [APPROVED_ROLE_NAMES]);
      case "ownership_state":
        return await connection.query(OWNERSHIP_STATE_SQL);
      case "privilege_state":
        return await connection.query(PRIVILEGE_STATE_SQL);
      case "default_acl_state":
        return await connection.query(DEFAULT_ACL_STATE_SQL, [APPROVED_ROLE_NAMES]);
      case "runtime_grant_state":
        return await connection.query(RUNTIME_GRANT_STATE_SQL);
      case "migration_journal_state": {
        const exists = await connection.query(MIGRATION_LEDGER_EXISTS_SQL);
        if (exists.rows[0]?.ledger_present !== true) fail("MIGRATION_IDENTITY_MISMATCH");
        return await connection.query(MIGRATION_LEDGER_ROWS_SQL);
      }
      case "readiness_state":
        return { rows: [await readCanonicalVerification(connection) as unknown as Record<string, unknown>] };
      case "runtime_posture_state":
        return { rows: [await readRuntimePosture(connection, identity.current_user) as unknown as Record<string, unknown>] };
      case "unknown_drift_state":
        return { rows: [classifyUnknownDrift((await connection.query(OWNERSHIP_STATE_SQL)).rows)] };
    }
  } catch (error) {
    if (error instanceof DurableOperationError) throw error;
    fail("OBSERVATION_FAILED");
  }
}

async function observeTargetIdentity(
  connection: DurableConnection,
  binding: DurableTargetBinding,
  requireReadOnly: boolean,
): Promise<ReturnType<typeof normalizeTargetIdentity>> {
  let result: DurableQueryResult;
  try {
    result = await connection.query(TARGET_IDENTITY_SQL);
  } catch {
    fail("TARGET_IDENTITY_UNAVAILABLE");
  }
  if (result.rows.length !== 1) fail("TARGET_IDENTITY_UNAVAILABLE");
  const identity = normalizeTargetIdentity(result.rows[0]);
  if (
    identity.cluster_system_identifier !== binding.expectedClusterSystemIdentifier ||
    identity.database_oid !== binding.expectedDatabaseOid ||
    identity.logical_database_name !== binding.logicalDatabaseName
  ) fail("TARGET_MISMATCH");
  if (identity.current_user !== binding.expectedCurrentUser || identity.session_user !== binding.expectedSessionUser) {
    fail("SESSION_IDENTITY_MISMATCH");
  }
  if (identity.postgres_major !== binding.expectedPostgresMajor) fail("POSTGRES_VERSION_UNSUPPORTED");
  if (identity.in_recovery) fail("RECOVERY_STATE_UNSUPPORTED");
  if (requireReadOnly && !identity.transaction_read_only) fail("READ_ONLY_ASSERTION_FAILED");
  return identity;
}

async function captureMutationPrestate(
  binding: DurableTargetBinding,
  connection: DurableConnection,
  journal: CanonicalMigrationJournalV1,
): Promise<{ prestate: NormalizedPrestateV1; prestate_digest: string }> {
  const identity = await observeTargetIdentity(connection, binding, false);
  if (identity.transaction_read_only) fail("READ_ONLY_ASSERTION_FAILED");
  return normalizeObservedPrestate(
    (queryId) => readObservationQuery(connection, identity, queryId),
    journal,
  );
}

function normalizeTargetIdentity(row: Record<string, unknown>): {
  cluster_system_identifier: string;
  database_oid: string;
  logical_database_name: string;
  current_user: string;
  session_user: string;
  postgres_major: number;
  in_recovery: boolean;
  transaction_read_only: boolean;
} {
  const clusterSystemIdentifier = targetNumericIdentifier(row.cluster_system_identifier, "TARGET_IDENTITY_UNAVAILABLE");
  const databaseOid = targetNumericIdentifier(row.database_oid, "TARGET_IDENTITY_UNAVAILABLE");
  const logicalDatabaseName = safeIdentifier(row.logical_database_name, "TARGET_MISMATCH");
  const currentUser = safeIdentifier(row.current_user, "SESSION_IDENTITY_MISMATCH") as ApprovedRoleName;
  const sessionUser = safeIdentifier(row.session_user, "SESSION_IDENTITY_MISMATCH") as ApprovedRoleName;
  if (!APPROVED_ROLE_NAMES.includes(currentUser) || !APPROVED_ROLE_NAMES.includes(sessionUser)) {
    fail("SESSION_IDENTITY_MISMATCH");
  }
  if (!Number.isInteger(row.postgres_major)) fail("POSTGRES_VERSION_UNSUPPORTED");
  if (typeof row.in_recovery !== "boolean") fail("RECOVERY_STATE_UNSUPPORTED");
  const transactionReadOnly = row.transaction_read_only === true || row.transaction_read_only === "on";
  if (row.transaction_read_only !== true && row.transaction_read_only !== false && row.transaction_read_only !== "on" && row.transaction_read_only !== "off") {
    fail("READ_ONLY_ASSERTION_FAILED");
  }
  return {
    cluster_system_identifier: clusterSystemIdentifier,
    database_oid: databaseOid,
    logical_database_name: logicalDatabaseName,
    current_user: currentUser,
    session_user: sessionUser,
    postgres_major: row.postgres_major as number,
    in_recovery: row.in_recovery,
    transaction_read_only: transactionReadOnly,
  };
}

async function readCanonicalVerification(
  connection: DurableConnection,
): Promise<CanonicalDatabaseVerification> {
  try {
    return await verifyCanonicalPlatformDatabase({
      client: connection as DatabaseReadinessClient,
      requiredTables: REQUIRED_PLATFORM_TABLES,
    });
  } catch (error) {
    if (error instanceof DurableOperationError) throw error;
    fail("OBSERVATION_FAILED");
  }
}

async function readRuntimePosture(
  connection: DurableConnection,
  expectedRole: string,
): Promise<RuntimeDatabaseRoleAuthorityPostureReport> {
  try {
    return await inspectRuntimeDatabaseRoleAuthorityPosture(
      connection,
      PLATFORM_RUNTIME_ROLE,
    );
  } catch (error) {
    if (error instanceof DurableOperationError) throw error;
    fail("OBSERVATION_FAILED");
  }
}

function classifyUnknownDrift(rows: readonly Record<string, unknown>[]): {
  relations: Array<Record<string, string>>;
  indexes: Array<Record<string, string>>;
  sequences: Array<Record<string, string>>;
  types: Array<Record<string, string>>;
  routines: Array<Record<string, string>>;
} {
  const drift = {
    relations: [] as Array<Record<string, string>>,
    indexes: [] as Array<Record<string, string>>,
    sequences: [] as Array<Record<string, string>>,
    types: [] as Array<Record<string, string>>,
    routines: [] as Array<Record<string, string>>,
  };
  for (const row of rows) {
    if (row.is_extension_member === true) continue;
    const objectClass = stringValue(row.object_class, "OBSERVATION_FAILED");
    if (!["relation", "index", "sequence", "type", "routine"].includes(objectClass)) continue;
    const record = {
      qualified_name: stringValue(row.qualified_name, "OBSERVATION_FAILED"),
      owner: stringValue(row.owner, "OBSERVATION_FAILED"),
    };
    if (isCanonicalObjectClassName(objectClass, record.qualified_name)) continue;
    drift[`${objectClass}s` as keyof typeof drift].push(record);
  }
  for (const values of Object.values(drift)) values.sort((a, b) => compareTuple([a.qualified_name, a.owner], [b.qualified_name, b.owner]));
  return drift;
}

const CANONICAL_INDEX_NAMES = new Set([
  "users_pkey", "users_email_unique", "users_status_idx",
  "provider_identities_pkey", "provider_identities_provider_subject_unique",
  "provider_identities_provider_user_unique", "provider_identities_user_id_idx",
  "workspaces_pkey", "workspaces_slug_unique", "workspaces_status_idx",
  "memberships_pkey", "memberships_workspace_user_unique", "memberships_user_id_idx",
  "memberships_workspace_status_idx", "workspace_membership_approvals_pkey",
  "workspace_membership_approvals_pending_unique", "workspace_membership_approvals_email_status_idx",
  "workspace_membership_approvals_workspace_status_idx", "workspace_membership_approvals_requested_by_user_id_idx",
  "invitations_pkey", "invitations_email_status_idx", "invitations_workspace_status_idx",
  "invitations_expires_at_idx", "invitations_invited_by_user_id_idx", "sessions_pkey",
  "sessions_user_id_idx", "sessions_expires_at_idx", "sessions_revoked_at_idx",
  "sessions_user_expiry_idx", "csrf_tokens_pkey", "csrf_tokens_session_id_idx",
  "csrf_tokens_session_hash_purpose_unique", "csrf_tokens_expires_at_idx",
  "auth_states_provider_state_unique", "auth_states_expires_at_idx", "auth_states_consumed_at_idx",
  "audit_events_pkey", "audit_events_workspace_created_at_idx", "audit_events_actor_user_id_idx",
  "audit_events_target_idx", "audit_events_event_type_idx", "apps_pkey", "apps_key_unique",
  "apps_status_idx", "app_launch_tokens_pkey", "app_launch_tokens_token_hash_unique",
  "app_launch_tokens_session_id_idx", "app_launch_tokens_workspace_app_idx",
  "app_launch_tokens_expires_at_idx", "app_launch_tokens_consumed_at_idx",
  "app_entitlements_pkey", "app_entitlements_workspace_app_unique", "app_entitlements_workspace_status_idx",
  "app_entitlements_app_id_idx", "app_entitlements_granted_by_user_id_idx",
  "access_validation_grants_pkey", "access_validation_grants_handle_hash_unique",
  "access_validation_grants_session_id_idx", "access_validation_grants_expiry_idx",
  "__drizzle_migrations_pkey",
]);
const CANONICAL_TABLE_NAMES = new Set<string>(CANONICAL_PLATFORM_TABLES);
const CANONICAL_ENUM_NAMES = new Set<string>(CANONICAL_PLATFORM_ENUM_TYPES);

function isCanonicalObjectClassName(objectClass: string, qualifiedName: string): boolean {
  const [namespace, name] = qualifiedName.split(".", 2);
  if (!namespace || !name) return false;
  if (objectClass === "relation") {
    return namespace === "public" && CANONICAL_TABLE_NAMES.has(name) ||
      namespace === "drizzle" && name === "__drizzle_migrations";
  }
  if (objectClass === "index") return CANONICAL_INDEX_NAMES.has(name);
  if (objectClass === "sequence") return namespace === "drizzle" && name === "__drizzle_migrations_id_seq";
  if (objectClass === "type") return namespace === "public" && CANONICAL_ENUM_NAMES.has(name);
  if (objectClass === "routine") return CANONICAL_PLATFORM_ROUTINES.includes(name as never);
  return false;
}

export interface NormalizedPrestateV1 {
  version: typeof PRESTATE_VERSION;
  target: {
    cluster_system_identifier: string;
    database_oid: string;
    logical_database_name: string;
    current_user: ApprovedRoleName;
    session_user: ApprovedRoleName;
    postgres_major: 17;
    in_recovery: false;
    transaction_read_only: true;
  };
  roles: {
    accepted_role_states: Array<RoleStateV1>;
    unknown_role_references: string[];
  };
  memberships: {
    granted_role: ApprovedRoleName[];
    member: ApprovedRoleName[];
    grantor: ApprovedRoleName[];
    admin_option: boolean[];
    inherit_option: boolean[];
    set_option: boolean[];
  };
  ownership: {
    database_owner: string;
    database_oid: string;
    public_schema_owner: string;
    public_schema_oid: string;
    drizzle_schema_owner: string;
    drizzle_schema_oid: string;
    canonical_relations: OwnershipRecordV1[];
    canonical_indexes: OwnershipRecordV1[];
    canonical_sequences: OwnershipRecordV1[];
    canonical_types: OwnershipRecordV1[];
    canonical_enums: OwnershipRecordV1[];
    canonical_routines: OwnershipRecordV1[];
  };
  privileges: {
    direct: PrivilegeRecordV1[];
    public: PrivilegeRecordV1[];
    grant_options: PrivilegeRecordV1[];
  };
  default_acls: {
    default_acl_oid: string[];
    row_present: boolean[];
    acl_is_null: boolean[];
    creator: string[];
    schema: string[];
    object_type: string[];
    grantee: string[];
    grantor: string[];
    privilege: string[];
    grant_option: boolean[];
  };
  runtime_grant_contract: {
    contract_digest: string;
    observed_direct_grants: ObservedRuntimeTableGrantRecord[];
  };
  migration_journal: {
    journal_version: string;
    dialect: string;
    source_entries: MigrationSourceEntryV1[];
    applied_rows: MigrationAppliedRowV1[];
    applied_prefix_digest: string;
    complete_journal_digest: string;
  };
  canonical_checks: {
    readiness_checks: Record<string, string>;
    migrator_readiness_fields: string[];
    runtime_posture_fields: Record<string, string>;
  };
  unknown_non_extension_drift: {
    relations: Array<Record<string, string>>;
    indexes: Array<Record<string, string>>;
    sequences: Array<Record<string, string>>;
    types: Array<Record<string, string>>;
    routines: Array<Record<string, string>>;
  };
}

export interface RoleStateV1 {
  rolname: ApprovedRoleName;
  role_oid: string;
  rolcanlogin: boolean;
  rolinherit: boolean;
  rolsuper: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
  rolconnlimit: number;
}

export interface OwnershipRecordV1 {
  object_class: string;
  qualified_name: string;
  object_oid: string;
  owner: string;
}

export interface PrivilegeRecordV1 {
  object_class: string;
  qualified_name: string;
  object_oid: string;
  acl_is_null: boolean;
  grantor: string;
  grantee: string;
  privilege: string;
  grant_option: boolean;
}

export interface MigrationSourceEntryV1 {
  idx: number;
  version: string;
  when: string;
  tag: string;
  breakpoints: boolean;
  sql_sha256: string;
}

export interface MigrationAppliedRowV1 {
  when: string;
  sql_sha256: string;
}

type ObservationReader = (
  queryId: ObservationQueryId,
) => Promise<{ rows: Array<Record<string, unknown>> }>;

async function normalizeObservedPrestate(
  read: ObservationReader,
  journal: CanonicalMigrationJournalV1,
): Promise<{ prestate: NormalizedPrestateV1; prestate_digest: string }> {
  const target = (await read("target_identity")).rows[0];
  const roleState = (await read("role_state")).rows;
  const memberships = (await read("membership_state")).rows;
  const ownership = (await read("ownership_state")).rows;
  const privileges = (await read("privilege_state")).rows;
  const defaultAcls = (await read("default_acl_state")).rows;
  const runtimeGrants = (await read("runtime_grant_state")).rows;
  const migrationRows = (await read("migration_journal_state")).rows;
  const readiness = (await read("readiness_state")).rows[0] as unknown as CanonicalDatabaseVerification;
  const runtimePosture = (await read("runtime_posture_state")).rows[0] as unknown as RuntimeDatabaseRoleAuthorityPostureReport;
  const unknownDrift = (await read("unknown_drift_state")).rows[0];
  const appliedRows = migrationRows.map((row) => ({
    when: decimalStringValue(row.when, "MIGRATION_IDENTITY_MISMATCH"),
    sql_sha256: hex(row.sql_sha256, 64, "MIGRATION_IDENTITY_MISMATCH"),
  }));
  assertAppliedPrefix(appliedRows, journal.entries);
  const prestate = normalizePrestate({
    version: PRESTATE_VERSION,
    target: {
      ...(target ?? {}),
      transaction_read_only: true,
    },
    roles: { accepted_role_states: roleState, unknown_role_references: [] },
    memberships: membershipColumns(memberships),
    ownership: ownershipSnapshot(ownership),
    privileges: privilegeSnapshot(privileges),
    default_acls: defaultAclColumns(defaultAcls),
    runtime_grant_contract: {
      contract_digest: RUNTIME_TABLE_GRANT_DIGEST,
      observed_direct_grants: runtimeGrants.map((row) => ({
        objectClass: stringValue(row.object_class, "OBSERVATION_FAILED"),
        schema: stringValue(row.schema, "OBSERVATION_FAILED"),
        objectName: stringValue(row.object_name, "OBSERVATION_FAILED"),
        privilege: stringValue(row.privilege, "OBSERVATION_FAILED"),
        authoritySource: stringValue(row.authority_source, "OBSERVATION_FAILED"),
        grantOption: booleanValue(row.grant_option, "OBSERVATION_FAILED"),
      })),
    },
    migration_journal: {
      journal_version: journal.version,
      dialect: journal.dialect,
      source_entries: journal.entries,
      applied_rows: appliedRows,
      applied_prefix_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, appliedRows),
      complete_journal_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, journal.entries),
    },
    canonical_checks: {
      readiness_checks: readiness.readiness_report.checks,
      migrator_readiness_fields: [...MIGRATOR_READINESS_FIELDS],
      runtime_posture_fields: runtimePostureRecord(runtimePosture),
    },
    unknown_non_extension_drift: unknownDrift ?? {
      relations: [], indexes: [], sequences: [], types: [], routines: [],
    },
  });
  assertFixedRolePosture(prestate, "OBSERVATION_FAILED");
  return { prestate, prestate_digest: canonicalDigest(PRESTATE_DOMAIN_SEPARATOR, prestate) };
}

export async function captureNormalizedPrestate(
  binding: DurableTargetBinding,
  journal?: CanonicalMigrationJournalV1,
): Promise<{ prestate: NormalizedPrestateV1; prestate_digest: string }> {
  if (!journal) fail("MIGRATION_IDENTITY_MISMATCH");
  const observation = await beginReadOnlyObservation(binding);
  try {
    return await normalizeObservedPrestate((queryId) => observation.read(queryId), journal);
  } finally {
    await observation.close();
  }
}

function membershipColumns(rows: readonly Record<string, unknown>[]) {
  const values = rows.map((row) => ({
    granted_role: row.granted_role,
    member: row.member,
    grantor: row.grantor,
    admin_option: row.admin_option,
    inherit_option: row.inherit_option,
    set_option: row.set_option,
  }));
  values.sort((a, b) => compareTuple([a.granted_role, a.member, a.grantor, a.admin_option, a.inherit_option, a.set_option], [b.granted_role, b.member, b.grantor, b.admin_option, b.inherit_option, b.set_option]));
  return {
    granted_role: values.map((value) => value.granted_role),
    member: values.map((value) => value.member),
    grantor: values.map((value) => value.grantor),
    admin_option: values.map((value) => value.admin_option),
    inherit_option: values.map((value) => value.inherit_option),
    set_option: values.map((value) => value.set_option),
  };
}

function ownershipSnapshot(rows: readonly Record<string, unknown>[]) {
  const records = rows.map((row) => ({
    object_class: stringValue(row.object_class, "OBSERVATION_FAILED"),
    qualified_name: stringValue(row.qualified_name, "OBSERVATION_FAILED"),
    object_oid: targetNumericIdentifier(row.object_oid, "OBSERVATION_FAILED"),
    owner: stringValue(row.owner, "OBSERVATION_FAILED"),
    is_extension_member: row.is_extension_member === true,
  }));
  const findRecord = (className: string, name: string) =>
    records.find((row) => row.object_class === className && row.qualified_name === name);
  const collect = (className: string) => records
    .filter((row) => row.object_class === className && row.is_extension_member === false && isCanonicalObjectClassName(className, row.qualified_name))
    .map(({ object_class, qualified_name, object_oid, owner }) => ({ object_class, qualified_name, object_oid, owner }))
    .sort((a, b) => compareTuple([a.qualified_name, a.owner], [b.qualified_name, b.owner]));
  const database = records.find((row) => row.object_class === "database");
  const publicSchema = findRecord("schema", "public");
  const drizzleSchema = findRecord("schema", "drizzle");
  return {
    database_owner: database?.owner ?? "",
    database_oid: database?.object_oid ?? "",
    public_schema_owner: publicSchema?.owner ?? "",
    public_schema_oid: publicSchema?.object_oid ?? "",
    drizzle_schema_owner: drizzleSchema?.owner ?? "",
    drizzle_schema_oid: drizzleSchema?.object_oid ?? "",
    canonical_relations: collect("relation"),
    canonical_indexes: collect("index"),
    canonical_sequences: collect("sequence"),
    canonical_types: collect("type"),
    canonical_enums: collect("type"),
    canonical_routines: collect("routine"),
  };
}

function privilegeSnapshot(rows: readonly Record<string, unknown>[]) {
  const values = rows.map((row) => ({
    object_class: stringValue(row.object_class, "OBSERVATION_FAILED"),
    qualified_name: stringValue(row.qualified_name, "OBSERVATION_FAILED"),
    object_oid: targetNumericIdentifier(row.object_oid, "OBSERVATION_FAILED"),
    acl_is_null: booleanValue(row.acl_is_null, "OBSERVATION_FAILED"),
    grantor: row.privilege === null ? null : stringAllowEmpty(row.grantor, "OBSERVATION_FAILED"),
    grantee: row.privilege === null ? null : stringValue(row.grantee, "OBSERVATION_FAILED"),
    privilege: row.privilege === null ? null : stringValue(row.privilege, "OBSERVATION_FAILED"),
    grant_option: row.privilege === null ? null : booleanValue(row.grant_option, "OBSERVATION_FAILED"),
  }));
  values.sort((a, b) => compareTuple(Object.values(a), Object.values(b)));
  return {
    direct: values.filter((value) => value.grantee !== "PUBLIC"),
    public: values.filter((value) => value.grantee === "PUBLIC"),
    grant_options: values.filter((value) => value.grant_option),
  };
}

function defaultAclColumns(rows: readonly Record<string, unknown>[]) {
  const values = rows.map((row) => ({
    default_acl_oid: targetNumericIdentifier(row.default_acl_oid, "OBSERVATION_FAILED"),
    row_present: booleanValue(row.row_present, "OBSERVATION_FAILED"),
    acl_is_null: booleanValue(row.acl_is_null, "OBSERVATION_FAILED"),
    creator: stringValue(row.creator, "OBSERVATION_FAILED"),
    schema: stringAllowEmpty(row.schema, "OBSERVATION_FAILED"),
    object_type: stringValue(row.object_type, "OBSERVATION_FAILED"),
    grantee: row.privilege === null ? "" : stringValue(row.grantee, "OBSERVATION_FAILED"),
    grantor: row.privilege === null || row.grantor === null ? "" : stringValue(row.grantor, "OBSERVATION_FAILED"),
    privilege: row.privilege === null ? "" : stringValue(row.privilege, "OBSERVATION_FAILED"),
    grant_option: row.grant_option === null ? false : booleanValue(row.grant_option, "OBSERVATION_FAILED"),
  }));
  values.sort((a, b) => compareTuple([a.creator, a.schema, a.object_type, a.default_acl_oid, a.grantee, a.grantor, a.privilege, a.grant_option], [b.creator, b.schema, b.object_type, b.default_acl_oid, b.grantee, b.grantor, b.privilege, b.grant_option]));
  return {
    default_acl_oid: values.map((value) => value.default_acl_oid),
    row_present: values.map((value) => value.row_present),
    acl_is_null: values.map((value) => value.acl_is_null),
    creator: values.map((value) => value.creator),
    schema: values.map((value) => value.schema),
    object_type: values.map((value) => value.object_type),
    grantee: values.map((value) => value.grantee),
    grantor: values.map((value) => value.grantor),
    privilege: values.map((value) => value.privilege),
    grant_option: values.map((value) => value.grant_option),
  };
}

function runtimePostureRecord(report: RuntimeDatabaseRoleAuthorityPostureReport): Record<string, string> {
  return Object.fromEntries(
    Object.entries(report).map(([key, value]) => [key, value]),
  );
}

export function normalizePrestate(value: unknown): NormalizedPrestateV1 {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, [
    "version", "target", "roles", "memberships", "ownership", "privileges",
    "default_acls", "runtime_grant_contract", "migration_journal",
    "canonical_checks", "unknown_non_extension_drift",
  ], "PRESTATE_INVALID");
  if (value.version !== PRESTATE_VERSION) fail("PRESTATE_INVALID");
  const target = normalizePrestateTarget(value.target);
  const roles = normalizeRoles(value.roles);
  const memberships = normalizeMemberships(value.memberships);
  const ownership = normalizeOwnership(value.ownership);
  const privileges = normalizePrivileges(value.privileges);
  const defaultAcls = normalizeDefaultAcls(value.default_acls);
  const runtimeGrantContract = normalizeRuntimeGrantContract(value.runtime_grant_contract);
  const migrationJournal = normalizeMigrationJournal(value.migration_journal);
  const canonicalChecks = normalizeCanonicalChecks(value.canonical_checks);
  const drift = normalizeDrift(value.unknown_non_extension_drift);
  const result: NormalizedPrestateV1 = {
    version: PRESTATE_VERSION,
    target,
    roles,
    memberships,
    ownership,
    privileges,
    default_acls: defaultAcls,
    runtime_grant_contract: runtimeGrantContract,
    migration_journal: migrationJournal,
    canonical_checks: canonicalChecks,
    unknown_non_extension_drift: drift,
  };
  if (Object.values(drift).some((items) => items.length > 0)) fail("UNKNOWN_DRIFT");
  return deepFreeze(result);
}

function normalizePrestateTarget(value: unknown): NormalizedPrestateV1["target"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["cluster_system_identifier", "database_oid", "logical_database_name", "current_user", "session_user", "postgres_major", "in_recovery", "transaction_read_only"], "PRESTATE_INVALID");
  const clusterSystemIdentifier = targetNumericIdentifier(value.cluster_system_identifier, "PRESTATE_INVALID");
  const databaseOid = targetNumericIdentifier(value.database_oid, "PRESTATE_INVALID");
  const currentUser = stringValue(value.current_user, "PRESTATE_INVALID") as ApprovedRoleName;
  const sessionUser = stringValue(value.session_user, "PRESTATE_INVALID") as ApprovedRoleName;
  if (!APPROVED_ROLE_NAMES.includes(currentUser) || !APPROVED_ROLE_NAMES.includes(sessionUser)) fail("PRESTATE_INVALID");
  if (value.postgres_major !== 17 || value.in_recovery !== false || value.transaction_read_only !== true) fail("PRESTATE_INVALID");
  return {
    cluster_system_identifier: clusterSystemIdentifier,
    database_oid: databaseOid,
    logical_database_name: safeIdentifier(value.logical_database_name, "PRESTATE_INVALID"),
    current_user: currentUser,
    session_user: sessionUser,
    postgres_major: 17,
    in_recovery: false,
    transaction_read_only: true,
  };
}

function normalizeRoles(value: unknown): NormalizedPrestateV1["roles"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["accepted_role_states", "unknown_role_references"], "PRESTATE_INVALID");
  if (!Array.isArray(value.accepted_role_states) || !Array.isArray(value.unknown_role_references)) fail("PRESTATE_INVALID");
  const accepted = value.accepted_role_states.map((raw) => {
    assertRecord(raw, "PRESTATE_INVALID");
    assertExactKeys(raw, ["rolname", "role_oid", "rolcanlogin", "rolinherit", "rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls", "rolconnlimit"], "PRESTATE_INVALID");
    const rolname = stringValue(raw.rolname, "PRESTATE_INVALID") as ApprovedRoleName;
    if (!APPROVED_ROLE_NAMES.includes(rolname)) fail("PRESTATE_INVALID");
    const roleOid = targetNumericIdentifier(raw.role_oid, "PRESTATE_INVALID");
    if (!Number.isSafeInteger(raw.rolconnlimit) || (raw.rolconnlimit as number) < -1) fail("PRESTATE_INVALID");
    return {
      rolname,
      role_oid: roleOid,
      rolcanlogin: booleanValue(raw.rolcanlogin, "PRESTATE_INVALID"),
      rolinherit: booleanValue(raw.rolinherit, "PRESTATE_INVALID"),
      rolsuper: booleanValue(raw.rolsuper, "PRESTATE_INVALID"),
      rolcreatedb: booleanValue(raw.rolcreatedb, "PRESTATE_INVALID"),
      rolcreaterole: booleanValue(raw.rolcreaterole, "PRESTATE_INVALID"),
      rolreplication: booleanValue(raw.rolreplication, "PRESTATE_INVALID"),
      rolbypassrls: booleanValue(raw.rolbypassrls, "PRESTATE_INVALID"),
      rolconnlimit: raw.rolconnlimit as number,
    } satisfies RoleStateV1;
  }).sort((a, b) => compareTuple([a.rolname], [b.rolname]));
  const unknown = value.unknown_role_references.map((raw) => safeIdentifier(raw, "PRESTATE_INVALID"));
  if (unknown.some((name) => APPROVED_ROLE_NAMES.includes(name as ApprovedRoleName))) fail("PRESTATE_INVALID");
  unknown.sort();
  return { accepted_role_states: accepted, unknown_role_references: unknown };
}

const FIXED_ROLE_POSTURES: Readonly<Record<string, Readonly<Record<string, boolean>>>> = Object.freeze({
  platform_runtime: Object.freeze({ rolcanlogin: false, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false }),
  platform_app: Object.freeze({ rolcanlogin: true, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false }),
  platform_migrator: Object.freeze({ rolcanlogin: true, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false }),
});

function assertFixedRolePosture(prestate: NormalizedPrestateV1, code: SemanticCode = "PRESTATE_INVALID"): void {
  for (const [roleName, expected] of Object.entries(FIXED_ROLE_POSTURES)) {
    const matches = prestate.roles.accepted_role_states.filter((role) => role.rolname === roleName);
    if (matches.length !== 1) fail(code);
    const role = matches[0];
    for (const [field, expectedValue] of Object.entries(expected)) {
      if (role[field as keyof RoleStateV1] !== expectedValue) fail(code);
    }
  }
  const runtime = prestate.ownership.canonical_relations.concat(
    prestate.ownership.canonical_indexes,
    prestate.ownership.canonical_sequences,
    prestate.ownership.canonical_types,
  );
  if (runtime.some((record) => record.owner === "platform_runtime")) fail(code);
  if (prestate.memberships.granted_role.some((role, index) =>
    role === "platform_runtime" || prestate.memberships.member[index] === "platform_runtime" || prestate.memberships.grantor[index] === "platform_runtime")) fail(code);
}

function normalizeMemberships(value: unknown): NormalizedPrestateV1["memberships"] {
  assertRecord(value, "PRESTATE_INVALID");
  const fields = ["granted_role", "member", "grantor", "admin_option", "inherit_option", "set_option"] as const;
  assertExactKeys(value, fields, "PRESTATE_INVALID");
  const arrays = Object.fromEntries(fields.map((field) => [field, value[field] as unknown[]])) as Record<(typeof fields)[number], unknown[]>;
  if (fields.some((field) => !Array.isArray(arrays[field]))) fail("PRESTATE_INVALID");
  const length = arrays.granted_role.length;
  if (fields.some((field) => arrays[field].length !== length)) fail("PRESTATE_INVALID");
  const rows = Array.from({ length }, (_, index) => {
    const grantedRole = stringValue(arrays.granted_role[index], "PRESTATE_INVALID") as ApprovedRoleName;
    const member = stringValue(arrays.member[index], "PRESTATE_INVALID") as ApprovedRoleName;
    const grantor = stringValue(arrays.grantor[index], "PRESTATE_INVALID") as ApprovedRoleName;
    if (!APPROVED_ROLE_NAMES.includes(grantedRole) || !APPROVED_ROLE_NAMES.includes(member) || !APPROVED_ROLE_NAMES.includes(grantor)) fail("PRESTATE_INVALID");
    return {
      granted_role: grantedRole,
      member,
      grantor,
      admin_option: booleanValue(arrays.admin_option[index], "PRESTATE_INVALID"),
      inherit_option: booleanValue(arrays.inherit_option[index], "PRESTATE_INVALID"),
      set_option: booleanValue(arrays.set_option[index], "PRESTATE_INVALID"),
    };
  }).sort((a, b) => compareTuple(Object.values(a), Object.values(b)));
  return {
    granted_role: rows.map((row) => row.granted_role),
    member: rows.map((row) => row.member),
    grantor: rows.map((row) => row.grantor),
    admin_option: rows.map((row) => row.admin_option),
    inherit_option: rows.map((row) => row.inherit_option),
    set_option: rows.map((row) => row.set_option),
  };
}

function normalizeOwnership(value: unknown): NormalizedPrestateV1["ownership"] {
  assertRecord(value, "PRESTATE_INVALID");
  const fields = ["database_owner", "database_oid", "public_schema_owner", "public_schema_oid", "drizzle_schema_owner", "drizzle_schema_oid", "canonical_relations", "canonical_indexes", "canonical_sequences", "canonical_types", "canonical_enums", "canonical_routines"] as const;
  assertExactKeys(value, fields, "PRESTATE_INVALID");
  for (const field of fields.slice(6)) if (!Array.isArray(value[field])) fail("PRESTATE_INVALID");
  const records = (field: string) => (value[field] as unknown[]).map((raw) => {
    assertRecord(raw, "PRESTATE_INVALID");
    assertExactKeys(raw, ["object_class", "qualified_name", "object_oid", "owner"], "PRESTATE_INVALID");
    const objectClass = safeIdentifier(raw.object_class, "PRESTATE_INVALID");
    const qualifiedName = stringValue(raw.qualified_name, "PRESTATE_INVALID");
    const objectOid = targetNumericIdentifier(raw.object_oid, "PRESTATE_INVALID");
    const owner = safeIdentifier(raw.owner, "PRESTATE_INVALID");
    if (!/^[a-z_][a-z0-9_$]{0,62}\.[a-z_][a-z0-9_$()$-]{0,126}$/u.test(qualifiedName)) fail("PRESTATE_INVALID");
    return { object_class: objectClass, qualified_name: qualifiedName, object_oid: objectOid, owner };
  }).sort((a, b) => compareTuple([a.qualified_name, a.owner], [b.qualified_name, b.owner]));
  return {
    database_owner: safeIdentifier(value.database_owner, "PRESTATE_INVALID"),
    database_oid: targetNumericIdentifier(value.database_oid, "PRESTATE_INVALID"),
    public_schema_owner: safeIdentifier(value.public_schema_owner, "PRESTATE_INVALID"),
    public_schema_oid: targetNumericIdentifier(value.public_schema_oid, "PRESTATE_INVALID"),
    drizzle_schema_owner: safeIdentifier(value.drizzle_schema_owner, "PRESTATE_INVALID"),
    drizzle_schema_oid: targetNumericIdentifier(value.drizzle_schema_oid, "PRESTATE_INVALID"),
    canonical_relations: records("canonical_relations"),
    canonical_indexes: records("canonical_indexes"),
    canonical_sequences: records("canonical_sequences"),
    canonical_types: records("canonical_types"),
    canonical_enums: records("canonical_enums"),
    canonical_routines: records("canonical_routines"),
  };
}

function normalizePrivileges(value: unknown): NormalizedPrestateV1["privileges"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["direct", "public", "grant_options"], "PRESTATE_INVALID");
  const normalize = (rawRows: unknown) => {
    if (!Array.isArray(rawRows)) fail("PRESTATE_INVALID");
    return rawRows.map((raw) => {
      assertRecord(raw, "PRESTATE_INVALID");
      assertExactKeys(raw, ["object_class", "qualified_name", "object_oid", "acl_is_null", "grantor", "grantee", "privilege", "grant_option"], "PRESTATE_INVALID");
      const aclIsNull = booleanValue(raw.acl_is_null, "PRESTATE_INVALID");
      const emptyAcl = raw.privilege === null || raw.privilege === undefined || (
        raw.privilege === "" &&
        (raw.grantor === "" || raw.grantor === null) &&
        (raw.grantee === "" || raw.grantee === null) &&
        (raw.grant_option === false || raw.grant_option === null)
      );
      if (emptyAcl && ![null, false].includes(raw.grant_option as null | boolean)) fail("PRESTATE_INVALID");
      if (!emptyAcl && raw.grant_option !== true && raw.grant_option !== false) fail("PRESTATE_INVALID");
      const grantor = emptyAcl ? "" : safeIdentifier(raw.grantor, "PRESTATE_INVALID");
      const grantee = emptyAcl ? "" : stringValue(raw.grantee, "PRESTATE_INVALID");
      const privilege = emptyAcl ? "" : safeIdentifier(String(raw.privilege).toLowerCase(), "PRESTATE_INVALID");
      const result = {
        object_class: safeIdentifier(raw.object_class, "PRESTATE_INVALID"),
        qualified_name: stringValue(raw.qualified_name, "PRESTATE_INVALID"),
        object_oid: targetNumericIdentifier(raw.object_oid, "PRESTATE_INVALID"),
        acl_is_null: aclIsNull,
        grantor,
        grantee,
        privilege,
        grant_option: emptyAcl ? false : raw.grant_option as boolean,
      };
      if (result.grantee !== "" && !/^[a-z_][a-z0-9_$]{0,62}$/u.test(result.grantee) && result.grantee !== "PUBLIC") fail("PRESTATE_INVALID");
      return result;
    }).sort((a, b) => compareTuple(Object.values(a), Object.values(b)));
  };
  return {
    direct: normalize(value.direct),
    public: normalize(value.public),
    grant_options: normalize(value.grant_options),
  };
}

function normalizeDefaultAcls(value: unknown): NormalizedPrestateV1["default_acls"] {
  assertRecord(value, "PRESTATE_INVALID");
  const fields = ["default_acl_oid", "row_present", "acl_is_null", "creator", "schema", "object_type", "grantee", "grantor", "privilege", "grant_option"] as const;
  assertExactKeys(value, fields, "PRESTATE_INVALID");
  const arrays = Object.fromEntries(fields.map((field) => [field, value[field] as unknown[]])) as Record<(typeof fields)[number], unknown[]>;
  if (fields.some((field) => !Array.isArray(arrays[field]))) fail("PRESTATE_INVALID");
  const length = arrays.creator.length;
  if (fields.some((field) => arrays[field].length !== length)) fail("PRESTATE_INVALID");
  const rows = Array.from({ length }, (_, index) => ({
    default_acl_oid: targetNumericIdentifier(arrays.default_acl_oid[index], "PRESTATE_INVALID"),
    row_present: booleanValue(arrays.row_present[index], "PRESTATE_INVALID"),
    acl_is_null: booleanValue(arrays.acl_is_null[index], "PRESTATE_INVALID"),
    creator: safeIdentifier(arrays.creator[index], "PRESTATE_INVALID"),
    schema: stringAllowEmpty(arrays.schema[index], "PRESTATE_INVALID"),
    object_type: stringValue(arrays.object_type[index], "PRESTATE_INVALID"),
    grantee: stringAllowEmpty(arrays.grantee[index], "PRESTATE_INVALID"),
    grantor: stringAllowEmpty(arrays.grantor[index], "PRESTATE_INVALID"),
    privilege: stringAllowEmpty(arrays.privilege[index], "PRESTATE_INVALID"),
    grant_option: booleanValue(arrays.grant_option[index], "PRESTATE_INVALID"),
  })).sort((a, b) => compareTuple(Object.values(a), Object.values(b)));
  return {
    default_acl_oid: rows.map((row) => row.default_acl_oid),
    row_present: rows.map((row) => row.row_present),
    acl_is_null: rows.map((row) => row.acl_is_null),
    creator: rows.map((row) => row.creator),
    schema: rows.map((row) => row.schema),
    object_type: rows.map((row) => row.object_type),
    grantee: rows.map((row) => row.grantee),
    grantor: rows.map((row) => row.grantor),
    privilege: rows.map((row) => row.privilege),
    grant_option: rows.map((row) => row.grant_option),
  };
}

function normalizeRuntimeGrantContract(value: unknown): NormalizedPrestateV1["runtime_grant_contract"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["contract_digest", "observed_direct_grants"], "PRESTATE_INVALID");
  const contractDigest = hex(value.contract_digest, 64, "PRESTATE_INVALID");
  if (!Array.isArray(value.observed_direct_grants)) fail("PRESTATE_INVALID");
  const observed = value.observed_direct_grants.map((raw) => {
    assertRecord(raw, "PRESTATE_INVALID");
    assertExactKeys(raw, ["objectClass", "schema", "objectName", "privilege", "authoritySource", "grantOption"], "PRESTATE_INVALID");
    return {
      objectClass: stringValue(raw.objectClass, "PRESTATE_INVALID"),
      schema: stringValue(raw.schema, "PRESTATE_INVALID"),
      objectName: stringValue(raw.objectName, "PRESTATE_INVALID"),
      privilege: stringValue(raw.privilege, "PRESTATE_INVALID"),
      authoritySource: stringValue(raw.authoritySource, "PRESTATE_INVALID"),
      grantOption: booleanValue(raw.grantOption, "PRESTATE_INVALID"),
    };
  }).sort((a, b) => compareTuple(Object.values(a), Object.values(b)));
  try {
    assertRuntimeTableGrantSet(observed);
  } catch {
    fail("PRESTATE_INVALID");
  }
  return { contract_digest: contractDigest, observed_direct_grants: observed };
}

function normalizeMigrationJournal(value: unknown): NormalizedPrestateV1["migration_journal"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["journal_version", "dialect", "source_entries", "applied_rows", "applied_prefix_digest", "complete_journal_digest"], "PRESTATE_INVALID");
  if (!Array.isArray(value.source_entries) || !Array.isArray(value.applied_rows)) fail("PRESTATE_INVALID");
  const sourceEntries = value.source_entries.map((raw) => {
    assertRecord(raw, "PRESTATE_INVALID");
    assertExactKeys(raw, ["idx", "version", "when", "tag", "breakpoints", "sql_sha256"], "PRESTATE_INVALID");
    return {
      idx: nonnegativeInteger(raw.idx, "PRESTATE_INVALID"),
      version: stringValue(raw.version, "PRESTATE_INVALID"),
      when: decimalStringValue(raw.when),
      tag: stringValue(raw.tag, "PRESTATE_INVALID"),
      breakpoints: booleanValue(raw.breakpoints, "PRESTATE_INVALID"),
      sql_sha256: hex(raw.sql_sha256, 64, "PRESTATE_INVALID"),
    };
  });
  sourceEntries.forEach((entry, index) => {
    if (entry.idx !== index) fail("PRESTATE_INVALID");
  });
  const appliedRows = value.applied_rows.map((raw) => {
    assertRecord(raw, "PRESTATE_INVALID");
    assertExactKeys(raw, ["when", "sql_sha256"], "PRESTATE_INVALID");
    return { when: decimalStringValue(raw.when), sql_sha256: hex(raw.sql_sha256, 64, "PRESTATE_INVALID") };
  });
  const digest = hex(value.applied_prefix_digest, 64, "PRESTATE_INVALID");
  const computed = canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, appliedRows);
  if (digest !== computed) fail("PRESTATE_INVALID");
  const completeJournalDigest = hex(value.complete_journal_digest, 64, "PRESTATE_INVALID");
  if (completeJournalDigest !== canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, sourceEntries)) fail("PRESTATE_INVALID");
  return {
    journal_version: stringValue(value.journal_version, "PRESTATE_INVALID"),
    dialect: stringValue(value.dialect, "PRESTATE_INVALID"),
    source_entries: sourceEntries,
    applied_rows: appliedRows,
    applied_prefix_digest: digest,
    complete_journal_digest: completeJournalDigest,
  };
}

function decimalStringValue(value: unknown, code: SemanticCode = "PRESTATE_INVALID"): string {
  if (typeof value === "bigint") return value.toString(10);
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value === "string" && /^\d+$/u.test(value)) return value;
  fail(code);
}

function normalizeCanonicalChecks(value: unknown): NormalizedPrestateV1["canonical_checks"] {
  assertRecord(value, "PRESTATE_INVALID");
  assertExactKeys(value, ["readiness_checks", "migrator_readiness_fields", "runtime_posture_fields"], "PRESTATE_INVALID");
  const readinessChecks = normalizeStringRecord(value.readiness_checks, "PRESTATE_INVALID");
  if (!Array.isArray(value.migrator_readiness_fields) || value.migrator_readiness_fields.some((field) => typeof field !== "string")) fail("PRESTATE_INVALID");
  const fields = [...value.migrator_readiness_fields].sort();
  const runtimeFields = normalizeStringRecord(value.runtime_posture_fields, "PRESTATE_INVALID");
  return { readiness_checks: readinessChecks, migrator_readiness_fields: fields, runtime_posture_fields: runtimeFields };
}

function normalizeStringRecord(value: unknown, code: SemanticCode): Record<string, string> {
  assertRecord(value, code);
  const result: Record<string, string> = {};
  for (const key of Object.keys(value).sort()) result[stringValue(key, code)] = stringValue(value[key], code);
  return result;
}

function normalizeDrift(value: unknown): NormalizedPrestateV1["unknown_non_extension_drift"] {
  assertRecord(value, "PRESTATE_INVALID");
  const fields = ["relations", "indexes", "sequences", "types", "routines"] as const;
  assertExactKeys(value, fields, "PRESTATE_INVALID");
  const normalize = (raw: unknown) => {
    if (!Array.isArray(raw)) fail("PRESTATE_INVALID");
    return raw.map((item) => {
      assertRecord(item, "PRESTATE_INVALID");
      const keys = Object.keys(item).sort();
      if (keys.some((key) => !["qualified_name", "owner", "kind"].includes(key))) fail("PRESTATE_INVALID");
      const qualifiedName = stringValue(item.qualified_name, "PRESTATE_INVALID");
      const owner = stringValue(item.owner, "PRESTATE_INVALID");
      return {
        ...(item.kind === undefined ? {} : { kind: stringValue(item.kind, "PRESTATE_INVALID") }),
        qualified_name: qualifiedName,
        owner,
      };
    }).sort((a, b) => compareTuple([a.qualified_name, a.owner, a.kind], [b.qualified_name, b.owner, b.kind]));
  };
  return {
    relations: normalize(value.relations),
    indexes: normalize(value.indexes),
    sequences: normalize(value.sequences),
    types: normalize(value.types),
    routines: normalize(value.routines),
  };
}

export interface CanonicalObjectReferenceV1 {
  object_class: "database" | "schema" | "relation" | "index" | "sequence" | "type" | "enum" | "routine";
  qualified_name: string;
}

export interface OwnershipOperationV1 {
  kind: "ownership";
  action: "set_owner";
  object: CanonicalObjectReferenceV1;
  previous_owner: ApprovedReceiptRoleName;
  next_owner: ApprovedReceiptRoleName;
}

export interface PrivilegeOperationV1 {
  kind: "privilege";
  action: "grant" | "revoke";
  object: CanonicalObjectReferenceV1;
  principal: ApprovedPrincipal;
  privilege: string;
  grant_option: boolean;
  previous_grant_option: boolean;
}

export interface MembershipOperationV1 {
  kind: "membership";
  action: "grant" | "revoke";
  granted_role: ApprovedRoleName;
  member: ApprovedRoleName;
  grantor: ApprovedRoleName;
  admin_option: boolean;
  inherit_option: boolean;
  set_option: boolean;
  previous: {
    present: boolean;
    admin_option: boolean;
    inherit_option: boolean;
    set_option: boolean;
  };
}

export interface DefaultAclOperationV1 {
  kind: "default_acl";
  action: "grant" | "revoke";
  creator: ApprovedRoleName;
  schema: "public" | "drizzle";
  object_type: "table" | "sequence" | "routine";
  principal: ApprovedPrincipal;
  privilege: "DELETE" | "INSERT" | "REFERENCES" | "SELECT" | "TRIGGER" | "TRUNCATE" | "UPDATE" | "EXECUTE" | "USAGE";
  grant_option: boolean;
  previous_grant_option: boolean;
}

export interface RolePostureOperationV1 {
  kind: "role_posture";
  role: "platform_runtime" | "platform_migrator" | "platform_app";
  attributes: RoleAttributesV1;
  previous_attributes: RoleAttributesV1;
}

export interface RoleAttributesV1 {
  rolcanlogin: boolean;
  rolinherit: boolean;
  rolsuper: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
}

export interface MigrationOperationV1 {
  kind: "migration";
  tag: string;
  journal_index: number;
  when: string;
  sql_sha256: string;
  expected_applied_prefix_digest: string;
  expected_post_journal_digest: string;
}

export type DurableOperationV1 =
  | OwnershipOperationV1
  | PrivilegeOperationV1
  | MembershipOperationV1
  | DefaultAclOperationV1
  | RolePostureOperationV1
  | MigrationOperationV1;

export interface DurablePlanV1 {
  version: typeof PLAN_VERSION;
  expected_git_sha: string;
  contract_digest: string;
  target_binding_digest: string;
  prestate_digest: string;
  operation_kind: OperationKind;
  operations: readonly DurableOperationV1[];
  plan_digest: string;
}

const CANONICAL_MIGRATION_TAGS = new Set([
  "0000_overconfident_onslaught",
  "0001_lovely_famine",
  "0002_futuristic_aaron_stack",
  "0003_worthless_scourge",
  "0004_illegal_william_stryker",
  "0005_sqag_app_key_migration",
  "0006_optimal_tomorrow_man",
  "0007_remove_legacy_kqag_tables",
  "0009_wonderful_star_brand",
  "0010_admin_operator_viewer_role_collapse",
]);

export function createDurablePlan(input: {
  expected_git_sha: string;
  contract_digest: string;
  target_binding_digest: string;
  prestate_digest: string;
  operation_kind?: OperationKind;
  operations: readonly DurableOperationV1[];
}): DurablePlanV1 {
  const expectedGitSha = hex(input.expected_git_sha, 40);
  const contractDigest = hex(input.contract_digest, 64);
  const targetBindingDigest = hex(input.target_binding_digest, 64);
  const prestateDigest = hex(input.prestate_digest, 64);
  if (!Array.isArray(input.operations)) fail("ARBITRARY_INPUT_REJECTED");
  const operations = input.operations.map(normalizeOperation);
  const kinds = new Set(operations.map((operation) => operation.kind));
  if (kinds.size > 1) fail("OPERATION_UNSUPPORTED");
  const operationKind = input.operation_kind ?? operations[0]?.kind ?? "migration";
  if (!OPERATION_KINDS.includes(operationKind) || (operations.length > 0 && operations.some((operation) => operation.kind !== operationKind))) fail("ARBITRARY_INPUT_REJECTED");
  if (operationKind === "membership" || operationKind === "role_posture") fail("OPERATION_UNSUPPORTED");
  if (operationKind === "migration" && operations.some((operation) => operation.kind !== "migration")) fail("OPERATION_UNSUPPORTED");
  if (operationKind !== "migration" && operations.some((operation) => operation.kind === "migration")) fail("OPERATION_UNSUPPORTED");
  const ranks = operations.map((operation) => operationRank(operation.kind));
  if (ranks.some((rank, index) => index > 0 && rank < ranks[index - 1])) fail("OPERATION_UNSUPPORTED");
  const payload = {
    version: PLAN_VERSION,
    expected_git_sha: expectedGitSha,
    contract_digest: contractDigest,
    target_binding_digest: targetBindingDigest,
    prestate_digest: prestateDigest,
    operation_kind: operationKind,
    operations,
  };
  return deepFreeze({ ...payload, plan_digest: canonicalDigest(PLAN_DOMAIN_SEPARATOR, payload) });
}

function operationRank(kind: OperationKind): number {
  return {
    role_posture: 1,
    membership: 2,
    ownership: 3,
    privilege: 4,
    default_acl: 5,
    migration: 6,
  }[kind];
}

function normalizeOperation(operation: DurableOperationV1): DurableOperationV1 {
  assertRecord(operation);
  const kind = stringValue(operation.kind) as OperationKind;
  if (!OPERATION_KINDS.includes(kind)) fail("ARBITRARY_INPUT_REJECTED");
  switch (kind) {
    case "ownership":
      return normalizeOwnershipOperation(operation);
    case "privilege":
      return normalizePrivilegeOperation(operation);
    case "membership":
      fail("OPERATION_UNSUPPORTED");
    case "default_acl":
      return normalizeDefaultAclOperation(operation);
    case "role_posture":
      fail("OPERATION_UNSUPPORTED");
    case "migration":
      return normalizeMigrationOperation(operation);
  }
}

function normalizeCanonicalObject(value: unknown): CanonicalObjectReferenceV1 {
  assertRecord(value);
  assertExactKeys(value, ["object_class", "qualified_name"]);
  const objectClass = stringValue(value.object_class);
  const qualifiedName = stringValue(value.qualified_name);
  if (!["database", "schema", "relation", "index", "sequence", "type"].includes(objectClass)) fail("OPERATION_UNSUPPORTED");
  if (!isCanonicalObjectClassName(objectClass, qualifiedName) && !(objectClass === "schema" && ["public", "drizzle"].includes(qualifiedName)) && !(objectClass === "database" && qualifiedName === "__current_database__")) fail("ARBITRARY_INPUT_REJECTED");
  return { object_class: objectClass as CanonicalObjectReferenceV1["object_class"], qualified_name: qualifiedName };
}

function normalizeOwnershipOperation(value: Record<string, unknown>): OwnershipOperationV1 {
  assertExactKeys(value, ["kind", "action", "object", "previous_owner", "next_owner"]);
  if (value.action !== "set_owner") fail("ARBITRARY_INPUT_REJECTED");
  return {
    kind: "ownership",
    action: "set_owner",
    object: normalizeCanonicalObject(value.object),
    previous_owner: normalizeReceiptRole(value.previous_owner),
    next_owner: normalizeReceiptRole(value.next_owner),
  };
}

function normalizePrivilegeOperation(value: Record<string, unknown>): PrivilegeOperationV1 {
  assertExactKeys(value, ["kind", "action", "object", "principal", "privilege", "grant_option", "previous_grant_option"]);
  if (value.action !== "grant" && value.action !== "revoke") fail("ARBITRARY_INPUT_REJECTED");
  const principal = normalizePrincipal(value.principal);
  const privilege = stringValue(value.privilege).toUpperCase();
  const object = normalizeCanonicalObject(value.object);
  if (object.object_class === "index") fail("OPERATION_UNSUPPORTED");
  const privilegesByObjectClass: Record<string, readonly string[]> = {
    database: ["CONNECT", "CREATE", "TEMPORARY"],
    schema: ["CREATE", "USAGE"],
    relation: ["DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"],
    sequence: ["SELECT", "UPDATE", "USAGE"],
    type: ["USAGE"],
  };
  if (!privilegesByObjectClass[object.object_class]?.includes(privilege)) fail("OPERATION_UNSUPPORTED");
  return {
    kind: "privilege",
    action: value.action,
    object,
    principal,
    privilege,
    grant_option: booleanValue(value.grant_option),
    previous_grant_option: booleanValue(value.previous_grant_option),
  };
}

function normalizeMembershipOperation(value: Record<string, unknown>): MembershipOperationV1 {
  assertExactKeys(value, ["kind", "action", "granted_role", "member", "grantor", "admin_option", "inherit_option", "set_option", "previous"]);
  if (value.action !== "grant" && value.action !== "revoke") fail("ARBITRARY_INPUT_REJECTED");
  const grantedRole = normalizeApprovedRole(value.granted_role);
  const member = normalizeApprovedRole(value.member);
  const grantor = normalizeApprovedRole(value.grantor);
  if (!(grantedRole === "platform_runtime" || grantedRole === "platform_migrator") || member !== "platform_app" || grantor !== "cloud_admin") fail("ARBITRARY_INPUT_REJECTED");
  const previous = value.previous;
  assertRecord(previous);
  assertExactKeys(previous, ["present", "admin_option", "inherit_option", "set_option"]);
  return {
    kind: "membership",
    action: value.action,
    granted_role: grantedRole,
    member,
    grantor,
    admin_option: booleanValue(value.admin_option),
    inherit_option: booleanValue(value.inherit_option),
    set_option: booleanValue(value.set_option),
    previous: {
      present: booleanValue(previous.present),
      admin_option: booleanValue(previous.admin_option),
      inherit_option: booleanValue(previous.inherit_option),
      set_option: booleanValue(previous.set_option),
    },
  };
}

function normalizeDefaultAclOperation(value: Record<string, unknown>): DefaultAclOperationV1 {
  assertExactKeys(value, ["kind", "action", "creator", "schema", "object_type", "principal", "privilege", "grant_option", "previous_grant_option"]);
  if (value.action !== "grant" && value.action !== "revoke") fail("ARBITRARY_INPUT_REJECTED");
  const creator = normalizeApprovedRole(value.creator);
  const schemaName = stringValue(value.schema);
  if (schemaName !== "public" && schemaName !== "drizzle") fail("ARBITRARY_INPUT_REJECTED");
  const objectType = stringValue(value.object_type);
  if (!["table", "sequence"].includes(objectType)) fail("OPERATION_UNSUPPORTED");
  const privilege = stringValue(value.privilege).toUpperCase();
  const privilegesByObjectType: Record<string, readonly string[]> = {
    table: ["DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"],
    sequence: ["SELECT", "UPDATE", "USAGE"],
  };
  if (!privilegesByObjectType[objectType]?.includes(privilege)) fail("OPERATION_UNSUPPORTED");
  return {
    kind: "default_acl",
    action: value.action,
    creator,
    schema: schemaName as DefaultAclOperationV1["schema"],
    object_type: objectType as DefaultAclOperationV1["object_type"],
    principal: normalizePrincipal(value.principal),
    privilege: privilege as DefaultAclOperationV1["privilege"],
    grant_option: booleanValue(value.grant_option),
    previous_grant_option: booleanValue(value.previous_grant_option),
  };
}

function normalizeRolePostureOperation(value: Record<string, unknown>): RolePostureOperationV1 {
  assertExactKeys(value, ["kind", "role", "attributes", "previous_attributes"]);
  const role = stringValue(value.role);
  if (!["platform_runtime", "platform_migrator", "platform_app"].includes(role)) fail("ARBITRARY_INPUT_REJECTED");
  return {
    kind: "role_posture",
    role: role as RolePostureOperationV1["role"],
    attributes: normalizeRoleAttributes(value.attributes),
    previous_attributes: normalizeRoleAttributes(value.previous_attributes),
  };
}

function normalizeRoleAttributes(value: unknown): RoleAttributesV1 {
  assertRecord(value);
  const fields = ["rolcanlogin", "rolinherit", "rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"] as const;
  assertExactKeys(value, fields);
  return Object.fromEntries(fields.map((field) => [field, booleanValue(value[field])])) as unknown as RoleAttributesV1;
}

function normalizeMigrationOperation(value: Record<string, unknown>): MigrationOperationV1 {
  assertExactKeys(value, ["kind", "tag", "journal_index", "when", "sql_sha256", "expected_applied_prefix_digest", "expected_post_journal_digest"]);
  const tag = stringValue(value.tag);
  if (!CANONICAL_MIGRATION_TAGS.has(tag)) fail("ARBITRARY_INPUT_REJECTED");
  return {
    kind: "migration",
    tag,
    journal_index: nonnegativeInteger(value.journal_index, "ARBITRARY_INPUT_REJECTED"),
    when: decimalStringValue(value.when),
    sql_sha256: hex(value.sql_sha256, 64),
    expected_applied_prefix_digest: hex(value.expected_applied_prefix_digest, 64),
    expected_post_journal_digest: hex(value.expected_post_journal_digest, 64),
  };
}

function normalizeApprovedRole(value: unknown): ApprovedRoleName {
  const role = stringValue(value) as ApprovedRoleName;
  if (!APPROVED_ROLE_NAMES.includes(role)) fail("ARBITRARY_INPUT_REJECTED");
  return role;
}

function normalizeReceiptRole(value: unknown): ApprovedReceiptRoleName {
  const role = stringValue(value) as ApprovedReceiptRoleName;
  if (!APPROVED_RECEIPT_ROLE_NAMES.includes(role)) fail("ARBITRARY_INPUT_REJECTED");
  return role;
}

function normalizePrincipal(value: unknown): ApprovedPrincipal {
  const principal = stringValue(value) as ApprovedPrincipal;
  if (![...APPROVED_ROLE_NAMES, "PUBLIC", "pg_database_owner"].includes(principal)) fail("ARBITRARY_INPUT_REJECTED");
  return principal;
}

export interface InverseStepV1 {
  original_operation_index: number;
  kind: OperationKind;
  operation: DurableOperationV1;
}

export interface DurableInverseV1 {
  version: typeof INVERSE_VERSION;
  source_plan_digest: string;
  steps: readonly InverseStepV1[];
  inverse_digest: string;
}

export function createDurableInverse(plan: DurablePlanV1, authoritativePrestate?: NormalizedPrestateV1): DurableInverseV1 {
  validatePlan(plan);
  if (plan.operations.some((operation) => operation.kind === "migration")) fail("RESTORE_CAPABILITY_REQUIRED");
  if (!authoritativePrestate) fail("PRESTATE_MISMATCH");
  const prestate = normalizePrestate(authoritativePrestate);
  if (canonicalDigest(PRESTATE_DOMAIN_SEPARATOR, prestate) !== plan.prestate_digest) fail("PRESTATE_MISMATCH");
  const steps = plan.operations.slice().reverse().map((operation, reverseIndex) => {
    const originalIndex = plan.operations.length - reverseIndex - 1;
    const inverse = inverseOperation(operation, prestate);
    return { original_operation_index: originalIndex, kind: inverse.kind, operation: inverse };
  });
  const payload = { version: INVERSE_VERSION, source_plan_digest: plan.plan_digest, steps };
  return deepFreeze({ ...payload, inverse_digest: canonicalDigest(INVERSE_DOMAIN_SEPARATOR, payload) });
}

function inverseOperation(operation: DurableOperationV1, prestate: NormalizedPrestateV1): DurableOperationV1 {
  switch (operation.kind) {
    case "ownership": {
      const previousOwner = observedOwnershipOwner(prestate, operation.object);
      if (operation.previous_owner !== previousOwner) fail("PRESTATE_MISMATCH");
      return {
        ...operation,
        previous_owner: operation.next_owner,
        next_owner: previousOwner,
      };
    }
    case "privilege": {
      const previous = observedPrivilege(prestate, operation);
      if (operation.previous_grant_option !== previous.grant_option) fail("PRESTATE_MISMATCH");
      return {
        ...operation,
        action: previous.present ? "grant" : "revoke",
        grant_option: previous.grant_option,
        previous_grant_option: operation.grant_option,
      };
    }
    case "membership":
      fail("OPERATION_UNSUPPORTED");
    case "default_acl": {
      const previous = observedDefaultAcl(prestate, operation);
      if (operation.previous_grant_option !== previous.grant_option) fail("PRESTATE_MISMATCH");
      return {
        ...operation,
        action: previous.present ? "grant" : "revoke",
        grant_option: previous.grant_option,
        previous_grant_option: operation.grant_option,
      };
    }
    case "role_posture":
      fail("OPERATION_UNSUPPORTED");
    case "migration":
      fail("INVERSE_INCOMPLETE");
  }
}

function observedOwnershipOwner(
  prestate: NormalizedPrestateV1,
  object: CanonicalObjectReferenceV1,
): string {
  if (object.object_class === "database") return prestate.ownership.database_owner;
  if (object.object_class === "schema") {
    if (object.qualified_name === "public") return prestate.ownership.public_schema_owner;
    if (object.qualified_name === "drizzle") return prestate.ownership.drizzle_schema_owner;
  }
  const records = object.object_class === "relation"
    ? prestate.ownership.canonical_relations
    : object.object_class === "index"
      ? prestate.ownership.canonical_indexes
      : object.object_class === "sequence"
        ? prestate.ownership.canonical_sequences
        : prestate.ownership.canonical_types;
  const matches = records.filter((record) => record.qualified_name === object.qualified_name);
  if (matches.length !== 1) fail("PRESTATE_MISMATCH");
  return matches[0].owner;
}

function observedPrivilege(
  prestate: NormalizedPrestateV1,
  operation: PrivilegeOperationV1,
): { present: boolean; grant_option: boolean } {
  const rows = [...prestate.privileges.direct, ...prestate.privileges.public].filter((row) =>
    row.object_class === operation.object.object_class &&
    row.qualified_name === operation.object.qualified_name &&
    row.grantee === operation.principal &&
    row.privilege.toUpperCase() === operation.privilege,
  );
  if (rows.length > 1) fail("PRESTATE_MISMATCH");
  return { present: rows.length === 1, grant_option: rows[0]?.grant_option ?? false };
}

function observedDefaultAcl(
  prestate: NormalizedPrestateV1,
  operation: DefaultAclOperationV1,
): { present: boolean; grant_option: boolean } {
  const rows = prestate.default_acls.creator.map((creator, index) => ({
    creator,
    schema: prestate.default_acls.schema[index],
    object_type: prestate.default_acls.object_type[index],
    grantee: prestate.default_acls.grantee[index],
    privilege: prestate.default_acls.privilege[index],
    grant_option: prestate.default_acls.grant_option[index],
  })).filter((row) =>
    row.creator === operation.creator &&
    row.schema === operation.schema &&
    row.object_type === operation.object_type &&
    row.grantee === operation.principal &&
    row.privilege.toUpperCase() === operation.privilege,
  );
  if (rows.length > 1) fail("PRESTATE_MISMATCH");
  return { present: rows.length === 1, grant_option: rows[0]?.grant_option ?? false };
}
export interface RestoreRequestV1 {
  target_binding_digest: string;
  prestate_digest: string;
  plan_digest: string;
  reason: "forward_failure" | "post_commit_failure" | "indeterminate_send";
}

export interface RestoreCapabilityV1 {
  version: typeof RESTORE_CAPABILITY_VERSION;
  target_binding_digest: string;
  prestate_digest: string;
  plan_digest: string;
  execute(request: RestoreRequestV1): Promise<void>;
}

export function requireRestoreCapability(
  capability: RestoreCapabilityV1 | undefined,
  plan: DurablePlanV1,
  targetBindingDigest: string,
): RestoreCapabilityV1 {
  if (!capability || typeof capability !== "object" || typeof capability.execute !== "function") fail("RESTORE_CAPABILITY_REQUIRED");
  if (
    capability.version !== "restore-capability-v1" ||
    capability.target_binding_digest !== targetBindingDigest ||
    capability.prestate_digest !== plan.prestate_digest ||
    capability.plan_digest !== plan.plan_digest
  ) fail("RESTORE_CAPABILITY_REQUIRED");
  return capability;
}

export function validatePlan(plan: DurablePlanV1): void {
  assertRecord(plan, "ARBITRARY_INPUT_REJECTED");
  assertExactKeys(plan, ["version", "expected_git_sha", "contract_digest", "target_binding_digest", "prestate_digest", "operation_kind", "operations", "plan_digest"]);
  if (plan.version !== PLAN_VERSION || !Array.isArray(plan.operations)) fail("ARBITRARY_INPUT_REJECTED");
  const expected = createDurablePlan({
    expected_git_sha: plan.expected_git_sha,
    contract_digest: plan.contract_digest,
    target_binding_digest: plan.target_binding_digest,
    prestate_digest: plan.prestate_digest,
    operation_kind: plan.operation_kind,
    operations: plan.operations,
  });
  if (expected.plan_digest !== plan.plan_digest) fail("PREWRITE_DRIFT");
}

export function assertPrewriteBinding(input: {
  expectedPrestateDigest: string;
  observedPrestateDigest: string;
  expectedContractDigest: string;
  observedContractDigest: string;
  expectedPlanDigest: string;
  observedPlanDigest: string;
  expectedTargetBindingDigest?: string;
  observedTargetBindingDigest?: string;
}): void {
  if (
    input.expectedPrestateDigest !== input.observedPrestateDigest ||
    input.expectedContractDigest !== input.observedContractDigest ||
    input.expectedPlanDigest !== input.observedPlanDigest ||
    (input.expectedTargetBindingDigest !== undefined && input.expectedTargetBindingDigest !== input.observedTargetBindingDigest)
  ) fail("PREWRITE_DRIFT");
}

export interface MutationSession {
  readonly mutationStarted: boolean;
  begin(): Promise<void>;
  acquireTargetLock(targetBindingDigest: string): Promise<void>;
  acquireMutationLocks(operations: readonly DurableOperationV1[]): Promise<void>;
  applyOperation(operation: DurableOperationV1): Promise<void>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}

class MutationSessionImpl implements MutationSession {
  private started = false;

  constructor(private readonly connection: DurableConnection) {}

  get mutationStarted(): boolean {
    return this.started;
  }

  async begin(): Promise<void> {
    await this.connection.query("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE");
  }

  async acquireTargetLock(targetBindingDigest: string): Promise<void> {
    const digest = hex(targetBindingDigest, 64, "TARGET_MISMATCH");
    const lockDigest = createHash("sha256")
      .update(Buffer.from(`swooshz-platform:durable-target-lock-v1\\0${digest}`, "utf8"))
      .digest();
    await this.connection.query(
      "select pg_catalog.pg_advisory_xact_lock($1::integer, $2::integer) /* platform durable:target_lock */",
      [lockDigest.readInt32BE(0), lockDigest.readInt32BE(4)],
    );
  }

  async acquireMutationLocks(operations: readonly DurableOperationV1[]): Promise<void> {
    const lockKeys = new Set<string>();
    for (const operation of operations) {
      if (operation.kind === "ownership" || operation.kind === "privilege") {
        lockKeys.add(`${operation.object.object_class}\0${operation.object.qualified_name}`);
      } else if (operation.kind === "default_acl") {
        lockKeys.add(`default_acl\0${operation.creator}\0${operation.schema}\0${operation.object_type}`);
      } else if (operation.kind === "migration") {
        lockKeys.add("migration\0ledger");
      }
    }
    for (const lockKey of [...lockKeys].sort()) {
      const [objectClass, qualifiedName, objectType] = lockKey.split("\0");
      if (objectClass === "default_acl") {
        continue;
      } else if (objectClass === "migration") {
        await this.connection.query("lock table \"drizzle\".\"__drizzle_migrations\" in access exclusive mode /* platform durable:object_lock */");
      } else if (["relation", "index", "sequence"].includes(objectClass)) {
        const [schemaName, relationName] = qualifiedName.split(".", 2);
        await this.connection.query(
          `lock table ${quoteIdentifier(schemaName)}.${quoteIdentifier(relationName)} in access exclusive mode /* platform durable:object_lock */`,
        );
      }
    }
  }

  async applyOperation(operation: DurableOperationV1): Promise<void> {
    if (operation.kind === "membership" || operation.kind === "role_posture") fail("OPERATION_UNSUPPORTED");
    const statement = operationSql(operation);
    this.started = true;
    try {
      await this.connection.query(statement.sql, statement.values);
    } catch (error) {
      fail(mutationFailureCode(error));
    }
  }

  async commit(): Promise<void> {
    await this.connection.query("COMMIT");
  }

  async rollback(): Promise<void> {
    await this.connection.query("ROLLBACK");
  }
}

export function createMutationSession(connection: DurableConnection): MutationSession {
  return new MutationSessionImpl(connection);
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function roleIdentifier(role: ApprovedReceiptRoleName): string {
  if (!APPROVED_RECEIPT_ROLE_NAMES.includes(role)) fail("ARBITRARY_INPUT_REJECTED");
  return quoteIdentifier(role);
}

function principalIdentifier(principal: ApprovedPrincipal): string {
  return principal === "PUBLIC" ? "PUBLIC" : roleIdentifier(principal);
}

function objectSql(reference: CanonicalObjectReferenceV1): string {
  if (reference.object_class === "database") return "current_database()";
  if (reference.object_class === "schema") return quoteIdentifier(reference.qualified_name);
  const [namespace, name] = reference.qualified_name.split(".", 2);
  if (!namespace || !name) fail("ARBITRARY_INPUT_REJECTED");
  if (reference.object_class === "routine") fail("OPERATION_UNSUPPORTED");
  return `${quoteIdentifier(namespace)}.${quoteIdentifier(name)}`;
}

function operationSql(operation: DurableOperationV1): { sql: string; values?: readonly unknown[] } {
  switch (operation.kind) {
    case "ownership":
      return {
        sql: operation.object.object_class === "database"
          ? `ALTER DATABASE ${objectSql(operation.object)} OWNER TO ${roleIdentifier(operation.next_owner)}`
          : `ALTER ${operation.object.object_class === "schema" ? "SCHEMA" : operation.object.object_class === "relation" ? "TABLE" : operation.object.object_class === "enum" || operation.object.object_class === "type" ? "TYPE" : operation.object.object_class.toUpperCase()} ${objectSql(operation.object)} OWNER TO ${roleIdentifier(operation.next_owner)}`,
      };
    case "privilege": {
      const verb = operation.action === "grant" ? "GRANT" : "REVOKE";
      const option = operation.action === "grant" && operation.grant_option ? " WITH GRANT OPTION" : "";
      const objectType = operation.object.object_class === "relation" ? "TABLE" : operation.object.object_class.toUpperCase();
      return { sql: `${verb} ${operation.privilege} ON ${objectType} ${objectSql(operation.object)} ${operation.action === "grant" ? "TO" : "FROM"} ${principalIdentifier(operation.principal)}${option}` };
    }
    case "membership":
      return { sql: `${operation.action === "grant" ? "GRANT" : "REVOKE"} ${roleIdentifier(operation.granted_role)} ${operation.action === "grant" ? "TO" : "FROM"} ${roleIdentifier(operation.member)}${operation.action === "grant" && operation.admin_option ? " WITH ADMIN OPTION" : ""}` };
    case "default_acl":
      return { sql: `ALTER DEFAULT PRIVILEGES FOR ROLE ${roleIdentifier(operation.creator)} IN SCHEMA ${quoteIdentifier(operation.schema)} ${operation.action === "grant" ? "GRANT" : "REVOKE"} ${operation.privilege} ON ${operation.object_type === "routine" ? "FUNCTIONS" : `${operation.object_type.toUpperCase()}S`} ${operation.action === "grant" ? "TO" : "FROM"} ${principalIdentifier(operation.principal)}${operation.action === "grant" && operation.grant_option ? " WITH GRANT OPTION" : ""}` };
    case "role_posture":
      return { sql: `ALTER ROLE ${roleIdentifier(operation.role)} ${roleAttributeSql(operation.attributes)}` };
    case "migration":
      fail("OPERATION_UNSUPPORTED");
  }
}

function roleAttributeSql(attributes: RoleAttributesV1): string {
  return [
    attributes.rolcanlogin ? "LOGIN" : "NOLOGIN",
    attributes.rolinherit ? "INHERIT" : "NOINHERIT",
    attributes.rolsuper ? "SUPERUSER" : "NOSUPERUSER",
    attributes.rolcreatedb ? "CREATEDB" : "NOCREATEDB",
    attributes.rolcreaterole ? "CREATEROLE" : "NOCREATEROLE",
    attributes.rolreplication ? "REPLICATION" : "NOREPLICATION",
    attributes.rolbypassrls ? "BYPASSRLS" : "NOBYPASSRLS",
  ].join(" ");
}

export function mapFailureCode(error: unknown): SemanticCode {
  return error instanceof DurableOperationError ? error.semanticCode : "UNEXPECTED_FAILURE";
}

export interface DurableCounts {
  canonical_objects: number;
  direct_privileges: number;
  public_privileges: number;
  default_acls: number;
  memberships: number;
  migration_entries: number;
  operations: number;
  inverse_steps: number;
}

export interface DurableReceiptV1 {
  receipt_version: 1;
  phase: ReceiptPhase;
  outcome: "PASS" | "FAIL" | "BLOCKED";
  semantic_code: SemanticCode;
  operation_kind: OperationKind;
  git_sha: string;
  contract_digest: string;
  role_names: readonly ApprovedReceiptRoleName[];
  counts: DurableCounts;
  mutation_started: boolean;
  rollback_attempted: boolean;
  rollback_verified: boolean;
  restoration_state: "NOT_REQUIRED" | "NOT_STARTED" | "VERIFIED" | "FAILED" | "AMBIGUOUS";
  final_readiness_state: "NOT_RUN" | "PASS" | "FAIL";
  migration_tag?: string;
}

export function projectReceipt(value: Record<string, unknown>): DurableReceiptV1 {
  assertRecord(value, "RECEIPT_REJECTED");
  const result: DurableReceiptV1 = {
    receipt_version: 1,
    phase: value.phase as ReceiptPhase,
    outcome: value.outcome as DurableReceiptV1["outcome"],
    semantic_code: value.semantic_code as SemanticCode,
    operation_kind: value.operation_kind as OperationKind,
    git_sha: String(value.git_sha),
    contract_digest: String(value.contract_digest),
    role_names: Array.isArray(value.role_names) ? [...value.role_names] as ApprovedReceiptRoleName[] : [],
    counts: value.counts as DurableCounts,
    mutation_started: value.mutation_started === true,
    rollback_attempted: value.rollback_attempted === true,
    rollback_verified: value.rollback_verified === true,
    restoration_state: value.restoration_state as DurableReceiptV1["restoration_state"],
    final_readiness_state: value.final_readiness_state as DurableReceiptV1["final_readiness_state"],
    ...(value.migration_tag === undefined ? {} : { migration_tag: String(value.migration_tag) }),
  };
  validateReceipt(result);
  return deepFreeze(result);
}

export function validateReceipt(value: unknown): asserts value is DurableReceiptV1 {
  assertRecord(value, "RECEIPT_REJECTED");
  const keys = ["receipt_version", "phase", "outcome", "semantic_code", "operation_kind", "git_sha", "contract_digest", "role_names", "counts", "mutation_started", "rollback_attempted", "rollback_verified", "restoration_state", "final_readiness_state"];
  if ("migration_tag" in value) keys.push("migration_tag");
  assertExactKeys(value, keys, "RECEIPT_REJECTED");
  if (value.receipt_version !== 1 || !RECEIPT_PHASES.includes(value.phase as ReceiptPhase) || !["PASS", "FAIL", "BLOCKED"].includes(value.outcome as string) || !SEMANTIC_CODES.includes(value.semantic_code as SemanticCode) || !OPERATION_KINDS.includes(value.operation_kind as OperationKind)) fail("RECEIPT_REJECTED");
  hex(value.git_sha, 40, "RECEIPT_REJECTED");
  hex(value.contract_digest, 64, "RECEIPT_REJECTED");
  if (!Array.isArray(value.role_names) || value.role_names.some((role) => !APPROVED_RECEIPT_ROLE_NAMES.includes(role as ApprovedReceiptRoleName))) fail("RECEIPT_REJECTED");
  assertRecord(value.counts, "RECEIPT_REJECTED");
  const countKeys = ["canonical_objects", "direct_privileges", "public_privileges", "default_acls", "memberships", "migration_entries", "operations", "inverse_steps"];
  assertExactKeys(value.counts, countKeys, "RECEIPT_REJECTED");
  for (const key of countKeys) nonnegativeInteger(value.counts[key], "RECEIPT_REJECTED");
  for (const key of ["mutation_started", "rollback_attempted", "rollback_verified"]) booleanValue(value[key], "RECEIPT_REJECTED");
  if (!["NOT_REQUIRED", "NOT_STARTED", "VERIFIED", "FAILED", "AMBIGUOUS"].includes(value.restoration_state as string) || !["NOT_RUN", "PASS", "FAIL"].includes(value.final_readiness_state as string)) fail("RECEIPT_REJECTED");
  if (value.rollback_verified === true && (!value.rollback_attempted || value.restoration_state !== "VERIFIED")) fail("RECEIPT_REJECTED");
  if (!value.mutation_started && (value.rollback_attempted || value.rollback_verified)) fail("RECEIPT_REJECTED");
  if (value.outcome === "PASS") {
    if (value.phase !== "FINAL_VERIFY" || value.semantic_code !== "SUCCESS" || value.final_readiness_state !== "PASS" || value.rollback_attempted || value.rollback_verified || value.restoration_state !== "NOT_REQUIRED") {
      fail("RECEIPT_REJECTED");
    }
  } else if (value.outcome === "BLOCKED") {
    if (!["ADMISSION", "OBSERVE", "PLAN", "PRESTATE", "INVERSE", "PREWRITE"].includes(value.phase as ReceiptPhase) || value.mutation_started || value.rollback_attempted || value.rollback_verified || value.restoration_state !== "NOT_REQUIRED" || value.final_readiness_state !== "NOT_RUN" || value.semantic_code === "SUCCESS") {
      fail("RECEIPT_REJECTED");
    }
  } else {
    if (value.semantic_code === "SUCCESS") fail("RECEIPT_REJECTED");
    if (!value.mutation_started) {
      if (value.phase !== "FORWARD" || value.rollback_attempted || value.rollback_verified || value.restoration_state !== "NOT_REQUIRED" || value.final_readiness_state !== "NOT_RUN" || !["MUTATION_FAILED", "UNEXPECTED_FAILURE"].includes(value.semantic_code as SemanticCode)) {
        fail("RECEIPT_REJECTED");
      }
    } else {
      if (![
        "FORWARD", "COMMIT", "ROLLBACK", "RESTORE", "RESTORE_VERIFY", "FINAL_VERIFY", "RECEIPT",
      ].includes(value.phase as ReceiptPhase) || value.restoration_state === "NOT_REQUIRED" || value.restoration_state === "NOT_STARTED") {
        fail("RECEIPT_REJECTED");
      }
      if (value.phase === "ROLLBACK" && (!value.rollback_attempted || value.semantic_code !== "ROLLBACK_FAILED")) fail("RECEIPT_REJECTED");
    }
    const phaseCodes: Partial<Record<ReceiptPhase, readonly SemanticCode[]>> = {
      FORWARD: ["MUTATION_FAILED", "WRITE_INDETERMINATE", "UNEXPECTED_FAILURE"],
      COMMIT: ["COMMIT_FAILED", "COMMIT_INDETERMINATE", "UNEXPECTED_FAILURE"],
      ROLLBACK: ["ROLLBACK_FAILED", "UNEXPECTED_FAILURE"],
      RESTORE: ["RESTORE_CAPABILITY_REQUIRED", "RESTORE_EXECUTION_FAILED", "RESTORATION_FAILED", "UNEXPECTED_FAILURE"],
      RESTORE_VERIFY: ["RESTORATION_FAILED", "RESTORATION_AMBIGUOUS", "UNEXPECTED_FAILURE"],
      FINAL_VERIFY: ["FINAL_VERIFICATION_FAILED", "UNEXPECTED_FAILURE"],
      RECEIPT: ["RECEIPT_REJECTED", "UNEXPECTED_FAILURE"],
    };
    const allowedCodes = phaseCodes[value.phase as ReceiptPhase];
    if (allowedCodes && !allowedCodes.includes(value.semantic_code as SemanticCode)) fail("RECEIPT_REJECTED");
  }
  if ("migration_tag" in value && (typeof value.migration_tag !== "string" || !CANONICAL_MIGRATION_TAGS.has(value.migration_tag))) fail("RECEIPT_REJECTED");
}

export function serializeReceipt(value: DurableReceiptV1): string {
  validateReceipt(value);
  const projected: Record<string, unknown> = {
    receipt_version: value.receipt_version,
    phase: value.phase,
    outcome: value.outcome,
    semantic_code: value.semantic_code,
    operation_kind: value.operation_kind,
    git_sha: value.git_sha,
    contract_digest: value.contract_digest,
    role_names: [...value.role_names],
    counts: { ...value.counts },
    mutation_started: value.mutation_started,
    rollback_attempted: value.rollback_attempted,
    rollback_verified: value.rollback_verified,
    restoration_state: value.restoration_state,
    final_readiness_state: value.final_readiness_state,
    ...(value.migration_tag ? { migration_tag: value.migration_tag } : {}),
  };
  return canonicalSerialize(projected);
}

export interface CanonicalMigrationJournalV1 {
  version: string;
  dialect: string;
  entries: MigrationSourceEntryV1[];
}

export async function loadCanonicalMigrationJournal(rootDir: string): Promise<CanonicalMigrationJournalV1> {
  const migrationDirectory = resolve(rootDir, "drizzle", "migrations");
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(join(migrationDirectory, "meta", "_journal.json"), "utf8"));
  } catch {
    fail("MIGRATION_IDENTITY_MISMATCH");
  }
  assertRecord(parsed, "MIGRATION_IDENTITY_MISMATCH");
  if (!Array.isArray(parsed.entries)) fail("MIGRATION_IDENTITY_MISMATCH");
  const files = readMigrationFiles({ migrationsFolder: migrationDirectory }) as Array<{ hash: string; folderMillis: number }>;
  if (files.length !== parsed.entries.length) fail("MIGRATION_IDENTITY_MISMATCH");
  const entries = parsed.entries.map((raw, index) => {
    assertRecord(raw, "MIGRATION_IDENTITY_MISMATCH");
    assertExactKeys(raw, ["idx", "version", "when", "tag", "breakpoints"], "MIGRATION_IDENTITY_MISMATCH");
    const tag = stringValue(raw.tag, "MIGRATION_IDENTITY_MISMATCH");
    if (!CANONICAL_MIGRATION_TAGS.has(tag) || files[index].folderMillis !== Number(raw.when)) fail("MIGRATION_IDENTITY_MISMATCH");
    return {
      idx: nonnegativeInteger(raw.idx, "MIGRATION_IDENTITY_MISMATCH"),
      version: stringValue(raw.version, "MIGRATION_IDENTITY_MISMATCH"),
      when: decimalStringValue(raw.when),
      tag,
      breakpoints: booleanValue(raw.breakpoints, "MIGRATION_IDENTITY_MISMATCH"),
      sql_sha256: hex(files[index].hash, 64, "MIGRATION_IDENTITY_MISMATCH"),
    };
  });
  return { version: stringValue(parsed.version, "MIGRATION_IDENTITY_MISMATCH"), dialect: stringValue(parsed.dialect, "MIGRATION_IDENTITY_MISMATCH"), entries };
}

const CONTRACT_SOURCE_PATHS = [
  "src/db/schema.ts",
  "drizzle.config.ts",
  "drizzle/migrations/meta/_journal.json",
  "src/db/client.ts",
  "src/db/readiness.ts",
  "src/db/runtime-posture.ts",
  "src/db/runtime-grant-contract.ts",
  "src/db/durable-operations.ts",
  "scripts/db-migrate.mjs",
  "package.json",
  "package-lock.json",
] as const;

export async function computeContractManifest(rootDir: string): Promise<Array<{ path: string; sha256: string }>> {
  const journal = await loadCanonicalMigrationJournal(rootDir);
  const paths = [
    CONTRACT_SOURCE_PATHS[0], CONTRACT_SOURCE_PATHS[1], CONTRACT_SOURCE_PATHS[2],
    ...journal.entries.map((entry) => `drizzle/migrations/${entry.tag}.sql`),
    ...CONTRACT_SOURCE_PATHS.slice(3),
  ];
  const manifest = [] as Array<{ path: string; sha256: string }>;
  for (const path of paths) {
    let contents: Buffer;
    try {
      contents = await readFile(resolve(rootDir, path));
    } catch {
      fail("CONTRACT_DIGEST_MISMATCH");
    }
    manifest.push({ path, sha256: createHash("sha256").update(contents).digest("hex") });
  }
  return manifest;
}

export async function computeContractDigest(rootDir: string): Promise<string> {
  return canonicalDigest(CONTRACT_DOMAIN_SEPARATOR, await computeContractManifest(rootDir));
}

const execFileAsync = promisify(execFile);

export async function assertRevisionBinding(input: {
  rootDir: string;
  expectedGitSha: string;
}): Promise<string> {
  const expected = hex(input.expectedGitSha, 40, "REVISION_MISMATCH");
  try {
    const revision = (await execFileAsync("git", ["rev-parse", "--verify", "HEAD"], { cwd: resolve(input.rootDir), windowsHide: true })).stdout.trim();
    if (!/^[0-9a-f]{40}$/u.test(revision)) fail("REVISION_UNAVAILABLE");
    if (revision !== expected) fail("REVISION_MISMATCH");
    const status = (await execFileAsync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: resolve(input.rootDir), windowsHide: true })).stdout.trim();
    if (status) fail("DIRTY_CHECKOUT");
    return revision;
  } catch (error) {
    if (error instanceof DurableOperationError) throw error;
    fail("REVISION_UNAVAILABLE");
  }
}

function queryText(input: DurableQueryInput): string {
  if (typeof input === "string") return input;
  return typeof input.text === "string" ? input.text : "";
}

function isMutationSql(text: DurableQueryInput): boolean {
  const normalized = queryText(text).trim().replace(/^(?:\/\*[\s\S]*?\*\/|--[^\r\n]*(?:\r?\n|$))+\s*/u, "");
  return /^(?:CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL)\b/iu.test(normalized);
}

class MutationAwareConnection implements DurableConnection {
  constructor(private readonly connection: DurableConnection, private readonly boundary: { markMutation(): void }) {}

  query(text: DurableQueryInput, values?: readonly unknown[]): Promise<DurableQueryResult> {
    if (isMutationSql(text)) this.boundary.markMutation();
    return this.connection.query(text, values);
  }

  release(): Promise<void> | void {
    return this.connection.release?.();
  }
}

class MutationAwarePool implements DurablePool {
  constructor(private readonly pool: DurablePool, private readonly boundary: { markMutation(): void }) {}

  query(text: DurableQueryInput, values?: readonly unknown[]): Promise<DurableQueryResult> {
    const query = this.pool.query;
    if (!query) fail("MUTATION_FAILED");
    if (isMutationSql(text)) this.boundary.markMutation();
    return query.call(this.pool, text, values);
  }

  async connect(): Promise<DurableConnection> {
    return new MutationAwareConnection(await this.pool.connect(), this.boundary);
  }
}

export interface CanonicalMigrationResult {
  mutation_started: boolean;
  before: MigrationAppliedRowV1[];
  after: MigrationAppliedRowV1[];
  applied_entries: MigrationSourceEntryV1[];
}

export async function runCanonicalMigrationPrimitive(input: {
  pool: DurablePool;
  migrationsFolder: string;
  expectedOperations?: readonly MigrationOperationV1[];
  existingTransaction?: boolean;
}): Promise<CanonicalMigrationResult> {
  const rootDir = resolve(input.migrationsFolder, "..", "..");
  const journal = await loadCanonicalMigrationJournal(rootDir);
  const files = readMigrationFiles({ migrationsFolder: resolve(input.migrationsFolder) }) as Array<{ hash: string; folderMillis: number }>;
  if (files.length !== journal.entries.length) fail("MIGRATION_IDENTITY_MISMATCH");
  const before = await readAppliedMigrationRows(input.pool);
  assertAppliedPrefix(before, journal.entries);
  const pending = journal.entries.slice(before.length);
  const expectedOperations = input.expectedOperations
    ? input.expectedOperations.map((operation) => normalizeMigrationOperation(operation as unknown as Record<string, unknown>))
    : pending.map((entry, index) => migrationOperationFromEntry(entry, [...before, ...pending.slice(0, index).map((prior) => ({ when: prior.when, sql_sha256: prior.sql_sha256 }))]));
  if (expectedOperations.length !== pending.length || expectedOperations.some((operation, index) => !sameMigrationEntry(operation, pending[index]))) fail("MIGRATION_IDENTITY_MISMATCH");
  let expectedRows = before.slice();
  expectedOperations.forEach((operation, index) => {
    const entry = pending[index];
    const nextRows = [...expectedRows, { when: entry.when, sql_sha256: entry.sql_sha256 }];
    if (operation.expected_applied_prefix_digest !== canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, expectedRows) || operation.expected_post_journal_digest !== canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, nextRows)) fail("MIGRATION_IDENTITY_MISMATCH");
    expectedRows = nextRows;
  });
  if (pending.length === 0) return { mutation_started: false, before, after: before, applied_entries: [] };

  const boundary = { value: false, markMutation() { this.value = true; } };
  const awarePool = new MutationAwarePool(input.pool, boundary);
  try {
    const database = drizzle(awarePool as never, { schema });
    if (input.existingTransaction) {
      const internals = database as unknown as {
        dialect: { migrate(migrations: unknown, session: unknown, config: unknown): Promise<void> };
        session: { transaction(callback: (session: unknown) => Promise<unknown>): Promise<unknown> };
      };
      const session = internals.session;
      const originalTransaction = session.transaction;
      session.transaction = async (callback) => callback(session);
      try {
        await internals.dialect.migrate(
          readMigrationFiles({ migrationsFolder: resolve(input.migrationsFolder) }),
          session,
          { migrationsFolder: resolve(input.migrationsFolder) },
        );
      } finally {
        session.transaction = originalTransaction;
      }
    } else {
      await migrate(database as never, { migrationsFolder: resolve(input.migrationsFolder) });
    }
  } catch {
    if (!boundary.value) fail("MIGRATION_IDENTITY_MISMATCH");
    const failure = new DurableOperationError("MUTATION_FAILED");
    failure.mutationStarted = true;
    throw failure;
  }
  let after: MigrationAppliedRowV1[] = [];
  try {
    after = await readAppliedMigrationRows(input.pool);
  } catch (error) {
    if (error instanceof DurableOperationError) error.mutationStarted = boundary.value;
    throw error;
  }
  try {
    assertAppliedPrefix(after, journal.entries);
    if (after.length !== journal.entries.length) fail("MIGRATION_IDENTITY_MISMATCH");
    if (canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, after) !== expectedOperations[expectedOperations.length - 1].expected_post_journal_digest) fail("MIGRATION_IDENTITY_MISMATCH");
  } catch (error) {
    if (boundary.value && error instanceof DurableOperationError) error.mutationStarted = true;
    throw error;
  }
  return { mutation_started: boundary.value, before, after, applied_entries: pending };
}

async function readAppliedMigrationRows(pool: DurablePool): Promise<MigrationAppliedRowV1[]> {
  const connection = await pool.connect();
  try {
    const exists = await connection.query(MIGRATION_LEDGER_EXISTS_SQL);
    if (exists.rows[0]?.ledger_present !== true) return [];
    const result = await connection.query(MIGRATION_LEDGER_ROWS_SQL);
    return result.rows.map((row) => ({
      when: decimalStringValue(row.when),
      sql_sha256: hex(row.sql_sha256, 64, "MIGRATION_IDENTITY_MISMATCH"),
    }));
  } catch (error) {
    if (error instanceof DurableOperationError) throw error;
    fail("MIGRATION_IDENTITY_MISMATCH");
  } finally {
    await closeConnection(connection);
  }
}

function assertAppliedPrefix(rows: readonly MigrationAppliedRowV1[], entries: readonly MigrationSourceEntryV1[]): void {
  if (rows.length > entries.length) fail("MIGRATION_IDENTITY_MISMATCH");
  const entrySeen = new Set<string>();
  entries.forEach((entry, index) => {
    const identity = `${entry.idx}|${entry.when}|${entry.sql_sha256}`;
    if (entry.idx !== index || entrySeen.has(identity)) fail("MIGRATION_IDENTITY_MISMATCH");
    entrySeen.add(identity);
  });
  const seen = new Set<string>();
  rows.forEach((row, index) => {
    const entry = entries[index];
    const identity = `${row.when}|${row.sql_sha256}`;
    if (!entry || row.when !== entry.when || row.sql_sha256 !== entry.sql_sha256 || seen.has(identity)) fail("MIGRATION_IDENTITY_MISMATCH");
    seen.add(identity);
  });
}

function migrationOperationFromEntry(entry: MigrationSourceEntryV1, before: readonly MigrationAppliedRowV1[]): MigrationOperationV1 {
  const prefix = canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, before);
  return {
    kind: "migration",
    tag: entry.tag,
    journal_index: entry.idx,
    when: entry.when,
    sql_sha256: entry.sql_sha256,
    expected_applied_prefix_digest: prefix,
    expected_post_journal_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, [...before, { when: entry.when, sql_sha256: entry.sql_sha256 }]),
  };
}

function sameMigrationEntry(operation: MigrationOperationV1, entry: MigrationSourceEntryV1): boolean {
  return operation.tag === entry.tag && operation.journal_index === entry.idx && operation.when === entry.when && operation.sql_sha256 === entry.sql_sha256;
}

export async function verifyRestoration(input: {
  binding: DurableTargetBinding;
  expectedPrestateDigest: string;
  journal?: CanonicalMigrationJournalV1;
}): Promise<{ state: "VERIFIED" | "FAILED" | "AMBIGUOUS"; prestate_digest?: string }> {
  try {
    const observed = await captureNormalizedPrestate(input.binding, input.journal);
    if (observed.prestate_digest !== input.expectedPrestateDigest) return { state: "FAILED", prestate_digest: observed.prestate_digest };
    const ready = canonicalReadinessPass(observed.prestate);
    return ready ? { state: "VERIFIED", prestate_digest: observed.prestate_digest } : { state: "FAILED", prestate_digest: observed.prestate_digest };
  } catch {
    return { state: "AMBIGUOUS" };
  }
}

function canonicalReadinessPass(prestate: NormalizedPrestateV1): boolean {
  try {
    assertFixedRolePosture(prestate, "FINAL_VERIFICATION_FAILED");
  } catch {
    return false;
  }
  const readiness = prestate.canonical_checks.readiness_checks;
  const readinessKeys = Object.keys(readiness).sort();
  const expectedReadinessKeys = ["config", "migrations", "migratorPosture", "reachability", "schema"];
  const migratorFields = [...prestate.canonical_checks.migrator_readiness_fields].sort();
  const expectedMigratorFields = [...MIGRATOR_READINESS_FIELDS].sort();
  const runtimeFields = Object.values(prestate.canonical_checks.runtime_posture_fields);
  return JSON.stringify(readinessKeys) === JSON.stringify(expectedReadinessKeys) &&
    readiness.config === "present" &&
    readiness.reachability === "passed" &&
    readiness.schema === "passed" &&
    readiness.migrations === "passed" &&
    readiness.migratorPosture === "passed" &&
    JSON.stringify(migratorFields) === JSON.stringify(expectedMigratorFields) &&
    runtimeFields.length > 0 &&
    runtimeFields.every((value) => value === "passed") &&
    prestate.runtime_grant_contract.contract_digest === RUNTIME_TABLE_GRANT_DIGEST &&
    Object.values(prestate.unknown_non_extension_drift).every((items) => items.length === 0);
}

async function executeFrozenInverse(input: {
  binding: DurableTargetBinding;
  targetBindingDigest: string;
  expectedPrestateDigest: string;
  journal: CanonicalMigrationJournalV1;
  inverse: DurableInverseV1;
}): Promise<void> {
  const connection = await input.binding.connect();
  const session = createMutationSession(connection);
  let begun = false;
  try {
    await session.begin();
    begun = true;
    await session.acquireTargetLock(input.targetBindingDigest);
    await session.acquireMutationLocks(input.inverse.steps.map((step) => step.operation));
    const revalidated = await captureMutationPrestate(input.binding, connection, input.journal);
    if (revalidated.prestate_digest !== input.expectedPrestateDigest) fail("PREWRITE_DRIFT");
    for (const step of input.inverse.steps) {
      if (step.kind !== step.operation.kind) fail("INVERSE_INCOMPLETE");
      await session.applyOperation(step.operation);
    }
    await session.commit();
  } catch {
    if (begun) {
      try {
        await session.rollback();
      } catch {
        // The restoration state below remains failed closed.
      }
    }
    fail("RESTORATION_FAILED");
  } finally {
    await closeConnection(connection);
  }
}

async function executeRestoreCapability(
  capability: RestoreCapabilityV1,
  plan: DurablePlanV1,
  reason: RestoreRequestV1["reason"],
): Promise<void> {
  try {
    await capability.execute({
      target_binding_digest: plan.target_binding_digest,
      prestate_digest: plan.prestate_digest,
      plan_digest: plan.plan_digest,
      reason,
    });
  } catch {
    fail("RESTORE_EXECUTION_FAILED");
  }
}

function mutationFailureCode(error: unknown): SemanticCode {
  if (error instanceof DurableOperationError) return error.semanticCode;
  const driverCode = isRecord(error) && typeof error.code === "string" ? error.code : "";
  return /^(?:ECONN|ETIMEDOUT|EPIPE|EAI_|ENET|EHOST|57P01|57P02|57P03)/u.test(driverCode)
    ? "WRITE_INDETERMINATE"
    : "MUTATION_FAILED";
}

function commitFailureCode(error: unknown): SemanticCode {
  if (error instanceof DurableOperationError) return error.semanticCode;
  const driverCode = isRecord(error) && typeof error.code === "string" ? error.code : "";
  return /^(?:ECONN|ETIMEDOUT|EPIPE|EAI_|ENET|EHOST|57P01|57P02|57P03)/u.test(driverCode)
    ? "COMMIT_INDETERMINATE"
    : "COMMIT_FAILED";
}

function assertFinalRolePosture(
  expected: NormalizedPrestateV1,
  observed: NormalizedPrestateV1,
): void {
  try {
    assertFixedRolePosture(observed, "FINAL_VERIFICATION_FAILED");
  } catch {
    fail("FINAL_VERIFICATION_FAILED");
  }
  for (const roleName of ["platform_runtime", "platform_app", "platform_migrator"] as const) {
    const expectedRole = expected.roles.accepted_role_states.find((role) => role.rolname === roleName);
    const observedRole = observed.roles.accepted_role_states.find((role) => role.rolname === roleName);
    if (!expectedRole || !observedRole || canonicalSerialize(expectedRole) !== canonicalSerialize(observedRole)) {
      fail("FINAL_VERIFICATION_FAILED");
    }
  }
  if (canonicalSerialize(expected.memberships) !== canonicalSerialize(observed.memberships)) {
    fail("FINAL_VERIFICATION_FAILED");
  }
}

export async function executeDurablePlan(input: {
  plan: DurablePlanV1;
  binding: DurableTargetBinding;
  expectedPrestate: NormalizedPrestateV1;
  expectedContractDigest: string;
  mutationConnection?: DurableConnection;
  restoreCapability?: RestoreCapabilityV1;
  rootDir?: string;
  migrationsFolder?: string;
  journal?: CanonicalMigrationJournalV1;
}): Promise<DurableReceiptV1> {
  validatePlan(input.plan);
  const expectedPrestate = normalizePrestate(input.expectedPrestate);
  assertFixedRolePosture(expectedPrestate);
  const expectedPrestateDigest = canonicalDigest(PRESTATE_DOMAIN_SEPARATOR, expectedPrestate);
  const isMigration = input.plan.operation_kind === "migration";
  const requiresRestoreCapability = input.plan.operations.some((operation) => operation.kind === "migration");
  if (!input.journal) fail("MIGRATION_IDENTITY_MISMATCH");
  let phase: ReceiptPhase = "ADMISSION";
  let observedContractDigest = input.expectedContractDigest;
  let observedTargetBindingDigest = "";
  let restoreCapability: RestoreCapabilityV1 | undefined;
  let inverse: DurableInverseV1 | undefined;
  let mutationConnection: DurableConnection | undefined;
  let session: MutationSession | undefined;
  let mutationStarted = false;
  let committed = false;
  let connectionClosed = false;
  let rollbackAttempted = false;
  let rollbackVerified = false;
  let finalReadinessState: DurableReceiptV1["final_readiness_state"] = "NOT_RUN";
  try {
    phase = "PLAN";
    if (input.rootDir) {
      phase = "ADMISSION";
      await assertRevisionBinding({
        rootDir: input.rootDir,
        expectedGitSha: input.plan.expected_git_sha,
      });
      observedContractDigest = await computeContractDigest(input.rootDir);
    }
    if (
      expectedPrestateDigest !== input.plan.prestate_digest ||
      input.expectedContractDigest !== input.plan.contract_digest ||
      observedContractDigest !== input.expectedContractDigest
    ) fail("CONTRACT_DIGEST_MISMATCH");
    observedTargetBindingDigest = computeTargetBindingDigest(input.binding);
    if (observedTargetBindingDigest !== input.plan.target_binding_digest) fail("TARGET_MISMATCH");
    if (input.restoreCapability) {
      restoreCapability = requireRestoreCapability(
        input.restoreCapability,
        input.plan,
        observedTargetBindingDigest,
      );
    }
    if (requiresRestoreCapability) {
      restoreCapability = requireRestoreCapability(
        input.restoreCapability,
        input.plan,
        observedTargetBindingDigest,
      );
    }
    phase = "OBSERVE";
    const observed = await captureNormalizedPrestate(input.binding, input.journal);
    phase = "PRESTATE";
    assertPrewriteBinding({
      expectedPrestateDigest,
      observedPrestateDigest: observed.prestate_digest,
      expectedContractDigest: input.expectedContractDigest,
      observedContractDigest,
      expectedPlanDigest: input.plan.plan_digest,
      observedPlanDigest: input.plan.plan_digest,
      expectedTargetBindingDigest: observedTargetBindingDigest,
      observedTargetBindingDigest: computeTargetBindingDigest(input.binding),
    });
    phase = "INVERSE";
    inverse = isMigration ? undefined : createDurableInverse(input.plan, expectedPrestate);
    if (isMigration && !input.migrationsFolder) fail("OPERATION_UNSUPPORTED");
    phase = "PREWRITE";
    mutationConnection = input.mutationConnection ?? await input.binding.connect();
    session = createMutationSession(mutationConnection);
    await session.begin();
    await session.acquireTargetLock(observedTargetBindingDigest);
    await session.acquireMutationLocks(input.plan.operations);
    const revalidated = await captureMutationPrestate(input.binding, mutationConnection, input.journal);
    assertPrewriteBinding({
      expectedPrestateDigest,
      observedPrestateDigest: revalidated.prestate_digest,
      expectedContractDigest: input.expectedContractDigest,
      observedContractDigest,
      expectedPlanDigest: input.plan.plan_digest,
      observedPlanDigest: input.plan.plan_digest,
      expectedTargetBindingDigest: observedTargetBindingDigest,
      observedTargetBindingDigest: computeTargetBindingDigest(input.binding),
    });
    phase = "FORWARD";
    if (isMigration) {
      const migrationResult = await runCanonicalMigrationPrimitive({
        pool: {
          connect: async () => ({
            query: (text: DurableQueryInput, values?: readonly unknown[]) => mutationConnection!.query(text, values),
            release() {},
          }),
          query: (text, values) => mutationConnection!.query(text, values),
        },
        migrationsFolder: input.migrationsFolder as string,
        expectedOperations: input.plan.operations as readonly MigrationOperationV1[],
        existingTransaction: true,
      });
      mutationStarted = migrationResult.mutation_started;
    } else {
      for (const operation of input.plan.operations) await session.applyOperation(operation);
      mutationStarted = session.mutationStarted;
    }
    phase = "COMMIT";
    try {
      await session.commit();
      committed = true;
    } catch (error) {
      if (error instanceof DurableOperationError) throw error;
      fail(commitFailureCode(error));
    }
    phase = "FINAL_VERIFY";
    const final = await captureNormalizedPrestate(input.binding, input.journal);
    assertFinalRolePosture(expectedPrestate, final.prestate);
    finalReadinessState = canonicalReadinessPass(final.prestate) ? "PASS" : "FAIL";
    if (finalReadinessState !== "PASS") fail("FINAL_VERIFICATION_FAILED");
    return makeReceipt({
      plan: input.plan,
      phase: "FINAL_VERIFY",
      outcome: "PASS",
      semanticCode: "SUCCESS",
      mutationStarted,
      rollbackAttempted,
      rollbackVerified,
      restorationState: "NOT_REQUIRED",
      finalReadinessState,
      inverseSteps: inverse?.steps.length ?? 0,
    });
  } catch (error) {
    mutationStarted ||= session?.mutationStarted === true ||
      (error instanceof DurableOperationError && error.mutationStarted);
    const originalPhase = phase;
    const originalCode = originalPhase === "FORWARD"
      ? mutationFailureCode(error)
      : originalPhase === "COMMIT"
        ? commitFailureCode(error)
        : mapFailureCode(error);
    if (!mutationStarted) {
      if (session) await session.rollback().catch(() => {});
      return makeReceipt({
        plan: input.plan,
        phase: originalPhase,
        outcome: originalPhase === "FORWARD" ? "FAIL" : "BLOCKED",
        semanticCode: originalCode,
        mutationStarted: false,
        rollbackAttempted: false,
        rollbackVerified: false,
        restorationState: "NOT_REQUIRED",
        finalReadinessState,
        inverseSteps: inverse?.steps.length ?? 0,
      });
    }
    let rollbackFailure = false;
    if (session && !committed) {
      rollbackAttempted = true;
      try {
        await session.rollback();
      } catch {
        rollbackFailure = true;
      }
    }
    if (mutationConnection && !connectionClosed) {
      await closeConnection(mutationConnection);
      connectionClosed = true;
    }
    let restoration = await verifyRestoration({
      binding: input.binding,
      expectedPrestateDigest,
      journal: input.journal,
    });
    if (restoration.state === "FAILED" && inverse) {
      rollbackAttempted = true;
      try {
        await executeFrozenInverse({
          binding: input.binding,
          targetBindingDigest: observedTargetBindingDigest || computeTargetBindingDigest(input.binding),
          expectedPrestateDigest,
          journal: input.journal as CanonicalMigrationJournalV1,
          inverse,
        });
        restoration = await verifyRestoration({
          binding: input.binding,
          expectedPrestateDigest,
          journal: input.journal,
        });
      } catch {
        restoration = { state: "FAILED" };
      }
    }
    let recoveryCode: SemanticCode | undefined;
    let recoveryPhase: ReceiptPhase | undefined;
    if (restoration.state !== "VERIFIED" && restoreCapability) {
      try {
        const reason: RestoreRequestV1["reason"] = committed
          ? "post_commit_failure"
          : originalCode === "MUTATION_FAILED" || originalCode === "WRITE_INDETERMINATE"
            ? "indeterminate_send"
            : "forward_failure";
        await executeRestoreCapability(restoreCapability, input.plan, reason);
        restoration = await verifyRestoration({
          binding: input.binding,
          expectedPrestateDigest,
          journal: input.journal,
        });
      } catch (restoreError) {
        recoveryCode = mapFailureCode(restoreError);
        recoveryPhase = "RESTORE";
        restoration = { state: "AMBIGUOUS" };
      }
    }
    rollbackVerified = restoration.state === "VERIFIED";
    const semanticCode = recoveryCode ??
      (rollbackFailure
        ? "ROLLBACK_FAILED"
        : restoration.state === "VERIFIED"
          ? originalCode
          : restoration.state === "FAILED"
            ? "RESTORATION_FAILED"
            : "RESTORATION_AMBIGUOUS");
    const receiptPhase = recoveryPhase ??
      (rollbackFailure
        ? "ROLLBACK"
        : restoration.state === "VERIFIED"
          ? originalPhase
          : "RESTORE_VERIFY");
    return makeReceipt({
      plan: input.plan,
      phase: receiptPhase,
      outcome: "FAIL",
      semanticCode,
      mutationStarted: true,
      rollbackAttempted,
      rollbackVerified,
      restorationState: restoration.state,
      finalReadinessState,
      inverseSteps: inverse?.steps.length ?? 0,
    });
  } finally {
    if (mutationConnection && !connectionClosed) await closeConnection(mutationConnection);
  }
}

function makeReceipt(input: {
  plan: DurablePlanV1;
  phase: ReceiptPhase;
  outcome: DurableReceiptV1["outcome"];
  semanticCode: SemanticCode;
  mutationStarted: boolean;
  rollbackAttempted: boolean;
  rollbackVerified: boolean;
  restorationState: DurableReceiptV1["restoration_state"];
  finalReadinessState: DurableReceiptV1["final_readiness_state"];
  inverseSteps: number;
}): DurableReceiptV1 {
  const roles = new Set<ApprovedReceiptRoleName>();
  for (const operation of input.plan.operations) {
    if (operation.kind === "role_posture") roles.add(operation.role);
    if (operation.kind === "membership") roles.add(operation.granted_role), roles.add(operation.member), roles.add(operation.grantor);
    if (operation.kind === "ownership") roles.add(operation.previous_owner), roles.add(operation.next_owner);
    if (operation.kind === "privilege" && operation.principal !== "PUBLIC") roles.add(operation.principal as ApprovedReceiptRoleName);
    if (operation.kind === "default_acl") {
      roles.add(operation.creator);
      if (operation.principal !== "PUBLIC") roles.add(operation.principal as ApprovedReceiptRoleName);
    }
  }
  const counts: DurableCounts = {
    canonical_objects: input.plan.operations.filter((operation) => operation.kind === "ownership" || operation.kind === "privilege").length,
    direct_privileges: input.plan.operations.filter((operation) => operation.kind === "privilege" && operation.principal !== "PUBLIC").length,
    public_privileges: input.plan.operations.filter((operation) => operation.kind === "privilege" && operation.principal === "PUBLIC").length,
    default_acls: input.plan.operations.filter((operation) => operation.kind === "default_acl").length,
    memberships: input.plan.operations.filter((operation) => operation.kind === "membership").length,
    migration_entries: input.plan.operations.filter((operation) => operation.kind === "migration").length,
    operations: input.plan.operations.length,
    inverse_steps: input.inverseSteps,
  };
  return projectReceipt({
    receipt_version: 1,
    phase: input.phase,
    outcome: input.outcome,
    semantic_code: input.semanticCode,
    operation_kind: input.plan.operation_kind,
    git_sha: input.plan.expected_git_sha,
    contract_digest: input.plan.contract_digest,
    role_names: [...roles].sort(),
    counts,
    mutation_started: input.mutationStarted,
    rollback_attempted: input.rollbackAttempted,
    rollback_verified: input.rollbackVerified,
    restoration_state: input.restorationState,
    final_readiness_state: input.finalReadinessState,
    ...(input.plan.operations.find((operation): operation is MigrationOperationV1 => operation.kind === "migration")?.tag ? { migration_tag: input.plan.operations.find((operation): operation is MigrationOperationV1 => operation.kind === "migration")?.tag } : {}),
  });
}
