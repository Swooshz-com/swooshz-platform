import { createHash } from "node:crypto";

import {
  CANONICAL_PLATFORM_ENUM_TYPES,
  CANONICAL_PLATFORM_ROUTINES,
  CANONICAL_PLATFORM_TABLES,
  MIGRATOR_READINESS_FIELDS,
  REQUIRED_PLATFORM_TABLES,
  migratorPostureSql,
} from "./readiness.js";

export const BROKER_TARGET_BINDING_VERSION = "platform-db-broker-target-v2" as const;
export const BROKER_OBSERVATION_BUNDLE_VERSION = "platform-db-broker-observation-bundle-v1" as const;
export const BROKER_OBSERVATION_EVIDENCE_VERSION = "platform-db-broker-observation-evidence-v1" as const;
export const BROKER_AUTHORITY_CLASSIFICATION_VERSION = "platform-db-broker-authority-classification-v1" as const;
export const BROKER_MUTATION_BUNDLE_VERSION = "platform-db-broker-mutation-bundle-v1" as const;
export const BROKER_ATTEMPT_RESERVATION_VERSION = "platform-db-migration-attempt-reservation-v1" as const;
export const BROKER_RESULT_VERSION = "platform-db-broker-result-v1" as const;

export const BROKER_TARGET_BINDING_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-target-v2\0" as const;
export const BROKER_OBSERVATION_BUNDLE_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-observation-bundle-v1\0" as const;
export const BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-observation-evidence-v1\0" as const;
export const BROKER_AUTHORITY_CLASSIFICATION_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-authority-classification-v1\0" as const;
export const BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-mutation-bundle-v1\0" as const;
export const BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-migration-attempt-reservation-v1\0" as const;
export const BROKER_RESULT_DOMAIN_SEPARATOR = "Swooshz-platform:platform-db-broker-result-v1\0" as const;

const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const POSITIVE_INTEGER = /^[1-9]\d*$/u;
const IDENTIFIER = /^[a-z_][a-z0-9_$]{0,62}$/u;
const MIGRATION_TAG = "0010_admin_operator_viewer_role_collapse";
const MIGRATION_CREATED_AT = 1787479999088;
const MIGRATION_SQL_SHA256 = "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b";
const FIRST_NINE_MIGRATIONS = Object.freeze([
  { created_at: "1782546111134", hashes: ["d156026594b36870455ba6df7525310be1ce1838cda1d58725c6f3a07514c0a6", "a4636f7af908cae22e8b15ed59103251b2f865f65a37b496b0ac4e38bc68d09b"] },
  { created_at: "1782571351615", hashes: ["861614ef57601aff17a15fe594becfc0206fa931f22052ba98217e300285666d", "f32a717626f2ab3d009a457b81664ba2666a2318129a3383a45146b0ea6634cd"] },
  { created_at: "1782629131478", hashes: ["76fd758786fa4583e18f3b89bf7fba0932bdb9c71de294f3291b19925bbd542b", "b8f3c2d5ac88d9cba57368695219325b025f9c953ce1e7ac59f2882ec1592321"] },
  { created_at: "1782651725342", hashes: ["41567c07fcdb3b6e41da516d346d1a20d5e3aa4b0c5d3297e8b19091fa8f5f09", "41a3648d3443e63031277734e805b8826e8f6f34b6f6fdb9db8ed63f5fcdeb1f"] },
  { created_at: "1783253616083", hashes: ["01179c79b777732dc03dbef0471738e00dc85964082aa22764184362722ac5fe", "5be34c50c70b76f167da4722920946f9272fd8b3aafd405718e3c76dfcea2b3d"] },
  { created_at: "1783479304000", hashes: ["651eaa1668341fc8bdbc8d6f47ccfdd9ec1e2c80fef018de73ab0a79b9896bbe", "b47e5a1575abc53c523fada3266e32556f3e3b267c7d6878719c5aee30876a3e"] },
  { created_at: "1783587520445", hashes: ["a8b5d90838c87ca3d74ada48295b92970c8a8476dacf5fc76b1a793995d7485b"] },
  { created_at: "1784354477743", hashes: ["0e82a5892f22b71f8894f8776388341519ac48944a417552443d639d09cdcbc0", "1a74bbfbe23b11693dd1d1571bf6eb6d4340832124143134afe89e2c9337d0b3"] },
  { created_at: "1784620602227", hashes: ["bc54f927f5ab0a2ebc97a61ede57119f29e8673ab1b902a4e132191ac688820f", "b1f9291edfb018633add360eb4e81520f9be9690c38bb1c2dede9de29a2fe25b"] },
]);
const POSTURE_RESULT_SCHEMA = Object.freeze([...MIGRATOR_READINESS_FIELDS, "application_relation_owner_exact"]);
const ROLE_DATA_RESULT_SCHEMA = Object.freeze([
  "role_labels",
  "role_values_valid",
  "nullable_requester_valid",
  "bootstrap_cardinality_valid",
  "active_workspace_admin_valid",
]);

export interface BrokerTargetBindingV2 {
  readonly version: typeof BROKER_TARGET_BINDING_VERSION;
  readonly project_id: string;
  readonly branch_id: string;
  readonly endpoint_id: string;
  readonly endpoint_type: "read_write";
  readonly logical_database_name: string;
  readonly expected_database_oid: string;
  readonly expected_cluster_system_identifier: string;
  readonly expected_postgres_major: 17;
  readonly expected_provider_role_name: string;
  readonly expected_provider_role_oid: string;
}

export interface BrokerAuthorityClassificationV1 {
  readonly version: typeof BROKER_AUTHORITY_CLASSIFICATION_VERSION;
  readonly nodes: readonly {
    readonly role_name: string;
    readonly role_oid: string;
    readonly authority_class: "APPLICATION" | "RUNTIME" | "MIGRATOR" | "PROVIDER_CONTROL" | "RUNTIME_CREATOR_TUPLE";
  }[];
  readonly runtime_creator_tuple: {
    readonly granted_role: "platform_runtime";
    readonly member: "platform_app";
    readonly grantor: "cloud_admin";
    readonly admin_option: true;
    readonly inherit_option: false;
    readonly set_option: false;
  };
}

export interface BrokerStatementV1 {
  readonly ordinal: number;
  readonly id: string;
  readonly phase: "OBSERVE" | "ADMISSION" | "LOCK" | "ASSUME_ROLE" | "MIGRATION" | "LEDGER" | "VERIFY" | "CLEANUP";
  readonly sql: string;
  readonly sha256: string;
  readonly mutating: boolean;
  readonly result_schema: readonly string[];
}

export type BrokerStatementResultMapV1 = Readonly<Record<string, readonly Record<string, unknown>[]>>;

export interface BrokerObservationBundleV1 {
  readonly version: typeof BROKER_OBSERVATION_BUNDLE_VERSION;
  readonly run: string;
  readonly lock: string;
  readonly git_sha: string;
  readonly git_tree: string;
  readonly contract_digest: string;
  readonly source_manifest_digest: string;
  readonly build_manifest_digest: string;
  readonly target_binding: BrokerTargetBindingV2;
  readonly target_binding_digest: string;
  readonly authority_classification: BrokerAuthorityClassificationV1;
  readonly authority_classification_digest: string;
  readonly transaction_policy: "REPEATABLE_READ_READ_ONLY_FAIL_ON_ERROR";
  readonly statements: readonly BrokerStatementV1[];
  readonly bundle_digest: string;
}

export interface BrokerObservationEvidenceV1 {
  readonly version: typeof BROKER_OBSERVATION_EVIDENCE_VERSION;
  readonly observation_bundle_digest: string;
  readonly target_binding_digest: string;
  readonly authority_classification_digest: string;
  readonly provider: {
    readonly current_user: string;
    readonly session_user: string;
    readonly role_oid: string;
    readonly rolsuper: boolean;
  };
  readonly target: {
    readonly logical_database_name: string;
    readonly database_oid: string;
    readonly cluster_system_identifier: string;
    readonly postgres_major: 17;
    readonly in_recovery: false;
  };
  readonly migrator: {
    readonly role_name: "platform_migrator";
    readonly role_oid: string;
    readonly rolcanlogin: false;
    readonly rolinherit: false;
    readonly rolsuper: false;
    readonly rolcreatedb: false;
    readonly rolcreaterole: false;
    readonly rolreplication: false;
    readonly rolbypassrls: false;
    readonly password_is_null: true;
    readonly provider_has_set: true;
  };
  readonly authority_graph: {
    readonly nodes: readonly {
      readonly role_name: string;
      readonly role_oid: string;
      readonly rolsuper: boolean;
      readonly rolcreaterole: boolean;
    }[];
    readonly edges: readonly {
      readonly granted_role: string;
      readonly granted_role_oid: string;
      readonly member: string;
      readonly member_oid: string;
      readonly grantor: string;
      readonly grantor_oid: string;
      readonly admin_option: boolean;
      readonly inherit_option: boolean;
      readonly set_option: boolean;
    }[];
    readonly closure_complete: true;
    readonly application_authority_absent: true;
  };
  readonly ledger: {
    readonly first_nine_identity_digest: string;
    readonly row_count: 9 | 10;
    readonly migration_0010_absent: boolean;
  };
  readonly canonical_posture_digest: string;
  readonly evidence_digest: string;
}

export interface BrokerMutationBundleV1 {
  readonly version: typeof BROKER_MUTATION_BUNDLE_VERSION;
  readonly run: string;
  readonly lock: string;
  readonly git_sha: string;
  readonly git_tree: string;
  readonly contract_digest: string;
  readonly source_manifest_digest: string;
  readonly build_manifest_digest: string;
  readonly target_binding_digest: string;
  readonly authority_classification_digest: string;
  readonly observation_evidence_digest: string;
  readonly prestate_digest: string;
  readonly plan_digest: string;
  readonly attempt_policy: { readonly maximum: 1 };
  readonly migration: {
    readonly tag: typeof MIGRATION_TAG;
    readonly journal_index: 9;
    readonly created_at: typeof MIGRATION_CREATED_AT;
    readonly sql_sha256: typeof MIGRATION_SQL_SHA256;
  };
  readonly transaction_policy: "SERIALIZABLE_READ_WRITE_FAIL_ON_ERROR_SINGLE_COMMIT";
  readonly statements: readonly BrokerStatementV1[];
  readonly bundle_digest: string;
}

export interface BrokerAttemptReservationV1 {
  readonly version: typeof BROKER_ATTEMPT_RESERVATION_VERSION;
  readonly state: "RESERVED_CONSUMED";
  readonly run: string;
  readonly lock: string;
  readonly target_binding_digest: string;
  readonly plan_digest: string;
  readonly mutation_bundle_digest: string;
  readonly reservation_id: string;
  readonly reservation_digest: string;
}

export interface BrokerMutationResultV1 {
  readonly version: typeof BROKER_RESULT_VERSION;
  readonly mutation_bundle_digest: string;
  readonly reservation_digest: string;
  readonly dispatch_state: "NOT_DISPATCHED" | "DISPATCHED" | "INDETERMINATE";
  readonly commit_state: "NOT_COMMITTED" | "COMMITTED" | "INDETERMINATE";
  readonly cleanup_state: "DISCARDED" | "FAILED" | "INDETERMINATE";
  readonly migration_tag: typeof MIGRATION_TAG;
  readonly migration_sql_sha256: typeof MIGRATION_SQL_SHA256;
  readonly safe_result_digest: string;
  readonly result_digest: string;
}

export interface MigrationAttemptStoreV1 {
  reserveOnce(input: {
    readonly run: string;
    readonly lock: string;
    readonly target_binding_digest: string;
    readonly plan_digest: string;
    readonly mutation_bundle_digest: string;
  }): Promise<BrokerAttemptReservationV1>;
}

export interface ProductionDatabaseBrokerV1 {
  observe(serializedObservationBundle: string, observationBundleDigest: string): Promise<unknown>;
  dispatchMutation(
    serializedMutationBundle: string,
    mutationBundleDigest: string,
    reservation: BrokerAttemptReservationV1,
  ): Promise<unknown>;
}

function reject(code: string): never {
  throw new Error(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== expected.size || actual.some((key) => !expected.has(key))) reject("BROKER_ARTIFACT_INVALID");
}

function text(value: unknown, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0 || (pattern && !pattern.test(value))) reject("BROKER_ARTIFACT_INVALID");
  return value;
}

function digest(value: unknown): string {
  return text(value, HEX64);
}

function oid(value: unknown): string {
  return text(value, POSITIVE_INTEGER);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonicalValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) reject("BROKER_CANONICALIZATION_REJECTED");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(",")}}`;
  }
  reject("BROKER_CANONICALIZATION_REJECTED");
}

export function canonicalSerializeBrokerBundle(value: unknown): string {
  return canonicalValue(value);
}

export function computeBrokerBundleDigest(domainSeparator: string, value: unknown): string {
  if (typeof domainSeparator !== "string" || !domainSeparator.endsWith("\0")) reject("BROKER_DOMAIN_INVALID");
  return sha256(domainSeparator + canonicalSerializeBrokerBundle(value));
}

function withoutDigest<T extends Record<string, unknown>>(value: T, key: string): Record<string, unknown> {
  const result = { ...value };
  delete result[key];
  return result;
}

function validateTarget(value: BrokerTargetBindingV2): BrokerTargetBindingV2 {
  if (!isRecord(value)) reject("BROKER_TARGET_INVALID");
  exactKeys(value, ["version", "project_id", "branch_id", "endpoint_id", "endpoint_type", "logical_database_name", "expected_database_oid", "expected_cluster_system_identifier", "expected_postgres_major", "expected_provider_role_name", "expected_provider_role_oid"]);
  if (value.version !== BROKER_TARGET_BINDING_VERSION || value.endpoint_type !== "read_write" || value.expected_postgres_major !== 17) reject("BROKER_TARGET_INVALID");
  text(value.project_id); text(value.branch_id); text(value.endpoint_id);
  text(value.logical_database_name, IDENTIFIER); oid(value.expected_database_oid); oid(value.expected_cluster_system_identifier);
  text(value.expected_provider_role_name, IDENTIFIER); oid(value.expected_provider_role_oid);
  if (["platform_app", "platform_runtime", "platform_migrator"].includes(value.expected_provider_role_name)) reject("BROKER_SESSION_IDENTITY_REJECTED");
  return Object.freeze({ ...value });
}

function validateClassification(value: BrokerAuthorityClassificationV1): BrokerAuthorityClassificationV1 {
  if (!isRecord(value)) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
  exactKeys(value, ["version", "nodes", "runtime_creator_tuple"]);
  if (value.version !== BROKER_AUTHORITY_CLASSIFICATION_VERSION || !Array.isArray(value.nodes) || !isRecord(value.runtime_creator_tuple)) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
  exactKeys(value.runtime_creator_tuple, ["granted_role", "member", "grantor", "admin_option", "inherit_option", "set_option"]);
  const tuple = value.runtime_creator_tuple;
  if (tuple.granted_role !== "platform_runtime" || tuple.member !== "platform_app" || tuple.grantor !== "cloud_admin" || tuple.admin_option !== true || tuple.inherit_option !== false || tuple.set_option !== false) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
  const names = new Set<string>();
  const oids = new Set<string>();
  let previous = "";
  for (const node of value.nodes) {
    if (!isRecord(node)) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
    exactKeys(node, ["role_name", "role_oid", "authority_class"]);
    const roleName = text(node.role_name, IDENTIFIER);
    const roleOid = oid(node.role_oid);
    const order = `${roleOid.padStart(20, "0")}\0${roleName}`;
    if (names.has(roleName) || oids.has(roleOid) || order <= previous) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
    if (!["APPLICATION", "RUNTIME", "MIGRATOR", "PROVIDER_CONTROL", "RUNTIME_CREATOR_TUPLE"].includes(String(node.authority_class))) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
    names.add(roleName); oids.add(roleOid); previous = order;
  }
  for (const required of ["platform_app", "platform_runtime", "platform_migrator"]) if (!names.has(required)) reject("BROKER_AUTHORITY_CLASSIFICATION_INVALID");
  return Object.freeze({ ...value, nodes: Object.freeze(value.nodes.map((node) => Object.freeze({ ...node }))), runtime_creator_tuple: Object.freeze({ ...tuple }) });
}

function statement(ordinal: number, id: string, phase: BrokerStatementV1["phase"], sql: string, mutating: boolean, resultSchema: readonly string[] = []): BrokerStatementV1 {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0 || !/^[a-z][a-z0-9_]{0,79}$/u.test(id) || typeof sql !== "string" || !sql.trim()) reject("BROKER_STATEMENT_INVALID");
  return Object.freeze({ ordinal, id, phase, sql, sha256: sha256(sql), mutating, result_schema: Object.freeze([...resultSchema]) });
}

function sqlTextArray(values: readonly string[]): string {
  return `array[${values.map((value) => `'${value.replaceAll("'", "''")}'`).join(",")}]::text[]`;
}

function compiledCanonicalPostureSql(): string {
  return migratorPostureSql
    .replaceAll("$1::text[]", sqlTextArray(REQUIRED_PLATFORM_TABLES))
    .replaceAll("$2::text[]", sqlTextArray(CANONICAL_PLATFORM_TABLES))
    .replaceAll("$3::text[]", sqlTextArray(CANONICAL_PLATFORM_ENUM_TYPES))
    .replaceAll("$4::text[]", sqlTextArray(CANONICAL_PLATFORM_ROUTINES));
}

function compiledAssumedRolePostureSql(providerRoleName: string): string {
  const provider = providerRoleName.replaceAll("'", "''");
  return compiledCanonicalPostureSql().replace(
    "current_user = session_user\n    and current_user not in ('platform_app', 'platform_runtime')",
    `current_user = 'platform_migrator'\n    and session_user = '${provider}'`,
  );
}

const ROLE_DATA_INVARIANTS_SQL = `select
  (select string_agg(enum_record.enumlabel, ',' order by enum_record.enumsortorder)
     from pg_catalog.pg_enum enum_record
     join pg_catalog.pg_type type_record on type_record.oid = enum_record.enumtypid
     join pg_catalog.pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace
    where namespace_record.nspname = 'public' and type_record.typname = 'role') as role_labels,
  not exists (
    select role_value from (
      select role::text as role_value from public.invitations
      union all select role::text from public.memberships
      union all select role::text from public.workspace_membership_approvals
    ) role_values
    where role_value not in ('owner', 'admin', 'member', 'operator', 'viewer')
  ) as role_values_valid,
  not exists (
    select 1 from public.workspace_membership_approvals approval
    left join public.workspaces workspace on workspace.id = approval.workspace_id
    where approval.status = 'pending' and approval.requested_by_user_id is null
      and not (workspace.status = 'active'
        and not exists (select 1 from public.memberships membership where membership.workspace_id = approval.workspace_id)
        and approval.role::text in ('owner', 'admin'))
  ) as nullable_requester_valid,
  not exists (
    select approval.workspace_id from public.workspace_membership_approvals approval
    where approval.status = 'pending' and approval.requested_by_user_id is null
      and approval.role::text in ('owner', 'admin')
    group by approval.workspace_id having count(*) <> 1
  ) as bootstrap_cardinality_valid,
  not exists (
    select 1 from public.workspaces workspace
    where workspace.status = 'active'
      and exists (select 1 from public.memberships membership where membership.workspace_id = workspace.id)
      and not exists (select 1 from public.memberships membership where membership.workspace_id = workspace.id
        and membership.status = 'active' and membership.role::text in ('owner', 'admin'))
  ) as active_workspace_admin_valid`;

function commonPayload(input: {
  run: string; lock: string; git_sha: string; git_tree: string; contract_digest: string;
  source_manifest_digest: string; build_manifest_digest: string;
  target_binding: BrokerTargetBindingV2; authority_classification: BrokerAuthorityClassificationV1;
}) {
  const target = validateTarget(input.target_binding);
  const classification = validateClassification(input.authority_classification);
  return {
    run: text(input.run), lock: text(input.lock), git_sha: text(input.git_sha, HEX40), git_tree: text(input.git_tree, HEX40),
    contract_digest: digest(input.contract_digest), source_manifest_digest: digest(input.source_manifest_digest), build_manifest_digest: digest(input.build_manifest_digest),
    target_binding: target,
    target_binding_digest: computeBrokerBundleDigest(BROKER_TARGET_BINDING_DOMAIN_SEPARATOR, target),
    authority_classification: classification,
    authority_classification_digest: computeBrokerBundleDigest(BROKER_AUTHORITY_CLASSIFICATION_DOMAIN_SEPARATOR, classification),
  };
}

export function compileBrokerObservationBundle(input: {
  run: string; lock: string; git_sha: string; git_tree: string; contract_digest: string;
  source_manifest_digest: string; build_manifest_digest: string;
  target_binding: BrokerTargetBindingV2; authority_classification: BrokerAuthorityClassificationV1;
}): BrokerObservationBundleV1 {
  const common = commonPayload(input);
  const closureSeeds = common.authority_classification.nodes.map((node) => `(${node.role_oid}::oid)`).join(", ");
  const closureSql = `with recursive role_closure(role_oid) as (values ${closureSeeds} union select incident.next_oid from role_closure seed join lateral (select edge.roleid as next_oid from pg_catalog.pg_auth_members edge where edge.roleid = seed.role_oid or edge.member = seed.role_oid or edge.grantor = seed.role_oid union select edge.member from pg_catalog.pg_auth_members edge where edge.roleid = seed.role_oid or edge.member = seed.role_oid or edge.grantor = seed.role_oid union select edge.grantor from pg_catalog.pg_auth_members edge where edge.roleid = seed.role_oid or edge.member = seed.role_oid or edge.grantor = seed.role_oid) incident on true)`;
  const statements = [
    statement(0, "provider_target_identity", "OBSERVE", `select current_user, session_user, role_record.oid::text as role_oid, role_record.rolsuper, current_database() as logical_database_name, database_record.oid::text as database_oid, control_state.system_identifier::text as cluster_system_identifier, (current_setting('server_version_num')::int / 10000)::int as postgres_major, pg_is_in_recovery() as in_recovery from pg_catalog.pg_roles role_record cross join pg_catalog.pg_database database_record cross join pg_catalog.pg_control_system() control_state where role_record.rolname = current_user and database_record.datname = current_database()`, false, ["current_user", "session_user", "role_oid", "rolsuper", "logical_database_name", "database_oid", "cluster_system_identifier", "postgres_major", "in_recovery"]),
    statement(1, "migrator_dormancy", "OBSERVE", `select role_record.rolname as role_name, role_record.oid::text as role_oid, role_record.rolcanlogin, role_record.rolinherit, role_record.rolsuper, role_record.rolcreatedb, role_record.rolcreaterole, role_record.rolreplication, role_record.rolbypassrls, (auth_record.rolpassword is null) as password_is_null, pg_catalog.pg_has_role(session_user, role_record.oid, 'SET') as provider_has_set from pg_catalog.pg_roles role_record join pg_catalog.pg_authid auth_record on auth_record.oid = role_record.oid where role_record.rolname = 'platform_migrator'`, false, ["role_name", "role_oid", "rolcanlogin", "rolinherit", "rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls", "password_is_null", "provider_has_set"]),
    statement(2, "authority_graph_nodes", "OBSERVE", `${closureSql} select role_record.rolname as role_name, role_record.oid::text as role_oid, role_record.rolsuper, role_record.rolcreaterole from role_closure closure join pg_catalog.pg_roles role_record on role_record.oid = closure.role_oid order by role_record.oid, role_record.rolname`, false, ["role_name", "role_oid", "rolsuper", "rolcreaterole"]),
    statement(3, "authority_graph_edges", "OBSERVE", `${closureSql} select granted.rolname as granted_role, granted.oid::text as granted_role_oid, member_role.rolname as member, member_role.oid::text as member_oid, grantor.rolname as grantor, grantor.oid::text as grantor_oid, edge.admin_option, edge.inherit_option, edge.set_option from pg_catalog.pg_auth_members edge join role_closure closure on closure.role_oid in (edge.roleid, edge.member, edge.grantor) join pg_catalog.pg_roles granted on granted.oid = edge.roleid join pg_catalog.pg_roles member_role on member_role.oid = edge.member join pg_catalog.pg_roles grantor on grantor.oid = edge.grantor order by granted.oid, member_role.oid, grantor.oid`, false, ["granted_role", "granted_role_oid", "member", "member_oid", "grantor", "grantor_oid", "admin_option", "inherit_option", "set_option"]),
    statement(4, "migration_ledger", "OBSERVE", `select id, hash, created_at from drizzle.__drizzle_migrations order by created_at, id`, false, ["id", "hash", "created_at"]),
    statement(5, "canonical_posture", "OBSERVE", compiledCanonicalPostureSql(), false, POSTURE_RESULT_SCHEMA),
    statement(6, "role_data_invariants", "OBSERVE", ROLE_DATA_INVARIANTS_SQL, false, ROLE_DATA_RESULT_SCHEMA),
  ];
  const payload = { version: BROKER_OBSERVATION_BUNDLE_VERSION, ...common, transaction_policy: "REPEATABLE_READ_READ_ONLY_FAIL_ON_ERROR" as const, statements: Object.freeze(statements) };
  return Object.freeze({ ...payload, bundle_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_BUNDLE_DOMAIN_SEPARATOR, payload) });
}

function exactResultRows(value: unknown, schema: readonly string[], expectedCount?: number): Record<string, unknown>[] {
  if (!Array.isArray(value) || (expectedCount !== undefined && value.length !== expectedCount)) reject("BROKER_STATEMENT_RESULT_REJECTED");
  return value.map((raw) => {
    if (!isRecord(raw)) reject("BROKER_STATEMENT_RESULT_REJECTED");
    exactKeys(raw, schema);
    return raw;
  });
}

function normalizedLedgerRows(rows: readonly Record<string, unknown>[], phase: "PREWRITE" | "FINAL"): Array<{ id: number; hash: string; created_at: string }> {
  const expectedCount = phase === "PREWRITE" ? 9 : 10;
  if (rows.length !== expectedCount) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
  const normalized = rows.map((row, index) => {
    const id = typeof row.id === "number" ? row.id : Number(row.id);
    const createdAt = String(row.created_at);
    const hash = digest(row.hash);
    if (!Number.isSafeInteger(id) || id !== index + 1) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
    if (index < FIRST_NINE_MIGRATIONS.length) {
      const expected = FIRST_NINE_MIGRATIONS[index]!;
      if (createdAt !== expected.created_at || !expected.hashes.includes(hash)) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
    } else if (createdAt !== String(MIGRATION_CREATED_AT) || hash !== MIGRATION_SQL_SHA256) {
      reject("BROKER_MIGRATION_IDENTITY_REJECTED");
    }
    return { id, hash, created_at: createdAt };
  });
  return normalized;
}

export function validateBrokerStatementResult(
  observationBundle: BrokerObservationBundleV1,
  brokerStatement: BrokerStatementV1,
  rawRows: unknown,
  phase: "PREWRITE" | "FINAL" = "PREWRITE",
): readonly Record<string, unknown>[] {
  const sourceIndex = observationBundle.statements.findIndex((candidate) =>
    candidate.sql === brokerStatement.sql &&
    canonicalSerializeBrokerBundle(candidate.result_schema) === canonicalSerializeBrokerBundle(brokerStatement.result_schema));
  const rows = exactResultRows(rawRows, brokerStatement.result_schema, brokerStatement.result_schema.length === 0 ? 0 : undefined);
  if (sourceIndex === 0) {
    if (rows.length !== 1) reject("BROKER_SESSION_IDENTITY_REJECTED");
    const row = rows[0]!;
    const target = observationBundle.target_binding;
    if (row.current_user !== target.expected_provider_role_name || row.session_user !== target.expected_provider_role_name || String(row.role_oid) !== target.expected_provider_role_oid || row.logical_database_name !== target.logical_database_name || String(row.database_oid) !== target.expected_database_oid || String(row.cluster_system_identifier) !== target.expected_cluster_system_identifier || Number(row.postgres_major) !== 17 || row.in_recovery !== false || typeof row.rolsuper !== "boolean") reject("BROKER_SESSION_IDENTITY_REJECTED");
  } else if (sourceIndex === 1) {
    if (rows.length !== 1) reject("BROKER_MIGRATOR_DORMANCY_REJECTED");
    const row = rows[0]!;
    if (row.role_name !== "platform_migrator" || !POSITIVE_INTEGER.test(String(row.role_oid)) || row.rolcanlogin !== false || row.rolinherit !== false || row.rolsuper !== false || row.rolcreatedb !== false || row.rolcreaterole !== false || row.rolreplication !== false || row.rolbypassrls !== false || row.password_is_null !== true || row.provider_has_set !== true) reject("BROKER_MIGRATOR_DORMANCY_REJECTED");
  } else if (sourceIndex === 4) {
    normalizedLedgerRows(rows, phase);
  } else if (sourceIndex === 5) {
    if (rows.length !== 1 || brokerStatement.result_schema.some((key) => rows[0]![key] !== true)) reject("BROKER_CANONICAL_POSTURE_REJECTED");
  } else if (sourceIndex === 6) {
    if (rows.length !== 1) reject("BROKER_CANONICAL_POSTURE_REJECTED");
    const expectedLabels = phase === "PREWRITE" ? "owner,admin,member,viewer" : "admin,operator,viewer";
    if (rows[0]!.role_labels !== expectedLabels || ROLE_DATA_RESULT_SCHEMA.slice(1).some((key) => rows[0]![key] !== true)) reject("BROKER_CANONICAL_POSTURE_REJECTED");
  } else if (brokerStatement.id === "assumed_identity_assertion" || brokerStatement.id === "final_role_assertion") {
    if (rows.length !== 1 || rows[0]!.current_user !== "platform_migrator" || rows[0]!.session_user !== observationBundle.target_binding.expected_provider_role_name || String(rows[0]!.current_role_oid) !== observationBundle.authority_classification.nodes.find((node) => node.role_name === "platform_migrator")?.role_oid || String(rows[0]!.session_role_oid) !== observationBundle.target_binding.expected_provider_role_oid) reject("BROKER_SESSION_IDENTITY_REJECTED");
  } else if (brokerStatement.id === "cleanup_identity_assertion") {
    if (rows.length !== 1 || rows[0]!.current_user !== observationBundle.target_binding.expected_provider_role_name || rows[0]!.session_user !== observationBundle.target_binding.expected_provider_role_name || String(rows[0]!.current_role_oid) !== observationBundle.target_binding.expected_provider_role_oid || String(rows[0]!.session_role_oid) !== observationBundle.target_binding.expected_provider_role_oid) reject("BROKER_SESSION_IDENTITY_REJECTED");
  } else if (brokerStatement.id === "final_canonical_posture_assertion") {
    if (rows.length !== 1 || brokerStatement.result_schema.some((key) => rows[0]![key] !== true)) reject("BROKER_CANONICAL_POSTURE_REJECTED");
  } else if (brokerStatement.id === "target_advisory_lock") {
    if (rows.length !== 1 || rows[0]!.lock_acquired !== true) reject("BROKER_STATEMENT_RESULT_REJECTED");
  } else if (brokerStatement.id === "locked_binding_assertion") {
    if (rows.length !== 1 || rows[0]!.contract_digest !== observationBundle.contract_digest || rows[0]!.source_manifest_digest !== observationBundle.source_manifest_digest || rows[0]!.build_manifest_digest !== observationBundle.build_manifest_digest || rows[0]!.target_binding_digest !== observationBundle.target_binding_digest || rows[0]!.authority_classification_digest !== observationBundle.authority_classification_digest || ["observation_evidence_digest", "prestate_digest", "plan_digest"].some((key) => !HEX64.test(String(rows[0]![key])))) reject("BROKER_STATEMENT_RESULT_REJECTED");
  } else if (sourceIndex < 0 && brokerStatement.result_schema.length > 0) {
    reject("BROKER_STATEMENT_RESULT_REJECTED");
  }
  return Object.freeze(rows.map((row) => Object.freeze({ ...row })));
}

export function normalizeBrokerAttemptReservation(
  input: unknown,
  bundle: BrokerMutationBundleV1,
): BrokerAttemptReservationV1 {
  if (!isRecord(input)) reject("BROKER_ATTEMPT_RESERVATION_INVALID");
  exactKeys(input, ["version", "state", "run", "lock", "target_binding_digest", "plan_digest", "mutation_bundle_digest", "reservation_id", "reservation_digest"]);
  if (input.version !== BROKER_ATTEMPT_RESERVATION_VERSION || input.state !== "RESERVED_CONSUMED" || input.run !== bundle.run || input.lock !== bundle.lock || input.target_binding_digest !== bundle.target_binding_digest || input.plan_digest !== bundle.plan_digest || input.mutation_bundle_digest !== bundle.bundle_digest) reject("BROKER_ATTEMPT_RESERVATION_INVALID");
  text(input.reservation_id);
  const claimed = digest(input.reservation_digest);
  if (claimed !== computeBrokerBundleDigest(BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR, withoutDigest(input, "reservation_digest"))) reject("BROKER_ATTEMPT_RESERVATION_INVALID");
  return Object.freeze(input as unknown as BrokerAttemptReservationV1);
}

export function deriveBrokerObservationEvidence(
  bundle: BrokerObservationBundleV1,
  resultMap: BrokerStatementResultMapV1,
  phase: "PREWRITE" | "FINAL" = "PREWRITE",
): BrokerObservationEvidenceV1 {
  if (!isRecord(resultMap)) reject("BROKER_OBSERVATION_EVIDENCE_INVALID");
  exactKeys(resultMap, bundle.statements.map((entry) => entry.id));
  const results = new Map(bundle.statements.map((entry) => [entry.id, validateBrokerStatementResult(bundle, entry, resultMap[entry.id], phase)]));
  const providerRow = results.get("provider_target_identity")![0]!;
  const migratorRow = results.get("migrator_dormancy")![0]!;
  const nodeRows = results.get("authority_graph_nodes")!;
  const edgeRows = results.get("authority_graph_edges")!;
  const ledgerRows = normalizedLedgerRows(results.get("migration_ledger")!, phase);
  const graph = { nodes: nodeRows, edges: edgeRows, closure_complete: true as const, application_authority_absent: true as const };
  validateAuthorityGraph(graph, bundle.authority_classification, providerRow, migratorRow);
  const firstNine = ledgerRows.slice(0, 9);
  const posturePayload = {
    canonical_posture: results.get("canonical_posture")![0]!,
    role_data_invariants: results.get("role_data_invariants")![0]!,
  };
  const payload = {
    version: BROKER_OBSERVATION_EVIDENCE_VERSION,
    observation_bundle_digest: bundle.bundle_digest,
    target_binding_digest: bundle.target_binding_digest,
    authority_classification_digest: bundle.authority_classification_digest,
    provider: {
      current_user: String(providerRow.current_user), session_user: String(providerRow.session_user),
      role_oid: String(providerRow.role_oid), rolsuper: providerRow.rolsuper as boolean,
    },
    target: {
      logical_database_name: String(providerRow.logical_database_name), database_oid: String(providerRow.database_oid),
      cluster_system_identifier: String(providerRow.cluster_system_identifier), postgres_major: 17 as const, in_recovery: false as const,
    },
    migrator: {
      role_name: "platform_migrator" as const, role_oid: String(migratorRow.role_oid),
      rolcanlogin: false as const, rolinherit: false as const, rolsuper: false as const,
      rolcreatedb: false as const, rolcreaterole: false as const, rolreplication: false as const,
      rolbypassrls: false as const, password_is_null: true as const, provider_has_set: true as const,
    },
    authority_graph: graph as BrokerObservationEvidenceV1["authority_graph"],
    ledger: {
      first_nine_identity_digest: computeBrokerBundleDigest("Swooshz-platform:platform-db-first-nine-ledger-v1\0", firstNine),
      row_count: (phase === "PREWRITE" ? 9 : 10) as 9 | 10,
      migration_0010_absent: phase === "PREWRITE",
    },
    canonical_posture_digest: computeBrokerBundleDigest("Swooshz-platform:platform-db-canonical-posture-v1\0", posturePayload),
  };
  return Object.freeze({ ...payload, evidence_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, payload) });
}

function validateAuthorityGraph(
  graph: Record<string, unknown>,
  classification: BrokerAuthorityClassificationV1,
  provider: Record<string, unknown>,
  migrator: Record<string, unknown>,
): void {
  if (!Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  const classesByOid = new Map(classification.nodes.map((node) => [node.role_oid, node]));
  const nodesByOid = new Map<string, Record<string, unknown>>();
  let previousNode = "";
  for (const raw of graph.nodes) {
    if (!isRecord(raw)) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    exactKeys(raw, ["role_name", "role_oid", "rolsuper", "rolcreaterole"]);
    const roleName = text(raw.role_name, IDENTIFIER);
    const roleOid = oid(raw.role_oid);
    const order = `${roleOid.padStart(20, "0")}\0${roleName}`;
    const classified = classesByOid.get(roleOid);
    if (!classified || classified.role_name !== roleName || nodesByOid.has(roleOid) || order <= previousNode || typeof raw.rolsuper !== "boolean" || typeof raw.rolcreaterole !== "boolean") reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    nodesByOid.set(roleOid, raw); previousNode = order;
  }
  if (nodesByOid.size !== classification.nodes.length) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  const edges: Array<Record<string, unknown>> = [];
  let previousEdge = "";
  for (const raw of graph.edges) {
    if (!isRecord(raw)) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    exactKeys(raw, ["granted_role", "granted_role_oid", "member", "member_oid", "grantor", "grantor_oid", "admin_option", "inherit_option", "set_option"]);
    const grantedOid = oid(raw.granted_role_oid); const memberOid = oid(raw.member_oid); const grantorOid = oid(raw.grantor_oid);
    if (nodesByOid.get(grantedOid)?.role_name !== raw.granted_role || nodesByOid.get(memberOid)?.role_name !== raw.member || nodesByOid.get(grantorOid)?.role_name !== raw.grantor) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    if (typeof raw.admin_option !== "boolean" || typeof raw.inherit_option !== "boolean" || typeof raw.set_option !== "boolean") reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    const order = `${grantedOid.padStart(20, "0")}\0${memberOid.padStart(20, "0")}\0${grantorOid.padStart(20, "0")}\0${String(raw.admin_option)}\0${String(raw.inherit_option)}\0${String(raw.set_option)}`;
    if (order <= previousEdge) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
    previousEdge = order; edges.push(raw);
  }
  const providerOid = oid(provider.role_oid);
  const migratorOid = oid(migrator.role_oid);
  const providerClass = classesByOid.get(providerOid);
  if (!providerClass || providerClass.authority_class !== "PROVIDER_CONTROL") reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  if (provider.rolsuper !== true) {
    const visited = new Set([providerOid]);
    const pending = [providerOid];
    while (pending.length > 0) {
      const current = pending.shift()!;
      for (const edge of edges) {
        if (edge.member_oid !== current || edge.set_option !== true) continue;
        const next = String(edge.granted_role_oid);
        const nextClass = classesByOid.get(next)?.authority_class;
        if (next !== migratorOid && nextClass !== "PROVIDER_CONTROL") reject("BROKER_AUTHORITY_GRAPH_REJECTED");
        if (!visited.has(next)) { visited.add(next); pending.push(next); }
      }
    }
    if (!visited.has(migratorOid)) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  }
  for (const edge of edges) {
    const classes = [String(edge.granted_role_oid), String(edge.member_oid), String(edge.grantor_oid)].map((roleOid) => classesByOid.get(roleOid)?.authority_class);
    if (!classes.some((authorityClass) => authorityClass === "APPLICATION" || authorityClass === "RUNTIME")) continue;
    const exactTuple = edge.granted_role === "platform_runtime" && edge.member === "platform_app" && edge.grantor === "cloud_admin" && edge.admin_option === true && edge.inherit_option === false && edge.set_option === false;
    if (!exactTuple) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  }
}

export function normalizeBrokerObservationEvidence(
  input: unknown,
  bundle: BrokerObservationBundleV1,
  phase: "PREWRITE" | "FINAL" = "PREWRITE",
): BrokerObservationEvidenceV1 {
  if (!isRecord(input)) reject("BROKER_OBSERVATION_EVIDENCE_INVALID");
  exactKeys(input, ["version", "observation_bundle_digest", "target_binding_digest", "authority_classification_digest", "provider", "target", "migrator", "authority_graph", "ledger", "canonical_posture_digest", "evidence_digest"]);
  if (input.version !== BROKER_OBSERVATION_EVIDENCE_VERSION || input.observation_bundle_digest !== bundle.bundle_digest || input.target_binding_digest !== bundle.target_binding_digest || input.authority_classification_digest !== bundle.authority_classification_digest) reject("BROKER_OBSERVATION_EVIDENCE_INVALID");
  for (const key of ["provider", "target", "migrator", "authority_graph", "ledger"] as const) if (!isRecord(input[key])) reject("BROKER_OBSERVATION_EVIDENCE_INVALID");
  const provider = input.provider as Record<string, unknown>;
  const target = input.target as Record<string, unknown>;
  const migrator = input.migrator as Record<string, unknown>;
  const graph = input.authority_graph as Record<string, unknown>;
  const ledger = input.ledger as Record<string, unknown>;
  exactKeys(provider, ["current_user", "session_user", "role_oid", "rolsuper"]);
  exactKeys(target, ["logical_database_name", "database_oid", "cluster_system_identifier", "postgres_major", "in_recovery"]);
  exactKeys(migrator, ["role_name", "role_oid", "rolcanlogin", "rolinherit", "rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls", "password_is_null", "provider_has_set"]);
  exactKeys(graph, ["nodes", "edges", "closure_complete", "application_authority_absent"]);
  exactKeys(ledger, ["first_nine_identity_digest", "row_count", "migration_0010_absent"]);
  const binding = bundle.target_binding;
  if (provider.current_user !== binding.expected_provider_role_name || provider.session_user !== binding.expected_provider_role_name || provider.role_oid !== binding.expected_provider_role_oid) reject("BROKER_SESSION_IDENTITY_REJECTED");
  if (target.logical_database_name !== binding.logical_database_name || target.database_oid !== binding.expected_database_oid || target.cluster_system_identifier !== binding.expected_cluster_system_identifier || target.postgres_major !== 17 || target.in_recovery !== false) reject("BROKER_TARGET_MISMATCH");
  if (migrator.role_name !== "platform_migrator" || !POSITIVE_INTEGER.test(String(migrator.role_oid)) || migrator.rolcanlogin !== false || migrator.rolinherit !== false || migrator.rolsuper !== false || migrator.rolcreatedb !== false || migrator.rolcreaterole !== false || migrator.rolreplication !== false || migrator.rolbypassrls !== false || migrator.password_is_null !== true || migrator.provider_has_set !== true) reject("BROKER_MIGRATOR_DORMANCY_REJECTED");
  if (!Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || graph.closure_complete !== true || graph.application_authority_absent !== true) reject("BROKER_AUTHORITY_GRAPH_REJECTED");
  validateAuthorityGraph(graph, bundle.authority_classification, provider, migrator);
  if (phase === "PREWRITE" && (ledger.row_count !== 9 || ledger.migration_0010_absent !== true)) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
  if (phase === "FINAL" && (ledger.row_count !== 10 || ledger.migration_0010_absent !== false)) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
  digest(ledger.first_nine_identity_digest); digest(input.canonical_posture_digest);
  const claimed = digest(input.evidence_digest);
  const computed = computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, withoutDigest(input, "evidence_digest"));
  if (claimed !== computed) reject("BROKER_OBSERVATION_EVIDENCE_INVALID");
  return Object.freeze(input as unknown as BrokerObservationEvidenceV1);
}

export function compileBrokerMutationBundle(input: {
  observation_bundle: BrokerObservationBundleV1;
  observation_evidence: BrokerObservationEvidenceV1;
  prestate_digest: string;
  plan_digest: string;
  migration_sql: string;
}): BrokerMutationBundleV1 {
  const observation = input.observation_bundle;
  const evidence = normalizeBrokerObservationEvidence(input.observation_evidence, observation);
  if (sha256(input.migration_sql) !== MIGRATION_SQL_SHA256) reject("BROKER_MIGRATION_IDENTITY_REJECTED");
  const statements: BrokerStatementV1[] = [];
  const add = (id: string, phase: BrokerStatementV1["phase"], sql: string, mutating: boolean, resultSchema: readonly string[] = []) => statements.push(statement(statements.length, id, phase, sql, mutating, resultSchema));
  add("target_advisory_lock", "LOCK", `select (pg_catalog.pg_advisory_xact_lock(hashtextextended('${observation.target_binding_digest}', 0)) is null) as lock_acquired`, false, ["lock_acquired"]);
  add("ledger_lock", "LOCK", `lock table drizzle.__drizzle_migrations in access exclusive mode`, true);
  for (const observed of observation.statements) {
    add(`locked_${observed.id}`, "ADMISSION", observed.sql, false, observed.result_schema);
  }
  add("locked_binding_assertion", "ADMISSION", `select '${observation.contract_digest}'::text as contract_digest, '${observation.source_manifest_digest}'::text as source_manifest_digest, '${observation.build_manifest_digest}'::text as build_manifest_digest, '${observation.target_binding_digest}'::text as target_binding_digest, '${observation.authority_classification_digest}'::text as authority_classification_digest, '${evidence.evidence_digest}'::text as observation_evidence_digest, '${digest(input.prestate_digest)}'::text as prestate_digest, '${digest(input.plan_digest)}'::text as plan_digest`, false, ["contract_digest", "source_manifest_digest", "build_manifest_digest", "target_binding_digest", "authority_classification_digest", "observation_evidence_digest", "prestate_digest", "plan_digest"]);
  add("set_local_migrator", "ASSUME_ROLE", `set local role platform_migrator`, false);
  add("assumed_identity_assertion", "ASSUME_ROLE", `select current_user, session_user, (select oid::text from pg_catalog.pg_roles where rolname = current_user) as current_role_oid, (select oid::text from pg_catalog.pg_roles where rolname = session_user) as session_role_oid`, false, ["current_user", "session_user", "current_role_oid", "session_role_oid"]);
  add("set_local_search_path", "ASSUME_ROLE", `set local search_path = pg_catalog, public, drizzle`, false);
  const migrationStatements = input.migration_sql.split("--> statement-breakpoint").map((part) => part.trim()).filter(Boolean);
  for (let index = 0; index < migrationStatements.length; index += 1) add(`migration_0010_${String(index).padStart(2, "0")}`, "MIGRATION", migrationStatements[index]!, true);
  add("migration_0010_ledger_insert", "LEDGER", `insert into drizzle.__drizzle_migrations (hash, created_at) values ('${MIGRATION_SQL_SHA256}', ${MIGRATION_CREATED_AT})`, true);
  add("final_ledger_assertion", "VERIFY", observation.statements[4]!.sql, false, observation.statements[4]!.result_schema);
  add("final_canonical_posture_assertion", "VERIFY", compiledAssumedRolePostureSql(observation.target_binding.expected_provider_role_name), false, observation.statements[5]!.result_schema);
  add("final_role_data_assertion", "VERIFY", observation.statements[6]!.sql, false, observation.statements[6]!.result_schema);
  add("final_role_assertion", "VERIFY", `select current_user, session_user, (select oid::text from pg_catalog.pg_roles where rolname = current_user) as current_role_oid, (select oid::text from pg_catalog.pg_roles where rolname = session_user) as session_role_oid`, false, ["current_user", "session_user", "current_role_oid", "session_role_oid"]);
  add("cleanup_identity_assertion", "CLEANUP", `select current_user, session_user, (select oid::text from pg_catalog.pg_roles where rolname = current_user) as current_role_oid, (select oid::text from pg_catalog.pg_roles where rolname = session_user) as session_role_oid`, false, ["current_user", "session_user", "current_role_oid", "session_role_oid"]);
  const payload = {
    version: BROKER_MUTATION_BUNDLE_VERSION,
    run: observation.run,
    lock: observation.lock,
    git_sha: observation.git_sha,
    git_tree: observation.git_tree,
    contract_digest: observation.contract_digest,
    source_manifest_digest: observation.source_manifest_digest,
    build_manifest_digest: observation.build_manifest_digest,
    target_binding_digest: observation.target_binding_digest,
    authority_classification_digest: observation.authority_classification_digest,
    observation_evidence_digest: evidence.evidence_digest,
    prestate_digest: digest(input.prestate_digest),
    plan_digest: digest(input.plan_digest),
    attempt_policy: Object.freeze({ maximum: 1 as const }),
    migration: Object.freeze({ tag: MIGRATION_TAG, journal_index: 9 as const, created_at: MIGRATION_CREATED_AT, sql_sha256: MIGRATION_SQL_SHA256 }),
    transaction_policy: "SERIALIZABLE_READ_WRITE_FAIL_ON_ERROR_SINGLE_COMMIT" as const,
    statements: Object.freeze(statements),
  };
  return Object.freeze({ ...payload, bundle_digest: computeBrokerBundleDigest(BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR, payload) });
}

export function validateBrokerMutationResult(input: unknown, bundle: BrokerMutationBundleV1, reservation: BrokerAttemptReservationV1): BrokerMutationResultV1 {
  if (!isRecord(input) || !isRecord(reservation)) reject("BROKER_RESULT_INVALID");
  reservation = normalizeBrokerAttemptReservation(reservation, bundle);
  exactKeys(input, ["version", "mutation_bundle_digest", "reservation_digest", "dispatch_state", "commit_state", "cleanup_state", "migration_tag", "migration_sql_sha256", "safe_result_digest", "result_digest"]);
  if (input.version !== BROKER_RESULT_VERSION || input.mutation_bundle_digest !== bundle.bundle_digest || input.reservation_digest !== reservation.reservation_digest || input.migration_tag !== MIGRATION_TAG || input.migration_sql_sha256 !== MIGRATION_SQL_SHA256) reject("BROKER_RESULT_INVALID");
  if (!["NOT_DISPATCHED", "DISPATCHED", "INDETERMINATE"].includes(String(input.dispatch_state)) || !["NOT_COMMITTED", "COMMITTED", "INDETERMINATE"].includes(String(input.commit_state)) || !["DISCARDED", "FAILED", "INDETERMINATE"].includes(String(input.cleanup_state))) reject("BROKER_RESULT_INVALID");
  digest(input.safe_result_digest);
  const claimed = digest(input.result_digest);
  if (claimed !== computeBrokerBundleDigest(BROKER_RESULT_DOMAIN_SEPARATOR, withoutDigest(input, "result_digest"))) reject("BROKER_RESULT_INVALID");
  return Object.freeze(input as unknown as BrokerMutationResultV1);
}
