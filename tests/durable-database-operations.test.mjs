import assert from "node:assert/strict";
import { access, copyFile, cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import {
  verifyPlatformDbOperationBuild,
  writePlatformDbOperationBuildManifest,
} from "../scripts/platform-db-operation-build.mjs";
import {
  APPROVED_ROLE_NAMES,
  DurableOperationError,
  JOURNAL_PREFIX_DOMAIN_SEPARATOR,
  OBSERVATION_QUERY_IDS,
  PLAN_DOMAIN_SEPARATOR,
  PRESTATE_DOMAIN_SEPARATOR,
  RECEIPT_PHASES,
  SEMANTIC_CODES,
  beginReadOnlyObservation,
  assertPrewriteBinding,
  assertRevisionBinding,
  canonicalDigest,
  canonicalSerialize,
  computeTargetBindingDigest,
  createDurableInverse,
  createDurablePlan,
  createMutationSession,
  mapFailureCode,
  normalizePrestate,
  parseCanonicalJson,
  projectReceipt,
  requireRestoreCapability,
  serializeReceipt,
  validateReceipt,
  verifyRestoration,
} from "../dist/db/durable-operations.js";
import { RUNTIME_TABLE_GRANT_CONTRACT } from "../dist/db/runtime-grant-contract.js";

const HEX64 = "a".repeat(64);
const HEX40 = "9ce40dce85484ef5fd8c849951527572e95afa24";
const execFileAsync = promisify(execFile);
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

async function currentRepositoryRevision() {
  const result = await execFileAsync("git", ["rev-parse", "--verify", "HEAD"], {
    cwd: repositoryRoot,
    windowsHide: true,
  });
  return result.stdout.trim();
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function copyGitlessBuildContext(destinationRoot) {
  const worktreeNodeModules = join(repositoryRoot, "node_modules");
  const sharedNodeModules = join(repositoryRoot, "..", "node_modules");
  const dependencyRoot = (await fileExists(worktreeNodeModules))
    ? worktreeNodeModules
    : sharedNodeModules;
  await Promise.all([
    cp(join(repositoryRoot, "package.json"), join(destinationRoot, "package.json")),
    cp(join(repositoryRoot, "package-lock.json"), join(destinationRoot, "package-lock.json")),
    cp(join(repositoryRoot, "tsconfig.json"), join(destinationRoot, "tsconfig.json")),
    cp(join(repositoryRoot, "src"), join(destinationRoot, "src"), { recursive: true }),
    cp(join(repositoryRoot, "scripts"), join(destinationRoot, "scripts"), { recursive: true }),
  ]);
  await symlink(
    dependencyRoot,
    join(destinationRoot, "node_modules"),
    process.platform === "win32" ? "junction" : "dir",
  );
}

function buildEnvironmentWithoutGitOverrides() {
  const environment = { ...process.env };
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"]) delete environment[key];
  return environment;
}

function operatorEnvironmentWithoutDatabase() {
  const environment = buildEnvironmentWithoutGitOverrides();
  for (const key of [
    "DATABASE_URL",
    "DATABASE_OPERATOR_URL",
    "DATABASE_MIGRATIONS_CONFIRM",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGPASSFILE",
  ]) delete environment[key];
  return environment;
}

function targetBinding({ transactionReadOnly = "on" } = {}) {
  const calls = [];
  const connection = {
    async query(text, values) {
      calls.push({ text, values });
      if (/^BEGIN\b/u.test(text)) return { rows: [] };
      if (/^ROLLBACK\b/u.test(text)) return { rows: [] };
      if (/^SET TRANSACTION READ ONLY\b/u.test(text)) return { rows: [] };
      if (text.includes("durable:target_identity")) {
        return {
          rows: [
            {
              cluster_system_identifier: "7000000000000001",
              database_oid: "16384",
              logical_database_name: "fixture",
              current_user: "cloud_admin",
              session_user: "cloud_admin",
              postgres_major: 17,
              in_recovery: false,
              transaction_read_only: transactionReadOnly,
            },
          ],
        };
      }
      return { rows: [] };
    },
    release() {},
  };
  return {
    binding: {
      version: "target-binding-v1",
      logicalDatabaseName: "fixture",
      expectedClusterSystemIdentifier: "7000000000000001",
      expectedDatabaseOid: "16384",
      expectedCurrentUser: "cloud_admin",
      expectedSessionUser: "cloud_admin",
      expectedPostgresMajor: 17,
      async connect() {
        return connection;
      },
    },
    calls,
  };
}

function independentTargetBinding({
  clusterSystemIdentifier = "7000000000000001",
  databaseOid = "16384",
  transactionReadOnly = true,
} = {}) {
  const calls = [];
  const connection = {
    async query(text, values) {
      calls.push({ text, values });
      if (/^BEGIN\b/u.test(text)) return { rows: [] };
      if (/^ROLLBACK\b/u.test(text)) return { rows: [] };
      if (/^SET TRANSACTION READ ONLY\b/u.test(text)) return { rows: [] };
      if (text.includes("durable:target_identity")) {
        return {
          rows: [{
            cluster_system_identifier: clusterSystemIdentifier,
            database_oid: databaseOid,
            logical_database_name: "fixture",
            current_user: "cloud_admin",
            session_user: "cloud_admin",
            postgres_major: 17,
            in_recovery: false,
            transaction_read_only: transactionReadOnly,
          }],
        };
      }
      return { rows: [] };
    },
    release() {},
  };
  return {
    binding: {
      version: "target-binding-v1",
      logicalDatabaseName: "fixture",
      expectedClusterSystemIdentifier: clusterSystemIdentifier ?? "7000000000000001",
      expectedDatabaseOid: databaseOid,
      expectedCurrentUser: "cloud_admin",
      expectedSessionUser: "cloud_admin",
      expectedPostgresMajor: 17,
      connect: async () => connection,
    },
    calls,
  };
}

function legacyPrestate() {
  return {
    version: "platform-db-prestate-v1",
    target: {
      logical_database_name: "fixture",
      current_user: "cloud_admin",
      session_user: "cloud_admin",
      postgres_major: 17,
      in_recovery: false,
      transaction_read_only: true,
    },
    roles: { accepted_role_states: [], unknown_role_references: [] },
    memberships: {
      granted_role: [],
      member: [],
      grantor: [],
      admin_option: [],
      inherit_option: [],
      set_option: [],
    },
    ownership: {
      database_owner: "platform_app",
      public_schema_owner: "pg_database_owner",
      drizzle_schema_owner: "platform_migrator",
      canonical_relations: [],
      canonical_indexes: [],
      canonical_sequences: [],
      canonical_types: [],
      canonical_enums: [],
      canonical_routines: [],
    },
    privileges: { direct: [], public: [], grant_options: [] },
    default_acls: {
      creator: [],
      schema: [],
      object_type: [],
      grantee: [],
      grantor: [],
      privilege: [],
      grant_option: [],
    },
    runtime_grant_contract: {
      contract_digest: "9474972215869ec9b194f537c3b2400d8701aa8f00494bcfc0ede849dd94bf65",
      observed_direct_grants: RUNTIME_TABLE_GRANT_CONTRACT.map((record) => ({
        objectClass: record.objectClass,
        schema: record.schema,
        objectName: record.objectName,
        privilege: record.privilege,
        authoritySource: record.authoritySource,
        grantOption: record.grantOption,
      })),
    },
    migration_journal: {
      journal_version: "7",
      dialect: "postgresql",
      source_entries: [],
      applied_rows: [],
      applied_prefix_digest: canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, []),
    },
    canonical_checks: {
      readiness_checks: {},
      migrator_readiness_fields: [],
      runtime_posture_fields: {},
    },
    unknown_non_extension_drift: {
      relations: [],
      indexes: [],
      sequences: [],
      types: [],
      routines: [],
    },
  };
}

function rawCompletePrestate({ unknownNonExtensionDrift = { relations: [], indexes: [], sequences: [], types: [], routines: [] } } = {}) {
  const base = legacyPrestate();
  const emptyJournalDigest = canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, []);
  return {
    ...base,
    target: {
      ...base.target,
      cluster_system_identifier: "7000000000000001",
      database_oid: "16384",
    },
    roles: {
      accepted_role_states: [
        { rolname: "platform_runtime", role_oid: "10", rolcanlogin: false, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolconnlimit: -1 },
        { rolname: "platform_app", role_oid: "11", rolcanlogin: true, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolconnlimit: -1 },
        { rolname: "platform_migrator", role_oid: "12", rolcanlogin: true, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolconnlimit: -1 },
        { rolname: "cloud_admin", role_oid: "13", rolcanlogin: true, rolinherit: true, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolconnlimit: -1 },
      ],
      unknown_role_references: [],
    },
    ownership: {
      ...base.ownership,
      database_oid: "16384",
      public_schema_oid: "2200",
      drizzle_schema_oid: "2201",
      canonical_relations: [{ object_class: "relation", qualified_name: "public.users", object_oid: "3000", owner: "platform_app" }],
    },
    privileges: {
      direct: [{ object_class: "relation", qualified_name: "public.users", object_oid: "3000", acl_is_null: false, grantor: "cloud_admin", grantee: "platform_app", privilege: "select", grant_option: true }],
      public: [],
      grant_options: [{ object_class: "relation", qualified_name: "public.users", object_oid: "3000", acl_is_null: false, grantor: "cloud_admin", grantee: "platform_app", privilege: "select", grant_option: true }],
    },
    default_acls: {
      default_acl_oid: ["5000"],
      row_present: [true],
      acl_is_null: [false],
      creator: ["platform_migrator"],
      schema: ["public"],
      object_type: ["table"],
      grantee: ["platform_app"],
      grantor: ["platform_migrator"],
      privilege: ["select"],
      grant_option: [true],
    },
    migration_journal: {
      ...base.migration_journal,
      applied_prefix_digest: emptyJournalDigest,
      complete_journal_digest: emptyJournalDigest,
    },
    unknown_non_extension_drift: unknownNonExtensionDrift,
  };
}

function completePrestateFixture() {
  return normalizePrestate(rawCompletePrestate());
}

function planForOperation(operation, prestate = completePrestateFixture()) {
  return createDurablePlan({
    expected_git_sha: HEX40,
    contract_digest: HEX64,
    target_binding_digest: computeTargetBindingDigest(targetBinding().binding),
    prestate_digest: canonicalDigest(PRESTATE_DOMAIN_SEPARATOR, prestate),
    operation_kind: operation.kind,
    operations: [operation],
  });
}

function receiptFixture(overrides = {}) {
  return {
    receipt_version: 1,
    phase: "FINAL_VERIFY",
    outcome: "PASS",
    semantic_code: "SUCCESS",
    operation_kind: "ownership",
    git_sha: HEX40,
    contract_digest: HEX64,
    role_names: ["platform_app"],
    counts: {
      canonical_objects: 1,
      direct_privileges: 0,
      public_privileges: 0,
      default_acls: 0,
      memberships: 0,
      migration_entries: 0,
      operations: 1,
      inverse_steps: 1,
    },
    mutation_started: true,
    commit_state: "COMMITTED",
    rollback_attempted: false,
    rollback_verified: false,
    repository_inverse_attempted: false,
    repository_inverse_verified: false,
    external_restore_attempted: false,
    external_restore_verified: false,
    restoration_state: "NOT_REQUIRED",
    final_readiness_state: "PASS",
    ...overrides,
  };
}

function assertReceiptAccepted(overrides) {
  assert.doesNotThrow(() => validateReceipt(receiptFixture(overrides)));
}

function assertReceiptRejected(overrides) {
  assert.throws(
    () => validateReceipt(receiptFixture(overrides)),
    (error) => error?.semanticCode === "RECEIPT_REJECTED",
  );
}

test("locked domain separators and query ids are exact", () => {
  assert.equal(PRESTATE_DOMAIN_SEPARATOR, "swooshz-platform:platform-db-prestate-v1\0");
  assert.equal(PLAN_DOMAIN_SEPARATOR, "Swooshz-platform:platform-db-plan-v1\0");
  assert.deepEqual(OBSERVATION_QUERY_IDS, [
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
  ]);
  assert.deepEqual(APPROVED_ROLE_NAMES, [
    "platform_runtime",
    "platform_migrator",
    "platform_app",
    "cloud_admin",
  ]);
  assert.ok(SEMANTIC_CODES.includes("PREWRITE_DRIFT"));
  assert.ok(RECEIPT_PHASES.includes("RESTORE_VERIFY"));
});

test("canonical serialization sorts UTF-16 object keys and digest deterministically", () => {
  assert.equal(canonicalSerialize({ z: 1, a: [true, null, "x"] }), '{"a":[true,null,"x"],"z":1}');
  assert.equal(
    canonicalDigest("swooshz-platform:platform-db-prestate-v1\0", { b: 2, a: 1 }),
    canonicalDigest("swooshz-platform:platform-db-prestate-v1\0", { a: 1, b: 2 }),
  );
  assert.throws(() => canonicalSerialize({ value: undefined }), /unsupported/i);
  assert.throws(() => canonicalSerialize({ value: 1.5 }), /floating/i);
  assert.throws(() => canonicalSerialize({ value: Number.MAX_SAFE_INTEGER + 1 }), /unsafe/i);
  assert.throws(() => parseCanonicalJson('{"a":1,"a":2}'), /duplicate/i);
});

test("observation accepts only fixed ids and enforces a read-only transaction", async () => {
  const { binding, calls } = targetBinding();
  const observation = await beginReadOnlyObservation(binding);
  await assert.rejects(
    () => observation.read("query"),
    (error) => error.semanticCode === "ARBITRARY_INPUT_REJECTED",
  );
  await observation.read("role_state");
  await observation.close();
  assert.equal(calls.some(({ text }) => text === "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"), true);
  assert.equal(calls.some(({ text }) => text.includes("durable:target_identity")), true);
  assert.equal(calls.some(({ text }) => /^ROLLBACK\b/u.test(text)), true);
});

test("observation rejects a missing read-only posture", async () => {
  const { binding } = targetBinding({ transactionReadOnly: "off" });
  await assert.rejects(
    () => beginReadOnlyObservation(binding),
    (error) => error.semanticCode === "READ_ONLY_ASSERTION_FAILED",
  );
});

test("Run-190 RED B1: independent target identity is required and bound", async () => {
  const clusterA = independentTargetBinding({ clusterSystemIdentifier: "7000000000000001" });
  const clusterB = independentTargetBinding({ clusterSystemIdentifier: "7000000000000002" });
  assert.notEqual(
    computeTargetBindingDigest(clusterA.binding),
    computeTargetBindingDigest(clusterB.binding),
  );
  const observation = await beginReadOnlyObservation(clusterA.binding);
  await observation.read("target_identity");
  await observation.close();
  assert.equal(
    clusterA.calls.some(({ text }) => text === "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"),
    true,
  );
  assert.equal(
    clusterA.calls.some(({ text }) => text.includes("pg_control_system") && text.includes("pg_database")),
    true,
  );
  await assert.rejects(
    () => beginReadOnlyObservation({ ...clusterA.binding, connect: clusterB.binding.connect }),
    (error) => error.semanticCode === "TARGET_MISMATCH",
  );
  const missing = independentTargetBinding({ clusterSystemIdentifier: null });
  await assert.rejects(
    () => beginReadOnlyObservation(missing.binding),
    (error) => error.semanticCode === "TARGET_IDENTITY_UNAVAILABLE",
  );
});

test("Run-190 RED B2: legacy prestate omits authoritative object identity and role connection limits", () => {
  assert.throws(
    () => normalizePrestate(legacyPrestate()),
    (error) => error.semanticCode === "PRESTATE_INVALID",
  );
});

test("Run-190 RED B2: caller-invented ownership prior state cannot define inverse", () => {
  const prestate = completePrestateFixture();
  const plan = planForOperation({
    kind: "ownership",
    action: "set_owner",
    object: { object_class: "relation", qualified_name: "public.users" },
    previous_owner: "platform_migrator",
    next_owner: "cloud_admin",
  }, prestate);
  assert.throws(
    () => createDurableInverse(plan, prestate),
    (error) => error.semanticCode === "PRESTATE_MISMATCH",
  );
});

test("Run-190 RED B2: caller-invented ACL and default-ACL prior state cannot define inverse", () => {
  const prestate = completePrestateFixture();
  const privilegePlan = planForOperation({
    kind: "privilege",
    action: "grant",
    object: { object_class: "relation", qualified_name: "public.users" },
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: false,
  }, prestate);
  assert.throws(
    () => createDurableInverse(privilegePlan, prestate),
    (error) => error.semanticCode === "PRESTATE_MISMATCH",
  );

  const defaultAclPlan = planForOperation({
    kind: "default_acl",
    action: "grant",
    creator: "platform_migrator",
    schema: "public",
    object_type: "table",
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: false,
  }, prestate);
  assert.throws(
    () => createDurableInverse(defaultAclPlan, prestate),
    (error) => error.semanticCode === "PRESTATE_MISMATCH",
  );
});

test("Run-190 RED B3: every role-posture administrative escalation is structurally rejected", () => {
  const attributes = {
    rolcanlogin: true,
    rolinherit: true,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolreplication: false,
    rolbypassrls: false,
  };
  for (const field of ["rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"]) {
    assert.throws(
      () => createDurablePlan({
        expected_git_sha: HEX40,
        contract_digest: HEX64,
        target_binding_digest: HEX64,
        prestate_digest: HEX64,
        operation_kind: "role_posture",
        operations: [{
          kind: "role_posture",
          role: "platform_app",
          attributes: { ...attributes, [field]: true },
          previous_attributes: attributes,
        }],
      }),
      (error) => error.semanticCode === "OPERATION_UNSUPPORTED",
    );
  }
});

test("Run-190 RED B4: PASS has a dedicated success code and final-verification phase", () => {
  const receipt = projectReceipt({
    receipt_version: 1,
    phase: "FINAL_VERIFY",
    outcome: "PASS",
    semantic_code: "SUCCESS",
    operation_kind: "migration",
    git_sha: HEX40,
    contract_digest: HEX64,
    role_names: [],
    counts: {
      canonical_objects: 0,
      direct_privileges: 0,
      public_privileges: 0,
      default_acls: 0,
      memberships: 0,
      migration_entries: 0,
      operations: 0,
      inverse_steps: 0,
    },
    mutation_started: false,
    rollback_attempted: false,
    rollback_verified: false,
    restoration_state: "NOT_REQUIRED",
    final_readiness_state: "PASS",
  });
  assert.equal(receipt.semantic_code, "SUCCESS");
  assert.throws(
    () => validateReceipt({ ...receipt, semantic_code: "UNEXPECTED_FAILURE" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  assert.throws(
    () => validateReceipt({ ...receipt, phase: "RECEIPT" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  const forwardFailure = {
    ...receipt,
    phase: "FORWARD",
    outcome: "FAIL",
    semantic_code: "MUTATION_FAILED",
    mutation_started: false,
    commit_state: "NOT_STARTED",
    final_readiness_state: "NOT_RUN",
  };
  assert.doesNotThrow(() => validateReceipt(forwardFailure));
  assert.throws(
    () => validateReceipt({ ...forwardFailure, mutation_started: true }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  assert.throws(
    () => validateReceipt({ ...receipt, outcome: "BLOCKED", phase: "FORWARD", semantic_code: "MUTATION_FAILED" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  assert.throws(
    () => validateReceipt({ ...receipt, outcome: "BLOCKED", phase: "ADMISSION", semantic_code: "COMMIT_FAILED", final_readiness_state: "NOT_RUN" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
});

test("Run-192 RED B2-A: inverse must bind exact post-forward authority", () => {
  const prestate = completePrestateFixture();
  const privilegeOperation = {
    kind: "privilege",
    action: "grant",
    object: { object_class: "relation", qualified_name: "public.users" },
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: true,
  };
  const privilegePlan = planForOperation(privilegeOperation, prestate);
  const privilegeInverse = createDurableInverse(privilegePlan, prestate);
  assert.match(privilegeInverse.expected_post_forward_digest, /^[0-9a-f]{64}$/u);
  assert.deepEqual(privilegeInverse.steps[0].operation.restore_authority, {
    object_class: "relation",
    qualified_name: "public.users",
    object_oid: "3000",
    acl_is_null: false,
    present: true,
    grantor: "cloud_admin",
    grantee: "platform_app",
    privilege: "select",
    grant_option: true,
  });

});

test("Run-192 RED B2-B: inverse must preserve complete ACL and default-ACL state", () => {
  const prestate = completePrestateFixture();
  const privilegePlan = planForOperation({
    kind: "privilege",
    action: "grant",
    object: { object_class: "relation", qualified_name: "public.users" },
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: true,
  }, prestate);
  const privilegeInverse = createDurableInverse(privilegePlan, prestate);
  assert.deepEqual(privilegeInverse.steps[0].operation.restore_authority, {
    object_class: "relation",
    qualified_name: "public.users",
    object_oid: "3000",
    acl_is_null: false,
    present: true,
    grantor: "cloud_admin",
    grantee: "platform_app",
    privilege: "select",
    grant_option: true,
  });
  const defaultAclOperation = {
    kind: "default_acl",
    action: "grant",
    creator: "platform_migrator",
    schema: "public",
    object_type: "table",
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: true,
  };
  const defaultAclPlan = planForOperation(defaultAclOperation, prestate);
  const defaultAclInverse = createDurableInverse(defaultAclPlan, prestate);
  assert.deepEqual(defaultAclInverse.steps[0].operation.restore_authority, {
    default_acl_oid: "5000",
    row_present: true,
    acl_is_null: false,
    creator: "platform_migrator",
    schema: "public",
    object_type: "table",
    grantee: "platform_app",
    grantor: "platform_migrator",
    privilege: "select",
    grant_option: true,
  });
});

test("Run-192 RED B2-C: execution must not retain caller-owned plan operations across the write boundary", async () => {
  const source = await readFile("src/db/durable-operations.ts", "utf8");
  const start = source.indexOf("export async function executeDurablePlan");
  const end = source.indexOf("function makeReceipt", start);
  assert.ok(start >= 0 && end > start);
  assert.doesNotMatch(source.slice(start, end), /input\.plan\.operations/u);
});

test("Run-192 RED B2-D: database naming and object-class locks must use PostgreSQL-valid forms", async () => {
  const calls = [];
  const session = createMutationSession({
    async query(text, values) {
      calls.push({ text, values });
      return { rows: [] };
    },
  }, "fixture");
  await session.acquireMutationLocks([
    {
      kind: "ownership",
      action: "set_owner",
      object: { object_class: "index", qualified_name: "public.users_pkey" },
      previous_owner: "platform_migrator",
      next_owner: "platform_app",
    },
    {
      kind: "ownership",
      action: "set_owner",
      object: { object_class: "sequence", qualified_name: "drizzle.__drizzle_migrations_id_seq" },
      previous_owner: "platform_migrator",
      next_owner: "platform_app",
    },
  ]);
  assert.equal(calls.some(({ text }) => /lock table/iu.test(text)), false);
  await session.applyOperation({
    kind: "ownership",
    action: "set_owner",
    object: { object_class: "database", qualified_name: "__current_database__" },
    previous_owner: "platform_app",
    next_owner: "platform_migrator",
  });
  assert.match(calls.at(-1).text, /ALTER DATABASE "fixture"/u);
});

test("Run-192 RED B4-B: external restoration must not be projected as rollback verification", () => {
  const receipt = projectReceipt({
    receipt_version: 1,
    phase: "FINAL_VERIFY",
    outcome: "FAIL",
    semantic_code: "FINAL_VERIFICATION_FAILED",
    operation_kind: "ownership",
    git_sha: HEX40,
    contract_digest: HEX64,
    role_names: ["platform_app"],
    counts: {
      canonical_objects: 1,
      direct_privileges: 0,
      public_privileges: 0,
      default_acls: 0,
      memberships: 0,
      migration_entries: 0,
      operations: 1,
      inverse_steps: 1,
    },
    mutation_started: true,
    rollback_attempted: false,
    rollback_verified: false,
    external_restore_attempted: true,
    external_restore_verified: true,
    restoration_state: "VERIFIED",
    final_readiness_state: "FAIL",
  });
  assert.equal(receipt.external_restore_attempted, true);
  assert.equal(receipt.external_restore_verified, true);
  assert.equal(receipt.rollback_verified, false);
  assert.doesNotThrow(() => validateReceipt(receipt));
});

test("Run-192 RED evidence: disposable runner must retain bounded sanitized diagnostics", async () => {
  const runner = await import("../scripts/run-disposable-durable-db-operations-tests.mjs");
  assert.equal(typeof runner.sanitizeDisposableDiagnostics, "function");
  const diagnostics = runner.sanitizeDisposableDiagnostics({
    stdout: "TAP version 13\nnot ok 1 - Run-190 durable database operations on two disposable PostgreSQL 17 clusters\n# reason: expected status 1\n# reason: internal customer@example.invalid detail\npostgres://secret@example.invalid/db",
    stderr: "Error: private driver detail\nDATABASE_URL=postgres://secret@example.invalid/db",
    outputOverflow: false,
  });
  assert.match(diagnostics, /Run-190 durable database operations/u);
  assert.match(diagnostics, /expected status 1/u);
  assert.doesNotMatch(diagnostics, /postgres:\/\/|DATABASE_URL|private driver detail/u);
  assert.doesNotMatch(diagnostics, /internal customer|example\.invalid/u);
  assert.ok(diagnostics.length <= 2000);
});

test("Run-192 receipt state machine accepts only the closed outcome/phase/recovery matrix", () => {
  const accepted = [
    {},
    { outcome: "BLOCKED", phase: "ADMISSION", semantic_code: "CONTRACT_DIGEST_MISMATCH", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "BLOCKED", phase: "OBSERVE", semantic_code: "TARGET_MISMATCH", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "BLOCKED", phase: "PLAN", semantic_code: "REVISION_MISMATCH", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "BLOCKED", phase: "PRESTATE", semantic_code: "PRESTATE_MISMATCH", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "BLOCKED", phase: "INVERSE", semantic_code: "RESTORE_CAPABILITY_REQUIRED", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "BLOCKED", phase: "PREWRITE", semantic_code: "PREWRITE_DRIFT", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "MUTATION_FAILED", mutation_started: false, commit_state: "NOT_STARTED", final_readiness_state: "NOT_RUN", restoration_state: "NOT_REQUIRED" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "MUTATION_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", rollback_attempted: true, rollback_verified: true, restoration_state: "VERIFIED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "COMMIT", semantic_code: "COMMIT_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", rollback_attempted: true, rollback_verified: true, restoration_state: "VERIFIED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "ROLLBACK", semantic_code: "ROLLBACK_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", rollback_attempted: true, restoration_state: "FAILED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "COMMITTED", repository_inverse_attempted: true, repository_inverse_verified: true, restoration_state: "VERIFIED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "COMMITTED", external_restore_attempted: true, external_restore_verified: true, restoration_state: "VERIFIED", final_readiness_state: "FAIL" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "COMMITTED", repository_inverse_attempted: true, external_restore_attempted: true, external_restore_verified: true, restoration_state: "VERIFIED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "RESTORE", semantic_code: "RESTORE_EXECUTION_FAILED", mutation_started: true, commit_state: "COMMITTED", external_restore_attempted: true, restoration_state: "AMBIGUOUS", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "RESTORE_VERIFY", semantic_code: "RESTORATION_FAILED", mutation_started: true, commit_state: "COMMITTED", repository_inverse_attempted: true, restoration_state: "FAILED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "RESTORE_VERIFY", semantic_code: "RESTORATION_AMBIGUOUS", mutation_started: true, commit_state: "COMMITTED", external_restore_attempted: true, restoration_state: "AMBIGUOUS", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "RECEIPT", semantic_code: "RECEIPT_REJECTED", mutation_started: false, commit_state: "NOT_STARTED", restoration_state: "NOT_REQUIRED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "RECEIPT", semantic_code: "UNEXPECTED_FAILURE", mutation_started: true, commit_state: "COMMITTED", restoration_state: "AMBIGUOUS", final_readiness_state: "FAIL" },
  ];
  for (const row of accepted) assertReceiptAccepted(row);

  const serialized = serializeReceipt(receiptFixture(accepted[12]));
  assert.deepEqual(projectReceipt(JSON.parse(serialized)), receiptFixture(accepted[12]));

  const rejected = [
    { outcome: "PASS", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED" },
    { outcome: "PASS", phase: "FORWARD", semantic_code: "SUCCESS" },
    { outcome: "PASS", phase: "FINAL_VERIFY", semantic_code: "SUCCESS", commit_state: "NOT_COMMITTED" },
    { outcome: "PASS", phase: "FINAL_VERIFY", semantic_code: "SUCCESS", final_readiness_state: "FAIL" },
    { outcome: "PASS", phase: "FINAL_VERIFY", semantic_code: "SUCCESS", external_restore_attempted: true, restoration_state: "VERIFIED" },
    { outcome: "BLOCKED", phase: "ADMISSION", semantic_code: "COMMIT_FAILED", commit_state: "NOT_COMMITTED" },
    { outcome: "BLOCKED", phase: "PREWRITE", semantic_code: "PREWRITE_DRIFT", mutation_started: true, commit_state: "NOT_COMMITTED" },
    { outcome: "BLOCKED", phase: "INVERSE", semantic_code: "RESTORE_CAPABILITY_REQUIRED", rollback_attempted: true, commit_state: "NOT_STARTED" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "SUCCESS", mutation_started: false, commit_state: "NOT_STARTED", restoration_state: "NOT_REQUIRED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "MUTATION_FAILED", mutation_started: true, commit_state: "NOT_STARTED", restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "MUTATION_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", restoration_state: "NOT_STARTED" },
    { outcome: "FAIL", phase: "FORWARD", semantic_code: "MUTATION_FAILED", mutation_started: true, commit_state: "COMMITTED", rollback_attempted: true, restoration_state: "VERIFIED" },
    { outcome: "FAIL", phase: "COMMIT", semantic_code: "COMMIT_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "ROLLBACK", semantic_code: "ROLLBACK_FAILED", mutation_started: true, commit_state: "COMMITTED", rollback_attempted: true, restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "ROLLBACK", semantic_code: "ROLLBACK_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", rollback_verified: true, restoration_state: "VERIFIED" },
    { outcome: "FAIL", phase: "RESTORE", semantic_code: "RESTORE_EXECUTION_FAILED", mutation_started: true, commit_state: "COMMITTED", restoration_state: "AMBIGUOUS" },
    { outcome: "FAIL", phase: "RESTORE", semantic_code: "RESTORE_EXECUTION_FAILED", mutation_started: true, commit_state: "COMMITTED", external_restore_attempted: true, external_restore_verified: true, restoration_state: "VERIFIED" },
    { outcome: "FAIL", phase: "RESTORE_VERIFY", semantic_code: "RESTORATION_FAILED", mutation_started: true, commit_state: "COMMITTED", restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "COMMITTED", restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "NOT_COMMITTED", repository_inverse_attempted: true, restoration_state: "VERIFIED" },
    { outcome: "FAIL", phase: "RECEIPT", semantic_code: "RECEIPT_REJECTED", mutation_started: false, commit_state: "NOT_STARTED", restoration_state: "FAILED" },
    { outcome: "FAIL", phase: "RECEIPT", semantic_code: "SUCCESS", mutation_started: false, commit_state: "NOT_STARTED", restoration_state: "NOT_REQUIRED", final_readiness_state: "NOT_RUN" },
    { outcome: "FAIL", phase: "FINAL_VERIFY", semantic_code: "FINAL_VERIFICATION_FAILED", mutation_started: true, commit_state: "COMMITTED", external_restore_verified: true, restoration_state: "FAILED" },
  ];
  for (const row of rejected) assertReceiptRejected(row);
});

test("malformed prestates and unknown drift are rejected", () => {
  assert.throws(
    () => normalizePrestate({ version: "platform-db-prestate-v1" }),
    (error) => error.semanticCode === "PRESTATE_INVALID",
  );
  assert.throws(
    () => normalizePrestate(rawCompletePrestate({
      unknownNonExtensionDrift: {
        relations: [{ qualified_name: "public.unexpected", owner: "cloud_admin", kind: "r" }],
        indexes: [],
        sequences: [],
        types: [],
        routines: [],
      },
    })),
    (error) => error.semanticCode === "UNKNOWN_DRIFT",
  );
});

test("typed plans reject arbitrary SQL, identifiers, roles, privileges, and migrations", () => {
  const base = {
    expected_git_sha: HEX40,
    contract_digest: HEX64,
    target_binding_digest: HEX64,
    prestate_digest: HEX64,
  };
  assert.throws(
    () => createDurablePlan({ ...base, operations: [{ kind: "sql", sql: "drop database" }] }),
    (error) => error.semanticCode === "ARBITRARY_INPUT_REJECTED",
  );
  assert.throws(
    () => createDurablePlan({
      ...base,
      operations: [{
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.not_canonical" },
        principal: "not_a_role",
        privilege: "DROP",
      }],
    }),
    (error) => error.semanticCode === "ARBITRARY_INPUT_REJECTED",
  );
  assert.throws(
    () => createDurablePlan({
      ...base,
      operations: [{
        kind: "migration",
        tag: "../../private.sql",
        journal_index: 0,
        when: "1",
        sql_sha256: HEX64,
        expected_applied_prefix_digest: HEX64,
        expected_post_journal_digest: HEX64,
      }],
    }),
    (error) => error.semanticCode === "ARBITRARY_INPUT_REJECTED",
  );
});

test("one-way migration plans require restore authority before mutation", () => {
  const plan = createDurablePlan({
    expected_git_sha: HEX40,
    contract_digest: HEX64,
    target_binding_digest: HEX64,
    prestate_digest: HEX64,
    operations: [{
      kind: "migration",
      tag: "0010_admin_operator_viewer_role_collapse",
      journal_index: 9,
      when: "1787479999088",
      sql_sha256: HEX64,
      expected_applied_prefix_digest: HEX64,
      expected_post_journal_digest: HEX64,
    }],
  });
  assert.throws(
    () => createDurableInverse(plan),
    (error) => error.semanticCode === "RESTORE_CAPABILITY_REQUIRED",
  );
  assert.throws(
    () => requireRestoreCapability(undefined, plan, HEX64),
    (error) => error.semanticCode === "RESTORE_CAPABILITY_REQUIRED",
  );
});

test("mutation boundary is set before first send and remains true on indeterminate send", async () => {
  let attempts = 0;
  const session = createMutationSession({
    async query() {
      attempts += 1;
      throw new Error("indeterminate");
    },
  });
  await assert.rejects(() => session.applyOperation({
    kind: "privilege",
    action: "grant",
    object: { object_class: "relation", qualified_name: "public.users" },
    principal: "platform_app",
    privilege: "SELECT",
    grant_option: false,
    previous_grant_option: false,
  }));
  assert.equal(attempts, 1);
  assert.equal(session.mutationStarted, true);
});

test("receipt projection is closed and rejects unknown public fields", () => {
  const receipt = projectReceipt({
    receipt_version: 1,
    phase: "FINAL_VERIFY",
    outcome: "PASS",
    semantic_code: "SUCCESS",
    operation_kind: "migration",
    git_sha: HEX40,
    contract_digest: HEX64,
    role_names: ["platform_migrator"],
    counts: {
      canonical_objects: 0,
      direct_privileges: 0,
      public_privileges: 0,
      default_acls: 0,
      memberships: 0,
      migration_entries: 1,
      operations: 1,
      inverse_steps: 0,
    },
    mutation_started: false,
    rollback_attempted: false,
    rollback_verified: false,
    restoration_state: "NOT_REQUIRED",
    final_readiness_state: "PASS",
    private_provider_id: "must-not-serialize",
  });
  assert.equal("private_provider_id" in receipt, false);
  assert.doesNotThrow(() => validateReceipt(receipt));
  assert.throws(
    () => validateReceipt({ ...receipt, unexpected: true }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
});

test("inverse vectors cover every admitted reversible operation kind", () => {
  const prestate = completePrestateFixture();
  const operations = [
    {
      kind: "ownership",
      action: "set_owner",
      object: { object_class: "relation", qualified_name: "public.users" },
      previous_owner: "platform_app",
      next_owner: "platform_migrator",
    },
    {
      kind: "privilege",
      action: "grant",
      object: { object_class: "relation", qualified_name: "public.users" },
      principal: "platform_app",
      privilege: "SELECT",
      grant_option: false,
      previous_grant_option: true,
    },
    {
      kind: "default_acl",
      action: "grant",
      creator: "platform_migrator",
      schema: "public",
      object_type: "table",
      principal: "platform_app",
      privilege: "SELECT",
      grant_option: false,
      previous_grant_option: true,
    },
  ];

  for (const operation of operations) {
    const plan = planForOperation(operation, prestate);
    const inverse = createDurableInverse(plan, prestate);
    assert.equal(inverse.version, "platform-db-inverse-v1");
    assert.equal(inverse.source_plan_digest, plan.plan_digest);
    assert.equal(inverse.steps.length, 1);
    assert.equal(inverse.steps[0].original_operation_index, 0);
    assert.equal(inverse.steps[0].kind, operation.kind);
    assert.ok(Object.isFrozen(inverse));
    const inverseOperation = inverse.steps[0].operation;
    if (operation.kind === "ownership") {
      assert.equal(inverseOperation.previous_owner, "platform_migrator");
      assert.equal(inverseOperation.next_owner, "platform_app");
    } else if (operation.kind === "privilege") {
      assert.equal(inverseOperation.action, "grant");
      assert.equal(inverseOperation.grant_option, true);
      assert.equal(inverseOperation.previous_grant_option, false);
    } else {
      assert.equal(inverseOperation.action, "grant");
      assert.equal(inverseOperation.grant_option, true);
      assert.equal(inverseOperation.previous_grant_option, false);
    }
  }
});

test("Run-197 generic npm build is Git-independent and emits no operator manifest", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "platform-run-197-gitless-build-"));
  try {
    await copyGitlessBuildContext(fixtureRoot);
    assert.equal(await fileExists(join(fixtureRoot, ".git")), false);
    await execFileAsync(npmCommand, ["run", "build"], {
      cwd: fixtureRoot,
      env: buildEnvironmentWithoutGitOverrides(),
      shell: process.platform === "win32",
      timeout: 120_000,
      windowsHide: true,
    });
    assert.equal(await fileExists(join(fixtureRoot, "dist/db/durable-operations.js")), true);
    assert.equal(
      await fileExists(join(fixtureRoot, "dist/db/platform-db-operation-build.json")),
      false,
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("Run-196 exact build binds the executable closure before operator import", async () => {
  const expectedGitSha = await currentRepositoryRevision();
  await writePlatformDbOperationBuildManifest({ rootDir: repositoryRoot });
  const verifiedBuild = await verifyPlatformDbOperationBuild({
    rootDir: repositoryRoot,
    expectedGitSha,
  });
  const manifest = JSON.parse(await readFile(verifiedBuild.manifestPath, "utf8"));
  assert.equal(verifiedBuild.sourceGitSha, expectedGitSha);
  assert.equal(manifest.source_git_sha, expectedGitSha);
  assert.equal(manifest.entrypoints.durableOperations, "db/durable-operations.js");
  assert.equal(manifest.entrypoints.databaseClient, "db/client.js");
  assert.ok(manifest.modules.some((record) => record.path === "db/durable-operations.js"));
  assert.ok(manifest.modules.some((record) => record.path === "db/client.js"));
  const launcherSource = await readFile(
    fileURLToPath(new URL("../scripts/platform-db-operation.mjs", import.meta.url)),
    "utf8",
  );
  assert.doesNotMatch(launcherSource, /from ["']\.\.\/dist/u);
  const selectedExecutable = await import(pathToFileURL(verifiedBuild.entrypoints.durableOperations).href);
  assert.equal(typeof selectedExecutable.assertRevisionBinding, "function");
});

test("Run-197 supported operator command builds and binds before the frozen launcher", async () => {
  const expectedGitSha = await currentRepositoryRevision();
  const manifestPath = join(repositoryRoot, "dist/db/platform-db-operation-build.json");
  const scratch = await mkdtemp(join(tmpdir(), "platform-run-197-operator-command-"));
  const backupPath = join(scratch, "platform-db-operation-build.json");
  const hadManifest = await fileExists(manifestPath);
  if (hadManifest) await copyFile(manifestPath, backupPath);
  try {
    await rm(manifestPath, { force: true });
    let childError = null;
    try {
      await execFileAsync(npmCommand, [
        "run",
        "platform:db-operation",
        "--",
        "--expected-git-sha",
        expectedGitSha,
        "--expected-cluster-system-identifier",
        "1",
        "--expected-database-oid",
        "1",
        "--operation",
        "migration",
      ], {
        cwd: repositoryRoot,
        env: operatorEnvironmentWithoutDatabase(),
        shell: process.platform === "win32",
        timeout: 120_000,
        windowsHide: true,
      });
    } catch (error) {
      childError = error;
    }
    assert.ok(childError);
    assert.notEqual(childError.code, 0);
    assert.equal(await fileExists(manifestPath), true);
    const verifiedBuild = await verifyPlatformDbOperationBuild({
      rootDir: repositoryRoot,
      expectedGitSha,
    });
    assert.equal(verifiedBuild.sourceGitSha, expectedGitSha);
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.equal(manifest.source_git_sha, expectedGitSha);
  } finally {
    if (hadManifest) await copyFile(backupPath, manifestPath);
    else await rm(manifestPath, { force: true });
    await rm(scratch, { recursive: true, force: true });
  }
});

test("Run-196 stale compiled output fails before database connection or mutation", async () => {
  const expectedGitSha = await currentRepositoryRevision();
  const target = fileURLToPath(new URL("../dist/db/durable-operations.js", import.meta.url));
  const scratch = await mkdtemp(join(tmpdir(), "platform-run-196-launcher-"));
  const backup = join(scratch, "durable-operations.js");
  const marker = join(scratch, "compiled-module-imported");
  await copyFile(target, backup);
  try {
    const poisonedModule = [
      'import { writeFileSync } from "node:fs";',
      "writeFileSync(" + JSON.stringify(marker) + ', "imported");',
      'export const JOURNAL_PREFIX_DOMAIN_SEPARATOR = "";',
      'export const PRESTATE_DOMAIN_SEPARATOR = "";',
      'export const assertRevisionBinding = async () => "' + expectedGitSha + '";',
      'export const canonicalDigest = () => "";',
      'export const captureNormalizedPrestate = async () => ({});',
      'export const createDurablePlan = () => ({});',
      'export const computeContractDigest = async () => "";',
      'export const computeTargetBindingDigest = () => "";',
      'export const executeDurablePlan = async () => ({});',
      'export const loadCanonicalMigrationJournal = async () => ({ entries: [] });',
      'export const projectReceipt = (value) => value;',
      'export const serializeReceipt = () => "";',
    ].join("\n");
    await writeFile(target, poisonedModule, "utf8");
    let childError = null;
    try {
      await execFileAsync(process.execPath, [
        "scripts/platform-db-operation.mjs",
        "--expected-git-sha", expectedGitSha,
        "--expected-cluster-system-identifier", "1",
        "--expected-database-oid", "1",
        "--operation", "migration",
      ], {
        cwd: repositoryRoot,
        env: {
          ...process.env,
          DATABASE_OPERATOR_URL: "postgres://127.0.0.1:1/durable_operations_test",
          DATABASE_MIGRATIONS_CONFIRM: "apply-reviewed-migrations",
        },
        timeout: 10_000,
        windowsHide: true,
      });
    } catch (error) {
      childError = error;
    }
    assert.ok(childError);
    assert.notEqual(childError.code, 0);
    assert.equal(await fileExists(marker), false);
  } finally {
    await copyFile(backup, target);
    await rm(scratch, { recursive: true, force: true });
  }
});

test("semantic failures, prewrite drift, and revision binding remain fail-closed", async () => {
  for (const code of SEMANTIC_CODES) {
    assert.equal(mapFailureCode(new DurableOperationError(code)), code);
  }
  assert.equal(mapFailureCode(new Error("private driver detail")), "UNEXPECTED_FAILURE");
  assert.throws(
    () => assertPrewriteBinding({
      expectedPrestateDigest: HEX64,
      observedPrestateDigest: "b".repeat(64),
      expectedContractDigest: HEX64,
      observedContractDigest: HEX64,
      expectedPlanDigest: HEX64,
      observedPlanDigest: HEX64,
    }),
    (error) => error.semanticCode === "PREWRITE_DRIFT",
  );
  await assert.rejects(
    () => assertRevisionBinding({ rootDir: process.cwd(), expectedGitSha: "0".repeat(40) }),
    (error) => error.semanticCode === "REVISION_MISMATCH",
  );
  const spoofed = targetBinding();
  spoofed.binding.expectedCurrentUser = "platform_app";
  await assert.rejects(
    () => beginReadOnlyObservation(spoofed.binding),
    (error) => error.semanticCode === "SESSION_IDENTITY_MISMATCH",
  );
  const unavailableBinding = {
    version: "target-binding-v1",
    logicalDatabaseName: "fixture",
    expectedClusterSystemIdentifier: "7000000000000001",
    expectedDatabaseOid: "16384",
    expectedCurrentUser: "cloud_admin",
    expectedSessionUser: "cloud_admin",
    expectedPostgresMajor: 17,
    async connect() {
      throw new Error("private connection failure");
    },
  };
  assert.deepEqual(
    await verifyRestoration({ binding: unavailableBinding, expectedPrestateDigest: HEX64 }),
    { state: "AMBIGUOUS" },
  );
});

test("restore authority and receipt invariants reject ambiguous recovery", () => {
  const plan = createDurablePlan({
    expected_git_sha: HEX40,
    contract_digest: HEX64,
    target_binding_digest: HEX64,
    prestate_digest: HEX64,
    operation_kind: "ownership",
    operations: [{
      kind: "ownership",
      action: "set_owner",
      object: { object_class: "relation", qualified_name: "public.users" },
      previous_owner: "platform_app",
      next_owner: "platform_migrator",
    }],
  });
  assert.throws(
    () => requireRestoreCapability({
      version: "restore-capability-v1",
      target_binding_digest: HEX64,
      prestate_digest: HEX64,
      plan_digest: "b".repeat(64),
      async execute() {},
    }, plan, HEX64),
    (error) => error.semanticCode === "RESTORE_CAPABILITY_REQUIRED",
  );
  const passReceipt = projectReceipt({
    receipt_version: 1,
    phase: "FINAL_VERIFY",
    outcome: "PASS",
    semantic_code: "SUCCESS",
    operation_kind: "ownership",
    git_sha: HEX40,
    contract_digest: HEX64,
    role_names: ["platform_app"],
    counts: {
      canonical_objects: 0,
      direct_privileges: 0,
      public_privileges: 0,
      default_acls: 0,
      memberships: 0,
      migration_entries: 0,
      operations: 1,
      inverse_steps: 1,
    },
    mutation_started: true,
    rollback_attempted: false,
    rollback_verified: false,
    restoration_state: "NOT_REQUIRED",
    final_readiness_state: "PASS",
  });
  assert.throws(
    () => validateReceipt({ ...passReceipt, restoration_state: "AMBIGUOUS" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  assert.throws(
    () => validateReceipt({ ...passReceipt, restoration_state: "FAILED" }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
  assert.throws(
    () => validateReceipt({ ...passReceipt, rollback_verified: true }),
    (error) => error.semanticCode === "RECEIPT_REJECTED",
  );
});
