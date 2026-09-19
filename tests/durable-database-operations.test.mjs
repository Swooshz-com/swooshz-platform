import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
  loadCanonicalMigrationJournal,
  mapFailureCode,
  normalizePrestate,
  parseCanonicalJson,
  projectReceipt,
  requireRestoreCapability,
  runCanonicalMigrationPrimitive,
  serializeReceipt,
  validateReceipt,
  verifyRestoration,
  executeBrokeredMigrationPlan,
  bindDurablePlanV2ToBrokerBundle,
  createBrokeredDurablePlanV2,
  normalizeBrokeredPrestateV2,
  createDurableInverseV2,
  requireRestoreCapabilityV2,
  RESTORE_CAPABILITY_VERSION,
  RESTORE_CAPABILITY_PROVIDER_VERSION,
} from "../dist/db/durable-operations.js";
import {
  BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR,
  BROKER_ATTEMPT_RESERVATION_VERSION,
  BROKER_AUTHORITY_CLASSIFICATION_VERSION,
  BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR,
  BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR,
  BROKER_OBSERVATION_EVIDENCE_VERSION,
  BROKER_RESULT_DOMAIN_SEPARATOR,
  BROKER_RESULT_VERSION,
  BROKER_TARGET_BINDING_VERSION,
  canonicalSerializeBrokerBundle,
  compileBrokerMutationBundle,
  compileBrokerObservationBundle,
  computeBrokerBundleDigest,
  deriveBrokerObservationEvidence,
  normalizeBrokerAttemptReservation,
  normalizeBrokerObservationEvidence,
  validateBrokerProviderFinalResultSet,
  validateBrokerMutationResult,
  validateBrokerStatementResult,
  validateLockedBrokerObservationResultSet,
} from "../dist/db/brokered-migration.js";
import { RUNTIME_TABLE_GRANT_CONTRACT } from "../dist/db/runtime-grant-contract.js";

const HEX64 = "a".repeat(64);
const HEX40 = "9ce40dce85484ef5fd8c849951527572e95afa24";
const execFileAsync = promisify(execFile);
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const CANONICAL_FIRST_NINE_LEDGER = [
  { id: 1, hash: "d156026594b36870455ba6df7525310be1ce1838cda1d58725c6f3a07514c0a6", created_at: "1782546111134" },
  { id: 2, hash: "861614ef57601aff17a15fe594becfc0206fa931f22052ba98217e300285666d", created_at: "1782571351615" },
  { id: 3, hash: "76fd758786fa4583e18f3b89bf7fba0932bdb9c71de294f3291b19925bbd542b", created_at: "1782629131478" },
  { id: 4, hash: "41567c07fcdb3b6e41da516d346d1a20d5e3aa4b0c5d3297e8b19091fa8f5f09", created_at: "1782651725342" },
  { id: 5, hash: "01179c79b777732dc03dbef0471738e00dc85964082aa22764184362722ac5fe", created_at: "1783253616083" },
  { id: 6, hash: "651eaa1668341fc8bdbc8d6f47ccfdd9ec1e2c80fef018de73ab0a79b9896bbe", created_at: "1783479304000" },
  { id: 7, hash: "a8b5d90838c87ca3d74ada48295b92970c8a8476dacf5fc76b1a793995d7485b", created_at: "1783587520445" },
  { id: 8, hash: "0e82a5892f22b71f8894f8776388341519ac48944a417552443d639d09cdcbc0", created_at: "1784354477743" },
  { id: 9, hash: "bc54f927f5ab0a2ebc97a61ede57119f29e8673ab1b902a4e132191ac688820f", created_at: "1784620602227" },
];
const CANONICAL_FIRST_NINE_IDENTITY_DIGEST = computeBrokerBundleDigest(
  BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR.replace(
    "platform-db-broker-observation-evidence-v1",
    "platform-db-first-nine-ledger-v1",
  ),
  CANONICAL_FIRST_NINE_LEDGER,
);

function brokerFixture() {
  const target_binding = {
    version: BROKER_TARGET_BINDING_VERSION,
    project_id: "project-fixture",
    branch_id: "branch-fixture",
    endpoint_id: "endpoint-fixture",
    endpoint_type: "read_write",
    logical_database_name: "swooshz_platform",
    expected_database_oid: "42",
    expected_cluster_system_identifier: "777",
    expected_postgres_major: 17,
    expected_provider_role_name: "cloud_admin",
    expected_provider_role_oid: "1",
  };
  const authority_classification = {
    version: BROKER_AUTHORITY_CLASSIFICATION_VERSION,
    nodes: [
      { role_name: "cloud_admin", role_oid: "1", authority_class: "PROVIDER_CONTROL" },
      { role_name: "platform_app", role_oid: "2", authority_class: "APPLICATION" },
      { role_name: "platform_runtime", role_oid: "3", authority_class: "RUNTIME" },
      { role_name: "platform_migrator", role_oid: "4", authority_class: "MIGRATOR" },
    ],
    runtime_creator_tuple: {
      granted_role: "platform_runtime",
      member: "platform_app",
      grantor: "cloud_admin",
      admin_option: true,
      inherit_option: false,
      set_option: false,
    },
  };
  const observationBundle = compileBrokerObservationBundle({
    run: "run-fixture",
    lock: "lock-fixture",
    git_sha: "1".repeat(40),
    git_tree: "2".repeat(40),
    contract_digest: "3".repeat(64),
    source_manifest_digest: "4".repeat(64),
    build_manifest_digest: "5".repeat(64),
    target_binding,
    authority_classification,
  });
  const evidencePayload = {
    version: BROKER_OBSERVATION_EVIDENCE_VERSION,
    observation_bundle_digest: observationBundle.bundle_digest,
    target_binding_digest: observationBundle.target_binding_digest,
    authority_classification_digest: observationBundle.authority_classification_digest,
    provider: { current_user: "cloud_admin", session_user: "cloud_admin", role_oid: "1", rolsuper: false },
    target: { logical_database_name: "swooshz_platform", database_oid: "42", cluster_system_identifier: "777", postgres_major: 17, in_recovery: false },
    migrator: { role_name: "platform_migrator", role_oid: "4", rolcanlogin: false, rolinherit: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, password_is_null: true, provider_has_set: true },
    authority_graph: {
      nodes: [
        { role_name: "cloud_admin", role_oid: "1", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_app", role_oid: "2", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_runtime", role_oid: "3", rolsuper: false, rolcreaterole: false },
        { role_name: "platform_migrator", role_oid: "4", rolsuper: false, rolcreaterole: false },
      ],
      edges: [
        { granted_role: "platform_runtime", granted_role_oid: "3", member: "platform_app", member_oid: "2", grantor: "cloud_admin", grantor_oid: "1", admin_option: true, inherit_option: false, set_option: false },
        { granted_role: "platform_migrator", granted_role_oid: "4", member: "cloud_admin", member_oid: "1", grantor: "cloud_admin", grantor_oid: "1", admin_option: false, inherit_option: false, set_option: true },
      ],
      closure_complete: true,
      application_authority_absent: true,
    },
    ledger: { first_nine_identity_digest: CANONICAL_FIRST_NINE_IDENTITY_DIGEST, row_count: 9, migration_0010_absent: true },
    canonical_posture_digest: "7".repeat(64),
  };
  const evidence = {
    ...evidencePayload,
    evidence_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, evidencePayload),
  };
  const finalPayload = {
    ...evidencePayload,
    ledger: { ...evidencePayload.ledger, row_count: 10, migration_0010_absent: false },
  };
  const finalEvidence = {
    ...finalPayload,
    evidence_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, finalPayload),
  };
  return { observationBundle, evidence, finalEvidence };
}

function durableV2Artifacts(observationBundle, evidence, migrationSql) {
  const prestate = normalizeBrokeredPrestateV2(observationBundle, evidence);
  const preliminaryPlan = createBrokeredDurablePlanV2(prestate);
  const bundle = compileBrokerMutationBundle({
    observation_bundle: observationBundle,
    observation_evidence: evidence,
    prestate_digest: prestate.prestate_digest,
    plan_digest: preliminaryPlan.plan_digest,
    migration_sql: migrationSql,
  });
  return {
    prestate,
    plan: bindDurablePlanV2ToBrokerBundle(preliminaryPlan, bundle),
    bundle,
  };
}

function reservationFor(bundle) {
  const payload = {
    version: BROKER_ATTEMPT_RESERVATION_VERSION,
    state: "RESERVED_CONSUMED",
    run: bundle.run,
    lock: bundle.lock,
    target_binding_digest: bundle.target_binding_digest,
    plan_digest: bundle.plan_digest,
    mutation_bundle_digest: bundle.bundle_digest,
    reservation_id: "fixture-reservation-1",
  };
  return { ...payload, reservation_digest: computeBrokerBundleDigest(BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR, payload) };
}

function reservationForRequest(input) {
  const payload = {
    version: BROKER_ATTEMPT_RESERVATION_VERSION,
    state: "RESERVED_CONSUMED",
    run: input.run,
    lock: input.lock,
    target_binding_digest: input.target_binding_digest,
    plan_digest: input.plan_digest,
    mutation_bundle_digest: input.mutation_bundle_digest,
    reservation_id: "fixture-reservation-1",
  };
  return { ...payload, reservation_digest: computeBrokerBundleDigest(BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR, payload) };
}

function capabilityFor(inverse, overrides = {}) {
  return {
    version: RESTORE_CAPABILITY_VERSION,
    target_binding_digest: inverse.target_binding_digest,
    prestate_digest: inverse.prestate_digest,
    plan_digest: inverse.plan_digest,
    authority_graph_digest: inverse.authority_graph_digest,
    broker_bundle_digest: inverse.broker_bundle_digest,
    reservation_digest: inverse.reservation_digest,
    execute: async () => {},
    ...overrides,
  };
}

function restoreCapabilityProviderFor(plan, { onBind, capability } = {}) {
  return {
    version: RESTORE_CAPABILITY_PROVIDER_VERSION,
    target_binding_digest: plan.target_binding_digest,
    prestate_digest: plan.prestate_digest,
    plan_digest: plan.plan_digest,
    authority_graph_digest: plan.authority_graph_digest,
    broker_bundle_digest: plan.broker_bundle_digest,
    bindReservation: async (inverse) => {
      onBind?.(inverse);
      return typeof capability === "function" ? capability(inverse) : capability ?? capabilityFor(inverse);
    },
  };
}

function resultFor(bundle, reservation) {
  return resultForState(bundle, reservation, "COMMITTED", "DISCARDED");
}

function resultForState(bundle, reservation, commit_state, cleanup_state) {
  const payload = {
    version: BROKER_RESULT_VERSION,
    mutation_bundle_digest: bundle.bundle_digest,
    reservation_digest: reservation.reservation_digest,
    dispatch_state: "DISPATCHED",
    commit_state,
    cleanup_state,
    migration_tag: "0010_admin_operator_viewer_role_collapse",
    migration_sql_sha256: "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b",
    safe_result_digest: "8".repeat(64),
  };
  return { ...payload, result_digest: computeBrokerBundleDigest(BROKER_RESULT_DOMAIN_SEPARATOR, payload) };
}

function rollbackResultFor(bundle, reservation) {
  const payload = {
    version: BROKER_RESULT_VERSION,
    mutation_bundle_digest: bundle.bundle_digest,
    reservation_digest: reservation.reservation_digest,
    dispatch_state: "DISPATCHED",
    commit_state: "NOT_COMMITTED",
    cleanup_state: "DISCARDED",
    migration_tag: "0010_admin_operator_viewer_role_collapse",
    migration_sql_sha256: "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b",
    safe_result_digest: "8".repeat(64),
  };
  return { ...payload, result_digest: computeBrokerBundleDigest(BROKER_RESULT_DOMAIN_SEPARATOR, payload) };
}

function assertExactMutationBundle(candidate, expected) {
  const { bundle_digest: claimedDigest, ...payload } = candidate;
  if (canonicalSerializeBrokerBundle(candidate) !== canonicalSerializeBrokerBundle(expected)) throw new Error("BROKER_MUTATION_BUNDLE_REJECTED");
  if (claimedDigest !== computeBrokerBundleDigest(BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR, payload)) throw new Error("BROKER_MUTATION_BUNDLE_REJECTED");
}

function tamperStatement(bundle, ordinal, change) {
  return {
    ...bundle,
    statements: bundle.statements.map((entry) => entry.ordinal === ordinal ? { ...entry, ...change } : entry),
  };
}

function rehashMutationBundle(bundle) {
  const { bundle_digest: _ignored, ...payload } = bundle;
  return { ...payload, bundle_digest: computeBrokerBundleDigest(BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR, payload) };
}

async function mutationFixture() {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  return { observationBundle, evidence, migrationSql, ...durableV2Artifacts(observationBundle, evidence, migrationSql) };
}

async function providerFinalResultMap(observationBundle, evidence) {
  const journal = JSON.parse(await readFile("drizzle/migrations/meta/_journal.json", "utf8"));
  const ledger = await Promise.all(journal.entries.slice(0, 9).map(async (entry, index) => ({
    id: index + 1,
    hash: createHash("sha256").update(await readFile(`drizzle/migrations/${entry.tag}.sql`, "utf8")).digest("hex"),
    created_at: String(entry.when),
  })));
  ledger.push({ id: 10, hash: "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b", created_at: "1787479999088" });
  const posture = observationBundle.statements.find((entry) => entry.id === "canonical_posture");
  const roleData = observationBundle.statements.find((entry) => entry.id === "role_data_invariants");
  assert.ok(posture);
  assert.ok(roleData);
  return {
    provider_final_target_identity: [{ ...evidence.provider, ...evidence.target }],
    provider_final_migrator_dormancy: [{ ...evidence.migrator }],
    provider_final_authority_graph_nodes: evidence.authority_graph.nodes,
    provider_final_authority_graph_edges: evidence.authority_graph.edges,
    provider_final_migration_ledger: ledger,
    provider_final_canonical_posture: [Object.fromEntries(posture.result_schema.map((key) => [key, true]))],
    provider_final_role_data_invariants: [{ role_labels: "admin,operator,viewer", ...Object.fromEntries(roleData.result_schema.slice(1).map((key) => [key, true])) }],
  };
}

test("blocking advisory lock compiler and native result contract are exact and fail closed before downstream dispatch", async () => {
  const { observationBundle, evidence, migrationSql } = await mutationFixture();
  const bundle = compileBrokerMutationBundle({
    observation_bundle: observationBundle,
    observation_evidence: evidence,
    prestate_digest: "9".repeat(64),
    plan_digest: "a".repeat(64),
    migration_sql: migrationSql,
  });
  const lockStatements = bundle.statements.filter((entry) => entry.id === "target_advisory_lock");
  assert.equal(lockStatements.length, 1);
  const lock = lockStatements[0];
  const expectedSql = `select true as lock_acquired from pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('${observationBundle.target_binding_digest}', 0)) as acquired`;
  assert.equal(lock.ordinal, 0);
  assert.equal(lock.phase, "LOCK");
  assert.equal(lock.mutating, false);
  assert.deepEqual(lock.result_schema, ["lock_acquired"]);
  assert.equal(lock.sql, expectedSql);
  assert.equal(lock.sha256, createHash("sha256").update(expectedSql, "utf8").digest("hex"));
  assert.equal((lock.sql.match(/pg_catalog\.pg_advisory_xact_lock/gu) ?? []).length, 1);
  assert.equal((lock.sql.match(/pg_catalog\.hashtextextended/gu) ?? []).length, 1);
  assert.doesNotMatch(lock.sql, /pg_try_advisory_xact_lock|is null|select true\s*$/u);
  assert.equal(bundle.statements.filter((entry) => entry.id === "target_advisory_lock").length, 1);

  assert.doesNotThrow(() => validateBrokerStatementResult(observationBundle, lock, [{ lock_acquired: true }]));
  for (const invalid of [
    null,
    undefined,
    [],
    [{ }],
    [{ lock_acquired: false }],
    [{ lock_acquired: null }],
    [{ lock_acquired: "true" }],
    [{ lock_acquired: "false" }],
    [{ lock_acquired: 0 }],
    [{ lock_acquired: 1 }],
    [{ lock_acquired: true, extra: false }],
    [{ lock_acquired: true }, { lock_acquired: true }],
    [[{ lock_acquired: true }]],
    [null],
    "[{\"lock_acquired\":true}]",
  ]) {
    assert.throws(() => validateBrokerStatementResult(observationBundle, lock, invalid), /BROKER_/u);
  }

  const dispatchTrace = [];
  assert.throws(() => {
    for (const statement of bundle.statements.filter((entry) => entry.phase !== "CLEANUP")) {
      dispatchTrace.push(statement.id);
      validateBrokerStatementResult(observationBundle, statement, statement.id === "target_advisory_lock" ? [{ lock_acquired: false }] : []);
    }
  }, /BROKER_STATEMENT_RESULT_REJECTED/u);
  assert.deepEqual(dispatchTrace, ["target_advisory_lock"]);
});

test("mutation, reservation, and result bindings reject deterministic identity and tamper matrices", async () => {
  const { observationBundle, evidence, migrationSql } = await mutationFixture();
  const { bundle } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  assert.throws(
    () => compileBrokerMutationBundle({
      observation_bundle: { ...observationBundle, statements: [observationBundle.statements[1], observationBundle.statements[0], ...observationBundle.statements.slice(2)] },
      observation_evidence: evidence,
      prestate_digest: "9".repeat(64),
      plan_digest: "a".repeat(64),
      migration_sql: migrationSql,
    }),
    /BROKER_OBSERVATION_BUNDLE_REJECTED/u,
  );
  const tamperedBundles = [
    ["statement id", tamperStatement(bundle, 0, { id: "wrong_lock" })],
    ["ordinal", tamperStatement(bundle, 0, { ordinal: 1 })],
    ["phase", tamperStatement(bundle, 0, { phase: "ADMISSION" })],
    ["sql", tamperStatement(bundle, 0, { sql: "select false" })],
    ["sql hash", tamperStatement(bundle, 0, { sha256: "f".repeat(64) })],
    ["mutating", tamperStatement(bundle, 0, { mutating: true })],
    ["result schema", tamperStatement(bundle, 0, { result_schema: ["wrong"] })],
    ["statement order", { ...bundle, statements: [bundle.statements[1], bundle.statements[0], ...bundle.statements.slice(2)] }],
    ["statement count", { ...bundle, statements: bundle.statements.slice(0, -1) }],
    ["target binding", { ...bundle, target_binding_digest: "b".repeat(64) }],
    ["observation evidence", { ...bundle, observation_evidence_digest: "c".repeat(64) }],
    ["plan", { ...bundle, plan_digest: "d".repeat(64) }],
    ["prestate", { ...bundle, prestate_digest: "e".repeat(64) }],
    ["source manifest", { ...bundle, source_manifest_digest: "f".repeat(64) }],
    ["build manifest", { ...bundle, build_manifest_digest: "0".repeat(64) }],
    ["contract", { ...bundle, contract_digest: "1".repeat(64) }],
    ["bundle digest", { ...bundle, bundle_digest: "2".repeat(64) }],
  ];
  for (const [label, candidate] of tamperedBundles) assert.throws(() => assertExactMutationBundle(candidate, bundle), /BROKER_MUTATION_BUNDLE_REJECTED/u, label);

  const reservation = reservationFor(bundle);
  for (const candidate of [
    { ...reservation, target_binding_digest: "3".repeat(64) },
    { ...reservation, plan_digest: "4".repeat(64) },
    { ...reservation, mutation_bundle_digest: "5".repeat(64) },
    { ...reservation, reservation_digest: "6".repeat(64) },
    { ...reservation, reservation_id: "" },
  ]) assert.throws(() => normalizeBrokerAttemptReservation(candidate, bundle), /BROKER_(?:ATTEMPT_RESERVATION_INVALID|ARTIFACT_INVALID)/u);

  const result = resultFor(bundle, reservation);
  for (const candidate of [
    { ...result, mutation_bundle_digest: "7".repeat(64) },
    { ...result, reservation_digest: "8".repeat(64) },
    { ...result, safe_result_digest: "9".repeat(64) },
    { ...result, result_digest: "a".repeat(64) },
  ]) assert.throws(() => validateBrokerMutationResult(candidate, bundle, reservation), /BROKER_RESULT_INVALID/u);
  for (const [dispatch_state, commit_state, cleanup_state] of [
    ["NOT_DISPATCHED", "COMMITTED", "DISCARDED"],
    ["NOT_DISPATCHED", "NOT_COMMITTED", "FAILED"],
    ["INDETERMINATE", "NOT_COMMITTED", "INDETERMINATE"],
    ["DISPATCHED", "INDETERMINATE", "DISCARDED"],
  ]) {
    const contradictory = resultForState(bundle, reservation, commit_state, cleanup_state);
    contradictory.dispatch_state = dispatch_state;
    contradictory.result_digest = computeBrokerBundleDigest(BROKER_RESULT_DOMAIN_SEPARATOR, Object.fromEntries(Object.entries(contradictory).filter(([key]) => key !== "result_digest")));
    assert.throws(() => validateBrokerMutationResult(contradictory, bundle, reservation), /BROKER_RESULT_INVALID/u);
  }
  assert.doesNotThrow(() => validateBrokerMutationResult(result, bundle, reservation));
});

test("broker bundles are canonical, target-bound, and contain the exact 0010 transaction-local role path", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  assert.doesNotThrow(() => normalizeBrokerObservationEvidence(evidence, observationBundle));
  const bundle = compileBrokerMutationBundle({
    observation_bundle: observationBundle,
    observation_evidence: evidence,
    prestate_digest: "9".repeat(64),
    plan_digest: "a".repeat(64),
    migration_sql: migrationSql,
  });
  assert.equal(bundle.attempt_policy.maximum, 1);
  assert.equal(bundle.migration.journal_index, 9);
  assert.equal(bundle.migration.created_at, 1787479999088);
  assert.equal(bundle.migration.sql_sha256, "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b");
  assert.equal(bundle.statements.some((entry) => entry.sql === "set local role platform_migrator"), true);
  assert.equal(bundle.statements.some((entry) => entry.sql === "set local search_path = pg_catalog, public, drizzle"), true);
  assert.deepEqual(
    bundle.statements.filter((entry) => entry.id.startsWith("locked_")).map((entry) => entry.id),
    [
      "locked_provider_target_identity",
      "locked_migrator_dormancy",
      "locked_authority_graph_nodes",
      "locked_authority_graph_edges",
      "locked_migration_ledger",
      "locked_canonical_posture",
      "locked_role_data_invariants",
      "locked_binding_assertion",
    ],
  );
  assert.equal(bundle.statements.at(-1).id, "cleanup_identity_assertion");
  assert.equal(bundle.statements.every((entry, index) => entry.ordinal === index), true);
  const authorityGraphEdges = observationBundle.statements.find((entry) => entry.id === "authority_graph_edges");
  assert.match(authorityGraphEdges.sql, /where exists \(select 1 from role_closure closure where closure\.role_oid in/u);
  assert.doesNotMatch(authorityGraphEdges.sql, /join role_closure closure on/u);
  assert.equal(canonicalSerializeBrokerBundle(bundle).includes("postgres://"), false);
  assert.equal(canonicalSerializeBrokerBundle(bundle).includes("rolpassword,"), false);
});

test("Repair-2 binds the v2 mutation tail and validates provider FINAL as an exact graph-first result set", async () => {
  const { observationBundle, evidence, bundle } = await mutationFixture();
  assert.equal(bundle.version, "platform-db-broker-mutation-bundle-v2");
  assert.equal(BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR, "Swooshz-platform:platform-db-broker-mutation-bundle-v2\0");
  assert.equal(bundle.statements.length, 40);
  assert.deepEqual(
    bundle.statements.slice(0, 27).map(({ ordinal, id, phase }) => ({ ordinal, id, phase })),
    [
      { ordinal: 0, id: "target_advisory_lock", phase: "LOCK" },
      { ordinal: 1, id: "ledger_lock", phase: "LOCK" },
      { ordinal: 2, id: "locked_provider_target_identity", phase: "ADMISSION" },
      { ordinal: 3, id: "locked_migrator_dormancy", phase: "ADMISSION" },
      { ordinal: 4, id: "locked_authority_graph_nodes", phase: "ADMISSION" },
      { ordinal: 5, id: "locked_authority_graph_edges", phase: "ADMISSION" },
      { ordinal: 6, id: "locked_migration_ledger", phase: "ADMISSION" },
      { ordinal: 7, id: "locked_canonical_posture", phase: "ADMISSION" },
      { ordinal: 8, id: "locked_role_data_invariants", phase: "ADMISSION" },
      { ordinal: 9, id: "locked_binding_assertion", phase: "ADMISSION" },
      { ordinal: 10, id: "set_local_migrator", phase: "ASSUME_ROLE" },
      { ordinal: 11, id: "assumed_identity_assertion", phase: "ASSUME_ROLE" },
      { ordinal: 12, id: "set_local_search_path", phase: "ASSUME_ROLE" },
      ...Array.from({ length: 13 }, (_, index) => ({ ordinal: 13 + index, id: `migration_0010_${String(index).padStart(2, "0")}`, phase: "MIGRATION" })),
      { ordinal: 26, id: "migration_0010_ledger_insert", phase: "LEDGER" },
    ],
  );
  assert.deepEqual(
    bundle.statements.slice(27).map(({ ordinal, id, phase }) => ({ ordinal, id, phase })),
    [
      { ordinal: 27, id: "migrator_final_ledger_assertion", phase: "MIGRATOR_VERIFY" },
      { ordinal: 28, id: "migrator_final_role_data_assertion", phase: "MIGRATOR_VERIFY" },
      { ordinal: 29, id: "migrator_final_identity_assertion", phase: "MIGRATOR_VERIFY" },
      { ordinal: 30, id: "restore_provider_role", phase: "RESTORE_PROVIDER" },
      { ordinal: 31, id: "restored_provider_identity_assertion", phase: "RESTORE_PROVIDER" },
      { ordinal: 32, id: "provider_final_target_identity", phase: "PROVIDER_VERIFY" },
      { ordinal: 33, id: "provider_final_migrator_dormancy", phase: "PROVIDER_VERIFY" },
      { ordinal: 34, id: "provider_final_authority_graph_nodes", phase: "PROVIDER_VERIFY" },
      { ordinal: 35, id: "provider_final_authority_graph_edges", phase: "PROVIDER_VERIFY" },
      { ordinal: 36, id: "provider_final_migration_ledger", phase: "PROVIDER_VERIFY" },
      { ordinal: 37, id: "provider_final_canonical_posture", phase: "PROVIDER_VERIFY" },
      { ordinal: 38, id: "provider_final_role_data_invariants", phase: "PROVIDER_VERIFY" },
      { ordinal: 39, id: "cleanup_identity_assertion", phase: "CLEANUP" },
    ],
  );
  assert.equal(bundle.statements[30].sql, "SET LOCAL ROLE NONE");
  assert.equal(bundle.statements.every((entry) => entry.sha256 === createHash("sha256").update(entry.sql, "utf8").digest("hex")), true);
  assert.equal(bundle.statements.slice(27).every((entry) => entry.mutating === false), true);

  const assumedIdentity = bundle.statements.find((entry) => entry.id === "assumed_identity_assertion");
  const migratorFinalIdentity = bundle.statements.find((entry) => entry.id === "migrator_final_identity_assertion");
  const restoredIdentity = bundle.statements.find((entry) => entry.id === "restored_provider_identity_assertion");
  const cleanupIdentity = bundle.statements.find((entry) => entry.id === "cleanup_identity_assertion");
  const migratorIdentity = [{ current_user: "platform_migrator", session_user: "cloud_admin", current_role_oid: "4", session_role_oid: "1" }];
  const providerIdentity = [{ current_user: "cloud_admin", session_user: "cloud_admin", current_role_oid: "1", session_role_oid: "1" }];
  assert.doesNotThrow(() => validateBrokerStatementResult(observationBundle, assumedIdentity, migratorIdentity));
  assert.doesNotThrow(() => validateBrokerStatementResult(observationBundle, migratorFinalIdentity, migratorIdentity, "FINAL"));
  assert.doesNotThrow(() => validateBrokerStatementResult(observationBundle, restoredIdentity, providerIdentity, "FINAL"));
  assert.doesNotThrow(() => validateBrokerStatementResult(observationBundle, cleanupIdentity, providerIdentity, "FINAL"));
  for (const changed of [
    [{ ...migratorIdentity[0], current_user: "cloud_admin" }],
    [{ ...migratorIdentity[0], session_user: "platform_app" }],
    [{ ...migratorIdentity[0], current_role_oid: "99" }],
    [{ ...migratorIdentity[0], session_role_oid: "99" }],
    [{ ...migratorIdentity[0], extra: false }],
    [],
  ]) assert.throws(() => validateBrokerStatementResult(observationBundle, migratorFinalIdentity, changed, "FINAL"), /BROKER_(?:SESSION_IDENTITY_REJECTED|STATEMENT_RESULT_REJECTED|ARTIFACT_INVALID)/u);
  for (const changed of [
    [{ ...providerIdentity[0], current_user: "platform_migrator" }],
    [{ ...providerIdentity[0], session_user: "platform_app" }],
    [{ ...providerIdentity[0], current_role_oid: "99" }],
    [{ ...providerIdentity[0], session_role_oid: "99" }],
    [{ ...providerIdentity[0], extra: false }],
    [],
  ]) assert.throws(() => validateBrokerStatementResult(observationBundle, restoredIdentity, changed, "FINAL"), /BROKER_(?:SESSION_IDENTITY_REJECTED|STATEMENT_RESULT_REJECTED|ARTIFACT_INVALID)/u);

  const finalResults = await providerFinalResultMap(observationBundle, evidence);
  const finalEvidence = validateBrokerProviderFinalResultSet(observationBundle, bundle, finalResults);
  assert.equal(finalEvidence.ledger.row_count, 10);
  assert.equal(finalEvidence.ledger.migration_0010_absent, false);
  assert.equal(finalEvidence.authority_graph.closure_complete, true);
  assert.equal(finalEvidence.migrator.password_is_null, true);
  for (const changedBundle of [
    rehashMutationBundle({ ...bundle, statements: bundle.statements.map((entry) => entry.ordinal === 32 ? { ...entry, phase: "MIGRATOR_VERIFY" } : entry) }),
    rehashMutationBundle({ ...bundle, statements: bundle.statements.map((entry) => entry.ordinal === 35 ? { ...entry, sha256: "f".repeat(64) } : entry) }),
    rehashMutationBundle({ ...bundle, statements: bundle.statements.map((entry) => entry.ordinal === 37 ? { ...entry, result_schema: ["wrong"] } : entry) }),
    rehashMutationBundle({ ...bundle, statements: bundle.statements.map((entry) => entry.ordinal === 38 ? { ...entry, mutating: true } : entry) }),
    rehashMutationBundle({ ...bundle, statements: bundle.statements.map((entry) => entry.ordinal === 34 ? { ...entry, ordinal: 35 } : entry) }),
  ]) assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, changedBundle, finalResults), /BROKER_PROVIDER_FINAL_RESULT_SET_REJECTED/u);
  assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, bundle, { ...finalResults, provider_final_role_data_invariants: undefined }), /BROKER_/u);
  assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, bundle, { ...finalResults, extra: [] }), /BROKER_/u);
  for (const changedResults of [
    { ...finalResults, provider_final_migrator_dormancy: [{ ...finalResults.provider_final_migrator_dormancy[0], rolcanlogin: true }] },
    { ...finalResults, provider_final_migrator_dormancy: [{ ...finalResults.provider_final_migrator_dormancy[0], password_is_null: false }] },
    { ...finalResults, provider_final_role_data_invariants: [{ ...finalResults.provider_final_role_data_invariants[0], role_values_valid: null }] },
    { ...finalResults, provider_final_role_data_invariants: [{ ...finalResults.provider_final_role_data_invariants[0], active_workspace_admin_valid: "true" }] },
    { ...finalResults, provider_final_canonical_posture: [{ ...finalResults.provider_final_canonical_posture[0], application_migrator_authority_absent: false }] },
  ]) assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, bundle, changedResults), /BROKER_/u);
  const directForbiddenEdge = {
    granted_role: "platform_migrator", granted_role_oid: "4", member: "platform_app", member_oid: "2", grantor: "cloud_admin", grantor_oid: "1", admin_option: false, inherit_option: false, set_option: false,
  };
  assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, bundle, { ...finalResults, provider_final_authority_graph_edges: [...finalResults.provider_final_authority_graph_edges, directForbiddenEdge] }), /BROKER_AUTHORITY_GRAPH_REJECTED/u);
  const bridgeNode = { role_name: "run618_unknown_bridge", role_oid: "5", rolsuper: false, rolcreaterole: false };
  const bridgeEdge = { granted_role: "platform_migrator", granted_role_oid: "4", member: "run618_unknown_bridge", member_oid: "5", grantor: "cloud_admin", grantor_oid: "1", admin_option: false, inherit_option: false, set_option: true };
  assert.throws(() => validateBrokerProviderFinalResultSet(observationBundle, bundle, { ...finalResults, provider_final_authority_graph_nodes: [...finalResults.provider_final_authority_graph_nodes, bridgeNode], provider_final_authority_graph_edges: [...finalResults.provider_final_authority_graph_edges, bridgeEdge] }), /BROKER_AUTHORITY_GRAPH_REJECTED/u);
});

test("broker evidence rejects target, dormancy, graph, and application authority drift before reservation", () => {
  const { observationBundle, evidence } = brokerFixture();
  const rehash = (value) => {
    const payload = { ...value };
    delete payload.evidence_digest;
    return { ...payload, evidence_digest: computeBrokerBundleDigest(BROKER_OBSERVATION_EVIDENCE_DOMAIN_SEPARATOR, payload) };
  };
  for (const changed of [
    { ...evidence, provider: { ...evidence.provider, session_user: "platform_app" } },
    { ...evidence, target: { ...evidence.target, database_oid: "43" } },
    { ...evidence, migrator: { ...evidence.migrator, password_is_null: false } },
    { ...evidence, authority_graph: { ...evidence.authority_graph, application_authority_absent: false } },
  ]) {
    assert.throws(() => normalizeBrokerObservationEvidence(rehash(changed), observationBundle), /BROKER_/u);
  }
  const directForbiddenEdge = {
    granted_role: "platform_migrator",
    granted_role_oid: "4",
    member: "platform_app",
    member_oid: "2",
    grantor: "cloud_admin",
    grantor_oid: "1",
    admin_option: false,
    inherit_option: false,
    set_option: false,
  };
  assert.throws(
    () => normalizeBrokerObservationEvidence(rehash({ ...evidence, authority_graph: { ...evidence.authority_graph, edges: [...evidence.authority_graph.edges, directForbiddenEdge] } }), observationBundle),
    /BROKER_AUTHORITY_GRAPH_REJECTED/u,
  );
  const unknownBridgeNode = { role_name: "run610_unknown_bridge", role_oid: "5", rolsuper: false, rolcreaterole: false };
  const unknownBridgeEdge = {
    granted_role: "platform_migrator",
    granted_role_oid: "4",
    member: "run610_unknown_bridge",
    member_oid: "5",
    grantor: "cloud_admin",
    grantor_oid: "1",
    admin_option: false,
    inherit_option: false,
    set_option: true,
  };
  assert.throws(
    () => normalizeBrokerObservationEvidence(rehash({ ...evidence, authority_graph: { ...evidence.authority_graph, nodes: [...evidence.authority_graph.nodes, unknownBridgeNode], edges: [...evidence.authority_graph.edges, unknownBridgeEdge] } }), observationBundle),
    /BROKER_AUTHORITY_GRAPH_REJECTED/u,
  );
});

test("locked admission derives the same graph proof and rejects direct and unknown bridge drift", async () => {
  const { observationBundle, evidence: fixtureEvidence } = brokerFixture();
  const journal = JSON.parse(await readFile("drizzle/migrations/meta/_journal.json", "utf8"));
  const migrationLedger = await Promise.all(journal.entries.slice(0, 9).map(async (entry, index) => ({
    id: index + 1,
    hash: createHash("sha256").update(await readFile(`drizzle/migrations/${entry.tag}.sql`, "utf8")).digest("hex"),
    created_at: String(entry.when),
  })));
  const postureStatement = observationBundle.statements.find((entry) => entry.id === "canonical_posture");
  const roleDataStatement = observationBundle.statements.find((entry) => entry.id === "role_data_invariants");
  assert.ok(postureStatement);
  assert.ok(roleDataStatement);
  const resultMap = {
    provider_target_identity: [{ ...fixtureEvidence.provider, ...fixtureEvidence.target }],
    migrator_dormancy: [{ ...fixtureEvidence.migrator }],
    authority_graph_nodes: fixtureEvidence.authority_graph.nodes,
    authority_graph_edges: fixtureEvidence.authority_graph.edges,
    migration_ledger: migrationLedger,
    canonical_posture: [Object.fromEntries(postureStatement.result_schema.map((key) => [key, true]))],
    role_data_invariants: [{ role_labels: "owner,admin,member,viewer", ...Object.fromEntries(roleDataStatement.result_schema.slice(1).map((key) => [key, true])) }],
  };
  const evidence = deriveBrokerObservationEvidence(observationBundle, resultMap);
  const mutationBundle = compileBrokerMutationBundle({
    observation_bundle: observationBundle,
    observation_evidence: evidence,
    prestate_digest: "9".repeat(64),
    plan_digest: "a".repeat(64),
    migration_sql: await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8"),
  });
  const lockedResultMap = Object.fromEntries(observationBundle.statements.map((entry) => [`locked_${entry.id}`, resultMap[entry.id]]));
  assert.equal(validateLockedBrokerObservationResultSet(observationBundle, mutationBundle, lockedResultMap).evidence_digest, evidence.evidence_digest);

  const directEdge = {
    granted_role: "platform_migrator",
    granted_role_oid: "4",
    member: "platform_app",
    member_oid: "2",
    grantor: "cloud_admin",
    grantor_oid: "1",
    admin_option: false,
    inherit_option: false,
    set_option: false,
  };
  assert.throws(
    () => validateLockedBrokerObservationResultSet(observationBundle, mutationBundle, { ...lockedResultMap, locked_authority_graph_edges: [...resultMap.authority_graph_edges, directEdge] }),
    /BROKER_AUTHORITY_GRAPH_REJECTED/u,
  );
  const unknownBridgeNode = { role_name: "run610_unknown_bridge", role_oid: "5", rolsuper: false, rolcreaterole: false };
  const unknownBridgeEdge = {
    granted_role: "platform_migrator",
    granted_role_oid: "4",
    member: "run610_unknown_bridge",
    member_oid: "5",
    grantor: "cloud_admin",
    grantor_oid: "1",
    admin_option: false,
    inherit_option: false,
    set_option: true,
  };
  assert.throws(
    () => validateLockedBrokerObservationResultSet(observationBundle, mutationBundle, { ...lockedResultMap, locked_authority_graph_nodes: [...resultMap.authority_graph_nodes, unknownBridgeNode], locked_authority_graph_edges: [...resultMap.authority_graph_edges, unknownBridgeEdge] }),
    /BROKER_AUTHORITY_GRAPH_REJECTED/u,
  );
});

test("broker execution reserves once before dispatch, validates the result, and performs a fresh observation", async () => {
  const { observationBundle, evidence, finalEvidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let observes = 0;
  let dispatches = 0;
  let reservations = 0;
  const attemptStore = {
    async reserveOnce(input) {
      reservations += 1;
      return reservationForRequest(input);
    },
  };
  const broker = {
    async observe() { observes += 1; return observes === 1 ? evidence : finalEvidence; },
    async dispatchMutation(serialized, digest, reservation) {
      dispatches += 1;
      const parsed = JSON.parse(serialized);
      assert.equal(parsed.bundle_digest, digest);
      return resultFor(parsed, reservation);
    },
  };
  const omitted = await executeBrokeredMigrationPlan({ observationBundle, prestate, plan, migrationSql, broker, attemptStore });
  assert.equal(omitted.outcome, "BLOCKED");
  assert.equal(omitted.phase, "RECOVERY_ADMISSION");
  assert.equal(omitted.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
  assert.equal(omitted.attempts_used, 0);
  assert.equal(omitted.dispatch_state, "NOT_DISPATCHED");
  assert.equal(omitted.mutation_started, false);
  assert.equal(omitted.recovery_state, "NOT_REQUIRED");
  assert.equal(observes, 0);
  assert.equal(reservations, 0);
  assert.equal(dispatches, 0);
  const receipt = await executeBrokeredMigrationPlan({ observationBundle, prestate, plan, migrationSql, broker, attemptStore, restoreCapabilityProvider: restoreCapabilityProviderFor(plan) });
  assert.equal(receipt.outcome, "PASS");
  assert.equal(receipt.attempts_used, 1);
  assert.equal(receipt.cleanup_state, "DISCARDED");
  assert.equal(observes, 2);
  assert.equal(reservations, 1);
  assert.equal(dispatches, 1);
  assert.equal(receipt.recovery_state, "AVAILABLE");
});

test("recovery provider structural and pre-reservation digest admission fail closed", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  for (const provider of [
    undefined,
    { ...restoreCapabilityProviderFor(plan), version: "restore-capability-provider-v1" },
    { ...restoreCapabilityProviderFor(plan), bindReservation: null },
    { ...restoreCapabilityProviderFor(plan), extra: true },
  ]) {
    let observes = 0;
    let reservations = 0;
    let dispatches = 0;
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: provider,
      broker: { async observe() { observes += 1; return evidence; }, async dispatchMutation() { dispatches += 1; } },
      attemptStore: { async reserveOnce() { reservations += 1; throw new Error("must not reserve"); } },
    });
    assert.equal(receipt.outcome, "BLOCKED");
    assert.equal(receipt.phase, "RECOVERY_ADMISSION");
    assert.equal(receipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
    assert.equal(receipt.attempts_used, 0);
    assert.equal(receipt.dispatch_state, "NOT_DISPATCHED");
    assert.equal(receipt.mutation_started, false);
    assert.equal(receipt.recovery_state, "NOT_REQUIRED");
    assert.equal(observes, 0);
    assert.equal(reservations, 0);
    assert.equal(dispatches, 0);
  }

  for (const field of [
    "target_binding_digest",
    "prestate_digest",
    "plan_digest",
    "authority_graph_digest",
    "broker_bundle_digest",
  ]) {
    const provider = { ...restoreCapabilityProviderFor(plan), [field]: "f".repeat(64) };
    let observes = 0;
    let reservations = 0;
    let dispatches = 0;
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: provider,
      broker: { async observe() { observes += 1; return evidence; }, async dispatchMutation() { dispatches += 1; } },
      attemptStore: { async reserveOnce() { reservations += 1; throw new Error("must not reserve"); } },
    });
    assert.equal(receipt.outcome, "BLOCKED");
    assert.equal(receipt.phase, "RECOVERY_ADMISSION");
    assert.equal(receipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
    assert.equal(receipt.attempts_used, 0);
    assert.equal(receipt.dispatch_state, "NOT_DISPATCHED");
    assert.equal(receipt.mutation_started, false);
    assert.equal(receipt.recovery_state, "NOT_REQUIRED");
    assert.equal(observes, 1);
    assert.equal(reservations, 0);
    assert.equal(dispatches, 0);
  }
});

test("recovery provider admission captures only enumerable data descriptors", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  const providerFields = [
    "version",
    "target_binding_digest",
    "prestate_digest",
    "plan_digest",
    "authority_graph_digest",
    "broker_bundle_digest",
    "bindReservation",
  ];

  for (const field of providerFields) {
    const provider = restoreCapabilityProviderFor(plan);
    const original = provider[field];
    let getterCalls = 0;
    Object.defineProperty(provider, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return original;
      },
    });
    let observes = 0;
    let reservations = 0;
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: provider,
      broker: { async observe() { observes += 1; return evidence; }, async dispatchMutation() {} },
      attemptStore: { async reserveOnce() { reservations += 1; throw new Error("must not reserve"); } },
    });
    assert.equal(receipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
    assert.equal(receipt.attempts_used, 0);
    assert.equal(observes, 0);
    assert.equal(reservations, 0);
    assert.equal(getterCalls, 0);
  }

  for (const provider of [
    { ...restoreCapabilityProviderFor(plan), unknown: true },
    (() => {
      const value = restoreCapabilityProviderFor(plan);
      Object.defineProperty(value, "unknown", { configurable: true, enumerable: false, value: true });
      return value;
    })(),
    (() => {
      const value = restoreCapabilityProviderFor(plan);
      Object.defineProperty(value, "target_binding_digest", { configurable: true, enumerable: true, get() { throw new Error("getter must not run"); } });
      return value;
    })(),
    (() => {
      const value = restoreCapabilityProviderFor(plan);
      Object.defineProperty(value, Symbol("unknown"), { configurable: true, enumerable: true, value: true });
      return value;
    })(),
  ]) {
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: provider,
      broker: { async observe() { throw new Error("must not observe"); }, async dispatchMutation() {} },
      attemptStore: { async reserveOnce() { throw new Error("must not reserve"); } },
    });
    assert.equal(receipt.phase, "RECOVERY_ADMISSION");
    assert.equal(receipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
    assert.equal(receipt.attempts_used, 0);
  }
});

test("recovery provider descriptor and get traps cannot substitute admitted authority", async () => {
  const { observationBundle, evidence, finalEvidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  const source = restoreCapabilityProviderFor(plan);
  let ownKeysCalls = 0;
  let descriptorCalls = 0;
  let getCalls = 0;
  const provider = new Proxy(source, {
    ownKeys(target) {
      ownKeysCalls += 1;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, property) {
      descriptorCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    get(target, property, receiver) {
      getCalls += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  let observations = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    restoreCapabilityProvider: provider,
    broker: {
      async observe() {
        observations += 1;
        if (observations === 1) {
          source.target_binding_digest = "f".repeat(64);
          source.bindReservation = async () => { throw new Error("replaced provider must not run"); };
          return evidence;
        }
        return finalEvidence;
      },
      async dispatchMutation(serialized, digest, reservation) {
        return resultFor(JSON.parse(serialized), reservation);
      },
    },
    attemptStore: { async reserveOnce(input) { return reservationForRequest(input); } },
  });
  assert.equal(receipt.outcome, "PASS");
  assert.equal(ownKeysCalls, 1);
  assert.equal(descriptorCalls, 7);
  assert.equal(getCalls, 0);
});

test("recovery binding consumes the reservation once but prevents dispatch on any returned-capability mismatch", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  for (const field of ["reservation_digest", "target_binding_digest"]) {
    let reservations = 0;
    let dispatches = 0;
    let binds = 0;
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: restoreCapabilityProviderFor(plan, {
        onBind: () => { binds += 1; },
        capability: (inverse) => capabilityFor(inverse, { [field]: "0".repeat(64) }),
      }),
      broker: { async observe() { return evidence; }, async dispatchMutation() { dispatches += 1; } },
      attemptStore: { async reserveOnce(input) { reservations += 1; return reservationForRequest(input); } },
    });
    assert.equal(receipt.outcome, "FAIL");
    assert.equal(receipt.phase, "RECOVERY_ADMISSION");
    assert.equal(receipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
    assert.equal(receipt.attempts_used, 1);
    assert.equal(receipt.dispatch_state, "NOT_DISPATCHED");
    assert.equal(receipt.commit_state, "NOT_COMMITTED");
    assert.equal(receipt.mutation_started, false);
    assert.equal(receipt.recovery_state, "NOT_REQUIRED");
    assert.equal(reservations, 1);
    assert.equal(binds, 1);
    assert.equal(dispatches, 0);
  }
});

test("post-reservation capability accessors fail before dispatch without invoking getters", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);

  for (const field of ["execute", "reservation_digest"]) {
    let getterCalls = 0;
    let reservations = 0;
    let binds = 0;
    let dispatches = 0;
    const provider = restoreCapabilityProviderFor(plan, {
      onBind: () => { binds += 1; },
      capability: (inverse) => {
        const capability = capabilityFor(inverse);
        const original = capability[field];
        Object.defineProperty(capability, field, {
          configurable: true,
          enumerable: true,
          get() {
            getterCalls += 1;
            return original;
          },
        });
        return capability;
      },
    });
    const receipt = await executeBrokeredMigrationPlan({
      observationBundle,
      prestate,
      plan,
      migrationSql,
      restoreCapabilityProvider: provider,
      broker: { async observe() { return evidence; }, async dispatchMutation() { dispatches += 1; } },
      attemptStore: { async reserveOnce(input) { reservations += 1; return reservationForRequest(input); } },
    });
    assert.equal(receipt.outcome, "FAIL");
    assert.equal(receipt.phase, "RECOVERY_ADMISSION");
    assert.equal(receipt.attempts_used, 1);
    assert.equal(reservations, 1);
    assert.equal(binds, 1);
    assert.equal(dispatches, 0);
    assert.equal(getterCalls, 0);
  }
});

test("broker execution order is observe, reserve, bind capability, dispatch, final observe", async () => {
  const { observationBundle, evidence, finalEvidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  const events = [];
  let observations = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan, { onBind: () => events.push("bind capability") }),
    broker: {
      async observe() { observations += 1; events.push(observations === 1 ? "observe" : "final observe"); return observations === 1 ? evidence : finalEvidence; },
      async dispatchMutation(serialized, digest, reservation) { events.push("dispatch"); return resultFor(JSON.parse(serialized), reservation); },
    },
    attemptStore: { async reserveOnce(input) { events.push("reserve"); return reservationForRequest(input); } },
  });
  assert.equal(receipt.outcome, "PASS");
  assert.deepEqual(events, ["observe", "reserve", "bind capability", "dispatch", "final observe"]);
});

test("admitted provider and capability are copied before caller-owned mutation, and capability execute is never invoked", async () => {
  const { observationBundle, evidence, finalEvidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  const provider = restoreCapabilityProviderFor(plan);
  let returnedCapability;
  let executeCalls = 0;
  provider.bindReservation = async (inverse) => {
    returnedCapability = capabilityFor(inverse, { execute: async () => { executeCalls += 1; } });
    return returnedCapability;
  };
  let observations = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    restoreCapabilityProvider: provider,
    broker: {
      async observe() {
        observations += 1;
        if (observations === 1) {
          provider.target_binding_digest = "f".repeat(64);
          provider.bindReservation = async () => { throw new Error("must not call replaced provider"); };
          return evidence;
        }
        return finalEvidence;
      },
      async dispatchMutation(serialized, digest, reservation) {
        returnedCapability.reservation_digest = "f".repeat(64);
        assert.equal(returnedCapability.reservation_digest, "f".repeat(64));
        return resultFor(JSON.parse(serialized), reservation);
      },
    },
    attemptStore: { async reserveOnce(input) { return reservationForRequest(input); } },
  });
  assert.equal(receipt.outcome, "PASS");
  assert.equal(receipt.recovery_state, "AVAILABLE");
  assert.equal(executeCalls, 0);
});

test("pre-dispatch rejection consumes no attempt and an indeterminate dispatch is never retried", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let reservations = 0;
  let dispatches = 0;
  const rejected = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    broker: { async observe() { return { ...evidence, target: { ...evidence.target, database_oid: "99" } }; }, async dispatchMutation() { dispatches += 1; } },
    attemptStore: { async reserveOnce() { reservations += 1; throw new Error("must not run"); } },
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan),
  });
  assert.equal(rejected.attempts_used, 0);
  assert.equal(reservations, 0);
  assert.equal(dispatches, 0);

  const failed = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    broker: { async observe() { return evidence; }, async dispatchMutation() { dispatches += 1; throw new Error("transport lost"); } },
    attemptStore: {
      async reserveOnce(input) {
        reservations += 1;
        return reservationForRequest(input);
      },
    },
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan),
  });
  assert.equal(failed.attempts_used, 1);
  assert.equal(failed.dispatch_state, "INDETERMINATE");
  assert.equal(failed.recovery_state, "INDETERMINATE");
  assert.equal(dispatches, 1);
  assert.equal(reservations, 1);
});

test("confirmed commit with cleanup failure is terminal and does not trigger a fresh observation", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let observes = 0;
  let dispatches = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    broker: {
      async observe() { observes += 1; return evidence; },
      async dispatchMutation(serialized, _digest, reservation) {
        dispatches += 1;
        return resultForState(JSON.parse(serialized), reservation, "COMMITTED", "FAILED");
      },
    },
    attemptStore: { async reserveOnce(input) { return reservationForRequest(input); } },
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan),
  });
  assert.equal(receipt.outcome, "FAIL");
  assert.equal(receipt.phase, "SESSION_CLEANUP");
  assert.equal(receipt.commit_state, "COMMITTED");
  assert.equal(receipt.cleanup_state, "FAILED");
  assert.equal(receipt.recovery_state, "REQUIRED");
  assert.equal(receipt.final_observation_state, "NOT_RUN");
  assert.equal(observes, 1);
  assert.equal(dispatches, 1);
});

test("broker execution rejects a reservation for different exact bundle bytes before dispatch", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let dispatches = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    broker: {
      async observe() { return evidence; },
      async dispatchMutation() { dispatches += 1; throw new Error("must not dispatch"); },
    },
    attemptStore: {
      async reserveOnce(input) {
        return reservationForRequest({ ...input, mutation_bundle_digest: "f".repeat(64) });
      },
    },
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan),
  });
  assert.equal(receipt.outcome, "FAIL");
  assert.equal(receipt.semantic_code, "ATTEMPT_RESERVATION_REJECTED");
  assert.equal(receipt.attempts_used, 1);
  assert.equal(receipt.phase, "ATTEMPT_RESERVATION");
  assert.equal(receipt.recovery_state, "NOT_REQUIRED");
  assert.equal(dispatches, 0);
});

test("determinate broker rollback requires a fresh exact restoration observation and never retries", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let observes = 0;
  let dispatches = 0;
  const receipt = await executeBrokeredMigrationPlan({
    observationBundle,
    prestate,
    plan,
    migrationSql,
    broker: {
      async observe() { observes += 1; return evidence; },
      async dispatchMutation(serialized, _digest, reservation) {
        dispatches += 1;
        return rollbackResultFor(JSON.parse(serialized), reservation);
      },
    },
    attemptStore: { async reserveOnce(input) { return reservationForRequest(input); } },
    restoreCapabilityProvider: restoreCapabilityProviderFor(plan),
  });
  assert.equal(receipt.outcome, "FAIL");
  assert.equal(receipt.commit_state, "NOT_COMMITTED");
  assert.equal(receipt.rollback_state, "VERIFIED");
  assert.equal(receipt.recovery_state, "AVAILABLE");
  assert.equal(receipt.final_observation_state, "PASS");
  assert.equal(receipt.attempts_used, 1);
  assert.equal(observes, 2);
  assert.equal(dispatches, 1);
});

test("v2 durable broker artifacts reject legacy and tampered evidence before reservation", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { prestate, plan } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  let reservations = 0;
  const attemptStore = { async reserveOnce() { reservations += 1; throw new Error("must not reserve"); } };
  const broker = { async observe() { return evidence; }, async dispatchMutation() { throw new Error("must not dispatch"); } };
  for (const changed of [
    { prestate: { ...prestate, version: "platform-db-prestate-v1" }, plan },
    { prestate, plan: { ...plan, version: "platform-db-plan-v1" } },
    { prestate, plan: { ...plan, authority_graph_digest: "f".repeat(64) } },
    { prestate, plan: { ...plan, source_manifest_digest: "e".repeat(64) } },
    { prestate, plan: { ...plan, broker_bundle_digest: "d".repeat(64) } },
  ]) {
    const receipt = await executeBrokeredMigrationPlan({ observationBundle, ...changed, migrationSql, broker, attemptStore, restoreCapabilityProvider: restoreCapabilityProviderFor(changed.plan) });
    assert.equal(receipt.outcome, "BLOCKED");
    assert.equal(receipt.attempts_used, 0);
  }
  assert.equal(reservations, 0);
});

test("v2 inverse and restoration capability bind target graph bundle and reservation", async () => {
  const { observationBundle, evidence } = brokerFixture();
  const migrationSql = await readFile("drizzle/migrations/0010_admin_operator_viewer_role_collapse.sql", "utf8");
  const { plan, bundle } = durableV2Artifacts(observationBundle, evidence, migrationSql);
  const reservation = reservationFor(bundle);
  const inverse = createDurableInverseV2(plan, reservation);
  const capability = {
    version: RESTORE_CAPABILITY_VERSION,
    target_binding_digest: inverse.target_binding_digest,
    prestate_digest: inverse.prestate_digest,
    plan_digest: inverse.plan_digest,
    authority_graph_digest: inverse.authority_graph_digest,
    broker_bundle_digest: inverse.broker_bundle_digest,
    reservation_digest: inverse.reservation_digest,
    async execute() {},
  };
  const admittedCapability = requireRestoreCapabilityV2(capability, inverse);
  assert.notEqual(admittedCapability, capability);
  assert.equal(Object.isFrozen(admittedCapability), true);
  assert.equal(admittedCapability.execute, capability.execute);
  assert.throws(
    () => requireRestoreCapabilityV2({ ...capability, reservation_digest: "0".repeat(64) }, inverse),
    (error) => error?.semanticCode === "RESTORE_CAPABILITY_REQUIRED",
  );
});

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
      version: "target-binding-v2",
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
      version: "target-binding-v2",
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
    version: "platform-db-prestate-v2",
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
    receipt_version: 2,
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
  assert.equal(PRESTATE_DOMAIN_SEPARATOR, "swooshz-platform:platform-db-prestate-v2\0");
  assert.equal(PLAN_DOMAIN_SEPARATOR, "Swooshz-platform:platform-db-plan-v2\0");
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
    canonicalDigest("swooshz-platform:platform-db-prestate-v2\0", { b: 2, a: 1 }),
    canonicalDigest("swooshz-platform:platform-db-prestate-v2\0", { a: 1, b: 2 }),
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
    stdout: "TAP version 13\nnot ok 1 - Run-598 exact durable broker bundle on two disposable PostgreSQL 17 clusters\n# reason: expected status 1\n# reason: internal customer@example.invalid detail\npostgres://secret@example.invalid/db",
    stderr: "Error: private driver detail\nDATABASE_URL=postgres://secret@example.invalid/db",
    outputOverflow: false,
  });
  assert.match(diagnostics, /Run-598 exact durable broker bundle/u);
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
    () => normalizePrestate({ version: "platform-db-prestate-v2" }),
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

test("migration admission accepts only exact historical CRLF aliases", async () => {
  const journal = await loadCanonicalMigrationJournal(repositoryRoot);
  const historicalTags = new Set([
    "0000_overconfident_onslaught",
    "0001_lovely_famine",
    "0002_futuristic_aaron_stack",
    "0003_worthless_scourge",
    "0004_illegal_william_stryker",
    "0005_sqag_app_key_migration",
    "0007_remove_legacy_kqag_tables",
    "0009_wonderful_star_brand",
  ]);
  const crlfHash = async (tag) => {
    const contents = await readFile(
      join(repositoryRoot, "drizzle", "migrations", `${tag}.sql`),
    );
    const crlfBytes = [];
    for (const byte of contents) {
      if (byte === 0x0a) crlfBytes.push(0x0d);
      crlfBytes.push(byte);
    }
    return createHash("sha256").update(Buffer.from(crlfBytes)).digest("hex");
  };
  const canonicalRows = journal.entries.map((entry) => ({
    when: entry.when,
    sql_sha256: entry.sql_sha256,
  }));
  const historicalRows = [];
  for (const entry of journal.entries) {
    historicalRows.push({
      when: entry.when,
      sql_sha256: historicalTags.has(entry.tag)
        ? await crlfHash(entry.tag)
        : entry.sql_sha256,
    });
  }

  const canonicalResult = await runCanonicalMigrationPrimitive({
    pool: migrationLedgerPool(canonicalRows),
    migrationsFolder: join(repositoryRoot, "drizzle", "migrations"),
  });
  assert.equal(canonicalResult.mutation_started, false);
  assert.deepEqual(canonicalResult.before, canonicalRows);

  const historicalResult = await runCanonicalMigrationPrimitive({
    pool: migrationLedgerPool(historicalRows),
    migrationsFolder: join(repositoryRoot, "drizzle", "migrations"),
  });
  assert.equal(historicalResult.mutation_started, false);
  assert.deepEqual(historicalResult.before, historicalRows);

  const arbitraryRows = historicalRows.map((row) => ({ ...row }));
  arbitraryRows[0].sql_sha256 = "0".repeat(64);
  await assert.rejects(
    () => runCanonicalMigrationPrimitive({
      pool: migrationLedgerPool(arbitraryRows),
      migrationsFolder: join(repositoryRoot, "drizzle", "migrations"),
    }),
    (error) => error?.semanticCode === "MIGRATION_IDENTITY_MISMATCH",
  );

  const futureAliasRows = historicalRows.map((row) => ({ ...row }));
  futureAliasRows[9].sql_sha256 = await crlfHash(
    "0010_admin_operator_viewer_role_collapse",
  );
  await assert.rejects(
    () => runCanonicalMigrationPrimitive({
      pool: migrationLedgerPool(futureAliasRows),
      migrationsFolder: join(repositoryRoot, "drizzle", "migrations"),
    }),
    (error) => error?.semanticCode === "MIGRATION_IDENTITY_MISMATCH",
  );
});

function migrationLedgerPool(rows) {
  return {
    async connect() {
      return {
        async query(text) {
          if (text.includes("select exists")) {
            return { rows: [{ ledger_present: true }] };
          }
          return { rows };
        },
        release() {},
      };
    },
  };
}

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
    assert.equal(inverse.version, "platform-db-inverse-v2");
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
    version: "target-binding-v2",
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
      version: "restore-capability-v2",
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
