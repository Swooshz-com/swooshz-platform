import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

import {
  bindDurablePlanV2ToBrokerBundle,
  createBrokeredDurablePlanV2,
  executeBrokeredMigrationPlan,
  normalizeBrokeredPrestateV2,
  RESTORE_CAPABILITY_PROVIDER_VERSION,
  RESTORE_CAPABILITY_VERSION,
} from "../dist/db/durable-operations.js";
import {
  BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR,
  BROKER_ATTEMPT_RESERVATION_OUTCOME_VERSION,
  BROKER_ATTEMPT_RESERVATION_VERSION,
  BROKER_AUTHORITY_CLASSIFICATION_VERSION,
  BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR,
  BROKER_OBSERVATION_BUNDLE_DOMAIN_SEPARATOR,
  BROKER_RESULT_DOMAIN_SEPARATOR,
  BROKER_RESULT_VERSION,
  BROKER_TARGET_BINDING_VERSION,
  canonicalSerializeBrokerBundle,
  compileBrokerMutationBundle,
  compileBrokerObservationBundle,
  computeBrokerBundleDigest,
  deriveBrokerObservationEvidence,
  normalizeBrokerAttemptReservation,
  validateBrokerProviderFinalResultSet,
  validateLockedBrokerObservationResultSet,
  validateBrokerStatementResult,
} from "../dist/db/brokered-migration.js";
import { RUNTIME_TABLE_GRANT_CONTRACT } from "../dist/db/runtime-grant-contract.js";

const testDatabaseUrlA = process.env.DURABLE_OPERATIONS_TEST_DATABASE_URL_A;
const testDatabaseUrlB = process.env.DURABLE_OPERATIONS_TEST_DATABASE_URL_B;
const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const migrationsFolder = resolve(rootDir, "drizzle", "migrations");
const databaseName = "durable_operations_test";
const migrationSha256 = "452829e49a5571a8b4e14a2cbf155e671fe81ef8ee2fa3583935b7cc2ffd996b";

function restoreCapabilityProviderFor(plan) {
  return {
    version: RESTORE_CAPABILITY_PROVIDER_VERSION,
    target_binding_digest: plan.target_binding_digest,
    prestate_digest: plan.prestate_digest,
    plan_digest: plan.plan_digest,
    authority_graph_digest: plan.authority_graph_digest,
    broker_bundle_digest: plan.broker_bundle_digest,
    bindReservation: async (inverse) => ({
      version: RESTORE_CAPABILITY_VERSION,
      target_binding_digest: inverse.target_binding_digest,
      prestate_digest: inverse.prestate_digest,
      plan_digest: inverse.plan_digest,
      authority_graph_digest: inverse.authority_graph_digest,
      broker_bundle_digest: inverse.broker_bundle_digest,
      reservation_digest: inverse.reservation_digest,
      execute: async () => {},
    }),
  };
}
const expectedFirstNineLedger = Object.freeze([
  { id: 1, hash: "d156026594b36870455ba6df7525310be1ce1838cda1d58725c6f3a07514c0a6", created_at: "1782546111134" },
  { id: 2, hash: "861614ef57601aff17a15fe594becfc0206fa931f22052ba98217e300285666d", created_at: "1782571351615" },
  { id: 3, hash: "76fd758786fa4583e18f3b89bf7fba0932bdb9c71de294f3291b19925bbd542b", created_at: "1782629131478" },
  { id: 4, hash: "41567c07fcdb3b6e41da516d346d1a20d5e3aa4b0c5d3297e8b19091fa8f5f09", created_at: "1782651725342" },
  { id: 5, hash: "01179c79b777732dc03dbef0471738e00dc85964082aa22764184362722ac5fe", created_at: "1783253616083" },
  { id: 6, hash: "651eaa1668341fc8bdbc8d6f47ccfdd9ec1e2c80fef018de73ab0a79b9896bbe", created_at: "1783479304000" },
  { id: 7, hash: "a8b5d90838c87ca3d74ada48295b92970c8a8476dacf5fc76b1a793995d7485b", created_at: "1783587520445" },
  { id: 8, hash: "0e82a5892f22b71f8894f8776388341519ac48944a417552443d639d09cdcbc0", created_at: "1784354477743" },
  { id: 9, hash: "bc54f927f5ab0a2ebc97a61ede57119f29e8673ab1b902a4e132191ac688820f", created_at: "1784620602227" },
]);
const expectedFinalLedger = Object.freeze([
  ...expectedFirstNineLedger,
  { id: 10, hash: migrationSha256, created_at: "1787479999088" },
]);
const expectedSequenceIdentity = "drizzle.__drizzle_migrations_id_seq";
const expectedBaselineSequence = Object.freeze({ identity: expectedSequenceIdentity, last_value: 9, is_called: true, increment: 1, next_id: 10 });
const expectedContaminatedSequence = Object.freeze({ identity: expectedSequenceIdentity, last_value: 10, is_called: true, increment: 1, next_id: 11 });
const expectedPrewriteRoleLabels = Object.freeze(["owner", "admin", "member", "viewer"]);

if (!testDatabaseUrlA || !testDatabaseUrlB) {
  test("durable PostgreSQL 17 proofs require the disposable runner", { skip: "runner-owned local fixture not supplied" }, () => {});
} else {
  test("Run-598 exact durable broker bundle on two disposable PostgreSQL 17 clusters", async () => {
    const connectionA = readConnectionTarget(testDatabaseUrlA);
    const connectionB = readConnectionTarget(testDatabaseUrlB);
    assert.notEqual(connectionA.port, connectionB.port);
    const providerA = new Pool({ ...connectionA, user: "cloud_admin" });
    const providerB = new Pool({ ...connectionB, user: "cloud_admin" });
    const appA = new Pool({ ...connectionA, user: "platform_app" });
    const appB = new Pool({ ...connectionB, user: "platform_app" });
    try {
      await Promise.all([createRoles(providerA), createRoles(providerB)]);
      await Promise.all([convergeCanonicalFixture(providerA, appA), convergeCanonicalFixture(providerB, appB)]);

      const contextA = await compileContext(providerA, "a");
      const contextB = await compileContext(providerB, "b");
      assert.notEqual(contextA.observationBundle.target_binding.expected_cluster_system_identifier, contextB.observationBundle.target_binding.expected_cluster_system_identifier);

      const adapterA = new DisposableBrokerAdapter(providerA, contextA, { captureProtectedEvidence: true });
      const preEvidenceA = await adapterA.observe(canonicalSerializeBrokerBundle(contextA.observationBundle), contextA.observationBundle.bundle_digest);
      assert.equal(preEvidenceA.ledger.row_count, 9);
      assert.equal(preEvidenceA.ledger.migration_0010_absent, true);
      assert.equal(preEvidenceA.migrator.rolcanlogin, false);
      assert.equal(preEvidenceA.migrator.password_is_null, true);
      assert.equal(preEvidenceA.authority_graph.application_authority_absent, true);

      const wrongClusterAdapter = new DisposableBrokerAdapter(providerB, contextA);
      await assert.rejects(
        () => wrongClusterAdapter.observe(canonicalSerializeBrokerBundle(contextA.observationBundle), contextA.observationBundle.bundle_digest),
        /BROKER_(?:SESSION_IDENTITY_REJECTED|TARGET_MISMATCH)/u,
      );

      const wrongProviderBundle = compileBrokerObservationBundle({
        ...contextA.compilerInput,
        target_binding: { ...contextA.compilerInput.target_binding, expected_provider_role_oid: String(Number(contextA.compilerInput.target_binding.expected_provider_role_oid) + 1) },
      });
      await assert.rejects(
        () => new DisposableBrokerAdapter(providerA, { ...contextA, observationBundle: wrongProviderBundle }).observe(canonicalSerializeBrokerBundle(wrongProviderBundle), wrongProviderBundle.bundle_digest),
        /BROKER_SESSION_IDENTITY_REJECTED/u,
      );

      const preAssumed = new DisposableBrokerAdapter(providerA, contextA, { preAssumeMigrator: true });
      await assert.rejects(
        () => preAssumed.observe(canonicalSerializeBrokerBundle(contextA.observationBundle), contextA.observationBundle.bundle_digest),
        /BROKER_SESSION_IDENTITY_REJECTED/u,
      );
      assert.deepEqual(preAssumed.observationDispatches, ["provider_target_identity"]);

      await providerA.query(`grant "platform_migrator" to "platform_app" with admin false, inherit false, set false`);
      try {
        await assert.rejects(
          () => adapterA.observe(canonicalSerializeBrokerBundle(contextA.observationBundle), contextA.observationBundle.bundle_digest),
          /BROKER_AUTHORITY_GRAPH_REJECTED/u,
        );
      } finally {
        await providerA.query(`revoke "platform_migrator" from "platform_app"`);
      }

      await providerA.query(`create role "run598_unknown_bridge" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
      await providerA.query(`grant "platform_migrator" to "run598_unknown_bridge" with admin false, inherit false, set true`);
      await providerA.query(`grant "run598_unknown_bridge" to "platform_app" with admin true, inherit false, set false`);
      try {
        await assert.rejects(
          () => adapterA.observe(canonicalSerializeBrokerBundle(contextA.observationBundle), contextA.observationBundle.bundle_digest),
          /BROKER_AUTHORITY_GRAPH_REJECTED/u,
        );
      } finally {
        await providerA.query(`revoke "run598_unknown_bridge" from "platform_app"`);
        await providerA.query(`revoke "platform_migrator" from "run598_unknown_bridge"`);
        await providerA.query(`drop role "run598_unknown_bridge"`);
      }

      const migrationSql = await readFile(join(migrationsFolder, "0010_admin_operator_viewer_role_collapse.sql"), "utf8");
      assert.equal(createHash("sha256").update(migrationSql).digest("hex"), migrationSha256);
      const artifactsA = brokerArtifacts(contextA.observationBundle, preEvidenceA, migrationSql);

      const attemptsA = new SingleUseAttemptStore();
      const successReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextA.observationBundle, prestate: artifactsA.prestate, plan: artifactsA.plan, migrationSql, broker: adapterA, attemptStore: attemptsA, restoreCapabilityProvider: restoreCapabilityProviderFor(artifactsA.plan) });
      if (successReceipt.outcome !== "PASS") {
        const diagnosticCode = adapterA.lastFailure?.code;
        if (typeof diagnosticCode === "string" && /^BROKER_[A-Z0-9_]+$/u.test(diagnosticCode)) console.error(diagnosticCode);
        else console.error("UNEXPECTED_FAILURE");
        assert.equal(packFailureDiagnostic(adapterA.lastFailure), -1, "source drift assertion failed: code");
      }
      assert.equal(successReceipt.outcome, "PASS");
      assert.equal(successReceipt.attempts_used, 1);
      assert.equal(successReceipt.commit_state, "COMMITTED");
      assert.equal(successReceipt.cleanup_state, "DISCARDED");
      assert.equal(successReceipt.recovery_state, "AVAILABLE");
      assert.equal(successReceipt.final_observation_state, "PASS");
      assert.equal(adapterA.dispatchCount, 1);
      assert.equal(adapterA.cleanupProofs, 1);
      assert.deepEqual(adapterA.dispatchedOrdinals, adapterA.dispatchedOrdinals.map((_, index) => index));
      assert.equal(adapterA.dispatchedStatementDigests.every((digest, index) => digest === adapterA.lastMutationBundle.statements[index].sha256), true);
      assert.equal(adapterA.backendPid, adapterA.protectedEvidence[0]?.pid);
      assert.equal(adapterA.protectedEvidence.length, 2);
      assert.equal(adapterA.protectedEvidence[0].label, "RESTORED_PROVIDER");
      assert.equal(adapterA.protectedEvidence[1].label, "PROVIDER_FINAL");
      assert.equal(adapterA.protectedEvidence[0].pid, adapterA.protectedEvidence[1].pid);
      assert.equal(adapterA.protectedEvidence[0].xact_start, adapterA.protectedEvidence[1].xact_start);
      assert.ok(adapterA.protectedEvidence[0].advisory_lock_count >= 1);
      assert.ok(adapterA.protectedEvidence[0].ledger_lock_count >= 1);
      assert.ok(adapterA.protectedEvidence[1].advisory_lock_count >= 1);
      assert.ok(adapterA.protectedEvidence[1].ledger_lock_count >= 1);
      await assert.rejects(() => attemptsA.reserveOnce(attemptsA.lastRequest), /ATTEMPT_ALREADY_CONSUMED/u);
      const finalLedgerA = await readLedger(providerA);
      assert.deepEqual(finalLedgerA, expectedFinalLedger);
      assert.deepEqual(await roleLabels(providerA), ["admin", "operator", "viewer"]);
      await assertDormantMigrator(providerA);

      const baselineB = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "cluster-B initial baseline");
      const artifactsB = baselineB.artifacts;
      const lockStatementB = artifactsB.bundle.statements.find((entry) => entry.id === "target_advisory_lock");
      assert.ok(lockStatementB);
      await runUncontendedAdvisoryLockProof(providerB, contextB.observationBundle, lockStatementB);
      await runAdvisoryLockContentionProof(providerB, contextB.observationBundle, lockStatementB);
      await runAdvisoryLockFailureProof(providerB, contextB.observationBundle, lockStatementB);

      const rejectedLockBaseline = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "rejected advisory lock: before");
      const rejectedLockAdapter = new DisposableBrokerAdapter(providerB, contextB, {
        resultOverride: (statement, rows) => statement.id === "target_advisory_lock" ? [{ lock_acquired: false }] : rows,
      });
      const rejectedLockReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: rejectedLockBaseline.artifacts.prestate, plan: rejectedLockBaseline.artifacts.plan, migrationSql, broker: rejectedLockAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(rejectedLockBaseline.artifacts.plan) });
      assert.equal(rejectedLockReceipt.outcome, "FAIL");
      assert.equal(rejectedLockReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(rejectedLockReceipt.attempts_used, 1);
      assert.deepEqual(rejectedLockAdapter.dispatchedOrdinals, [lockStatementB.ordinal]);
      assert.deepEqual(rejectedLockAdapter.roleAssumptionStatements, []);
      assert.deepEqual(rejectedLockAdapter.migrationStatements, []);
      assert.deepEqual(await readLedger(providerB), expectedFirstNineLedger);

      const deadlockBaseline = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "deadlock: before");
      const deadlockAdapter = new DisposableBrokerAdapter(providerB, contextB, {
        failureInjection: { ordinal: lockStatementB.ordinal, boundary: "AFTER", code: "40P01", message: "deadlock detected" },
      });
      const deadlockReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: deadlockBaseline.artifacts.prestate, plan: deadlockBaseline.artifacts.plan, migrationSql, broker: deadlockAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(deadlockBaseline.artifacts.plan) });
      assert.equal(deadlockReceipt.outcome, "FAIL");
      assert.equal(deadlockReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(deadlockReceipt.attempts_used, 1);
      assert.deepEqual(deadlockAdapter.dispatchedOrdinals, [lockStatementB.ordinal]);
      assert.deepEqual(deadlockAdapter.roleAssumptionStatements, []);
      assert.deepEqual(deadlockAdapter.migrationStatements, []);
      assert.deepEqual(await readLedger(providerB), expectedFirstNineLedger);

      const rollbackBaseline = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "rollback before ledger insert: before");
      const injectedOrdinal = rollbackBaseline.artifacts.bundle.statements.find((entry) => entry.id === "migration_0010_05")?.ordinal;
      assert.ok(Number.isInteger(injectedOrdinal));
      const rollbackAdapter = new DisposableBrokerAdapter(providerB, contextB, { failureInjection: { ordinal: injectedOrdinal, boundary: "AFTER" } });
      const rollbackReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: rollbackBaseline.artifacts.prestate, plan: rollbackBaseline.artifacts.plan, migrationSql, broker: rollbackAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(rollbackBaseline.artifacts.plan) });
      assert.equal(rollbackReceipt.outcome, "FAIL");
      assert.equal(rollbackReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(rollbackReceipt.rollback_state, "VERIFIED");
      assert.equal(rollbackReceipt.recovery_state, "AVAILABLE");
      assert.equal(rollbackReceipt.final_observation_state, "PASS");
      assert.equal(rollbackReceipt.attempts_used, 1);
      assert.equal(rollbackAdapter.dispatchCount, 1);
      assert.equal(rollbackAdapter.cleanupProofs, 1);
      assert.deepEqual(await readLedger(providerB), expectedFirstNineLedger);
      assert.deepEqual(await readLedgerSequence(providerB), expectedBaselineSequence);
      assert.deepEqual(await roleLabels(providerB), expectedPrewriteRoleLabels);
      await assertDormantMigrator(providerB);
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "rollback before ledger insert: after");

      const driftContext = await compileContext(providerB, "drift");
      const driftBaseline = await assertCompleteClusterBaseline(providerB, driftContext, migrationSql, "canonical posture drift: before");
      const driftAdapter = new DisposableBrokerAdapter(providerB, driftContext, { beforeDispatch: async () => providerB.query(`grant create on schema public to public`) });
      try {
        const driftReceipt = await executeBrokeredMigrationPlan({ observationBundle: driftContext.observationBundle, prestate: driftBaseline.artifacts.prestate, plan: driftBaseline.artifacts.plan, migrationSql, broker: driftAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(driftBaseline.artifacts.plan) });
        assert.equal(driftReceipt.outcome, "FAIL");
        assert.equal(driftReceipt.commit_state, "NOT_COMMITTED");
        assert.equal(driftReceipt.attempts_used, 1);
        assert.deepEqual(await readLedger(providerB), expectedFirstNineLedger);
      } finally {
        await providerB.query(`revoke create on schema public from public`);
      }
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "canonical posture drift: after");

      const lockedDirectContext = await compileContext(providerB, "locked-direct");
      const lockedDirectBaseline = await assertCompleteClusterBaseline(providerB, lockedDirectContext, migrationSql, "direct authority edge: before");
      const lockedDirectAdapter = new DisposableBrokerAdapter(providerB, lockedDirectContext, {
        beforeDispatch: async () => providerB.query(`grant "platform_migrator" to "platform_app" with admin false, inherit false, set false`),
      });
      try {
        const lockedDirectReceipt = await executeBrokeredMigrationPlan({ observationBundle: lockedDirectContext.observationBundle, prestate: lockedDirectBaseline.artifacts.prestate, plan: lockedDirectBaseline.artifacts.plan, migrationSql, broker: lockedDirectAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(lockedDirectBaseline.artifacts.plan) });
        assert.equal(lockedDirectReceipt.outcome, "FAIL");
        assert.equal(lockedDirectReceipt.commit_state, "NOT_COMMITTED");
        assert.deepEqual(lockedDirectAdapter.roleAssumptionStatements, []);
        assert.deepEqual(lockedDirectAdapter.migrationStatements, []);
      } finally {
        await providerB.query(`revoke "platform_migrator" from "platform_app"`);
      }
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "direct authority edge: after");

      const lockedUnknownContext = await compileContext(providerB, "locked-unknown");
      const lockedUnknownBaseline = await assertCompleteClusterBaseline(providerB, lockedUnknownContext, migrationSql, "unknown authority bridge: before");
      const lockedUnknownAdapter = new DisposableBrokerAdapter(providerB, lockedUnknownContext, {
        beforeDispatch: async () => {
          await providerB.query(`create role "run610_unknown_bridge" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
          await providerB.query(`grant "platform_migrator" to "run610_unknown_bridge" with admin false, inherit false, set true`);
          await providerB.query(`grant "run610_unknown_bridge" to "platform_app" with admin true, inherit false, set false`);
        },
      });
      try {
        const lockedUnknownReceipt = await executeBrokeredMigrationPlan({ observationBundle: lockedUnknownContext.observationBundle, prestate: lockedUnknownBaseline.artifacts.prestate, plan: lockedUnknownBaseline.artifacts.plan, migrationSql, broker: lockedUnknownAdapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(lockedUnknownBaseline.artifacts.plan) });
        assert.equal(lockedUnknownReceipt.outcome, "FAIL");
        assert.equal(lockedUnknownReceipt.commit_state, "NOT_COMMITTED");
        assert.deepEqual(lockedUnknownAdapter.roleAssumptionStatements, []);
        assert.deepEqual(lockedUnknownAdapter.migrationStatements, []);
      } finally {
        await providerB.query(`revoke "run610_unknown_bridge" from "platform_app"`);
        await providerB.query(`revoke "platform_migrator" from "run610_unknown_bridge"`);
        await providerB.query(`drop role "run610_unknown_bridge"`);
      }
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "unknown authority bridge: after");

      const statementByIdB = (id) => {
        const statement = artifactsB.bundle.statements.find((entry) => entry.id === id);
        assert.ok(statement);
        return statement;
      };
      assert.equal(statementByIdB("provider_final_target_identity").ordinal, 32);
      assert.equal(statementByIdB("provider_final_migrator_dormancy").ordinal, 33);
      const runExpectedRollbackB = async (name, options) => {
        const baseline = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, `${name}: before`);
        const adapter = new DisposableBrokerAdapter(providerB, contextB, options);
        const receipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: baseline.artifacts.prestate, plan: baseline.artifacts.plan, migrationSql, broker: adapter, attemptStore: new SingleUseAttemptStore(), restoreCapabilityProvider: restoreCapabilityProviderFor(baseline.artifacts.plan) });
        assert.equal(receipt.outcome, "FAIL");
        assert.equal(receipt.commit_state, "NOT_COMMITTED");
        assert.equal(receipt.rollback_state, "VERIFIED");
        assert.equal(receipt.final_observation_state, "PASS");
        assert.equal(receipt.attempts_used, 1);
        assert.equal(adapter.dispatchCount, 1);
        assert.equal(adapter.cleanupProofs, 1);
        assert.deepEqual(normalizeLedgerRows(adapter.migratorFinalLedgerRows), expectedFinalLedger);
        assert.deepEqual(await readLedger(providerB), expectedFirstNineLedger);
        assert.deepEqual(await readLedgerSequence(providerB), expectedContaminatedSequence);
        await assertDormantMigrator(providerB);
        await restoreDisposableLedgerSequence(providerB);
        await assertCompleteClusterBaseline(providerB, contextB, migrationSql, `${name}: after restoration`);
        return { receipt, adapter };
      };
      const migratorFailure = await runExpectedRollbackB("migrator final failure", { failureInjection: { ordinal: statementByIdB("migrator_final_ledger_assertion").ordinal, boundary: "AFTER" } });
      const migratorFailureAdapter = migratorFailure.adapter;
      assert.equal(migratorFailureAdapter.dispatchedOrdinals.some((ordinal) => ordinal >= statementByIdB("provider_final_target_identity").ordinal), false);

      const restorationFailure = await runExpectedRollbackB("restoration failure", { failureInjection: { ordinal: statementByIdB("restore_provider_role").ordinal, boundary: "AFTER" } });
      const restorationFailureAdapter = restorationFailure.adapter;
      assert.equal(restorationFailureAdapter.dispatchedOrdinals.some((ordinal) => ordinal >= statementByIdB("provider_final_target_identity").ordinal), false);

      const postRestoreFailure = await runExpectedRollbackB("post-restoration failure", { failureInjection: { ordinal: statementByIdB("restored_provider_identity_assertion").ordinal, boundary: "AFTER" } });
      const postRestoreFailureAdapter = postRestoreFailure.adapter;
      assert.equal(postRestoreFailureAdapter.dispatchedOrdinals.some((ordinal) => ordinal >= statementByIdB("provider_final_target_identity").ordinal), false);

      const wrongRestoredIdentity = await runExpectedRollbackB("wrong restored provider identity", {
        resultOverride: (statement, rows) => statement.id === "restored_provider_identity_assertion" ? [{ ...rows[0], current_user: "platform_migrator" }] : rows,
      });
      const wrongRestoredIdentityAdapter = wrongRestoredIdentity.adapter;
      assert.equal(wrongRestoredIdentityAdapter.dispatchedOrdinals.includes(statementByIdB("provider_final_target_identity").ordinal), false);

      const wrongRestoredOid = await runExpectedRollbackB("wrong restored provider OID", {
        resultOverride: (statement, rows) => statement.id === "restored_provider_identity_assertion" ? [{ ...rows[0], current_role_oid: "999" }] : rows,
      });
      const wrongRestoredOidAdapter = wrongRestoredOid.adapter;
      assert.equal(wrongRestoredOidAdapter.dispatchedOrdinals.includes(statementByIdB("provider_final_target_identity").ordinal), false);

      const providerIdentityFailure = await runExpectedRollbackB("provider final target identity failure", {
        resultOverride: (statement, rows) => statement.id === "provider_final_target_identity" ? [{ ...rows[0], session_role_oid: "999" }] : rows,
      });
      const providerIdentityFailureAdapter = providerIdentityFailure.adapter;
      assert.equal(providerIdentityFailureAdapter.dispatchedOrdinals.includes(statementByIdB("provider_final_target_identity").ordinal), true);

      const providerFinalFailure = await runExpectedRollbackB("provider final migrator dormancy failure", {
        resultOverride: (statement, rows) => statement.id === "provider_final_migrator_dormancy" ? [{ ...rows[0], password_is_null: false }] : rows,
      });
      const providerFinalFailureAdapter = providerFinalFailure.adapter;
      assert.equal(providerFinalFailureAdapter.dispatchedOrdinals.includes(statementByIdB("provider_final_migrator_dormancy").ordinal), true);

      await proveLedgerGapRejection(providerB, contextB);
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "ledger-gap rollback restoration");

      const indeterminateBaseline = await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "indeterminate dispatch: before");
      const indeterminateStore = new SingleUseAttemptStore();
      let indeterminateDispatches = 0;
      const indeterminateAdapter = new DisposableBrokerAdapter(providerB, contextB);
      const indeterminateReceipt = await executeBrokeredMigrationPlan({
        observationBundle: contextB.observationBundle,
        prestate: indeterminateBaseline.artifacts.prestate,
        plan: indeterminateBaseline.artifacts.plan,
        migrationSql,
        broker: {
          observe: (...args) => indeterminateAdapter.observe(...args),
          async dispatchMutation() { indeterminateDispatches += 1; throw new Error("indeterminate dispatch"); },
        },
        attemptStore: indeterminateStore,
        restoreCapabilityProvider: restoreCapabilityProviderFor(indeterminateBaseline.artifacts.plan),
      });
      assert.equal(indeterminateReceipt.dispatch_state, "INDETERMINATE");
      assert.equal(indeterminateReceipt.attempts_used, 1);
      assert.equal(indeterminateReceipt.recovery_state, "INDETERMINATE");
      assert.equal(indeterminateDispatches, 1);
      await assertCompleteClusterBaseline(providerB, contextB, migrationSql, "indeterminate dispatch: after");
    } finally {
      await Promise.all([appA.end(), appB.end(), providerA.end(), providerB.end()]);
    }
  });
}

class SingleUseAttemptStore {
  consumed = false;
  lastRequest = null;

  async reserveOnce(input) {
    if (this.consumed) throw new Error("ATTEMPT_ALREADY_CONSUMED");
    this.consumed = true;
    this.lastRequest = { ...input };
    const payload = {
      version: BROKER_ATTEMPT_RESERVATION_VERSION,
      state: "RESERVED_CONSUMED",
      ...input,
      reservation_id: `fixture-${createHash("sha256").update(canonicalSerializeBrokerBundle(input)).digest("hex").slice(0, 24)}`,
    };
    return {
      version: BROKER_ATTEMPT_RESERVATION_OUTCOME_VERSION,
      state: "RESERVED_CONSUMED",
      reservation: {
        ...payload,
        reservation_digest: computeBrokerBundleDigest(BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR, payload),
      },
    };
  }
}

class DisposableBrokerAdapter {
  dispatchCount = 0;
  observationDispatches = [];
  cleanupProofs = 0;
  dispatchedOrdinals = [];
  dispatchedStatementDigests = [];
  roleAssumptionStatements = [];
  migrationStatements = [];
  lastMutationBundle = null;
  lastPreEvidence = null;
  lockedPreEvidence = null;
  providerFinalEvidence = null;
  migratorFinalLedgerRows = null;
  protectedEvidence = [];
  backendPid = null;
  beforeDispatchUsed = false;
  lastFailure = null;

  constructor(pool, context, options = {}) {
    this.pool = pool;
    this.context = context;
    this.options = options;
  }

  async captureProtectedEvidence(client, label) {
    const activity = await this.pool.query("select pid, xact_start::text as xact_start from pg_catalog.pg_stat_activity where pid = $1", [client.processID]);
    const locks = await this.pool.query("select count(*) filter (where locktype = 'advisory' and granted) as advisory_lock_count, count(*) filter (where locktype = 'relation' and relation = 'drizzle.__drizzle_migrations'::regclass and mode = 'AccessExclusiveLock' and granted) as ledger_lock_count from pg_catalog.pg_locks where pid = $1", [client.processID]);
    assert.equal(activity.rows.length, 1);
    assert.equal(locks.rows.length, 1);
    this.protectedEvidence.push({
      label,
      pid: Number(activity.rows[0].pid),
      xact_start: activity.rows[0].xact_start,
      advisory_lock_count: Number(locks.rows[0].advisory_lock_count),
      ledger_lock_count: Number(locks.rows[0].ledger_lock_count),
    });
  }

  async observe(serialized, digest) {
    const bundle = strictParsedBundle(serialized, digest, this.context.observationBundle, BROKER_OBSERVATION_BUNDLE_DOMAIN_SEPARATOR);
    const client = await this.pool.connect();
    try {
      await client.query("begin isolation level repeatable read read only");
      if (this.options.preAssumeMigrator) await client.query("set local role platform_migrator");
      const resultMap = {};
      for (const statement of bundle.statements) {
        this.observationDispatches.push(statement.id);
        const rows = (await client.query(statement.sql)).rows;
        resultMap[statement.id] = rows;
        if (statement.id === "provider_target_identity") validateBrokerStatementResult(bundle, statement, rows);
      }
      const ledgerCount = resultMap.migration_ledger.length;
      const phase = ledgerCount === 9 ? "PREWRITE" : ledgerCount === 10 ? "FINAL" : "PREWRITE";
      for (const statement of bundle.statements) validateBrokerStatementResult(bundle, statement, resultMap[statement.id], phase, statement.id === "canonical_posture");
      const evidence = deriveBrokerObservationEvidence(bundle, resultMap, phase);
      await client.query("commit");
      if (phase === "PREWRITE") this.lastPreEvidence = evidence;
      return evidence;
    } catch (error) {
      await client.query("rollback").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async dispatchMutation(serialized, digest, reservation) {
    this.dispatchCount += 1;
    if (!this.lastPreEvidence) throw new Error("BROKER_OBSERVATION_REQUIRED");
    const parsed = strictCanonicalJson(serialized);
    const expected = compileBrokerMutationBundle({ observation_bundle: this.context.observationBundle, observation_evidence: this.lastPreEvidence, prestate_digest: parsed.prestate_digest, plan_digest: parsed.plan_digest, migration_sql: this.context.migrationSql });
    const bundle = strictParsedBundle(serialized, digest, expected, BROKER_MUTATION_BUNDLE_DOMAIN_SEPARATOR);
    normalizeBrokerAttemptReservation(reservation, bundle);
    this.lastMutationBundle = bundle;
    if (!this.beforeDispatchUsed && this.options.beforeDispatch) {
      this.beforeDispatchUsed = true;
      await this.options.beforeDispatch();
    }
    const client = await this.pool.connect();
    const lockedResultMap = {};
    let committed = false;
    let rolledBack = false;
    let currentStatement = null;
    let failureStage = 0;
    let restoredProvider = false;
    const providerFinalResultMap = {};
    const migratorFinalIds = [];
    const transportLoss = (boundary) => this.options.transportLoss?.boundary === boundary;
    const transportError = (boundary) => Object.assign(new Error(`transport lost at ${boundary}`), { transportLoss: true, boundary });
    try {
      await client.query("begin isolation level serializable read write");
      this.backendPid = client.processID;
      for (const statement of bundle.statements.filter((entry) => entry.phase !== "CLEANUP")) {
        currentStatement = statement;
        this.dispatchedOrdinals.push(statement.ordinal);
        this.dispatchedStatementDigests.push(statement.sha256);
        failureStage = 1;
        if (sameInjection(this.options.failureInjection, statement.ordinal, "BEFORE")) throw injectedFailure(this.options.failureInjection);
        failureStage = 2;
        const result = await client.query(statement.sql);
        const rows = this.options.resultOverride?.(statement, result.rows) ?? result.rows;
        if (statement.phase === "ASSUME_ROLE") this.roleAssumptionStatements.push(statement.id);
        if (statement.phase === "MIGRATION") this.migrationStatements.push(statement.id);
        const phase = statement.phase === "MIGRATOR_VERIFY" || statement.phase === "RESTORE_PROVIDER" || statement.phase === "PROVIDER_VERIFY" ? "FINAL" : "PREWRITE";
        failureStage = 3;
        validateBrokerStatementResult(this.context.observationBundle, statement, rows, phase, statement.id === "locked_canonical_posture");
        if (statement.id.startsWith("locked_") && statement.id !== "locked_binding_assertion") {
          lockedResultMap[statement.id] = rows;
        }
        if (statement.id === "locked_role_data_invariants") {
          failureStage = 4;
          this.lockedPreEvidence = validateLockedBrokerObservationResultSet(this.context.observationBundle, bundle, lockedResultMap);
        }
        if (statement.id === "migrator_final_ledger_assertion") this.migratorFinalLedgerRows = rows.map((row) => ({ ...row }));
        if (statement.phase === "MIGRATOR_VERIFY") migratorFinalIds.push(statement.id);
        if (statement.id === "restored_provider_identity_assertion") restoredProvider = true;
        if (statement.phase === "PROVIDER_VERIFY") {
          if (!restoredProvider) throw new Error("BROKER_PROVIDER_FINAL_BEFORE_RESTORATION");
          providerFinalResultMap[statement.id] = rows;
        }
        failureStage = 5;
        if (sameInjection(this.options.failureInjection, statement.ordinal, "AFTER")) throw injectedFailure(this.options.failureInjection);
        if (statement.id === "restored_provider_identity_assertion" && transportLoss("RESTORE_PROVIDER")) throw transportError("RESTORE_PROVIDER");
        if (statement.phase === "PROVIDER_VERIFY" && transportLoss("PROVIDER_VERIFY")) throw transportError("PROVIDER_VERIFY");
        if (this.options.captureProtectedEvidence && statement.id === "restored_provider_identity_assertion") await this.captureProtectedEvidence(client, "RESTORED_PROVIDER");
      }
      assert.deepEqual(migratorFinalIds, ["migrator_final_ledger_assertion", "migrator_final_role_data_assertion", "migrator_final_identity_assertion"]);
      failureStage = 4;
      this.providerFinalEvidence = validateBrokerProviderFinalResultSet(this.context.observationBundle, bundle, providerFinalResultMap);
      if (this.options.captureProtectedEvidence) await this.captureProtectedEvidence(client, "PROVIDER_FINAL");
      failureStage = 6;
      if (transportLoss("COMMIT")) {
        await client.query("commit");
        throw transportError("COMMIT");
      }
      await client.query("commit");
      committed = true;
    } catch (error) {
      this.lastFailure = { ordinal: currentStatement?.ordinal ?? -1, stage: failureStage, code: typeof error?.code === "string" ? error.code : error?.message ?? "NONE" };
      if (error?.transportLoss) {
        client.release(true);
        throw error;
      }
      await client.query("rollback");
      rolledBack = true;
    }
    let cleanupState = "FAILED";
    try {
      const cleanup = bundle.statements.find((entry) => entry.phase === "CLEANUP");
      assert.ok(cleanup);
      if (transportLoss("CLEANUP")) {
        await client.query(cleanup.sql);
        throw transportError("CLEANUP");
      }
      const result = await client.query(cleanup.sql);
      validateBrokerStatementResult(this.context.observationBundle, cleanup, result.rows, "FINAL");
      cleanupState = "DISCARDED";
      this.cleanupProofs += 1;
    } catch (error) {
      cleanupState = error?.transportLoss ? "INDETERMINATE" : "FAILED";
      this.lastFailure ??= { ordinal: 39, stage: 7, code: typeof error?.code === "string" ? error.code : error?.message ?? "NONE" };
    } finally {
      client.release(true);
    }
    assert.equal(committed || rolledBack, true);
    return brokerResult(bundle, reservation, committed ? "COMMITTED" : "NOT_COMMITTED", cleanupState);
  }
}

function sameInjection(injection, ordinal, boundary) {
  return injection?.ordinal === ordinal && injection?.boundary === boundary;
}

function injectedFailure(injection) {
  const error = new Error(injection?.message ?? "INJECTED_BUNDLE_FAILURE");
  if (injection?.code) error.code = injection.code;
  return error;
}

const DIAGNOSTIC_CODE_BASE = 128 ** 6;

function packFailureDiagnostic(failure) {
  if (!failure) return -2;
  const code = String(failure.code ?? "NONE").slice(0, 6);
  let packedCode = 0;
  for (let index = 0; index < 6; index += 1) packedCode = packedCode * 128 + (index < code.length ? code.charCodeAt(index) : 0);
  return (((Number(failure.ordinal) + 1) * 8) + Number(failure.stage)) * DIAGNOSTIC_CODE_BASE + packedCode;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForAdvisoryLockWait(pool, waiterPid, holderPid, timeoutMilliseconds = 4_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    const result = await pool.query(`
      select waiter.pid as waiter_pid, holder.pid as holder_pid, activity.wait_event_type, activity.wait_event
        from pg_catalog.pg_locks waiter
        join pg_catalog.pg_locks holder
          on holder.locktype = 'advisory'
         and holder.pid = $2
         and holder.granted
         and holder.database = waiter.database
         and holder.classid = waiter.classid
         and holder.objid = waiter.objid
         and holder.objsubid = waiter.objsubid
        join pg_catalog.pg_stat_activity activity on activity.pid = waiter.pid
       where waiter.locktype = 'advisory'
         and waiter.pid = $1
         and not waiter.granted`, [waiterPid, holderPid]);
    if (result.rows.length === 1) return result.rows[0];
    await delay(25);
  }
  throw new Error("ADVISORY_LOCK_WAIT_EVIDENCE_TIMEOUT");
}

async function queryCompiledTargetLock(client, observationBundle, lockStatement) {
  const result = await client.query(lockStatement.sql);
  validateBrokerStatementResult(observationBundle, lockStatement, result.rows);
  return result.rows;
}

async function runUncontendedAdvisoryLockProof(pool, observationBundle, lockStatement) {
  const client = await pool.connect();
  try {
    await client.query("begin isolation level serializable read write");
    assert.deepEqual(await queryCompiledTargetLock(client, observationBundle, lockStatement), [{ lock_acquired: true }]);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function runAdvisoryLockContentionProof(pool, observationBundle, lockStatement) {
  for (const releaseStatement of ["commit", "rollback"]) {
    const holder = await pool.connect();
    const waiter = await pool.connect();
    let holderReleased = false;
    let waiterFinished = false;
    let waiterPromise;
    try {
      await holder.query("begin isolation level serializable read write");
      assert.deepEqual(await queryCompiledTargetLock(holder, observationBundle, lockStatement), [{ lock_acquired: true }]);

      let waiterStartedResolve;
      const waiterStarted = new Promise((resolve) => { waiterStartedResolve = resolve; });
      const waiterDispatchTrace = [];
      waiterPromise = (async () => {
        await waiter.query("begin isolation level serializable read write");
        waiterStartedResolve();
        waiterDispatchTrace.push(lockStatement.id);
        try {
          return await queryCompiledTargetLock(waiter, observationBundle, lockStatement);
        } finally {
          waiterFinished = true;
        }
      })();
      await waiterStarted;

      const waitEvidence = await waitForAdvisoryLockWait(pool, waiter.processID, holder.processID);
      assert.equal(waitEvidence.waiter_pid, waiter.processID);
      assert.equal(waitEvidence.holder_pid, holder.processID);
      assert.equal(waitEvidence.wait_event_type, "Lock");
      assert.equal(waitEvidence.wait_event, "advisory");
      assert.equal(waiterFinished, false);
      assert.deepEqual(waiterDispatchTrace, ["target_advisory_lock"]);

      await holder.query(releaseStatement);
      holderReleased = true;
      assert.deepEqual(await waiterPromise, [{ lock_acquired: true }]);
      assert.deepEqual(waiterDispatchTrace, ["target_advisory_lock"]);
      await waiter.query("commit");
    } finally {
      if (waiterPromise) await waiterPromise.catch(() => {});
      if (!holderReleased) await holder.query("rollback").catch(() => {});
      await waiter.query("rollback").catch(() => {});
      holder.release();
      waiter.release();
    }
  }
}

async function runAdvisoryLockFailureProof(pool, observationBundle, lockStatement) {
  const runBlockedFailure = async (mode) => {
    const holder = await pool.connect();
    const waiter = await pool.connect();
    let holderReleased = false;
    try {
      await holder.query("begin isolation level serializable read write");
      assert.deepEqual(await queryCompiledTargetLock(holder, observationBundle, lockStatement), [{ lock_acquired: true }]);
      await waiter.query("begin isolation level serializable read write");
      if (mode === "timeout") await waiter.query("set local lock_timeout = '200ms'");
      const downstreamDispatches = [];
      const waiterQuery = (async () => {
        const trace = [lockStatement.id];
        const rows = await queryCompiledTargetLock(waiter, observationBundle, lockStatement);
        return { rows, trace };
      })();
      await waitForAdvisoryLockWait(pool, waiter.processID, holder.processID);
      if (mode === "cancel") {
        const cancelResult = await pool.query("select pg_catalog.pg_cancel_backend($1) as cancelled", [waiter.processID]);
        assert.deepEqual(cancelResult.rows, [{ cancelled: true }]);
      }
      await assert.rejects(waiterQuery, (error) => mode === "timeout" ? error?.code === "55P03" : error?.code === "57014");
      assert.deepEqual(downstreamDispatches, []);
      await waiter.query("rollback");
      await holder.query("rollback");
      holderReleased = true;
    } finally {
      if (!holderReleased) await holder.query("rollback").catch(() => {});
      await waiter.query("rollback").catch(() => {});
      holder.release();
      waiter.release();
    }
  };
  await runBlockedFailure("timeout");
  await runBlockedFailure("cancel");
}

function strictCanonicalJson(serialized) {
  const parsed = JSON.parse(serialized);
  if (canonicalSerializeBrokerBundle(parsed) !== serialized) throw new Error("BROKER_CANONICALIZATION_REJECTED");
  return parsed;
}

function strictParsedBundle(serialized, digest, expected, domain) {
  const parsed = strictCanonicalJson(serialized);
  assert.equal(serialized, canonicalSerializeBrokerBundle(expected));
  assert.equal(digest, expected.bundle_digest);
  const { bundle_digest: claimed, ...payload } = parsed;
  assert.equal(claimed, computeBrokerBundleDigest(domain, payload));
  return parsed;
}

function brokerResult(bundle, reservation, commitState, cleanupState) {
  const safeResultDigest = createHash("sha256").update(canonicalSerializeBrokerBundle({ statement_digests: bundle.statements.map((entry) => entry.sha256), commit_state: commitState, cleanup_state: cleanupState })).digest("hex");
  const payload = { version: BROKER_RESULT_VERSION, mutation_bundle_digest: bundle.bundle_digest, reservation_digest: reservation.reservation_digest, dispatch_state: "DISPATCHED", commit_state: commitState, cleanup_state: cleanupState, migration_tag: "0010_admin_operator_viewer_role_collapse", migration_sql_sha256: migrationSha256, safe_result_digest: safeResultDigest };
  return { ...payload, result_digest: computeBrokerBundleDigest(BROKER_RESULT_DOMAIN_SEPARATOR, payload) };
}

function brokerArtifacts(observationBundle, evidence, migrationSql) {
  const prestate = normalizeBrokeredPrestateV2(observationBundle, evidence);
  const preliminaryPlan = createBrokeredDurablePlanV2(prestate);
  const bundle = compileBrokerMutationBundle({ observation_bundle: observationBundle, observation_evidence: evidence, prestate_digest: prestate.prestate_digest, plan_digest: preliminaryPlan.plan_digest, migration_sql: migrationSql });
  return { prestate, bundle, plan: bindDurablePlanV2ToBrokerBundle(preliminaryPlan, bundle) };
}

async function compileContext(pool, suffix) {
  const identity = await readIdentity(pool);
  const nodes = identity.roles.map((role) => ({ role_name: role.role_name, role_oid: role.role_oid, authority_class: role.role_name === "cloud_admin" ? "PROVIDER_CONTROL" : role.role_name === "platform_app" ? "APPLICATION" : role.role_name === "platform_runtime" ? "RUNTIME" : "MIGRATOR" })).sort((left, right) => Number(left.role_oid) - Number(right.role_oid));
  const target_binding = { version: BROKER_TARGET_BINDING_VERSION, project_id: `disposable-project-${suffix}`, branch_id: `disposable-branch-${suffix}`, endpoint_id: `disposable-endpoint-${suffix}`, endpoint_type: "read_write", logical_database_name: databaseName, expected_database_oid: identity.database_oid, expected_cluster_system_identifier: identity.cluster_system_identifier, expected_postgres_major: 17, expected_provider_role_name: "cloud_admin", expected_provider_role_oid: identity.roles.find((role) => role.role_name === "cloud_admin").role_oid };
  const authority_classification = { version: BROKER_AUTHORITY_CLASSIFICATION_VERSION, nodes, runtime_creator_tuple: { granted_role: "platform_runtime", member: "platform_app", grantor: "cloud_admin", admin_option: true, inherit_option: false, set_option: false } };
  const compilerInput = { run: `run-598-${suffix}`, lock: `lock-598-${suffix}`, git_sha: "1".repeat(40), git_tree: "2".repeat(40), contract_digest: "3".repeat(64), source_manifest_digest: "4".repeat(64), build_manifest_digest: "5".repeat(64), target_binding, authority_classification };
  return { compilerInput, observationBundle: compileBrokerObservationBundle(compilerInput), migrationSql: await readFile(join(migrationsFolder, "0010_admin_operator_viewer_role_collapse.sql"), "utf8") };
}

function readConnectionTarget(value) {
  const parsed = new URL(value);
  const port = Number(parsed.port);
  const database = decodeURIComponent(parsed.pathname.replace(/^\//u, ""));
  if ((parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") || parsed.hostname !== "127.0.0.1" || !Number.isInteger(port) || database !== databaseName) throw new Error("disposable fixture target rejected");
  return { host: parsed.hostname, port, database, max: 4, connectionTimeoutMillis: 4_000 };
}

function quoteIdentifier(value) {
  if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(value)) throw new Error("fixture identifier rejected");
  return `"${value}"`;
}

function normalizeLedgerRows(rows) {
  assert.ok(Array.isArray(rows));
  return rows.map((row) => ({ id: Number(row.id), hash: String(row.hash), created_at: String(row.created_at) }));
}

async function readLedgerSequence(pool) {
  const identityResult = await pool.query("select pg_catalog.pg_get_serial_sequence('drizzle.__drizzle_migrations', 'id') as sequence_identity");
  assert.equal(identityResult.rows.length, 1);
  const identity = String(identityResult.rows[0].sequence_identity);
  assert.equal(identity, expectedSequenceIdentity);
  const identityParts = identity.split(".");
  assert.equal(identityParts.length, 2);
  const quotedSequence = quoteIdentifier(identityParts[0]) + "." + quoteIdentifier(identityParts[1]);
  const stateResult = await pool.query("select last_value::text as last_value, is_called from " + quotedSequence);
  const incrementResult = await pool.query("select sequence_record.seqincrement::text as increment from pg_catalog.pg_sequence sequence_record where sequence_record.seqrelid = $1::pg_catalog.regclass", [identity]);
  assert.equal(stateResult.rows.length, 1);
  assert.equal(incrementResult.rows.length, 1);
  const lastValue = Number(stateResult.rows[0].last_value);
  const isCalled = stateResult.rows[0].is_called;
  const increment = Number(incrementResult.rows[0].increment);
  assert.ok(Number.isSafeInteger(lastValue));
  assert.equal(typeof isCalled, "boolean");
  assert.ok(Number.isSafeInteger(increment));
  assert.equal(increment, 1);
  return { identity, last_value: lastValue, is_called: isCalled, increment, next_id: isCalled ? lastValue + increment : lastValue };
}

async function assertCompleteClusterBaseline(providerPool, context, migrationSql, label) {
  assert.deepEqual(await readLedger(providerPool), expectedFirstNineLedger, label + ": exact first-nine ledger");
  assert.deepEqual(await readLedgerSequence(providerPool), expectedBaselineSequence, label + ": exact sequence baseline");
  assert.deepEqual(await roleLabels(providerPool), expectedPrewriteRoleLabels, label + ": prewrite role labels");
  await assertDormantMigrator(providerPool);
  const adapter = new DisposableBrokerAdapter(providerPool, context);
  const evidence = await adapter.observe(canonicalSerializeBrokerBundle(context.observationBundle), context.observationBundle.bundle_digest);
  const target = context.observationBundle.target_binding;
  assert.equal(evidence.provider.current_user, "cloud_admin");
  assert.equal(evidence.provider.session_user, "cloud_admin");
  assert.equal(evidence.provider.role_oid, target.expected_provider_role_oid);
  assert.equal(evidence.target.logical_database_name, target.logical_database_name);
  assert.equal(evidence.target.database_oid, target.expected_database_oid);
  assert.equal(evidence.target.cluster_system_identifier, target.expected_cluster_system_identifier);
  assert.equal(evidence.target.postgres_major, 17);
  assert.equal(evidence.target.in_recovery, false);
  assert.equal(evidence.ledger.row_count, 9);
  assert.equal(evidence.ledger.migration_0010_absent, true);
  assert.equal(evidence.authority_graph.closure_complete, true);
  assert.equal(evidence.authority_graph.application_authority_absent, true);
  assert.equal(evidence.migrator.rolcanlogin, false);
  assert.equal(evidence.migrator.password_is_null, true);
  return { evidence, artifacts: brokerArtifacts(context.observationBundle, evidence, migrationSql) };
}

async function restoreDisposableLedgerSequence(providerPool) {
  assert.deepEqual(await readLedger(providerPool), expectedFirstNineLedger);
  assert.deepEqual(await readLedgerSequence(providerPool), expectedContaminatedSequence);
  const identityResult = await providerPool.query("select current_user::text as current_user, session_user::text as session_user");
  assert.deepEqual(identityResult.rows, [{ current_user: "cloud_admin", session_user: "cloud_admin" }]);
  const restoredResult = await providerPool.query("select pg_catalog.setval(pg_catalog.pg_get_serial_sequence('drizzle.__drizzle_migrations', 'id')::pg_catalog.regclass, 9, true) as restored_value");
  assert.equal(Number(restoredResult.rows[0].restored_value), 9);
  assert.deepEqual(await readLedgerSequence(providerPool), expectedBaselineSequence);
}

async function proveLedgerGapRejection(providerPool, context) {
  const ledgerStatement = context.observationBundle.statements.find((entry) => entry.id === "migration_ledger");
  assert.ok(ledgerStatement);
  const client = await providerPool.connect();
  let transactionOpen = false;
  try {
    await client.query("begin");
    transactionOpen = true;
    await client.query("update drizzle.__drizzle_migrations set id = 10 where id = 9");
    const rows = (await client.query(ledgerStatement.sql)).rows;
    assert.deepEqual(normalizeLedgerRows(rows).map((row) => row.id), [1, 2, 3, 4, 5, 6, 7, 8, 10]);
    assert.throws(
      () => validateBrokerStatementResult(context.observationBundle, ledgerStatement, rows, "PREWRITE"),
      /BROKER_MIGRATION_IDENTITY_REJECTED/u,
    );
    await client.query("rollback");
    transactionOpen = false;
  } finally {
    if (transactionOpen) await client.query("rollback").catch(() => {});
    client.release();
  }
  assert.deepEqual(await readLedger(providerPool), expectedFirstNineLedger);
  assert.deepEqual(await readLedgerSequence(providerPool), expectedBaselineSequence);
}

async function createRoles(pool) {
  await pool.query(`revoke "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables" from "pg_monitor"`);
  await pool.query(`create role "platform_migrator" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password null`);
  await pool.query(`create role "platform_runtime" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await pool.query(`create role "platform_app" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await pool.query(`grant "platform_runtime" to "platform_app" with admin true, inherit false, set false granted by "cloud_admin"`);
}

async function convergeCanonicalFixture(providerPool, appPool) {
  const database = quoteIdentifier(databaseName);
  const migrator = quoteIdentifier("platform_migrator");
  const runtime = quoteIdentifier("platform_runtime");
  const app = quoteIdentifier("platform_app");
  await providerPool.query(`alter database ${database} owner to ${app}`);
  await providerPool.query(`revoke temporary on database ${database} from public`);
  await providerPool.query(`grant connect on database ${database} to ${migrator}`);
  await providerPool.query(`revoke create on schema public from public`);
  await providerPool.query(`grant usage, create on schema public to ${migrator}`);
  await providerPool.query(`alter schema drizzle owner to ${migrator}`);
  await providerPool.query(`revoke all on schema drizzle from public`);
  await providerPool.query(`grant usage, create on schema drizzle to ${migrator}`);
  for (const role of ["cloud_admin", "platform_app", "pg_database_owner", "platform_migrator"]) await providerPool.query(`alter default privileges for role ${quoteIdentifier(role)} revoke execute on functions from public`);
  await providerPool.query(`alter default privileges for role ${migrator} revoke all privileges on tables from public`);
  await providerPool.query(`alter default privileges for role ${migrator} revoke all privileges on sequences from public`);
  const relations = await providerPool.query(`select namespace_record.nspname as schema_name, relation_record.relname as object_name, relation_record.relkind from pg_catalog.pg_class relation_record join pg_catalog.pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace where namespace_record.nspname in ('public','drizzle') and relation_record.relkind in ('r','p','S','i','I') order by namespace_record.nspname, relation_record.relname`);
  for (const row of relations.rows) {
    const object = `${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.object_name)}`;
    await providerPool.query(row.relkind === "S" ? `alter sequence ${object} owner to ${migrator}` : row.relkind === "i" || row.relkind === "I" ? `alter index ${object} owner to ${migrator}` : `alter table ${object} owner to ${migrator}`);
  }
  const types = await providerPool.query(`select namespace_record.nspname as schema_name, type_record.typname as type_name from pg_catalog.pg_type type_record join pg_catalog.pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace where namespace_record.nspname = 'public' and type_record.typtype = 'e' and type_record.typisdefined order by type_record.typname`);
  for (const row of types.rows) await providerPool.query(`alter type ${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.type_name)} owner to ${migrator}`);
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) await providerPool.query(`grant ${record.privilege} on table ${quoteIdentifier(record.schema)}.${quoteIdentifier(record.objectName)} to ${runtime}`);
  await appPool.query("create function public.show_db_tree() returns integer language sql immutable as 'select 1'");
  await appPool.query("revoke execute on function public.show_db_tree() from public");
}

async function readIdentity(pool) {
  const target = await pool.query(`select control_state.system_identifier::text as cluster_system_identifier, database_record.oid::text as database_oid from pg_catalog.pg_control_system() control_state cross join pg_catalog.pg_database database_record where database_record.datname = current_database()`);
  const roles = await pool.query(`select rolname as role_name, oid::text as role_oid from pg_catalog.pg_roles where rolname in ('cloud_admin','platform_app','platform_runtime','platform_migrator') order by oid`);
  assert.equal(target.rows.length, 1);
  assert.equal(roles.rows.length, 4);
  return { ...target.rows[0], roles: roles.rows };
}

async function readLedger(pool) {
  const result = await pool.query(`select id, hash, created_at::text as created_at from drizzle.__drizzle_migrations order by created_at, id`);
  return result.rows.map((row) => ({ id: Number(row.id), hash: String(row.hash), created_at: String(row.created_at) }));
}

async function roleLabels(pool) {
  const result = await pool.query(`select enum_record.enumlabel from pg_catalog.pg_enum enum_record join pg_catalog.pg_type type_record on type_record.oid = enum_record.enumtypid join pg_catalog.pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace where namespace_record.nspname = 'public' and type_record.typname = 'role' order by enum_record.enumsortorder`);
  return result.rows.map((row) => row.enumlabel);
}

async function assertDormantMigrator(pool) {
  const result = await pool.query(`select role_record.rolcanlogin, auth_record.rolpassword is null as password_is_null from pg_catalog.pg_roles role_record join pg_catalog.pg_authid auth_record on auth_record.oid = role_record.oid where role_record.rolname = 'platform_migrator'`);
  assert.deepEqual(result.rows, [{ rolcanlogin: false, password_is_null: true }]);
}
