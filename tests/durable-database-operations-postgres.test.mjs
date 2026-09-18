import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";

import {
  bindDurablePlanV2ToBrokerBundle,
  createBrokeredDurablePlanV2,
  executeBrokeredMigrationPlan,
  normalizeBrokeredPrestateV2,
} from "../dist/db/durable-operations.js";
import {
  BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR,
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
      await Promise.all([applyFirstNine(providerA), applyFirstNine(providerB)]);
      await Promise.all([convergeCanonicalFixture(providerA, appA), convergeCanonicalFixture(providerB, appB)]);

      const contextA = await compileContext(providerA, "a");
      const contextB = await compileContext(providerB, "b");
      assert.notEqual(contextA.observationBundle.target_binding.expected_cluster_system_identifier, contextB.observationBundle.target_binding.expected_cluster_system_identifier);

      const adapterA = new DisposableBrokerAdapter(providerA, contextA);
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
      const successReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextA.observationBundle, prestate: artifactsA.prestate, plan: artifactsA.plan, migrationSql, broker: adapterA, attemptStore: attemptsA });
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
      assert.equal(successReceipt.final_observation_state, "PASS");
      assert.equal(adapterA.dispatchCount, 1);
      assert.equal(adapterA.cleanupProofs, 1);
      assert.deepEqual(adapterA.dispatchedOrdinals, adapterA.dispatchedOrdinals.map((_, index) => index));
      assert.equal(adapterA.dispatchedStatementDigests.every((digest, index) => digest === adapterA.lastMutationBundle.statements[index].sha256), true);
      await assert.rejects(() => attemptsA.reserveOnce(attemptsA.lastRequest), /ATTEMPT_ALREADY_CONSUMED/u);
      const finalLedgerA = await readLedger(providerA);
      assert.equal(finalLedgerA.length, 10);
      assert.equal(finalLedgerA.at(-1).hash, migrationSha256);
      assert.equal(finalLedgerA.at(-1).created_at, "1787479999088");
      assert.deepEqual(await roleLabels(providerA), ["admin", "operator", "viewer"]);
      await assertDormantMigrator(providerA);

      const preAdapterB = new DisposableBrokerAdapter(providerB, contextB);
      const preEvidenceB = await preAdapterB.observe(canonicalSerializeBrokerBundle(contextB.observationBundle), contextB.observationBundle.bundle_digest);
      const artifactsB = brokerArtifacts(contextB.observationBundle, preEvidenceB, migrationSql);
      const lockStatementB = artifactsB.bundle.statements.find((entry) => entry.id === "target_advisory_lock");
      assert.ok(lockStatementB);
      await runUncontendedAdvisoryLockProof(providerB, contextB.observationBundle, lockStatementB);
      await runAdvisoryLockContentionProof(providerB, contextB.observationBundle, lockStatementB);
      await runAdvisoryLockFailureProof(providerB, contextB.observationBundle, lockStatementB);

      const rejectedLockAdapter = new DisposableBrokerAdapter(providerB, contextB, {
        resultOverride: (statement, rows) => statement.id === "target_advisory_lock" ? [{ lock_acquired: false }] : rows,
      });
      const rejectedLockReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: artifactsB.prestate, plan: artifactsB.plan, migrationSql, broker: rejectedLockAdapter, attemptStore: new SingleUseAttemptStore() });
      assert.equal(rejectedLockReceipt.outcome, "FAIL");
      assert.equal(rejectedLockReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(rejectedLockReceipt.attempts_used, 1);
      assert.deepEqual(rejectedLockAdapter.dispatchedOrdinals, [lockStatementB.ordinal]);
      assert.deepEqual(rejectedLockAdapter.roleAssumptionStatements, []);
      assert.deepEqual(rejectedLockAdapter.migrationStatements, []);
      assert.equal((await readLedger(providerB)).length, 9);

      const deadlockAdapter = new DisposableBrokerAdapter(providerB, contextB, {
        failureInjection: { ordinal: lockStatementB.ordinal, boundary: "AFTER", code: "40P01", message: "deadlock detected" },
      });
      const deadlockReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: artifactsB.prestate, plan: artifactsB.plan, migrationSql, broker: deadlockAdapter, attemptStore: new SingleUseAttemptStore() });
      assert.equal(deadlockReceipt.outcome, "FAIL");
      assert.equal(deadlockReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(deadlockReceipt.attempts_used, 1);
      assert.deepEqual(deadlockAdapter.dispatchedOrdinals, [lockStatementB.ordinal]);
      assert.deepEqual(deadlockAdapter.roleAssumptionStatements, []);
      assert.deepEqual(deadlockAdapter.migrationStatements, []);
      assert.equal((await readLedger(providerB)).length, 9);

      const injectedOrdinal = artifactsB.bundle.statements.find((entry) => entry.id === "migration_0010_05")?.ordinal;
      assert.ok(Number.isInteger(injectedOrdinal));
      const rollbackAdapter = new DisposableBrokerAdapter(providerB, contextB, { failureInjection: { ordinal: injectedOrdinal, boundary: "AFTER" } });
      const rollbackReceipt = await executeBrokeredMigrationPlan({ observationBundle: contextB.observationBundle, prestate: artifactsB.prestate, plan: artifactsB.plan, migrationSql, broker: rollbackAdapter, attemptStore: new SingleUseAttemptStore() });
      assert.equal(rollbackReceipt.outcome, "FAIL");
      assert.equal(rollbackReceipt.commit_state, "NOT_COMMITTED");
      assert.equal(rollbackReceipt.rollback_state, "VERIFIED");
      assert.equal(rollbackReceipt.final_observation_state, "PASS");
      assert.equal(rollbackReceipt.attempts_used, 1);
      assert.equal(rollbackAdapter.dispatchCount, 1);
      assert.equal(rollbackAdapter.cleanupProofs, 1);
      assert.equal((await readLedger(providerB)).length, 9);
      assert.deepEqual(await roleLabels(providerB), ["owner", "admin", "member", "viewer"]);
      await assertDormantMigrator(providerB);

      const driftContext = await compileContext(providerB, "drift");
      const driftAdapter = new DisposableBrokerAdapter(providerB, driftContext, { beforeDispatch: async () => providerB.query(`grant create on schema public to public`) });
      const driftEvidence = await driftAdapter.observe(canonicalSerializeBrokerBundle(driftContext.observationBundle), driftContext.observationBundle.bundle_digest);
      const driftArtifacts = brokerArtifacts(driftContext.observationBundle, driftEvidence, migrationSql);
      try {
        const driftReceipt = await executeBrokeredMigrationPlan({ observationBundle: driftContext.observationBundle, prestate: driftArtifacts.prestate, plan: driftArtifacts.plan, migrationSql, broker: driftAdapter, attemptStore: new SingleUseAttemptStore() });
        assert.equal(driftReceipt.outcome, "FAIL");
        assert.equal(driftReceipt.commit_state, "NOT_COMMITTED");
        assert.equal(driftReceipt.attempts_used, 1);
        assert.equal((await readLedger(providerB)).length, 9);
      } finally {
        await providerB.query(`revoke create on schema public from public`);
      }

      const lockedDirectContext = await compileContext(providerB, "locked-direct");
      const lockedDirectAdapter = new DisposableBrokerAdapter(providerB, lockedDirectContext, {
        beforeDispatch: async () => providerB.query(`grant "platform_migrator" to "platform_app" with admin false, inherit false, set false`),
      });
      const lockedDirectEvidence = await lockedDirectAdapter.observe(canonicalSerializeBrokerBundle(lockedDirectContext.observationBundle), lockedDirectContext.observationBundle.bundle_digest);
      const lockedDirectArtifacts = brokerArtifacts(lockedDirectContext.observationBundle, lockedDirectEvidence, migrationSql);
      try {
        const lockedDirectReceipt = await executeBrokeredMigrationPlan({ observationBundle: lockedDirectContext.observationBundle, prestate: lockedDirectArtifacts.prestate, plan: lockedDirectArtifacts.plan, migrationSql, broker: lockedDirectAdapter, attemptStore: new SingleUseAttemptStore() });
        assert.equal(lockedDirectReceipt.outcome, "FAIL");
        assert.equal(lockedDirectReceipt.commit_state, "NOT_COMMITTED");
        assert.deepEqual(lockedDirectAdapter.roleAssumptionStatements, []);
        assert.deepEqual(lockedDirectAdapter.migrationStatements, []);
      } finally {
        await providerB.query(`revoke "platform_migrator" from "platform_app"`);
      }

      const lockedUnknownContext = await compileContext(providerB, "locked-unknown");
      const lockedUnknownAdapter = new DisposableBrokerAdapter(providerB, lockedUnknownContext, {
        beforeDispatch: async () => {
          await providerB.query(`create role "run610_unknown_bridge" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
          await providerB.query(`grant "platform_migrator" to "run610_unknown_bridge" with admin false, inherit false, set true`);
          await providerB.query(`grant "run610_unknown_bridge" to "platform_app" with admin true, inherit false, set false`);
        },
      });
      const lockedUnknownEvidence = await lockedUnknownAdapter.observe(canonicalSerializeBrokerBundle(lockedUnknownContext.observationBundle), lockedUnknownContext.observationBundle.bundle_digest);
      const lockedUnknownArtifacts = brokerArtifacts(lockedUnknownContext.observationBundle, lockedUnknownEvidence, migrationSql);
      try {
        const lockedUnknownReceipt = await executeBrokeredMigrationPlan({ observationBundle: lockedUnknownContext.observationBundle, prestate: lockedUnknownArtifacts.prestate, plan: lockedUnknownArtifacts.plan, migrationSql, broker: lockedUnknownAdapter, attemptStore: new SingleUseAttemptStore() });
        assert.equal(lockedUnknownReceipt.outcome, "FAIL");
        assert.equal(lockedUnknownReceipt.commit_state, "NOT_COMMITTED");
        assert.deepEqual(lockedUnknownAdapter.roleAssumptionStatements, []);
        assert.deepEqual(lockedUnknownAdapter.migrationStatements, []);
      } finally {
        await providerB.query(`revoke "run610_unknown_bridge" from "platform_app"`);
        await providerB.query(`revoke "platform_migrator" from "run610_unknown_bridge"`);
        await providerB.query(`drop role "run610_unknown_bridge"`);
      }

      const indeterminateStore = new SingleUseAttemptStore();
      let indeterminateDispatches = 0;
      const indeterminateAdapter = new DisposableBrokerAdapter(providerB, contextB);
      const indeterminateReceipt = await executeBrokeredMigrationPlan({
        observationBundle: contextB.observationBundle,
        prestate: artifactsB.prestate,
        plan: artifactsB.plan,
        migrationSql,
        broker: {
          observe: (...args) => indeterminateAdapter.observe(...args),
          async dispatchMutation() { indeterminateDispatches += 1; throw new Error("indeterminate dispatch"); },
        },
        attemptStore: indeterminateStore,
      });
      assert.equal(indeterminateReceipt.dispatch_state, "INDETERMINATE");
      assert.equal(indeterminateReceipt.attempts_used, 1);
      assert.equal(indeterminateDispatches, 1);
      assert.equal((await readLedger(providerB)).length, 9);
      await assertDormantMigrator(providerB);
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
    return { ...payload, reservation_digest: computeBrokerBundleDigest(BROKER_ATTEMPT_RESERVATION_DOMAIN_SEPARATOR, payload) };
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
  beforeDispatchUsed = false;
  lastFailure = null;

  constructor(pool, context, options = {}) {
    this.pool = pool;
    this.context = context;
    this.options = options;
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
    try {
      await client.query("begin isolation level serializable read write");
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
        const phase = statement.id.startsWith("final_") ? "FINAL" : "PREWRITE";
        failureStage = 3;
        validateBrokerStatementResult(this.context.observationBundle, statement, rows, phase, statement.id === "locked_canonical_posture");
        if (statement.id.startsWith("locked_") && statement.id !== "locked_binding_assertion") {
          lockedResultMap[statement.id] = rows;
        }
        if (statement.id === "locked_role_data_invariants") {
          failureStage = 4;
          this.lockedPreEvidence = validateLockedBrokerObservationResultSet(this.context.observationBundle, bundle, lockedResultMap);
        }
        failureStage = 5;
        if (sameInjection(this.options.failureInjection, statement.ordinal, "AFTER")) throw injectedFailure(this.options.failureInjection);
      }
      failureStage = 6;
      await client.query("commit");
      committed = true;
    } catch (error) {
      this.lastFailure = { ordinal: currentStatement?.ordinal ?? -1, stage: failureStage, code: typeof error?.code === "string" ? error.code : error?.message ?? "NONE" };
      await client.query("rollback");
      rolledBack = true;
    }
    let cleanupState = "FAILED";
    try {
      const cleanup = bundle.statements.find((entry) => entry.phase === "CLEANUP");
      assert.ok(cleanup);
      const result = await client.query(cleanup.sql);
      validateBrokerStatementResult(this.context.observationBundle, cleanup, result.rows, "FINAL");
      cleanupState = "DISCARDED";
      this.cleanupProofs += 1;
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

async function createRoles(pool) {
  await pool.query(`revoke "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables" from "pg_monitor"`);
  await pool.query(`create role "platform_migrator" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password null`);
  await pool.query(`create role "platform_runtime" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await pool.query(`create role "platform_app" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await pool.query(`grant "platform_runtime" to "platform_app" with admin true, inherit false, set false granted by "cloud_admin"`);
}

async function applyFirstNine(pool) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "swooshz-run598-first-nine-"));
  const target = join(temporaryRoot, "drizzle", "migrations");
  try {
    await mkdir(join(target, "meta"), { recursive: true });
    const journal = JSON.parse(await readFile(join(migrationsFolder, "meta", "_journal.json"), "utf8"));
    journal.entries = journal.entries.slice(0, 9);
    await writeFile(join(target, "meta", "_journal.json"), `${JSON.stringify(journal, null, 2)}\n`, "utf8");
    for (const entry of journal.entries) await cp(join(migrationsFolder, `${entry.tag}.sql`), join(target, `${entry.tag}.sql`));
    await migrate(drizzle(pool), { migrationsFolder: target });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
  assert.equal((await readLedger(pool)).length, 9);
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
