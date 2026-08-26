import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { appendFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import test from "node:test";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Pool } from "pg";

import {
  JOURNAL_PREFIX_DOMAIN_SEPARATOR,
  captureNormalizedPrestate,
  canonicalDigest,
  computeContractDigest,
  computeTargetBindingDigest,
  createDurableInverse,
  createMutationSession,
  createDurablePlan,
  executeDurablePlan,
  loadCanonicalMigrationJournal,
  runCanonicalMigrationPrimitive,
} from "../dist/db/durable-operations.js";
import { RUNTIME_TABLE_GRANT_CONTRACT } from "../dist/db/runtime-grant-contract.js";

const testDatabaseUrlA = process.env.DURABLE_OPERATIONS_TEST_DATABASE_URL_A;
const testDatabaseUrlB = process.env.DURABLE_OPERATIONS_TEST_DATABASE_URL_B;
const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const execFileAsync = promisify(execFile);
const migrationsFolder = resolve(rootDir, "drizzle", "migrations");
const databaseName = "durable_operations_test";
const expectedGitSha = "9ce40dce85484ef5fd8c849951527572e95afa24";
const startingHead = "87007af436f04d92722d7857e396e650ce80e2a4";
const contractDigest = "a".repeat(64);

if (!testDatabaseUrlA || !testDatabaseUrlB) {
  test("durable PostgreSQL 17 proofs require the disposable runner", { skip: "runner-owned local fixture not supplied" }, () => {});
} else {
  test("Run-190 durable database operations on two disposable PostgreSQL 17 clusters", async () => {
    const connectionA = readConnectionTarget(testDatabaseUrlA);
    const connectionB = readConnectionTarget(testDatabaseUrlB);
    assert.notEqual(connectionA.port, connectionB.port);
    const adminPool = new Pool({ ...connectionA, user: "cloud_admin" });
    const cloudAdminPool = new Pool({ ...connectionA, user: "cloud_admin" });
    const migratorPool = new Pool({ ...connectionA, user: "platform_migrator" });
    const appPool = new Pool({ ...connectionA, user: "platform_app" });
    const secondAdminPool = new Pool({ ...connectionB, user: "cloud_admin" });
    const secondMigratorPool = new Pool({ ...connectionB, user: "platform_migrator" });

    try {
      await createRoles(adminPool);
      await createRoles(secondAdminPool);
      await cloudAdminPool.query("select 1");
      const migration = await provisionCanonicalFixture(cloudAdminPool);
      const secondMigration = await provisionCanonicalFixture(secondAdminPool);
      assert.equal(migration.after.length, 10);
      assert.equal(migration.applied_entries.length, 10);
      assert.equal(migration.applied_entries.at(-1).tag, "0010_admin_operator_viewer_role_collapse");
      assert.equal(secondMigration.after.length, 10);
      const targetA = await readTargetIdentity(adminPool);
      const targetB = await readTargetIdentity(secondAdminPool);
      assert.notDeepEqual(targetA, targetB);

      const binding = {
        version: "target-binding-v1",
        logicalDatabaseName: databaseName,
        expectedClusterSystemIdentifier: targetA.cluster_system_identifier,
        expectedDatabaseOid: targetA.database_oid,
        expectedCurrentUser: "platform_migrator",
        expectedSessionUser: "platform_migrator",
        expectedPostgresMajor: 17,
        connect: () => migratorPool.connect(),
      };
      const wrongTargetBinding = {
        ...binding,
        connect: () => secondMigratorPool.connect(),
      };
      const journal = await loadCanonicalMigrationJournal(rootDir);
      const secondBinding = {
        ...binding,
        expectedClusterSystemIdentifier: targetB.cluster_system_identifier,
        expectedDatabaseOid: targetB.database_oid,
        connect: () => secondMigratorPool.connect(),
      };
      const secondBaseline = await captureNormalizedPrestate(secondBinding, journal);
      assert.notEqual(binding.expectedClusterSystemIdentifier, secondBinding.expectedClusterSystemIdentifier);
      await assert.rejects(
        () => captureNormalizedPrestate(wrongTargetBinding, journal),
        (error) => error?.semanticCode === "TARGET_MISMATCH",
      );
      const wrongTargetPlan = makePlan(wrongTargetBinding, secondBaseline, [{
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      const wrongTargetReceipt = await executeDurablePlan({
        plan: wrongTargetPlan,
        binding: wrongTargetBinding,
        expectedPrestate: secondBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(wrongTargetReceipt.outcome, "BLOCKED");
      assert.equal(wrongTargetReceipt.phase, "OBSERVE");
      assert.equal(wrongTargetReceipt.semantic_code, "TARGET_MISMATCH");
      assert.equal(wrongTargetReceipt.mutation_started, false);
      assert.equal((await secondAdminPool.query("select has_table_privilege('platform_app', 'public.users', 'select') as present")).rows[0].present, false);
      const baseline = await captureNormalizedPrestate(binding, journal);
      assert.equal(baseline.prestate.target.current_user, "platform_migrator");
      assert.equal(baseline.prestate.target.session_user, "platform_migrator");
      assert.equal(baseline.prestate.migration_journal.applied_rows.length, 10);
      assert.equal(
        baseline.prestate.migration_journal.applied_prefix_digest,
        canonicalDigest(JOURNAL_PREFIX_DOMAIN_SEPARATOR, baseline.prestate.migration_journal.applied_rows),
      );
      assertCanonicalReadiness(baseline.prestate);

      const nonMigrationPlan = makePlan(binding, baseline, [{
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      const firstLedgerRow = (await cloudAdminPool.query(`
        select created_at::text as when, hash as sql_sha256
        from drizzle.__drizzle_migrations
        order by created_at, hash
        limit 1
      `)).rows[0];
      assert.ok(firstLedgerRow);
      await cloudAdminPool.query(
        `update drizzle.__drizzle_migrations set hash = $1 where created_at = $2`,
        ["0".repeat(64), firstLedgerRow.when],
      );
      try {
        const nonPrefixReceipt = await executeDurablePlan({
          plan: nonMigrationPlan,
          binding,
          expectedPrestate: baseline.prestate,
          expectedContractDigest: contractDigest,
          journal,
        });
        assert.equal(nonPrefixReceipt.outcome, "BLOCKED");
        assert.equal(nonPrefixReceipt.phase, "OBSERVE");
        assert.equal(nonPrefixReceipt.semantic_code, "MIGRATION_IDENTITY_MISMATCH");
        assert.equal(nonPrefixReceipt.mutation_started, false);
      } finally {
        await cloudAdminPool.query(
          `update drizzle.__drizzle_migrations set hash = $1 where created_at = $2`,
          [firstLedgerRow.sql_sha256, firstLedgerRow.when],
        );
      }

      const raceClient = await migratorPool.connect();
      let raceInjected = false;
      let executionReturned = false;
      let raceMutationCompletedBeforeReturn = false;
      let raceMutationPromise = Promise.resolve();
      const raceConnection = {
        async query(text, values) {
          const result = await raceClient.query(text, values);
          if (!raceInjected && typeof text === "string" && text.includes("platform durable:target_lock")) {
            raceInjected = true;
            raceMutationPromise = cloudAdminPool.query(`alter table "public"."users" owner to "platform_app"`).then(() => {
              if (!executionReturned) raceMutationCompletedBeforeReturn = true;
            });
            await raceMutationPromise;
          }
          return result;
        },
        release() {
          raceClient.release();
        },
      };
      const raceReceipt = await executeDurablePlan({
        plan: nonMigrationPlan,
        binding,
        expectedPrestate: baseline.prestate,
        expectedContractDigest: contractDigest,
        mutationConnection: raceConnection,
        journal,
      });
      assert.equal(raceInjected, true);
      executionReturned = true;
      await raceMutationPromise;
      assert.equal(raceReceipt.outcome === "PASS" && raceMutationCompletedBeforeReturn, false);
      await assert.doesNotReject(() => cloudAdminPool.query(`alter table "public"."users" owner to "platform_migrator"`), "index drift restore");

      await assertReadOnlyWriteRejected(migratorPool);
      await assertRuntimeAndAppSeparation(cloudAdminPool, appPool);

      await cloudAdminPool.query(`grant select on table "public"."users" to "platform_app"`);
      const aclDrift = await captureNormalizedPrestate(binding, journal);
      assert.ok(aclDrift.prestate.privileges.direct.some((row) => row.grantee === "platform_app" && row.privilege === "select"));
      await cloudAdminPool.query(`revoke select on table "public"."users" from "platform_app"`);

      await cloudAdminPool.query(`alter default privileges for role "cloud_admin" in schema "public" grant select on tables to "platform_app"`);
      const defaultAclDrift = await captureNormalizedPrestate(binding, journal);
      assert.ok(defaultAclDrift.prestate.default_acls.creator.includes("cloud_admin"));
      await cloudAdminPool.query(`alter default privileges for role "cloud_admin" in schema "public" revoke select on tables from "platform_app"`);

      await cloudAdminPool.query(`create table "public"."run185_unknown_drift" ("id" integer)`);
      await assert.rejects(
        () => captureNormalizedPrestate(binding, journal),
        (error) => error?.semanticCode === "UNKNOWN_DRIFT",
      );
      await cloudAdminPool.query(`drop table "public"."run185_unknown_drift"`);

      const prewriteBaseline = await captureNormalizedPrestate(binding, journal);
      await cloudAdminPool.query(`grant select on table "public"."users" to "platform_app"`);
      const prewriteOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const prewritePlan = makePlan(binding, prewriteBaseline, [prewriteOperation]);
      const prewriteReceipt = await executeDurablePlan({
          plan: prewritePlan,
          binding,
          expectedPrestate: prewriteBaseline.prestate,
          expectedContractDigest: contractDigest,
          journal,
        });
      assert.equal(prewriteReceipt.outcome, "BLOCKED");
      assert.equal(prewriteReceipt.phase, "PRESTATE");
      assert.equal(prewriteReceipt.semantic_code, "PREWRITE_DRIFT");
      await cloudAdminPool.query(`revoke select on table "public"."users" from "platform_app"`);
      await assert.rejects(
        () => executeDurablePlan({
          plan: prewritePlan,
          binding,
          expectedPrestate: {},
          expectedContractDigest: contractDigest,
          journal,
        }),
        (error) => error?.semanticCode === "PRESTATE_INVALID",
      );

      const successBaseline = await captureNormalizedPrestate(binding, journal);
      const privilegeOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const successPlan = makePlan(binding, successBaseline, [privilegeOperation]);
      const successReceipt = await executeDurablePlan({
        plan: successPlan,
        binding,
        expectedPrestate: successBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(successReceipt.outcome, "PASS");
      assert.equal(successReceipt.phase, "FINAL_VERIFY");
      assert.equal(successReceipt.semantic_code, "SUCCESS");
      assert.equal(successReceipt.mutation_started, true);
      assert.equal(successReceipt.final_readiness_state, "PASS");
      assert.equal(successReceipt.counts.inverse_steps, 1);

      const afterSuccess = await captureNormalizedPrestate(binding, journal);
      const inverse = createDurableInverse(successPlan, successBaseline.prestate);
      assert.equal(inverse.steps[0].operation.action, "revoke");
      const inversePlan = makePlan(binding, afterSuccess, [inverse.steps[0].operation]);
      const inverseReceipt = await executeDurablePlan({
        plan: inversePlan,
        binding,
        expectedPrestate: afterSuccess.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(inverseReceipt.outcome, "PASS");
      const restored = await captureNormalizedPrestate(binding, journal);
      assert.equal(restored.prestate_digest, successBaseline.prestate_digest);

      const partialBaseline = await captureNormalizedPrestate(binding, journal);
      const partialOperations = [
        {
          kind: "default_acl",
          action: "grant",
          creator: "platform_migrator",
          schema: "drizzle",
          object_type: "table",
          principal: "platform_app",
          privilege: "SELECT",
          grant_option: false,
          previous_grant_option: false,
        },
        {
          kind: "default_acl",
          action: "grant",
          creator: "platform_app",
          schema: "public",
          object_type: "table",
          principal: "platform_app",
          privilege: "SELECT",
          grant_option: false,
          previous_grant_option: false,
        },
      ];
      const partialPlan = makePlan(binding, partialBaseline, partialOperations);
      const partialReceipt = await executeDurablePlan({
        plan: partialPlan,
        binding,
        expectedPrestate: partialBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(partialReceipt.outcome, "BLOCKED");
      assert.equal(partialReceipt.phase, "INVERSE");
      assert.equal(partialReceipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
      assert.equal(partialReceipt.mutation_started, false);
      assert.equal(partialReceipt.restoration_state, "NOT_REQUIRED");

      const inverseBaseline = await captureNormalizedPrestate(binding, journal);
      const recoveryOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const recoveryPlan = makePlan(binding, inverseBaseline, [recoveryOperation]);
      const finalFailureReceipt = await executeDurablePlan({
        plan: recoveryPlan,
        binding: bindingWithFinalVerificationFailure(binding, migratorPool),
        expectedPrestate: inverseBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(finalFailureReceipt.outcome, "FAIL");
      assert.equal(finalFailureReceipt.semantic_code, "FINAL_VERIFICATION_FAILED");
      assert.equal(finalFailureReceipt.mutation_started, true);
      assert.equal(finalFailureReceipt.commit_state, "COMMITTED");
      assert.equal(finalFailureReceipt.rollback_attempted, false);
      assert.equal(finalFailureReceipt.rollback_verified, false);
      assert.equal(finalFailureReceipt.repository_inverse_attempted, true);
      assert.equal(finalFailureReceipt.repository_inverse_verified, true);
      assert.equal(finalFailureReceipt.restoration_state, "VERIFIED");
      assert.equal(finalFailureReceipt.final_readiness_state, "NOT_RUN");
      assert.equal(finalFailureReceipt.phase, "FINAL_VERIFY");
      assert.equal((await captureNormalizedPrestate(binding, journal)).prestate_digest, inverseBaseline.prestate_digest);

      const driftBaseline = await captureNormalizedPrestate(binding, journal);
      const driftPlan = makePlan(binding, driftBaseline, [recoveryOperation]);
      const driftReceipt = await executeDurablePlan({
        plan: driftPlan,
        binding: bindingWithFinalVerificationFailure(
          binding,
          migratorPool,
          () => cloudAdminPool.query(`grant update on table "public"."users" to "platform_app"`),
        ),
        expectedPrestate: driftBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(driftReceipt.outcome, "FAIL");
      assert.equal(driftReceipt.phase, "RESTORE_VERIFY");
      assert.equal(driftReceipt.semantic_code, "RESTORATION_FAILED");
      assert.equal(driftReceipt.commit_state, "COMMITTED");
      assert.equal(driftReceipt.repository_inverse_attempted, true);
      assert.equal(driftReceipt.repository_inverse_verified, false);
      assert.equal(driftReceipt.restoration_state, "FAILED");
      await cloudAdminPool.query(`revoke select, update on table "public"."users" from "platform_app"`);
      assert.equal((await captureNormalizedPrestate(binding, journal)).prestate_digest, driftBaseline.prestate_digest);

      const aclBaseline = await captureNormalizedPrestate(binding, journal);
      assert.equal(
        aclBaseline.prestate.privileges.direct.some((row) =>
          row.qualified_name === "public.users" && row.grantee === "platform_runtime" && row.privilege === "select"),
        true,
      );
      const grantOptionOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: true,
        previous_grant_option: false,
      };
      const grantOptionPlan = makePlan(binding, aclBaseline, [grantOptionOperation]);
      const grantOptionReceipt = await executeDurablePlan({
        plan: grantOptionPlan,
        binding,
        expectedPrestate: aclBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(grantOptionReceipt.outcome, "PASS");
      const grantOptionAfter = await captureNormalizedPrestate(binding, journal);
      assert.equal(
        grantOptionAfter.prestate.privileges.direct.some((row) =>
          row.qualified_name === "public.users" && row.grantee === "platform_app" &&
          row.privilege === "select" && row.grant_option === true),
        true,
      );
      const grantOptionInverse = createDurableInverse(grantOptionPlan, aclBaseline.prestate);
      const grantOptionRestore = await executeDurablePlan({
        plan: makePlan(binding, grantOptionAfter, [grantOptionInverse.steps[0].operation]),
        binding,
        expectedPrestate: grantOptionAfter.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(grantOptionRestore.outcome, "PASS");
      assert.equal((await captureNormalizedPrestate(binding, journal)).prestate_digest, aclBaseline.prestate_digest);

      const toctouBaseline = await captureNormalizedPrestate(binding, journal);
      const toctouOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const toctouPlan = makePlan(binding, toctouBaseline, [toctouOperation]);
      const mutableToctouPlan = {
        ...toctouPlan,
        operations: toctouPlan.operations.map((operation) => ({ ...operation })),
      };
      let toctouConnectionCount = 0;
      const mutatingCallerBinding = {
        ...binding,
        async connect() {
          const connection = await binding.connect();
          if (++toctouConnectionCount === 1) {
            mutableToctouPlan.operations[0] = { ...mutableToctouPlan.operations[0], privilege: "UPDATE" };
          }
          return connection;
        },
      };
      const toctouReceipt = await executeDurablePlan({
        plan: mutableToctouPlan,
        binding: mutatingCallerBinding,
        expectedPrestate: toctouBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(toctouReceipt.outcome, "PASS");
      const toctouAfter = await captureNormalizedPrestate(binding, journal);
      assert.equal(
        toctouAfter.prestate.privileges.direct.some((row) =>
          row.qualified_name === "public.users" && row.grantee === "platform_app" && row.privilege === "select"),
        true,
      );
      assert.equal(
        toctouAfter.prestate.privileges.direct.some((row) =>
          row.qualified_name === "public.users" && row.grantee === "platform_app" && row.privilege === "update"),
        false,
      );
      await cloudAdminPool.query(`revoke select on table "public"."users" from "platform_app"`);

      const sourceDriftTempRoot = await mkdtemp(join(tmpdir(), "swooshz-run192-source-drift-"));
      try {
        const sourceDriftRoot = join(sourceDriftTempRoot, "repo");
        await execFileAsync("git", ["clone", "--quiet", rootDir, sourceDriftRoot], { windowsHide: true });
        const sourceDriftContractDigest = await computeContractDigest(sourceDriftRoot);
        const sourceDriftBaseline = await captureNormalizedPrestate(binding, journal);
        const sourceDriftPlan = makePlan(binding, sourceDriftBaseline, [toctouOperation], sourceDriftContractDigest, startingHead);
        const sourceDriftResult = await executeWithPostLockDrift({
          plan: sourceDriftPlan,
          binding,
          pool: migratorPool,
          expectedPrestate: sourceDriftBaseline.prestate,
          expectedContractDigest: sourceDriftContractDigest,
          journal,
          rootDir: sourceDriftRoot,
          drift: () => appendFile(join(sourceDriftRoot, "src", "db", "durable-operations.ts"), "\n", "utf8"),
        });
        const assertSourceDrift = (actual, expected, label) => {
          try {
            assert.equal(actual, expected);
          } catch (error) {
            console.error("source drift assertion failed: " + label);
            throw error;
          }
        };
        assertSourceDrift(sourceDriftResult.injected, true, "injected");
        assertSourceDrift(sourceDriftResult.receipt.outcome, "BLOCKED", "outcome");
        assertSourceDrift(sourceDriftResult.receipt.phase, "PREWRITE", "phase");
        assertSourceDrift(sourceDriftResult.receipt.semantic_code, "PREWRITE_DRIFT", "code");
        assertSourceDrift(sourceDriftResult.receipt.mutation_started, false, "mutation");
      } finally {
        await rm(sourceDriftTempRoot, { recursive: true, force: true });
      }

      await migratorPool.query(`grant select on table "public"."users" to "platform_app" with grant option`);
      await appPool.query(`grant select on table "public"."users" to "cloud_admin"`);
      const grantorBaseline = await captureNormalizedPrestate(binding, journal);
      const grantorRow = grantorBaseline.prestate.privileges.direct.find((row) =>
        row.qualified_name === "public.users" && row.grantee === "cloud_admin" && row.privilege === "select");
      assert.equal(grantorBaseline.prestate.target.current_user, "platform_migrator");
      assert.equal(grantorRow?.grantor, "platform_app");
      const grantorPlan = makePlan(binding, grantorBaseline, [{
        kind: "privilege",
        action: "revoke",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "cloud_admin",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      assert.throws(
        () => createDurableInverse(grantorPlan, grantorBaseline.prestate),
        (error) => error?.semanticCode === "RESTORE_CAPABILITY_REQUIRED",
      );
      const grantorReceipt = await executeDurablePlan({
        plan: grantorPlan,
        binding,
        expectedPrestate: grantorBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(grantorReceipt.outcome, "BLOCKED");
      assert.equal(grantorReceipt.phase, "INVERSE");
      assert.equal(grantorReceipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
      assert.equal(grantorReceipt.mutation_started, false);
      await appPool.query(`revoke select on table "public"."users" from "cloud_admin"`);
      await migratorPool.query(`revoke select on table "public"."users" from "platform_app"`);

      const callerInventedBaseline = await captureNormalizedPrestate(binding, journal);
      const callerInventedPlan = makePlan(binding, callerInventedBaseline, [{
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "public.users" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: true,
      }]);
      assert.throws(
        () => createDurableInverse(callerInventedPlan, callerInventedBaseline.prestate),
        (error) => error?.semanticCode === "PRESTATE_MISMATCH",
      );

      const nullAclBaseline = await captureNormalizedPrestate(binding, journal);
      const nullAclRow = nullAclBaseline.prestate.privileges.direct
        .concat(nullAclBaseline.prestate.privileges.public)
        .find((row) => row.qualified_name === "drizzle.__drizzle_migrations");
      assert.equal(nullAclRow?.acl_is_null, true);
      const nullAclPlan = makePlan(binding, nullAclBaseline, [{
        kind: "privilege",
        action: "grant",
        object: { object_class: "relation", qualified_name: "drizzle.__drizzle_migrations" },
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      const nullAclReceipt = await executeDurablePlan({
        plan: nullAclPlan,
        binding,
        expectedPrestate: nullAclBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(nullAclReceipt.outcome, "BLOCKED");
      assert.equal(nullAclReceipt.phase, "INVERSE");
      assert.equal(nullAclReceipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
      assert.equal(nullAclReceipt.mutation_started, false);

      const absentDefaultBaseline = await captureNormalizedPrestate(binding, journal);
      assert.equal(
        absentDefaultBaseline.prestate.default_acls.creator.some((creator, index) =>
          creator === "platform_app" &&
          absentDefaultBaseline.prestate.default_acls.schema[index] === "public" &&
          absentDefaultBaseline.prestate.default_acls.object_type[index] === "table"),
        false,
      );
      const absentDefaultPlan = makePlan(binding, absentDefaultBaseline, [{
        kind: "default_acl",
        action: "grant",
        creator: "platform_app",
        schema: "public",
        object_type: "table",
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      const absentDefaultReceipt = await executeDurablePlan({
        plan: absentDefaultPlan,
        binding,
        expectedPrestate: absentDefaultBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(absentDefaultReceipt.outcome, "BLOCKED");
      assert.equal(absentDefaultReceipt.phase, "INVERSE");
      assert.equal(absentDefaultReceipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
      assert.equal(absentDefaultReceipt.mutation_started, false);

      await cloudAdminPool.query(`alter default privileges for role "platform_migrator" in schema "drizzle" revoke all privileges on tables from public, "platform_runtime", "platform_app", "platform_migrator", "cloud_admin"`);
      await migratorPool.query(`alter default privileges for role "platform_migrator" in schema "drizzle" grant select on tables to "platform_app"`);
      const defaultBaseline = await captureNormalizedPrestate(binding, journal);
      const defaultRows = defaultBaseline.prestate.default_acls.creator.map((creator, index) => ({
        default_acl_oid: defaultBaseline.prestate.default_acls.default_acl_oid[index],
        row_present: defaultBaseline.prestate.default_acls.row_present[index],
        acl_is_null: defaultBaseline.prestate.default_acls.acl_is_null[index],
        creator,
        schema: defaultBaseline.prestate.default_acls.schema[index],
        object_type: defaultBaseline.prestate.default_acls.object_type[index],
        grantee: defaultBaseline.prestate.default_acls.grantee[index],
        grantor: defaultBaseline.prestate.default_acls.grantor[index],
        privilege: defaultBaseline.prestate.default_acls.privilege[index],
        grant_option: defaultBaseline.prestate.default_acls.grant_option[index],
      })).filter((row) => row.creator === "platform_migrator" && row.schema === "drizzle" && row.object_type === "table");
      assert.equal(defaultRows.length, 1);
      assert.equal(defaultRows[0].row_present, true);
      assert.equal(defaultRows[0].acl_is_null, false);
      assert.equal(defaultRows[0].grantee, "platform_app");
      assert.equal(defaultRows[0].grantor, "platform_migrator");
      assert.equal(defaultRows[0].privilege, "SELECT");
      assert.equal(defaultRows[0].grant_option, false);
      const defaultDeletionPlan = makePlan(binding, defaultBaseline, [{
        kind: "default_acl",
        action: "revoke",
        creator: "platform_migrator",
        schema: "drizzle",
        object_type: "table",
        principal: "platform_app",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      }]);
      const defaultDeletionReceipt = await executeDurablePlan({
        plan: defaultDeletionPlan,
        binding,
        expectedPrestate: defaultBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(defaultDeletionReceipt.outcome, "BLOCKED");
      assert.equal(defaultDeletionReceipt.phase, "INVERSE");
      assert.equal(defaultDeletionReceipt.semantic_code, "RESTORE_CAPABILITY_REQUIRED");
      assert.equal(defaultDeletionReceipt.mutation_started, false);

      const defaultGrantOperation = {
        kind: "default_acl",
        action: "grant",
        creator: "platform_migrator",
        schema: "drizzle",
        object_type: "table",
        principal: "cloud_admin",
        privilege: "SELECT",
        grant_option: false,
        previous_grant_option: false,
      };
      const defaultGrantPlan = makePlan(binding, defaultBaseline, [defaultGrantOperation]);
      const defaultGrantReceipt = await executeDurablePlan({
        plan: defaultGrantPlan,
        binding,
        expectedPrestate: defaultBaseline.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(defaultGrantReceipt.outcome, "PASS");
      assert.equal(defaultGrantReceipt.semantic_code, "SUCCESS");
      assert.equal(defaultGrantReceipt.phase, "FINAL_VERIFY");
      const defaultAfter = await captureNormalizedPrestate(binding, journal);
      assert.equal(
        defaultAfter.prestate.default_acls.grantee.some((grantee, index) =>
          defaultAfter.prestate.default_acls.creator[index] === "platform_migrator" &&
          defaultAfter.prestate.default_acls.schema[index] === "drizzle" &&
          defaultAfter.prestate.default_acls.object_type[index] === "table" &&
          grantee === "cloud_admin"),
        true,
      );
      const defaultInverse = createDurableInverse(defaultGrantPlan, defaultBaseline.prestate);
      const defaultRestore = await executeDurablePlan({
        plan: makePlan(binding, defaultAfter, [defaultInverse.steps[0].operation]),
        binding,
        expectedPrestate: defaultAfter.prestate,
        expectedContractDigest: contractDigest,
        journal,
      });
      assert.equal(defaultRestore.outcome, "PASS");
      assert.equal((await captureNormalizedPrestate(binding, journal)).prestate_digest, defaultBaseline.prestate_digest);
      await migratorPool.query(`alter default privileges for role "platform_migrator" in schema "drizzle" revoke select on tables from "platform_app"`);

      const adminBinding = bindingForPool(binding, adminPool, "cloud_admin");
      const objectBaseline = await captureNormalizedPrestate(binding, journal);
      const indexRecord = objectBaseline.prestate.ownership.canonical_indexes.find((record) => record.qualified_name === "public.users_pkey");
      assert.equal(indexRecord?.owner, "platform_migrator");
      const indexOperation = {
        kind: "ownership",
        action: "set_owner",
        object: { object_class: "index", qualified_name: "public.users_pkey" },
        previous_owner: "platform_migrator",
        next_owner: "platform_migrator",
      };
      const indexPlan = makePlan(adminBinding, objectBaseline, [indexOperation]);
      const indexInverse = createDurableInverse(indexPlan, objectBaseline.prestate);
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, indexOperation), "index direct mutation");
      let indexAfter;
      await assert.doesNotReject(async () => {
        indexAfter = await captureNormalizedPrestate(adminBinding, journal);
      }, "index after capture");
      assert.equal(indexAfter.prestate.ownership.canonical_indexes.find((record) => record.qualified_name === "public.users_pkey")?.owner, "platform_migrator", "index direct forward owner");
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, indexInverse.steps[0].operation), "index inverse mutation");
      let indexRestored;
      await assert.doesNotReject(async () => {
        indexRestored = await captureNormalizedPrestate(binding, journal);
      }, "index restored capture");
      assert.equal(indexRestored.prestate_digest, objectBaseline.prestate_digest);
      let indexDurableReceipt;
      await assert.doesNotReject(async () => {
        indexDurableReceipt = await executeDurablePlan({
          plan: makePlan(binding, objectBaseline, [indexOperation]),
          binding,
          expectedPrestate: objectBaseline.prestate,
          expectedContractDigest: contractDigest,
          journal,
        });
      }, "index durable execution");
      assert.equal(indexDurableReceipt.outcome, "PASS");
      assert.equal(indexDurableReceipt.phase, "FINAL_VERIFY");
      assert.equal(indexDurableReceipt.semantic_code, "SUCCESS");
      assert.equal(indexDurableReceipt.commit_state, "COMMITTED");
      assert.equal(indexDurableReceipt.mutation_started, true);

      const sequenceRecord = objectBaseline.prestate.ownership.canonical_sequences.find((record) => record.qualified_name === "drizzle.__drizzle_migrations_id_seq");
      assert.equal(sequenceRecord?.owner, "platform_migrator");
      const sequenceOperation = {
        kind: "ownership",
        action: "set_owner",
        object: { object_class: "sequence", qualified_name: "drizzle.__drizzle_migrations_id_seq" },
        previous_owner: "platform_migrator",
        next_owner: "platform_migrator",
      };
      const sequencePlan = makePlan(adminBinding, objectBaseline, [sequenceOperation]);
      const sequenceInverse = createDurableInverse(sequencePlan, objectBaseline.prestate);
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, sequenceOperation), "sequence direct mutation");
      let sequenceAfter;
      await assert.doesNotReject(async () => {
        sequenceAfter = await captureNormalizedPrestate(adminBinding, journal);
      }, "sequence after capture");
      assert.equal(sequenceAfter.prestate.ownership.canonical_sequences.find((record) => record.qualified_name === "drizzle.__drizzle_migrations_id_seq")?.owner, "platform_migrator", "sequence direct forward owner");
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, sequenceInverse.steps[0].operation), "sequence inverse mutation");
      let sequenceRestored;
      await assert.doesNotReject(async () => {
        sequenceRestored = await captureNormalizedPrestate(binding, journal);
      }, "sequence restored capture");
      assert.equal(sequenceRestored.prestate_digest, objectBaseline.prestate_digest);
      const sequenceDurableOperation = {
        ...sequenceOperation,
        next_owner: "platform_migrator",
      };
      let sequenceDurableReceipt;
      await assert.doesNotReject(async () => {
        sequenceDurableReceipt = await executeDurablePlan({
          plan: makePlan(binding, objectBaseline, [sequenceDurableOperation]),
          binding,
          expectedPrestate: objectBaseline.prestate,
          expectedContractDigest: contractDigest,
          journal,
        });
      }, "sequence durable execution");
      assert.equal(sequenceDurableReceipt.outcome, "PASS");
      assert.equal(sequenceDurableReceipt.phase, "FINAL_VERIFY");
      assert.equal(sequenceDurableReceipt.semantic_code, "SUCCESS");
      assert.equal(sequenceDurableReceipt.commit_state, "COMMITTED");
      assert.equal(sequenceDurableReceipt.mutation_started, true);

      const databaseOperation = {
        kind: "privilege",
        action: "grant",
        object: { object_class: "database", qualified_name: "__current_database__" },
        principal: "platform_runtime",
        privilege: "CREATE",
        grant_option: false,
        previous_grant_option: false,
      };
      let databasePlan;
      assert.doesNotThrow(() => {
        databasePlan = makePlan(adminBinding, objectBaseline, [databaseOperation]);
      }, "database plan creation");
      const databaseRows = [...objectBaseline.prestate.privileges.direct, ...objectBaseline.prestate.privileges.public]
        .filter((row) => row.object_class === "database" && row.qualified_name === databaseName && row.privilege !== "");
      const databasePrevious = databaseRows.find((row) => row.grantee === "platform_runtime" && row.privilege.toUpperCase() === "CREATE");
      assert.ok(databaseRows.length > 0);
      assert.equal(databaseRows.some((row) => row.acl_is_null), false);
      if (databasePrevious) assert.equal(databasePrevious.grantor, "platform_migrator");
      let databaseInverse;
      databaseInverse = createDurableInverse(databasePlan, objectBaseline.prestate);
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, databaseOperation), "database direct mutation");
      let databaseAfter;
      await assert.doesNotReject(async () => {
        databaseAfter = await captureNormalizedPrestate(adminBinding, journal);
      }, "database after capture");
      assert.equal(
        databaseAfter.prestate.privileges.direct.some((row) =>
          row.qualified_name === databaseName && row.grantee === "platform_runtime" && row.privilege === "create"),
        true,
        "database direct forward privilege",
      );
      await assert.doesNotReject(() => executeDirectMutation(adminPool, adminBinding, databaseInverse.steps[0].operation), "database inverse mutation");
      let databaseRestored;
      await assert.doesNotReject(async () => {
        databaseRestored = await captureNormalizedPrestate(binding, journal);
      }, "database restored capture");
      assert.equal(databaseRestored.prestate_digest, objectBaseline.prestate_digest, "database restored digest");

      let indexRaceBaseline;
      await assert.doesNotReject(async () => {
        indexRaceBaseline = await captureNormalizedPrestate(adminBinding, journal);
      }, "index race baseline capture");
      let indexRace;
      await assert.doesNotReject(async () => {
        indexRace = await executeWithPostLockDrift({
          plan: makePlan(adminBinding, indexRaceBaseline, [indexOperation]),
          binding: adminBinding,
          pool: adminPool,
          expectedPrestate: indexRaceBaseline.prestate,
          journal,
          drift: () => cloudAdminPool.query(`alter table "public"."users" owner to "platform_app"`),
        });
      }, "index drift execution");
      if (indexRace.injected !== true) {
        throw new Error("index race result rejected");
      }
      if (indexRace.receipt.outcome !== "BLOCKED") {
        throw new Error("index race result rejected");
      }
      if (indexRace.receipt.phase !== "PREWRITE") {
        throw new Error("index race result rejected");
      }
      if (indexRace.receipt.semantic_code !== "PREWRITE_DRIFT") {
        throw new Error("index race result rejected");
      }
      if (indexRace.receipt.mutation_started !== false) {
        throw new Error("index race result rejected");
      }
      await cloudAdminPool.query(`alter table "public"."users" owner to "platform_migrator"`);

      let sequenceRaceBaseline;
      await assert.doesNotReject(async () => {
        sequenceRaceBaseline = await captureNormalizedPrestate(adminBinding, journal);
      }, "sequence race baseline capture");
      let sequenceRace;
      await assert.doesNotReject(async () => {
        sequenceRace = await executeWithPostLockDrift({
          plan: makePlan(adminBinding, sequenceRaceBaseline, [sequenceOperation]),
          binding: adminBinding,
          pool: adminPool,
          expectedPrestate: sequenceRaceBaseline.prestate,
          journal,
          drift: () => cloudAdminPool.query(`alter schema "drizzle" owner to "platform_app"`),
        });
      }, "sequence drift execution");
      assert.equal(sequenceRace.injected, true);
      assert.equal(sequenceRace.receipt.outcome, "BLOCKED");
      assert.equal(sequenceRace.receipt.phase, "PREWRITE");
      assert.equal(sequenceRace.receipt.semantic_code, "PREWRITE_DRIFT");
      assert.equal(sequenceRace.receipt.mutation_started, false);
      await assert.doesNotReject(() => cloudAdminPool.query(`alter schema "drizzle" owner to "platform_migrator"`), "sequence drift restore");

      let databaseRaceBaseline;
      await assert.doesNotReject(async () => {
        databaseRaceBaseline = await captureNormalizedPrestate(adminBinding, journal);
      }, "database race baseline capture");
      let databaseRace;
      await assert.doesNotReject(async () => {
        databaseRace = await executeWithPostLockDrift({
          plan: makePlan(adminBinding, databaseRaceBaseline, [databaseOperation]),
          binding: adminBinding,
          pool: adminPool,
          expectedPrestate: databaseRaceBaseline.prestate,
          journal,
          drift: () => cloudAdminPool.query(`grant temporary on database "durable_operations_test" to "platform_migrator"`),
        });
      }, "database drift execution");
      assert.equal(databaseRace.injected, true);
      assert.equal(databaseRace.receipt.outcome, "BLOCKED");
      assert.equal(databaseRace.receipt.phase, "PREWRITE");
      assert.equal(databaseRace.receipt.semantic_code, "PREWRITE_DRIFT");
      assert.equal(databaseRace.receipt.mutation_started, false);
      await assert.doesNotReject(() => cloudAdminPool.query(`revoke temporary on database "durable_operations_test" from "platform_migrator"`), "database drift restore");
    } finally {
      await Promise.all([
        appPool.end(),
        migratorPool.end(),
        cloudAdminPool.end(),
        adminPool.end(),
        secondMigratorPool.end(),
        secondAdminPool.end(),
      ]);
    }
  });
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

async function readTargetIdentity(pool) {
  const result = await pool.query(`
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
  `);
  assert.equal(result.rows.length, 1);
  return {
    cluster_system_identifier: String(result.rows[0].cluster_system_identifier),
    database_oid: String(result.rows[0].database_oid),
  };
}

async function createRoles(adminPool) {
  await adminPool.query(`revoke "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables" from "pg_monitor"`);
  await adminPool.query(`create role "platform_migrator" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await adminPool.query(`create role "platform_runtime" nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
  await adminPool.query(`create role "platform_app" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`);
}

async function provisionCanonicalFixture(cloudAdminPool) {
  const migration = await runCanonicalMigrationPrimitive({ pool: cloudAdminPool, migrationsFolder });
  const database = quoteIdentifier(databaseName);
  const migrator = quoteIdentifier("platform_migrator");
  const runtime = quoteIdentifier("platform_runtime");
  const app = quoteIdentifier("platform_app");
  await cloudAdminPool.query(`alter database ${database} owner to ${app}`);
  await cloudAdminPool.query(`revoke temporary on database ${database} from public`);
  await cloudAdminPool.query(`grant connect on database ${database} to ${migrator}`);
  await cloudAdminPool.query(`revoke create on schema public from public`);
  await cloudAdminPool.query(`grant usage, create on schema public to ${migrator}`);
  await cloudAdminPool.query(`alter schema drizzle owner to ${migrator}`);
  await cloudAdminPool.query(`revoke all on schema drizzle from public`);
  await cloudAdminPool.query(`grant usage, create on schema drizzle to ${migrator}`);
  await cloudAdminPool.query(`grant ${migrator} to ${app} with admin true, inherit false, set false granted by "cloud_admin"`);
  await cloudAdminPool.query(`alter default privileges for role "cloud_admin" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role "platform_app" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role "pg_database_owner" revoke execute on functions from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke all privileges on tables from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke all privileges on sequences from public`);
  await cloudAdminPool.query(`alter default privileges for role ${migrator} revoke execute on functions from public`);

  const relations = await cloudAdminPool.query(`
    select namespace_record.nspname as schema_name,
           relation_record.relname as object_name,
           relation_record.relkind
    from pg_class relation_record
    join pg_namespace namespace_record on namespace_record.oid = relation_record.relnamespace
    where namespace_record.nspname in ('public', 'drizzle')
      and relation_record.relkind in ('r', 'p', 'S', 'i', 'I')
    order by namespace_record.nspname, relation_record.relname
  `);
  for (const row of relations.rows) {
    const object = `${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.object_name)}`;
    const command = row.relkind === "S"
      ? `alter sequence ${object} owner to ${migrator}`
      : row.relkind === "i" || row.relkind === "I"
        ? `alter index ${object} owner to ${migrator}`
        : `alter table ${object} owner to ${migrator}`;
    await cloudAdminPool.query(command);
  }
  const enumTypes = await cloudAdminPool.query(`
    select namespace_record.nspname as schema_name, type_record.typname as type_name
    from pg_type type_record
    join pg_namespace namespace_record on namespace_record.oid = type_record.typnamespace
    where namespace_record.nspname = 'public' and type_record.typtype = 'e' and type_record.typisdefined
    order by type_record.typname
  `);
  for (const row of enumTypes.rows) {
    await cloudAdminPool.query(`alter type ${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.type_name)} owner to ${migrator}`);
  }
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    await cloudAdminPool.query(`grant ${record.privilege} on table ${quoteIdentifier(record.schema)}.${quoteIdentifier(record.objectName)} to ${runtime}`);
  }
  return migration;
}

function roleAttributes(role) {
  assert.ok(role);
  return {
    rolcanlogin: role.rolcanlogin,
    rolinherit: role.rolinherit,
    rolsuper: role.rolsuper,
    rolcreatedb: role.rolcreatedb,
    rolcreaterole: role.rolcreaterole,
    rolreplication: role.rolreplication,
    rolbypassrls: role.rolbypassrls,
  };
}

function makePlan(binding, captured, operations, expectedContractDigest = contractDigest, expectedGitShaOverride = expectedGitSha) {
  const publicOperations = operations.map((operation) => {
    const { restore_authority: _restoreAuthority, revoke_grant_option_only: _revokeGrantOptionOnly, ...publicOperation } = operation;
    return publicOperation;
  });
  return createDurablePlan({
    expected_git_sha: expectedGitShaOverride,
    contract_digest: expectedContractDigest,
    target_binding_digest: computeTargetBindingDigest(binding),
    prestate_digest: captured.prestate_digest,
    operation_kind: publicOperations[0].kind,
    operations: publicOperations,
  });
}

function bindingForPool(binding, pool, user) {
  return {
    ...binding,
    expectedCurrentUser: user,
    expectedSessionUser: user,
    connect: () => pool.connect(),
  };
}

function bindingWithFinalVerificationFailure(binding, pool, onPostForwardObservationRelease) {
  let connectionIndex = 0;
  return {
    ...binding,
    async connect() {
      const index = ++connectionIndex;
      const client = await pool.connect();
      return {
        async query(text, values) {
          if (index === 4 && typeof text === "string" && text.includes("platform durable:target_identity")) {
            throw new Error("final verification intentionally unavailable");
          }
          return client.query(text, values);
        },
        async release() {
          client.release();
          if (index === 6) await onPostForwardObservationRelease?.();
        },
      };
    },
  };
}

async function executeDirectMutation(pool, binding, operation) {
  const connection = await pool.connect();
  const session = createMutationSession(connection, binding.logicalDatabaseName);
  let committed = false;
  try {
    await session.begin();
    await session.acquireTargetLock(computeTargetBindingDigest(binding));
    await session.acquireMutationLocks([operation]);
    await session.applyOperation(operation);
    await session.commit();
    committed = true;
  } finally {
    if (!committed) await session.rollback().catch(() => {});
    await connection.release?.();
  }
}

async function executeWithPostLockDrift({ plan, binding, pool, expectedPrestate, expectedContractDigest = contractDigest, journal, rootDir: executionRootDir, drift }) {
  const client = await pool.connect();
  let injected = false;
  const connection = {
    async query(text, values) {
      const result = await client.query(text, values);
      if (!injected && typeof text === "string" && text.includes("platform durable:target_lock")) {
        injected = true;
        await drift();
      }
      return result;
    },
    release() {
      client.release();
    },
  };
  const receipt = await executeDurablePlan({
    plan,
    binding,
    expectedPrestate,
    expectedContractDigest,
    journal,
    mutationConnection: connection,
    rootDir: executionRootDir,
  });
  return { injected, receipt };
}

function assertCanonicalReadiness(prestate) {
  assert.deepEqual(prestate.canonical_checks.readiness_checks, {
    config: "present",
    reachability: "passed",
    schema: "passed",
    migrations: "passed",
    migratorPosture: "passed",
  });
  assert.ok(Object.values(prestate.canonical_checks.runtime_posture_fields).every((value) => value === "passed"));
}

async function assertReadOnlyWriteRejected(migratorPool) {
  const client = await migratorPool.connect();
  try {
    await client.query("begin");
    await client.query("set transaction read only");
    await assert.rejects(
      () => client.query(`create temp table "run185_read_only_forbidden" ("id" integer)`),
      /read-only transaction/i,
    );
  } finally {
    await client.query("rollback").catch(() => {});
    client.release();
  }
}

async function assertRuntimeAndAppSeparation(cloudAdminPool, appPool) {
  const runtimeClient = await cloudAdminPool.connect();
  try {
    await runtimeClient.query("begin");
    await runtimeClient.query(`set local role "platform_runtime"`);
    await assert.rejects(
      () => runtimeClient.query(`create table "public"."run190_runtime_forbidden" ("id" integer)`),
      /permission denied/i,
    );
  } finally {
    await runtimeClient.query("rollback").catch(() => {});
    runtimeClient.release();
  }
  await assert.rejects(
    () => appPool.query(`select count(*) from "public"."users"`),
    /permission denied/i,
  );
}
