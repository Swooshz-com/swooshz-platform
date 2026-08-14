import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, renameSync, unlinkSync, writeFileSync } from "node:fs";
import test from "node:test";
import { join } from "node:path";

import { readFile, writeFile } from "node:fs/promises";
import { Pool } from "pg";

import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../dist/db/runtime-posture.js";
import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresFixtures,
  createAdmittedMutationPool,
  invalidateDisposablePostgresAdmission,
} from "./support/disposable-postgres-fixture.mjs";
import {
  buildFocusedDefaultPgpassControlEnvironment,
} from "../scripts/run-disposable-migrator-alignment-tests.mjs";

const requireNode = createRequire(import.meta.url);
const pgPassHelper = requireNode("pgpass/lib/helper.js");

const primaryDatabaseUrl = process.env.MIGRATOR_ALIGNMENT_TEST_DATABASE_URL;
const primaryOperatorUrl = process.env.MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL;
const secondaryDatabaseUrl = process.env.MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL;
const secondaryOperatorUrl = process.env.MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL;
const disposableConfirmed =
  process.env.MIGRATOR_ALIGNMENT_TEST_CONFIRM === "disposable-only";
const skipReason =
  primaryDatabaseUrl &&
  primaryOperatorUrl &&
  secondaryDatabaseUrl &&
  secondaryOperatorUrl &&
  disposableConfirmed
    ? false
    : "requires the explicitly confirmed disposable migrator alignment fixture";

const primaryDatabaseName = "migrator_alignment_test";
const secondaryDatabaseName = "migrator_alignment_test_secondary";
const ownedPort = 56432;
const fixtureRoleNames = [
  "platform_app",
  "platform_migrator",
  "platform_runtime",
  "provider_owner",
];
const allowedAclRoles = new Set([
  ...fixtureRoleNames,
  "pg_database_owner",
  "postgres",
  "PUBLIC",
]);
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const syntheticMigratorPassword = "synthetic-migrator-password";
const wrongMigratorPassword = "synthetic-wrong-migrator-password";
const publicAuthorityProbeTable = "__pgdbowner_authority_probe";
const structuredFailureReceiptPrefix = "PLATFORM_MIGRATOR_FAILURE_V1=";
const structuredFailureReceiptFileEnvironmentVariable =
  "PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE";
const structuredFailureProgressFileEnvironmentVariable =
  "PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE";
const defaultPgpassControlScript = `
import { Pool } from "pg";

let pool = null;
let client = null;
try {
  const databaseUrl =
    process.env.MIGRATOR_ALIGNMENT_TEST_DEFAULT_PGPASS_URL;
  const parsed = new URL(databaseUrl);
  if (
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    typeof process.env.HOME !== "string" ||
    typeof process.env.APPDATA !== "string" ||
    Object.keys(process.env).some((key) => key.startsWith("PG"))
  ) {
    throw new Error();
  }
  pool = new Pool({ connectionString: databaseUrl, max: 1 });
  client = await pool.connect();
  const result = await client.query(
    "select current_user::text as cu, session_user::text as su, current_database()::text as cd",
  );
  if (
    result.rows[0]?.cu !== "platform_migrator" ||
    result.rows[0]?.su !== "platform_migrator" ||
    result.rows[0]?.cd !== "migrator_alignment_test"
  ) {
    throw new Error();
  }
} catch {
  process.exitCode = 1;
} finally {
  client?.release();
  await pool?.end().catch(() => {});
}
`;

const structuredReceiptProgressMaxBytes = 16 * 1024;
const structuredReceiptTransportTestMode =
  process.env.PLATFORM_MIGRATOR_FAILURE_RECEIPT_TEST ?? "";
const structuredFingerprintFields = [
  "databaseOwner",
  "schemaOwners",
  "objectOwners",
  "enumOwners",
  "routineOwners",
  "databaseAcl",
  "schemaAcls",
  "defaultAcl",
  "attributes",
  "memberships",
];
const structuredFailurePhases = new Set([
  "baseline_capture",
  "forward_migration",
  "migrated_state_assertion",
  "reverse_transfer",
  "reverse_role_restoration",
  "post_reverse_exact_fingerprint",
  "acl_residue_setup",
  "acl_residue_permissive_helper",
  "acl_residue_exact_rejection",
  "acl_residue_cleanup",
  "post_acl_exact_fingerprint",
  "default_acl_residue_setup",
  "default_acl_permissive_helper",
  "default_acl_exact_rejection",
  "default_acl_residue_cleanup",
  "post_default_acl_exact_fingerprint",
]);
const structuredAssertionCategories = new Set([
  "baseline_lifecycle",
  "forward_migration",
  "migrated_state_assertion",
  "exact_reverse_rollback",
  "acl_residue_cleanup",
  "default_acl_residue_cleanup",
  "membership_inventory",
  "focused_child_defect",
]);
const structuredCleanupPhases = new Set([
  "not_started",
  "started",
  "complete",
  "failed",
]);
const structuredTransportStates = new Set([
  "phase_armed",
  "failure_catch_entered",
  "failure_receipt_write_armed",
]);
let activeStructuredFailureContext = null;

test(
  "ACL residue expected grantor derives from the baseline database owner",
  () => {
    const baseline = { databaseOwner: "platform_app" };
    const residue = buildExpectedDatabaseAclResidue(
      "migrator_alignment_test",
      baseline,
    );
    assert.deepEqual(residue.split("\u0000"), [
      "migrator_alignment_test",
      "platform_app",
      "platform_runtime",
      "CONNECT",
      "false",
    ]);
    assert.notEqual(residue.split("\u0000")[1], "postgres");
  },
);

function withStructuredFailureReceipt(testId, operation) {
  const previousContext = activeStructuredFailureContext;
  const context = {
    version: 1,
    testId,
    phase: "baseline_capture",
    assertionCategory: "focused_child_defect",
    fingerprintFields: [],
    tupleCounts: [],
    cleanupPhase: "not_started",
    transportState: "phase_armed",
  };
  activeStructuredFailureContext = context;
  try {
    persistStructuredFailureProgress(context);
  } catch (error) {
    activeStructuredFailureContext = previousContext;
    throw error;
  }
  return Promise.resolve()
    .then(operation)
    .catch(async (error) => {
      try {
        context.transportState = "failure_catch_entered";
        persistStructuredFailureProgress(context);
        context.transportState = "failure_receipt_write_armed";
        persistStructuredFailureProgress(context);
        await emitStructuredFailureReceipt(context);
      } catch {
        // Preserve the original test failure; the parent reads durable progress when the final receipt is absent.
      }
      throw error;
    })
    .finally(() => {
      activeStructuredFailureContext = previousContext;
    });
}
function markStructuredFailurePhase(phase, assertionCategory) {
  if (!activeStructuredFailureContext) return;
  if (structuredFailurePhases.has(phase)) {
    activeStructuredFailureContext.phase = phase;
  }
  if (structuredAssertionCategories.has(assertionCategory)) {
    activeStructuredFailureContext.assertionCategory = assertionCategory;
  }
  persistStructuredFailureProgress(activeStructuredFailureContext);
}

function markStructuredCleanupPhase(phase) {
  if (
    activeStructuredFailureContext &&
    structuredCleanupPhases.has(phase)
  ) {
    activeStructuredFailureContext.cleanupPhase = phase;
    persistStructuredFailureProgress(activeStructuredFailureContext);
  }
}

function recordStructuredFingerprintSnapshot(fingerprint) {
  if (!activeStructuredFailureContext) return;
  activeStructuredFailureContext.fingerprintFields = [
    ...structuredFingerprintFields,
  ];
  activeStructuredFailureContext.tupleCounts = structuredFingerprintFields.map(
    (field) => `${field}:${structuredTupleCount(fingerprint[field])}/${structuredTupleCount(fingerprint[field])}`,
  );
  persistStructuredFailureProgress(activeStructuredFailureContext);
}

function recordStructuredFingerprintComparison(actual, expected) {
  if (!activeStructuredFailureContext) return;
  const differingFields = structuredFingerprintFields.filter(
    (field) => JSON.stringify(actual?.[field]) !== JSON.stringify(expected?.[field]),
  );
  if (differingFields.length > 0) {
    activeStructuredFailureContext.fingerprintFields = differingFields;
    activeStructuredFailureContext.tupleCounts = differingFields.map(
      (field) => `${field}:${structuredTupleCount(actual?.[field])}/${structuredTupleCount(expected?.[field])}`,
    );
  }
  persistStructuredFailureProgress(activeStructuredFailureContext);
}

function structuredTupleCount(value) {
  if (Array.isArray(value)) return value.length;
  return value === null || value === undefined ? 0 : 1;
}

async function emitStructuredFailureReceipt(context) {
  const filePath = process.env[structuredFailureReceiptFileEnvironmentVariable];
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new Error();
  }
  if (structuredReceiptTransportTestMode === "writer-failure-boundary") {
    throw new Error();
  }
  const receipt = {
    version: 1,
    test_id: typeof context.testId === "string" ? context.testId : "unknown",
    phase: structuredFailurePhases.has(context.phase)
      ? context.phase
      : "baseline_capture",
    assertion_category: structuredAssertionCategories.has(
      context.assertionCategory,
    )
      ? context.assertionCategory
      : "focused_child_defect",
    fingerprint_fields: structuredFingerprintFields.filter((field) =>
      context.fingerprintFields?.includes(field),
    ),
    tuple_counts: Array.isArray(context.tupleCounts)
      ? context.tupleCounts.filter((entry) =>
          typeof entry === "string" &&
          /^(?:databaseOwner|schemaOwners|objectOwners|enumOwners|routineOwners|databaseAcl|schemaAcls|defaultAcl|attributes|memberships):(?:0|[1-9]\d*)\/(?:0|[1-9]\d*)$/u.test(entry),
        )
      : [],
    cleanup_phase: structuredCleanupPhases.has(context.cleanupPhase)
      ? context.cleanupPhase
      : "not_started",
  };
  await writeFile(
    filePath,
    structuredFailureReceiptPrefix + JSON.stringify(receipt) + "\n",
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
}

function persistStructuredFailureProgress(context) {
  const filePath = process.env[structuredFailureProgressFileEnvironmentVariable];
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new Error();
  }
  const payload = {
    version: 1,
    test_id: isSafeStructuredTestId(context?.testId) ? context.testId : "unknown",
    phase: structuredFailurePhases.has(context?.phase)
      ? context.phase
      : "baseline_capture",
    assertion_category: structuredAssertionCategories.has(context?.assertionCategory)
      ? context.assertionCategory
      : "focused_child_defect",
    fingerprint_fields: structuredFingerprintFields.filter((field) =>
      context?.fingerprintFields?.includes(field),
    ),
    tuple_counts: Array.isArray(context?.tupleCounts)
      ? context.tupleCounts.filter(isBoundedStructuredTupleCount)
      : [],
    cleanup_phase: structuredCleanupPhases.has(context?.cleanupPhase)
      ? context.cleanupPhase
      : "not_started",
    transport_state: structuredTransportStates.has(context?.transportState)
      ? context.transportState
      : "phase_armed",
  };
  const serialized = JSON.stringify(payload) + "\n";
  if (Buffer.byteLength(serialized, "utf8") > structuredReceiptProgressMaxBytes) {
    throw new Error();
  }
  const temporaryPath = filePath + "." + randomUUID() + ".tmp";
  try {
    writeFileSync(temporaryPath, serialized, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    renameSync(temporaryPath, filePath);
  } finally {
    try {
      unlinkSync(temporaryPath);
    } catch {
      // Parent cleanup removes the runner-owned directory if replacement fails.
    }
  }
}

function isSafeStructuredTestId(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 96 && /^[A-Za-z0-9._:-]+$/u.test(value);
}

function isBoundedStructuredTupleCount(entry) {
  if (typeof entry !== "string") return false;
  const parts = entry.split(/[:/]/u);
  return parts.length === 3 &&
    structuredFingerprintFields.includes(parts[0]) &&
    isNonnegativeStructuredCount(parts[1]) &&
    isNonnegativeStructuredCount(parts[2]);
}

function isNonnegativeStructuredCount(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 6) return false;
  if (value.length > 1 && value.startsWith("0")) return false;
  return [...value].every((character) => character >= "0" && character <= "9");
}
async function forceStructuredReceiptTransportFailure(testId) {
  return withStructuredFailureReceipt(testId, async () => {
    markStructuredFailurePhase(
      "post_reverse_exact_fingerprint",
      "exact_reverse_rollback",
    );
    recordStructuredFingerprintComparison(
      { databaseAcl: ["actual"] },
      { databaseAcl: ["expected"] },
    );
    markStructuredCleanupPhase("complete");
    throw new Error("synthetic structured receipt transport failure");
  });
}

if (structuredReceiptTransportTestMode === "child-boundary") {
  process.stdout.write("# TAP-looking diagnostic noise\n");
  process.stderr.write("spec-looking diagnostic noise\n");
  test(
    "test-only structured receipt transport child failure",
    async () => forceStructuredReceiptTransportFailure(
      "DL-128-REPO-011-A3-child-boundary",
    ),
  );
}

if (structuredReceiptTransportTestMode === "writer-failure-boundary") {
  test(
    "test-only final receipt writer failure preserves durable progress",
    async () => forceStructuredReceiptTransportFailure(
      "DL-128-REPO-011-A3-writer-failure",
    ),
  );
}

if (structuredReceiptTransportTestMode === "abrupt-exit-boundary") {
  test(
    "test-only abrupt child exit preserves durable progress",
    async () => withStructuredFailureReceipt(
      "DL-128-REPO-011-A3-abrupt-exit",
      async () => {
        markStructuredFailurePhase(
          "post_reverse_exact_fingerprint",
          "exact_reverse_rollback",
        );
        recordStructuredFingerprintComparison(
          { databaseAcl: ["actual"] },
          { databaseAcl: ["expected"] },
        );
        markStructuredCleanupPhase("complete");
        process.exit(23);
      },
    ),
  );
}

if (structuredReceiptTransportTestMode === "duplicate-boundary") {
  test(
    "test-only duplicate structured receipt writes fail closed",
    async () => {
      await assert.rejects(() =>
        forceStructuredReceiptTransportFailure(
          "DL-128-REPO-011-A3-first-receipt",
        ),
      );
      await assert.rejects(() =>
        forceStructuredReceiptTransportFailure(
          "DL-128-REPO-011-A3-second-receipt",
        ),
      );
      throw new Error("synthetic duplicate receipt test failure");
    },
  );
}
let retainedPrimaryPreForwardBaseline;

test(
  "DL-128-REPO-003: the automatic ADMIN=true bootstrap edge is accident protection only and admits latent self-escalation until provider revocation",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-003-bootstrap-edge",
    async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      const baseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(baseline, "pg_database_owner");

      await createMigratorRoleAsLegacyOwner(primary.appPool);

      await assertExactProtectedEdge(primary.adminPool);
      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /permission denied to set role/i,
      );

      await primary.appPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await primary.appPool.query(
        `grant platform_migrator to platform_app with set true, inherit false`,
      );
      assertExactTransferWindowEdges(await readMembershipEdges(primary.adminPool));
      await proveSelfGrantEscalation(primary.appPool);

      await primary.appPool.query(
        `revoke platform_migrator from platform_app granted by platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);
      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /permission denied to set role/i,
      );

      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await assertZeroMigratorMembership(primary.adminPool);
      await assertMigratorRoleAttribute(
        primary.adminPool,
        "rolcreatedb",
        false,
      );

      await assertQueryRejected(
        primary.appPool,
        `grant platform_migrator to platform_app with set true, inherit false`,
        /permission denied to grant role/i,
      );
      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /permission denied to set role/i,
      );

      await dropMigratorRole(primary.adminPool);
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      assertExactFingerprint(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );
    } finally {
      await closeFixtures(fixture);
    }
    },
  ),
);

test(
  "bounded supplemental SET edge, real password credential admission, target-NOCREATEDB negative control, pg_database_owner authority transfer, provider final revocation, pre-completion legacy-retirement guard",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-003-forward-migration",
    async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      const baseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      retainedPrimaryPreForwardBaseline = baseline;
      assertBaselineFingerprint(baseline, "pg_database_owner");

      await createMigratorRoleAsLegacyOwner(primary.appPool);
      await primary.appPool.query(
        `grant connect on database ${identifier(primary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(primary.adminPool);
      await assertExactProtectedEdge(primary.adminPool);

      // platform_migrator begins NOLOGIN with no password: prove catalog state
      // and prove direct migrator login fails before activation. The migrator
      // host-authentication path is scram-sha-256 enforced by the disposable
      // runner, so a passwordless connection cannot authenticate and a
      // password-bearing connection fails until the exact synthetic password
      // is installed.
      await assertMigratorRoleAttribute(primary.adminPool, "rolcanlogin", false);
      await assertMigratorPasswordInstalled(primary.adminPool, false);
      await assertQueryRejected(
        primary.migratorPasswordPool,
        `select 1`,
        /password authentication failed|no password supplied/i,
      );
      await assertQueryRejected(
        primary.migratorNoPasswordPool,
        `select 1`,
        /client password must be a string|no password supplied|password authentication failed/i,
      );
      assertOwnershipFieldsUnchanged(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );

      await primary.adminPool.query(
        `alter role platform_migrator login password '${syntheticMigratorPassword}'`,
      );
      await assertMigratorRoleAttribute(primary.adminPool, "rolcanlogin", true);
      await assertMigratorPasswordInstalled(primary.adminPool, true);
      await assertFocusedPassfileIsolation(primary);

      // Correct password succeeds: the fresh admitted connection reads back
      // the exact expected role and database before any ownership transfer.
      await validateMigratorLoginAdmission(
        primary.migratorPasswordPool,
        primary.databaseName,
      );
      await assertQueryRejected(
        primary.migratorWrongPasswordPool,
        `select 1`,
        /password authentication failed/i,
      );
      await assertQueryRejected(
        primary.migratorNoPasswordPool,
        `select 1`,
        /client password must be a string|no password supplied|password authentication failed/i,
      );
      assertOwnershipFieldsUnchanged(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );

      // Corrected target-NOCREATEDB negative control: the executing legacy
      // owner holds the automatic bootstrap edge (SET=false) and therefore
      // lacks the target-role assumption/SET-capable authority required for
      // the transfer. The transfer is rejected, the target remains
      // NOCREATEDB with LOGIN unchanged, and no persistent mutation occurs.
      await assertQueryRejected(
        primary.appPool,
        `alter database ${identifier(primary.databaseName)} owner to platform_migrator`,
        /must be able to SET ROLE|permission denied/i,
      );
      await assertMigratorRoleAttribute(primary.adminPool, "rolcreatedb", false);
      await assertMigratorRoleAttribute(primary.adminPool, "rolcanlogin", true);
      assertOwnershipFieldsUnchanged(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        baseline,
      );

      // Real pg_database_owner starting-state proof: the fresh PostgreSQL 17
      // database leaves `public` owned by the predefined pg_database_owner
      // role, whose single implicit member is the current database owner
      // (platform_app at baseline). The database owner therefore exercises
      // the public owner authority before transfer; platform_migrator does
      // not.
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertCurrentDatabaseOwner(
        primary.adminPool,
        primary.databaseName,
        "platform_app",
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        true,
      );
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        false,
      );

      await primary.appPool.query(
        `grant platform_migrator to platform_app with set true, inherit false`,
      );
      assertExactTransferWindowEdges(await readMembershipEdges(primary.adminPool));

      await primary.adminPool.query(
        `grant create on schema drizzle to platform_migrator`,
      );
      await primary.adminPool.query(
        `grant create on schema appdata to platform_migrator`,
      );

      markStructuredFailurePhase("forward_migration", "forward_migration");
      await forwardTransferInOneTransaction(primary);

      await assertMigratorRoleAttribute(primary.adminPool, "rolcreatedb", false);
      await assertMigratorFinalAttributes(primary.adminPool);

      await primary.appPool.query(
        `revoke platform_migrator from platform_app granted by platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      markStructuredFailurePhase("migrated_state_assertion", "migrated_state_assertion");
      const forwardFingerprint = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(forwardFingerprint.databaseOwner, "platform_migrator");
      assert.deepEqual(forwardFingerprint.schemaOwners, [
        "appdata=platform_migrator",
        "drizzle=platform_migrator",
        "public=pg_database_owner",
      ]);
      for (const objectName of [
        "widgets",
        "widgets_label_uidx",
        "counter_seq",
        "__drizzle_migrations",
        "users",
        ...contractTableNames(),
      ]) {
        assert.ok(
          forwardFingerprint.objectOwners.includes(
            `${objectName}=platform_migrator`,
          ),
          `expected ${objectName} owned by platform_migrator`,
        );
      }
      assert.ok(forwardFingerprint.enumOwners.includes("widget_status=platform_migrator"));
      assert.ok(forwardFingerprint.routineOwners.includes("widget_summary=platform_migrator"));

      const ledgerBefore = await primary.adminPool.query(
        "select count(*)::int as c from drizzle.__drizzle_migrations",
      );
      const migrationClient = await primary.migratorPasswordPool.connect();
      try {
        await migrationClient.query("begin");
        await migrationClient.query(
          "insert into drizzle.__drizzle_migrations (id, hash) select coalesce(max(id), 0) + 1, 'bounded-migration-proof' from drizzle.__drizzle_migrations",
        );
        await migrationClient.query("rollback");
      } finally {
        migrationClient.release();
      }
      const ledgerAfter = await primary.adminPool.query(
        "select count(*)::int as c from drizzle.__drizzle_migrations",
      );
      assert.equal(ledgerAfter.rows[0].c, ledgerBefore.rows[0].c);

      // Database-owner transfer consequence: `public` remains owned by
      // pg_database_owner, so the implicit role exercising that public owner
      // authority is now the new database owner (platform_migrator), and the
      // former database owner (platform_app) loses it.
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertCurrentDatabaseOwner(
        primary.adminPool,
        primary.databaseName,
        "platform_migrator",
      );
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        true,
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        false,
      );
      await assertRuntimeGrantSetExact(primary.adminPool);
      await assertRuntimePosture(primary.adminPool);

      await primary.appPool.query(
        `grant platform_migrator to platform_app with set true, inherit false`,
      );
      assertExactTransferWindowEdges(await readMembershipEdges(primary.adminPool));
      await proveSelfGrantEscalation(primary.appPool);
      await primary.appPool.query(
        `revoke platform_migrator from platform_app granted by platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await assertZeroMigratorMembership(primary.adminPool);

      // Pre-completion legacy-retirement guard: at the migrated zero-membership
      // state, before the replacement and rollback proof completes, the legacy
      // role cannot be retired or dropped and its authority remains available
      // for rollback.
      await runReversibleLegacyNoLoginControl(primary);
      await assertQueryRejected(
        primary.adminPool,
        `drop role platform_app`,
        /depends on it|cannot be dropped/i,
      );
      await assertLegacyAuthorityAvailable(primary.appPool);

      await assertQueryRejected(
        primary.appPool,
        `grant platform_migrator to platform_app with set true, inherit false`,
        /permission denied to grant role/i,
      );
      await assertQueryRejected(
        primary.appPool,
        `set role platform_migrator`,
        /permission denied to set role/i,
      );

      markStructuredFailurePhase("migrated_state_assertion", "migrated_state_assertion");
      const finalFingerprint = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(finalFingerprint.databaseOwner, "platform_migrator");
      assert.deepEqual(finalFingerprint.schemaOwners, [
        "appdata=platform_migrator",
        "drizzle=platform_migrator",
        "public=pg_database_owner",
      ]);
      for (const objectName of [
        "widgets",
        "widgets_label_uidx",
        "counter_seq",
        "__drizzle_migrations",
        "users",
        ...contractTableNames(),
      ]) {
        assert.ok(
          finalFingerprint.objectOwners.includes(
            `${objectName}=platform_migrator`,
          ),
          `expected ${objectName} owned by platform_migrator`,
        );
      }
      assert.ok(finalFingerprint.enumOwners.includes("widget_status=platform_migrator"));
      assert.ok(finalFingerprint.routineOwners.includes("widget_summary=platform_migrator"));
      assert.equal(finalFingerprint.memberships.length, 0);

      await assertMigratorFinalAttributes(primary.adminPool);
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        true,
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        false,
      );
      await assertRuntimeFinalPosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
    },
  ),
);

test(
  "exact reverse rollback via the provider authority restores the complete baseline including pg_database_owner authority from the final zero-membership state",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-003-exact-reverse-rollback",
    async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      const preForwardBaseline = retainedPrimaryPreForwardBaseline;
      assert.ok(preForwardBaseline);
      markStructuredFailurePhase("migrated_state_assertion", "migrated_state_assertion");
      const migratedState = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assert.equal(migratedState.databaseOwner, "platform_migrator");
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertZeroMigratorMembership(primary.adminPool);
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        true,
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        false,
      );

      markStructuredFailurePhase("reverse_transfer", "exact_reverse_rollback");
      await reverseTransferViaProviderAuthority(primary);
      markStructuredFailurePhase("reverse_role_restoration", "exact_reverse_rollback");
      await dropMigratorRole(primary.adminPool);

      markStructuredFailurePhase("post_reverse_exact_fingerprint", "exact_reverse_rollback");
      const restored = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertExactFingerprint(
        restored,
        preForwardBaseline,
      );
      assertBaselineFingerprint(restored, "pg_database_owner");
      assert.equal(restored.databaseOwner, "platform_app");
      assert.equal(restored.memberships.length, 0);
      assert.equal(
        restored.attributes.some((row) => row.rolname === "platform_migrator"),
        false,
      );
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        true,
      );
      await assertAclResidueNegativeControl(
        primary.adminPool,
        primary.databaseName,
        preForwardBaseline,
      );
      await assertDefaultAclResidueNegativeControl(
        primary.adminPool,
        primary.databaseName,
        preForwardBaseline,
      );
      assertExactFingerprint(
        await readOwnershipFingerprint(
          primary.adminPool,
          primary.databaseName,
        ),
        preForwardBaseline,
      );
      await assertRuntimeFinalPosture(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
    },
  ),
);

test(
  "platform_runtime edge revocation and the explicitly labelled stable-provider-owner public variant executes the bounded migrator transaction",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-003-secondary-transfer",
    async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      const secondary = fixture.secondary;
      const primaryBaseline = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertBaselineFingerprint(primaryBaseline, "pg_database_owner");
      const secondaryBaseline = await readOwnershipFingerprint(
        secondary.adminPool,
        secondary.databaseName,
      );
      assertBaselineFingerprint(secondaryBaseline, "provider_owner");

      await primary.adminPool.query(
        `grant platform_runtime to platform_app with admin true, inherit false, set false`,
      );
      const runtimeEdge = (await readMembershipEdges(primary.adminPool))
        .filter((edge) => edge.granted_role === "platform_runtime");
      assert.equal(runtimeEdge.length, 1);
      assert.equal(runtimeEdge[0].granted_role, "platform_runtime");
      assert.equal(runtimeEdge[0].member, "platform_app");
      assert.equal(runtimeEdge[0].grantor, "postgres");
      assert.equal(runtimeEdge[0].admin_option, true);
      assert.equal(runtimeEdge[0].inherit_option, false);
      assert.equal(runtimeEdge[0].set_option, false);
      const edgesWhereRuntimeIsMember = (await readMembershipEdges(primary.adminPool))
        .filter((edge) => edge.member === "platform_runtime");
      assert.equal(edgesWhereRuntimeIsMember.length, 0);
      await assertRuntimeGrantSetExact(primary.adminPool);
      const runtimeOwns = await runtimeOwnershipCounts(primary.adminPool);
      assert.deepEqual(runtimeOwns, {
        dbs: 0,
        relations: 0,
        routines: 0,
        schemas: 0,
        types: 0,
      });

      await primary.adminPool.query(
        `revoke platform_runtime from platform_app`,
      );
      assert.equal(
        (await readMembershipEdges(primary.adminPool))
          .filter((edge) => edge.granted_role === "platform_runtime").length,
        0,
      );
      await assertRuntimePosture(primary.adminPool);
      assertExactFingerprint(
        await readOwnershipFingerprint(primary.adminPool, primary.databaseName),
        primaryBaseline,
      );

      markStructuredFailurePhase("forward_migration", "forward_migration");
      await createMigratorRoleAsLegacyOwner(secondary.appPool);
      await secondary.appPool.query(
        `grant connect on database ${identifier(secondary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(secondary.adminPool);
      await assertExactProtectedEdge(secondary.adminPool);
      await secondary.adminPool.query(
        `grant create, usage on schema public to platform_migrator`,
      );
      await secondary.adminPool.query(
        `alter role platform_migrator login password '${syntheticMigratorPassword}'`,
      );
      await validateMigratorLoginAdmission(
        secondary.migratorPasswordPool,
        secondaryDatabaseName,
      );
      await assertQueryRejected(
        secondary.migratorWrongPasswordPool,
        `select 1`,
        /password authentication failed/i,
      );
      await assertQueryRejected(
        secondary.migratorNoPasswordPool,
        `select 1`,
        /client password must be a string|no password supplied|password authentication failed/i,
      );
      const boundedClient = await secondary.migratorPasswordPool.connect();
      try {
        await boundedClient.query("begin");
        await boundedClient.query(
          `create table public.__migrator_bounded_probe (id integer primary key)`,
        );
        await boundedClient.query(
          `insert into public.__migrator_bounded_probe (id) values (1)`,
        );
        const probe = await boundedClient.query(
          `select count(*)::int as c from public.__migrator_bounded_probe`,
        );
        assert.equal(probe.rows[0].c, 1);
        await boundedClient.query("rollback");
      } finally {
        boundedClient.release();
      }
      const probeResidue = await secondary.adminPool.query(
        `
          select count(*)::int as c
            from pg_class probe_record
            join pg_namespace probe_schema
              on probe_schema.oid = probe_record.relnamespace
           where probe_schema.nspname = 'public'
             and probe_record.relname = '__migrator_bounded_probe'
        `,
      );
      assert.equal(probeResidue.rows[0].c, 0);
      assert.equal(
        await schemaOwner(secondary.adminPool, secondary.databaseName, "public"),
        "provider_owner",
      );
      await assertRuntimePosture(secondary.adminPool);

      await secondary.adminPool.query(
        `revoke create, usage on schema public from platform_migrator`,
      );
      await secondary.adminPool.query(
        `revoke connect on database ${identifier(secondary.databaseName)} from platform_migrator`,
      );
      await secondary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await dropMigratorRole(secondary.adminPool);
      markStructuredFailurePhase(
        "post_reverse_exact_fingerprint",
        "exact_reverse_rollback",
      );
      assertExactFingerprint(
        await readOwnershipFingerprint(
          secondary.adminPool,
          secondary.databaseName,
        ),
        secondaryBaseline,
      );
    } finally {
      await closeFixtures(fixture);
    }
    },
  ),
);

test(
  "DL-128-REPO-004: the complete membership inventory rejects unexpected platform_migrator edges in member and grantor positions",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-004-membership-inventory",
    async () => {
    const fixture = await openFixtures();
    try {
      const primary = fixture.primary;
      markStructuredFailurePhase("baseline_capture", "baseline_lifecycle");
      markStructuredFailurePhase("migrated_state_assertion", "membership_inventory");
      await createMigratorRoleAsLegacyOwner(primary.appPool);
      await assertExactProtectedEdge(primary.adminPool);

      await primary.adminPool.query(
        `grant platform_runtime to platform_migrator`,
      );
      await assert.rejects(
        () => assertExactProtectedEdge(primary.adminPool),
        /exactly/,
      );
      await primary.adminPool.query(
        `revoke platform_runtime from platform_migrator`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await primary.adminPool.query(
        `grant platform_runtime to platform_migrator with admin true`,
      );
      const grantorClient = await primary.adminPool.connect();
      try {
        await grantorClient.query(`set role platform_migrator`);
        await grantorClient.query(`grant platform_runtime to platform_app`);
        await assert.rejects(
          () => assertExactProtectedEdge(primary.adminPool),
          /exactly/,
        );
        await grantorClient.query(`revoke platform_runtime from platform_app`);
        await grantorClient.query(`reset role`);
      } finally {
        grantorClient.release();
      }
      await primary.adminPool.query(
        `revoke platform_runtime from platform_migrator`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await primary.adminPool.query(
        `revoke platform_migrator from platform_app`,
      );
      await assertZeroMigratorMembership(primary.adminPool);
      await dropMigratorRole(primary.adminPool);
    } finally {
      await closeFixtures(fixture);
    }
    },
  ),
);

async function createMigratorRoleAsLegacyOwner(appPool) {
  await appPool.query(
    `create role platform_migrator nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls`,
  );
}

async function installMigratorDefaultPrivileges(adminPool) {
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke all privileges on tables from public",
  );
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke all privileges on sequences from public",
  );
  await adminPool.query(
    "alter default privileges for role platform_migrator revoke execute on functions from public",
  );
}

async function dropMigratorRole(adminPool) {
  await adminPool.query(`drop owned by platform_migrator`);
  const defaultPrivilegeResidue = await adminPool.query(
    `
      select count(*)::int as c
        from pg_default_acl default_record
        join pg_roles role_record on role_record.oid = default_record.defaclrole
       where role_record.rolname = 'platform_migrator'
    `,
  );
  assert.equal(defaultPrivilegeResidue.rows.length, 1);
  assert.equal(
    defaultPrivilegeResidue.rows[0].c,
    0,
    "platform_migrator default-privilege records must be removed before the role drop",
  );
  await adminPool.query(`drop role platform_migrator`);
}

async function validateMigratorLoginAdmission(migratorPool, expectedDatabase) {
  const client = await migratorPool.connect();
  try {
    const result = await client.query(
      `select current_user::text as cu, session_user::text as su, current_database()::text as cd`,
    );
    assert.equal(result.rows[0].cu, "platform_migrator");
    assert.equal(result.rows[0].su, "platform_migrator");
    assert.equal(result.rows[0].cd, expectedDatabase);
  } finally {
    client.release();
  }
}

async function proveSelfGrantEscalation(appPool) {
  const client = await appPool.connect();
  try {
    await client.query(`set role platform_migrator`);
    const identity = await client.query(
      `select current_user::text as cu, session_user::text as su`,
    );
    assert.equal(identity.rows[0].cu, "platform_migrator");
    assert.equal(identity.rows[0].su, "platform_app");
  } finally {
    await client.query(`reset role`).catch(() => {});
    client.release();
  }
}

async function forwardTransferInOneTransaction(primary) {
  const { appPool } = primary;
  const databaseName = primary.databaseName;

  const statements = [
    `alter table drizzle.__drizzle_migrations owner to platform_migrator`,
    `alter table appdata.widgets owner to platform_migrator`,
    `alter sequence appdata.counter_seq owner to platform_migrator`,
    `alter type appdata.widget_status owner to platform_migrator`,
    `alter function appdata.widget_summary() owner to platform_migrator`,
    `alter schema drizzle owner to platform_migrator`,
    `alter schema appdata owner to platform_migrator`,
    `alter database ${identifier(databaseName)} owner to platform_migrator`,
    ...[...new Set(["users", ...contractTableNames()])].map(
      (tableName) =>
        `alter table public.${identifier(tableName)} owner to platform_migrator`,
    ),
  ];
  const client = await appPool.connect();
  try {
    await client.query("begin");
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function reverseTransferViaProviderAuthority(primary) {
  const { adminPool } = primary;
  const databaseName = primary.databaseName;

  const statements = [
    `alter database ${identifier(databaseName)} owner to platform_app`,
    `alter schema drizzle owner to platform_app`,
    `alter schema appdata owner to platform_app`,
    `alter table drizzle.__drizzle_migrations owner to platform_app`,
    `alter table appdata.widgets owner to platform_app`,
    `alter sequence appdata.counter_seq owner to platform_app`,
    `alter type appdata.widget_status owner to platform_app`,
    `alter function appdata.widget_summary() owner to platform_app`,
    ...[...new Set(["users", ...contractTableNames()])].map(
      (tableName) =>
        `alter table public.${identifier(tableName)} owner to platform_app`,
    ),
    `revoke create on schema drizzle from platform_migrator`,
    `revoke create on schema appdata from platform_migrator`,
    `revoke connect on database ${identifier(databaseName)} from platform_migrator`,
  ];
  const client = await adminPool.connect();
  try {
    await client.query("begin");
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function readMembershipEdges(adminPool) {
  const result = await adminPool.query(
    `
      select roleid_role.rolname as granted_role,
             member_role.rolname as member,
             grantor_role.rolname as grantor,
             membership.admin_option,
             membership.inherit_option,
             membership.set_option
        from pg_auth_members membership
        join pg_roles roleid_role on roleid_role.oid = membership.roleid
        join pg_roles member_role on member_role.oid = membership.member
        left join pg_roles grantor_role on grantor_role.oid = membership.grantor
       where member_role.rolname = any($1::text[])
          or roleid_role.rolname = any($1::text[])
          or grantor_role.rolname = any($1::text[])
       order by granted_role, member, grantor
    `,
    [fixtureRoleNames],
  );
  return result.rows.map((row) => ({
    admin_option: row.admin_option,
    granted_role: row.granted_role,
    grantor: row.grantor,
    inherit_option: row.inherit_option,
    member: row.member,
    set_option: row.set_option,
  }));
}

async function assertZeroMigratorMembership(adminPool) {
  const result = await adminPool.query(
    `
      select count(*)::int as c
        from pg_auth_members membership
        left join pg_roles granted_role on granted_role.oid = membership.roleid
        left join pg_roles member_role on member_role.oid = membership.member
        left join pg_roles grantor_role on grantor_role.oid = membership.grantor
       where granted_role.rolname = 'platform_migrator'
          or member_role.rolname = 'platform_migrator'
          or grantor_role.rolname = 'platform_migrator'
    `,
  );
  assert.equal(result.rows.length, 1);
  assert.equal(
    result.rows[0].c,
    0,
    "final platform_migrator membership inventory must be zero across granted-role, member and grantor positions",
  );
}

async function assertExactProtectedEdge(adminPool) {
  const edges = await readMembershipEdges(adminPool);
  assert.equal(
    edges.length,
    1,
    "complete membership inventory must contain exactly the protected edge",
  );
  const edge = edges[0];
  assert.equal(edge.granted_role, "platform_migrator");
  assert.equal(edge.member, "platform_app");
  assert.equal(edge.grantor, "postgres");
  assert.equal(edge.admin_option, true);
  assert.equal(edge.inherit_option, false);
  assert.equal(edge.set_option, false);
}

function assertExactTransferWindowEdges(edges) {
  assert.equal(
    edges.length,
    2,
    "complete membership inventory must contain exactly the two transfer-window edges",
  );
  const protectedEdge = edges.find((edge) => edge.grantor === "postgres");
  assert.ok(protectedEdge);
  assert.equal(protectedEdge.member, "platform_app");
  assert.equal(protectedEdge.admin_option, true);
  assert.equal(protectedEdge.inherit_option, false);
  assert.equal(protectedEdge.set_option, false);
  const supplementalEdge = edges.find((edge) => edge.grantor === "platform_app");
  assert.ok(supplementalEdge);
  assert.equal(supplementalEdge.member, "platform_app");
  assert.equal(supplementalEdge.admin_option, false);
  assert.equal(supplementalEdge.inherit_option, false);
  assert.equal(supplementalEdge.set_option, true);
}

async function assertMigratorRoleAttribute(adminPool, field, expected) {
  const result = await adminPool.query(
    `select ${field} from pg_roles where rolname = 'platform_migrator'`,
  );
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0][field], expected);
}

async function assertMigratorPasswordInstalled(adminPool, installed) {
  const result = await adminPool.query(
    `
      select (rolpassword is null) as missing
        from pg_authid
       where rolname = 'platform_migrator'
    `,
  );
  assert.equal(result.rows.length, 1);
  assert.equal(
    result.rows[0].missing,
    !installed,
    "platform_migrator password must be installed exactly at the admission step",
  );
}

async function assertMigratorFinalAttributes(adminPool) {
  const result = await adminPool.query(
    `
      select rolsuper, rolcreatedb, rolcreaterole, rolreplication,
             rolbypassrls, rolcanlogin
        from pg_roles
       where rolname = 'platform_migrator'
    `,
  );
  assert.equal(result.rows.length, 1);
  const row = result.rows[0];
  assert.deepEqual(
    {
      bypassrls: row.rolbypassrls,
      createdb: row.rolcreatedb,
      createrole: row.rolcreaterole,
      login: row.rolcanlogin,
      replication: row.rolreplication,
      super: row.rolsuper,
    },
    {
      bypassrls: false,
      createdb: false,
      createrole: false,
      login: true,
      replication: false,
      super: false,
    },
  );
}

async function runtimeOwnershipCounts(adminPool) {
  const result = await adminPool.query(
    `
      select
        (select count(*)::int from pg_database d where d.datdba = (select oid from pg_roles where rolname='platform_runtime')) as dbs,
        (select count(*)::int from pg_namespace s where s.nspowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as schemas,
        (select count(*)::int from pg_class c join pg_namespace s on s.oid=c.relnamespace where c.relowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as relations,
        (select count(*)::int from pg_proc p join pg_namespace s on s.oid=p.pronamespace where p.proowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as routines,
        (select count(*)::int from pg_type t join pg_namespace s on s.oid=t.typnamespace where t.typowner = (select oid from pg_roles where rolname='platform_runtime') and s.nspname not like 'pg_%') as types
    `,
  );
  return result.rows[0];
}

function assertOwnershipFieldsUnchanged(fingerprint, baseline) {
  assert.equal(fingerprint.databaseOwner, baseline.databaseOwner);
  assert.deepEqual(fingerprint.schemaOwners, baseline.schemaOwners);
  assert.deepEqual(fingerprint.objectOwners, baseline.objectOwners);
  assert.deepEqual(fingerprint.enumOwners, baseline.enumOwners);
  assert.deepEqual(fingerprint.routineOwners, baseline.routineOwners);
}

async function assertRuntimeFinalPosture(adminPool) {
  await assertRuntimePosture(adminPool);
  const runtimeEdges = (await readMembershipEdges(adminPool))
    .filter((edge) => edge.granted_role === "platform_runtime");
  assert.equal(runtimeEdges.length, 0);
  assert.deepEqual(await runtimeOwnershipCounts(adminPool), {
    dbs: 0,
    relations: 0,
    routines: 0,
    schemas: 0,
    types: 0,
  });
  await assertRuntimeGrantSetExact(adminPool);
}

async function assertCurrentDatabaseOwner(adminPool, databaseName, expected) {
  const result = await adminPool.query(
    `
      select role_record.rolname as owner
        from pg_database database_record
        join pg_roles role_record on role_record.oid = database_record.datdba
       where database_record.datname = $1
    `,
    [databaseName],
  );
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].owner, expected);
}

async function assertCanCreateInPublic(pool, expectedUser, canCreate) {
  const client = await pool.connect();
  try {
    const identity = await client.query(
      `select current_user::text as cu, session_user::text as su`,
    );
    assert.equal(identity.rows[0].cu, expectedUser);
    await client.query("begin");
    if (canCreate) {
      await client.query(
        `create table public.${identifier(publicAuthorityProbeTable)} (id integer primary key)`,
      );
    } else {
      await assert.rejects(
        () => client.query(
          `create table public.${identifier(publicAuthorityProbeTable)} (id integer primary key)`,
        ),
        /permission denied for schema public/i,
      );
    }
    await client.query("rollback");
  } finally {
    client.release();
  }
}

async function assertLegacyAuthorityAvailable(appPool) {
  const client = await appPool.connect();
  try {
    const identity = await client.query(
      `select current_user::text as cu, session_user::text as su, current_database()::text as cd`,
    );
    assert.equal(identity.rows[0].cu, "platform_app");
    assert.equal(identity.rows[0].su, "platform_app");
  } finally {
    client.release();
  }
}

async function openFixtures() {
  assertFixtureUrl(primaryDatabaseUrl, {
    expectedUser: "platform_app",
    expectedDatabase: primaryDatabaseName,
  });
  assertFixtureUrl(primaryOperatorUrl, {
    expectedUser: "postgres",
    expectedDatabase: primaryDatabaseName,
  });
  assertFixtureUrl(secondaryDatabaseUrl, {
    expectedUser: "platform_app",
    expectedDatabase: secondaryDatabaseName,
  });
  assertFixtureUrl(secondaryOperatorUrl, {
    expectedUser: "postgres",
    expectedDatabase: secondaryDatabaseName,
  });

  const primaryOperatorPool = new Pool({
    connectionString: primaryOperatorUrl,
    max: 4,
  });
  const secondaryOperatorPool = new Pool({
    connectionString: secondaryOperatorUrl,
    max: 4,
  });
  const admission = await admitDisposablePostgresFixtures([
    fixtureDefinition(
      "primary",
      primaryDatabaseUrl,
      primaryOperatorUrl,
      primaryDatabaseName,
    ),
    fixtureDefinition(
      "secondary",
      secondaryDatabaseUrl,
      secondaryOperatorUrl,
      secondaryDatabaseName,
    ),
  ]);
  const primaryAdmin = createAdmittedMutationPool(
    primaryOperatorPool,
    admission,
    "primary",
  );
  const secondaryAdmin = createAdmittedMutationPool(
    secondaryOperatorPool,
    admission,
    "secondary",
  );
  const primaryApp = new Pool({
    connectionString: roleUrl("platform_app", primaryDatabaseName),
    max: 2,
  });
  const primaryMigratorNoPassword = new Pool({
    connectionString: roleUrl("platform_migrator", primaryDatabaseName),
    max: 2,
  });
  const primaryMigratorPassword = new Pool({
    connectionString: roleUrl(
      "platform_migrator",
      primaryDatabaseName,
      syntheticMigratorPassword,
    ),
    max: 2,
  });
  const primaryMigratorWrongPassword = new Pool({
    connectionString: roleUrl(
      "platform_migrator",
      primaryDatabaseName,
      wrongMigratorPassword,
    ),
    max: 2,
  });
  const secondaryApp = new Pool({
    connectionString: roleUrl("platform_app", secondaryDatabaseName),
    max: 2,
  });
  const secondaryMigratorNoPassword = new Pool({
    connectionString: roleUrl("platform_migrator", secondaryDatabaseName),
    max: 2,
  });
  const secondaryMigratorPassword = new Pool({
    connectionString: roleUrl(
      "platform_migrator",
      secondaryDatabaseName,
      syntheticMigratorPassword,
    ),
    max: 2,
  });
  const secondaryMigratorWrongPassword = new Pool({
    connectionString: roleUrl(
      "platform_migrator",
      secondaryDatabaseName,
      wrongMigratorPassword,
    ),
    max: 2,
  });

  return {
    admission,
    pools: [
      primaryOperatorPool,
      secondaryOperatorPool,
      primaryApp,
      primaryMigratorNoPassword,
      primaryMigratorPassword,
      primaryMigratorWrongPassword,
      secondaryApp,
      secondaryMigratorNoPassword,
      secondaryMigratorPassword,
      secondaryMigratorWrongPassword,
    ],
    primary: {
      adminPool: primaryAdmin,
      appPool: primaryApp,
      databaseName: primaryDatabaseName,
      migratorNoPasswordPool: primaryMigratorNoPassword,
      migratorPasswordPool: primaryMigratorPassword,
      migratorWrongPasswordPool: primaryMigratorWrongPassword,
    },
    secondary: {
      adminPool: secondaryAdmin,
      appPool: secondaryApp,
      databaseName: secondaryDatabaseName,
      migratorNoPasswordPool: secondaryMigratorNoPassword,
      migratorPasswordPool: secondaryMigratorPassword,
      migratorWrongPasswordPool: secondaryMigratorWrongPassword,
    },
  };
}

async function closeFixtures(fixture) {
  markStructuredCleanupPhase("started");
  try {
    invalidateDisposablePostgresAdmission(fixture.admission);
    for (const pool of fixture.pools) {
      await pool.end().catch(() => {});
    }
    markStructuredCleanupPhase("complete");
  } catch (error) {
    markStructuredCleanupPhase("failed");
    throw error;
  }
}

function fixtureDefinition(name, databaseUrl, operatorUrl, expectedDatabase) {
  return {
    name,
    connectionString: databaseUrl,
    expectedDatabase,
    expectedUser: "platform_app",
    expectedRuntimeRole: "platform_runtime",
    expectedMutationUser: "postgres",
    operatorUrl,
    expectedObjects: {
      schemas: ["public", "appdata", "drizzle"],
      relations: [
        { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
        { schema: "public", name: "users", kind: "r" },
        { schema: "appdata", name: "widgets", kind: "r" },
        ...contractTableNames().map((name) => ({
          schema: "public",
          name,
          kind: "r",
        })),
      ],
      sequences: [{ schema: "appdata", name: "counter_seq" }],
      routines: [{ schema: "appdata", name: "widget_summary", kind: "f" }],
    },
    transport: { kind: "loopback", phase: "final_start" },
    operatorTransport: { kind: "loopback", phase: "final_start" },
  };
}

async function readOwnershipFingerprint(adminPool, databaseName) {
  const ownership = await adminPool.query(
    `
      select
        (select rolname
           from pg_database database_record
           join pg_roles role_record on role_record.oid = database_record.datdba
          where database_record.datname = $1) as database_owner,
        (select array_agg(schema_record.nspname || '=' || role_record.rolname
                order by schema_record.nspname)
           from pg_namespace schema_record
           join pg_roles role_record on role_record.oid = schema_record.nspowner
          where schema_record.nspname in ('public', 'appdata', 'drizzle')) as schema_owners,
        (select array_agg(relation_record.relname || '=' || role_record.rolname
                order by relation_record.relname)
           from pg_class relation_record
           join pg_namespace schema_record
             on schema_record.oid = relation_record.relnamespace
           join pg_roles role_record on role_record.oid = relation_record.relowner
          where relation_record.relkind in ('r', 'S', 'i')
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as object_owners,
        (select array_agg(type_record.typname || '=' || role_record.rolname
                order by type_record.typname)
           from pg_type type_record
           join pg_namespace schema_record
             on schema_record.oid = type_record.typnamespace
           join pg_roles role_record on role_record.oid = type_record.typowner
          where type_record.typtype = 'e'
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as enum_owners,
        (select array_agg(routine_record.proname || '=' || role_record.rolname
                order by routine_record.proname)
           from pg_proc routine_record
           join pg_namespace schema_record
             on schema_record.oid = routine_record.pronamespace
           join pg_roles role_record on role_record.oid = routine_record.proowner
          where routine_record.prokind = 'f'
            and schema_record.nspname in ('public', 'appdata', 'drizzle')) as routine_owners
    `,
    [databaseName],
  );
  assert.equal(ownership.rows.length, 1);

  const aclRecords = await adminPool.query(
    `
      select 'database' as surface,
             $1::text as object_name,
             coalesce(grantor_role.rolname, 'PUBLIC') as grantor,
             coalesce(grantee_role.rolname, 'PUBLIC') as grantee,
             grant_record.privilege_type as privilege_type,
             grant_record.is_grantable as is_grantable
        from pg_database database_record
        join lateral aclexplode(
          coalesce(
            database_record.datacl,
            acldefault('d', database_record.datdba)
          )
        ) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where database_record.datname = $1
      union all
      select 'schema', schema_record.nspname,
             coalesce(grantor_role.rolname, 'PUBLIC'),
             coalesce(grantee_role.rolname, 'PUBLIC'),
             grant_record.privilege_type,
             grant_record.is_grantable
        from pg_namespace schema_record
        join lateral aclexplode(
          coalesce(
            schema_record.nspacl,
            acldefault('n', schema_record.nspowner)
          )
        ) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where schema_record.nspname in ('public', 'appdata', 'drizzle')
      union all
      select 'default', coalesce(namespace_record.nspname, '<global>')
             || ':' || default_record.defaclobjtype::text,
             coalesce(grantor_role.rolname, 'PUBLIC'),
             coalesce(grantee_role.rolname, 'PUBLIC'),
             grant_record.privilege_type,
             grant_record.is_grantable
        from pg_default_acl default_record
        left join pg_namespace namespace_record
          on namespace_record.oid = default_record.defaclnamespace
        join lateral aclexplode(default_record.defaclacl) grant_record on true
        left join pg_roles grantor_role on grantor_role.oid = grant_record.grantor
        left join pg_roles grantee_role on grantee_role.oid = grant_record.grantee
       where default_record.defaclrole in (
         select oid from pg_roles where rolname = any($2::text[])
       )
      order by surface, object_name, grantor, grantee, privilege_type
    `,
    [databaseName, fixtureRoleNames],
  );

  const attributes = await adminPool.query(
    `
      select rolname, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
             rolreplication, rolbypassrls, rolcanlogin
        from pg_roles
       where rolname = any($1::text[])
       order by rolname
    `,
    [fixtureRoleNames],
  );

  const memberships = await readMembershipEdges(adminPool);

  const aclSurfaces = {
    database: [],
    "default": [],
    schema: [],
  };
  for (const row of aclRecords.rows) {
    if (
      typeof row.surface !== "string" ||
      typeof row.object_name !== "string" ||
      typeof row.grantor !== "string" ||
      typeof row.grantee !== "string" ||
      typeof row.privilege_type !== "string" ||
      typeof row.is_grantable !== "boolean"
    ) {
      throw new Error();
    }
    if (!aclSurfaces[row.surface]) throw new Error();
    aclSurfaces[row.surface].push(
      `${row.object_name}\u0000${row.grantor}\u0000${row.grantee}\u0000${row.privilege_type}\u0000${row.is_grantable}`,
    );
  }

  const fingerprint = {
    attributes: attributes.rows,
    databaseAcl: [...new Set(aclSurfaces.database)].sort(),
    databaseOwner: ownership.rows[0].database_owner,
    defaultAcl: [...new Set(aclSurfaces.default)].sort(),
    enumOwners: ownership.rows[0].enum_owners ?? [],
    memberships,
    objectOwners: ownership.rows[0].object_owners ?? [],
    routineOwners: ownership.rows[0].routine_owners ?? [],
    schemaAcls: [...new Set(aclSurfaces.schema)].sort(),
    schemaOwners: ownership.rows[0].schema_owners ?? [],
  };
  recordStructuredFingerprintSnapshot(fingerprint);
  return fingerprint;
}

function assertBaselineFingerprint(fingerprint, expectedPublicOwner) {
  assert.equal(fingerprint.databaseOwner, "platform_app");
  assert.deepEqual(fingerprint.schemaOwners, [
    "appdata=platform_app",
    "drizzle=platform_app",
    `public=${expectedPublicOwner}`,
  ]);
  for (const objectName of [
    "widgets",
    "widgets_label_uidx",
    "counter_seq",
    "__drizzle_migrations",
    "users",
    ...contractTableNames(),
  ]) {
    assert.ok(
      fingerprint.objectOwners.includes(`${objectName}=platform_app`),
      `expected baseline ${objectName} owned by platform_app`,
    );
  }
  assert.ok(fingerprint.enumOwners.includes("widget_status=platform_app"));
  assert.ok(fingerprint.routineOwners.includes("widget_summary=platform_app"));
  assert.equal(fingerprint.memberships.length, 0);

  const attributes = new Map(
    fingerprint.attributes.map((row) => [row.rolname, row]),
  );
  assert.equal(attributes.has("platform_migrator"), false);
  const app = attributes.get("platform_app");
  assert.equal(app.rolcanlogin, true);
  assert.equal(app.rolcreatedb, true);
  assert.equal(app.rolcreaterole, true);
  assert.equal(app.rolsuper, false);
  const runtime = attributes.get("platform_runtime");
  assert.equal(runtime.rolcanlogin, false);
  assert.equal(runtime.rolsuper, false);
  assert.equal(runtime.rolcreatedb, false);
  const provider = attributes.get("provider_owner");
  assert.equal(provider.rolcanlogin, false);
  assert.equal(provider.rolsuper, false);

  assertAclSurfaceBounded(fingerprint.databaseAcl, "database");
  assertAclSurfaceBounded(fingerprint.schemaAcls, "schema");
  assertAclSurfaceBounded(fingerprint.defaultAcl, "default");
  assert.ok(fingerprint.databaseAcl.length > 0);
  assert.ok(fingerprint.schemaAcls.length > 0);
  assert.ok(fingerprint.defaultAcl.length > 0);
}

function assertAclSurfaceBounded(records, surface) {
  assert.ok(Array.isArray(records));
  for (const record of records) {
    const fields = record.split("\u0000");
    assert.equal(fields.length, 5);
    const objectName = fields[0];
    const grantor = fields[1];
    const grantee = fields[2];
    const privilegeType = fields[3];
    const isGrantable = fields[4];
    assert.ok(
      allowedAclRoles.has(grantor),
      `unexpected ${surface} grantor ${grantor}`,
    );
    assert.ok(
      allowedAclRoles.has(grantee),
      `unexpected ${surface} grantee ${grantee}`,
    );
    assert.match(privilegeType, /^[A-Z_]+$/);
    assert.ok(isGrantable === "true" || isGrantable === "false");
    assert.ok(objectName.length > 0);
  }
}

function assertExactFingerprint(actual, expected, label) {
  recordStructuredFingerprintComparison(actual, expected);
  assert.deepEqual(actual, expected, label);
}

function buildExpectedDatabaseAclResidue(databaseName, baseline) {
  return [
    databaseName,
    baseline.databaseOwner,
    "platform_runtime",
    "CONNECT",
    "false",
  ].join("\u0000");
}

function parseDatabaseAclResidue(record) {
  const fields = record.split("\u0000");
  assert.equal(fields.length, 5);
  return {
    database: fields[0],
    grantor: fields[1],
    grantee: fields[2],
    privilege: fields[3],
    grantable: fields[4],
  };
}

async function assertAclResidueNegativeControl(adminPool, databaseName, baseline) {
  assert.equal(baseline.databaseOwner, "platform_app");
  const expectedGrantor = baseline.databaseOwner;
  const expectedResidue = buildExpectedDatabaseAclResidue(
    databaseName,
    baseline,
  );
  markStructuredFailurePhase("acl_residue_setup", "acl_residue_cleanup");
  assert.deepEqual(
    baseline.databaseAcl
      .map(parseDatabaseAclResidue)
      .filter(
        (record) =>
          record.database === databaseName &&
          record.grantee === "platform_runtime" &&
          record.privilege === "CONNECT",
      ),
    [],
  );
  let grantAttempted = false;
  try {
    grantAttempted = true;
    await adminPool.query(
      "grant connect on database " +
        identifier(databaseName) +
        " to platform_runtime",
    );
    markStructuredFailurePhase(
      "acl_residue_permissive_helper",
      "acl_residue_cleanup",
    );
    const perturbed = await readOwnershipFingerprint(adminPool, databaseName);
    const addedDatabaseAcl = perturbed.databaseAcl.filter(
      (record) => !baseline.databaseAcl.includes(record),
    );
    assert.equal(addedDatabaseAcl.length, 1);
    assert.deepEqual(addedDatabaseAcl, [expectedResidue]);
    assert.deepEqual(
      parseDatabaseAclResidue(addedDatabaseAcl[0]),
      {
        database: databaseName,
        grantor: expectedGrantor,
        grantee: "platform_runtime",
        privilege: "CONNECT",
        grantable: "false",
      },
    );
    assert.notEqual(
      parseDatabaseAclResidue(addedDatabaseAcl[0]).grantor,
      "postgres",
    );
    assert.deepEqual(
      baseline.databaseAcl.filter((record) =>
        perturbed.databaseAcl.includes(record),
      ),
      baseline.databaseAcl,
    );
    assertBaselineFingerprint(perturbed, "pg_database_owner");
    markStructuredFailurePhase(
      "acl_residue_exact_rejection",
      "acl_residue_cleanup",
    );
    assert.throws(
      () => assertExactFingerprint(perturbed, baseline),
      assert.AssertionError,
    );
  } finally {
    markStructuredFailurePhase("acl_residue_cleanup", "acl_residue_cleanup");
    if (grantAttempted) {
      await adminPool.query(
        "revoke connect on database " +
          identifier(databaseName) +
          " from platform_runtime",
      );
    }
  }
  markStructuredFailurePhase(
    "post_acl_exact_fingerprint",
    "acl_residue_cleanup",
  );
  const restored = await readOwnershipFingerprint(adminPool, databaseName);
  assert.equal(restored.databaseAcl.includes(expectedResidue), false);
  assert.deepEqual(restored.databaseAcl, baseline.databaseAcl);
  assertExactFingerprint(restored, baseline);
}
async function assertDefaultAclResidueNegativeControl(
  adminPool,
  databaseName,
  baseline,
) {
  const expectedResidue = [
    "<global>:f",
    "platform_app",
    "platform_runtime",
    "EXECUTE",
    "false",
  ].join("\u0000");
  markStructuredFailurePhase(
    "default_acl_residue_setup",
    "default_acl_residue_cleanup",
  );
  assert.equal(baseline.defaultAcl.includes(expectedResidue), false);
  let grantAttempted = false;
  try {
    grantAttempted = true;
    await adminPool.query(
      "alter default privileges for role platform_app " +
        "grant execute on functions to platform_runtime",
    );
    markStructuredFailurePhase(
      "default_acl_permissive_helper",
      "default_acl_residue_cleanup",
    );
    const perturbed = await readOwnershipFingerprint(adminPool, databaseName);
    assert.deepEqual(
      perturbed.defaultAcl.filter(
        (record) => !baseline.defaultAcl.includes(record),
      ),
      [expectedResidue],
    );
    assertBaselineFingerprint(perturbed, "pg_database_owner");
    markStructuredFailurePhase(
      "default_acl_exact_rejection",
      "default_acl_residue_cleanup",
    );
    assert.throws(
      () => assertExactFingerprint(perturbed, baseline),
      assert.AssertionError,
    );
  } finally {
    markStructuredFailurePhase(
      "default_acl_residue_cleanup",
      "default_acl_residue_cleanup",
    );
    if (grantAttempted) {
      await adminPool.query(
        "alter default privileges for role platform_app " +
          "revoke execute on functions from platform_runtime",
      );
    }
  }
  markStructuredFailurePhase(
    "post_default_acl_exact_fingerprint",
    "default_acl_residue_cleanup",
  );
  assertExactFingerprint(
    await readOwnershipFingerprint(adminPool, databaseName),
    baseline,
  );
}
async function assertRuntimePosture(adminPool) {
  const report = await inspectRuntimeDatabaseRoleAuthorityPosture(
    adminPool,
    "platform_runtime",
  );
  assert.equal(report.runtimeRoleAuthorityPosture, "passed");
}

async function assertRuntimeGrantSetExact(adminPool) {
  const runtimeGrantSet = await adminPool.query(
    `
      select case c.relkind
               when 'r' then 'table'
               when 'p' then 'table'
               when 'v' then 'view'
               when 'm' then 'materialized_view'
               when 'f' then 'foreign_table'
               else 'unsupported_relation'
             end::text as object_class,
             s.nspname::text as schema_name,
             c.relname::text as object_name,
             upper(acl.privilege_type)::text as privilege_type,
             acl.is_grantable as is_grantable
        from pg_class c
        join pg_namespace s on s.oid = c.relnamespace
        join pg_roles runtime_role on runtime_role.rolname = 'platform_runtime'
        cross join lateral aclexplode(c.relacl) acl
       where s.nspname = 'public'
         and c.relkind in ('r','p','v','m','f')
         and acl.grantee = runtime_role.oid
       order by object_class, schema_name, object_name, privilege_type
    `,
  );
  const expectedKeys = new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map(
      (record) =>
        [
          record.objectClass,
          record.schema,
          record.objectName,
          record.privilege,
          record.authoritySource,
          record.grantOption ? "YES" : "NO",
        ].join("\u0000"),
    ),
  );
  const observed = runtimeGrantSet.rows.map((row) =>
    [
      row.object_class,
      row.schema_name,
      row.object_name,
      row.privilege_type,
      "direct",
      row.is_grantable ? "YES" : "NO",
    ].join("\u0000"),
  );
  const observedSet = new Set(observed);
  const missing = RUNTIME_TABLE_GRANT_CONTRACT.filter(
    (record) =>
      !observedSet.has(
        [
          record.objectClass,
          record.schema,
          record.objectName,
          record.privilege,
          record.authoritySource,
          record.grantOption ? "YES" : "NO",
        ].join("\u0000"),
      ),
  );
  const extra = observed.filter((key) => !expectedKeys.has(key));
  assert.equal(observed.length, RUNTIME_TABLE_GRANT_CONTRACT.length);
  assert.equal(missing.length, 0);
  assert.equal(extra.length, 0);
}

async function schemaOwner(adminPool, databaseName, schemaName) {
  const result = await adminPool.query(
    `
      select role_record.rolname
        from pg_namespace schema_record
        join pg_roles role_record on role_record.oid = schema_record.nspowner
       where schema_record.nspname = $1
    `,
    [schemaName],
  );
  assert.equal(result.rows.length, 1);
  void databaseName;
  return result.rows[0].rolname;
}

async function schemaPrivileges(adminPool, roleName, schemaName) {
  const result = await adminPool.query(
    `
      select
        has_schema_privilege($1, $2, 'CREATE') as can_create,
        has_schema_privilege($1, $2, 'USAGE') as can_usage
    `,
    [roleName, schemaName],
  );
  assert.equal(result.rows.length, 1);
  return result.rows[0];
}

async function assertFocusedPassfileIsolation(primary) {
  const homeDirectory = process.env.HOME;
  const appDataDirectory = process.env.APPDATA;
  const controlledPassfilePath = process.env.PGPASSFILE;
  assert.equal(typeof homeDirectory, "string", "synthetic HOME must exist");
  assert.equal(typeof appDataDirectory, "string", "synthetic APPDATA must exist");
  assert.equal(
    typeof controlledPassfilePath,
    "string",
    "controlled PGPASSFILE must exist",
  );
  assert.equal(
    Object.hasOwn(process.env, "PGPASSWORD"),
    false,
    "PGPASSWORD must be absent at the focused child",
  );
  await assertPrivateFilePresent(join(homeDirectory, ".pgpass"));
  await assertPrivateFilePresent(
    join(appDataDirectory, "postgresql", "pgpass.conf"),
  );
  let controlledPassfileContent;
  try {
    controlledPassfileContent = await readFile(
      controlledPassfilePath,
      "utf8",
    );
  } catch {
    assert.fail("controlled passfile must be readable");
  }
  assert.equal(
    controlledPassfileContent.length,
    0,
    "controlled passfile must be empty",
  );

  // RED/default-pgpass causal control: remove only the bounded child process's
  // quarantine so the parent retains the runner-owned passfile for every
  // subsequent control.
  assert.equal(
    process.env.PGPASSFILE,
    controlledPassfilePath,
    "runner-owned PGPASSFILE must be active before RED",
  );
  const redEnvironment = buildFocusedDefaultPgpassControlEnvironment(
    {
      ...process.env,
      HOME: homeDirectory,
      APPDATA: appDataDirectory,
    },
    roleUrl("platform_migrator", primary.databaseName),
  );
  assert.equal(
    Object.keys(redEnvironment).some((key) => key.startsWith("PG")),
    false,
    "RED child must remove inherited PostgreSQL connection state",
  );
  assert.equal(redEnvironment.HOME, homeDirectory);
  assert.equal(redEnvironment.APPDATA, appDataDirectory);
  await new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "--eval", defaultPgpassControlScript],
      {
        env: redEnvironment,
        stdio: "ignore",
        windowsHide: true,
      },
    );
    child.once("error", () => reject(new Error("RED pgpass control failed.")));
    child.once("close", (code, signal) => {
      if (code === 0 && signal === null) {
        resolve();
      } else {
        reject(new Error("RED pgpass control failed."));
      }
    });
  });
  assert.equal(
    process.env.PGPASSFILE,
    controlledPassfilePath,
    "runner-owned PGPASSFILE must remain active after RED",
  );

  const quarantinedPool = new Pool({
    connectionString: roleUrl("platform_migrator", primary.databaseName),
    max: 1,
  });
  try {
    await assertQueryRejected(
      quarantinedPool,
      "select 1",
      /client password must be a string|no password supplied|password authentication failed/i,
    );
  } finally {
    await quarantinedPool.end();
  }

  const previousIsWin = pgPassHelper.isWin;
  try {
    pgPassHelper.isWin = true;
    assert.equal(
      pgPassHelper.getFileName({ APPDATA: appDataDirectory }) ===
        join(appDataDirectory, "postgresql", "pgpass.conf"),
      true,
      "Windows APPDATA default passfile must resolve to the synthetic location",
    );
    assert.equal(
      pgPassHelper.getFileName({
        APPDATA: appDataDirectory,
        PGPASSFILE: controlledPassfilePath,
      }) === controlledPassfilePath,
      true,
      "explicit PGPASSFILE must override APPDATA",
    );
  } finally {
    pgPassHelper.isWin = previousIsWin;
  }
}

async function assertPrivateFilePresent(filePath) {
  try {
    await access(filePath);
  } catch {
    assert.fail("synthetic passfile must exist");
  }
}
async function assertQueryRejected(pool, sql, pattern) {
  await assert.rejects(
    () => pool.query(sql),
    (error) => pattern.test(String(error?.message ?? error)),
  );
}

function assertFixtureUrl(url, { expectedUser, expectedDatabase }) {
  const parsed = new URL(url);
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new Error();
  }
  if (parsed.password || parsed.search || parsed.hash) {
    throw new Error();
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  const port = parsed.port || "5432";
  if (hostname !== "127.0.0.1" && hostname !== "::1") {
    throw new Error();
  }
  if (port !== String(ownedPort)) {
    throw new Error();
  }
  const user = decodeURIComponent(parsed.username);
  const database = decodeURIComponent(parsed.pathname.slice(1));
  if (user !== expectedUser || database !== expectedDatabase) {
    throw new Error();
  }
}

function roleUrl(user, databaseName, password) {
  if (!safeIdentifier.test(user) || !safeIdentifier.test(databaseName)) {
    throw new Error();
  }
  const authority = password
    ? `${user}:${encodeURIComponent(password)}`
    : user;
  return `postgres://${authority}@127.0.0.1:${ownedPort}/${databaseName}`;
}

async function assertFreshPlatformAppLogin(primary) {
  const pool = new Pool({
    connectionString: roleUrl("platform_app", primary.databaseName),
    max: 1,
  });
  try {
    const client = await pool.connect();
    try {
      const result = await client.query(
        "select current_user, session_user",
      );
      assert.equal(result.rows[0]?.current_user, "platform_app");
      assert.equal(result.rows[0]?.session_user, "platform_app");
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

async function assertFreshPlatformAppLoginRejected(primary) {
  const pool = new Pool({
    connectionString: roleUrl("platform_app", primary.databaseName),
    max: 1,
  });
  try {
    await assert.rejects(
      async () => {
        const client = await pool.connect();
        try {
          await client.query("select 1");
        } finally {
          client.release();
        }
      },
      (error) =>
        /not permitted to log in|cannot log in|authentication failed/i.test(
          String(error?.message ?? ""),
        ),
    );
  } finally {
    await pool.end();
  }
}

function contractTableNames() {
  return [...new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map((record) => record.objectName),
  )];
}

export async function runReversibleLegacyNoLoginControl(primary) {
  const baselineFingerprint = await readOwnershipFingerprint(
    primary.adminPool,
    primary.databaseName,
  );
  let existingClient;
  let noLoginAttempted = false;

  try {
    const initialRole = await primary.adminPool.query(
      "select rolcanlogin from pg_roles where rolname = 'platform_app'",
    );
    assert.equal(initialRole.rows[0]?.rolcanlogin, true);

    await assertFreshPlatformAppLogin(primary);

    existingClient = await primary.appPool.connect();
    await existingClient.query("select 1");

    noLoginAttempted = true;
    await primary.adminPool.query("ALTER ROLE platform_app NOLOGIN");
    const noLoginRole = await primary.adminPool.query(
      "select rolcanlogin from pg_roles where rolname = 'platform_app'",
    );
    assert.equal(noLoginRole.rows[0]?.rolcanlogin, false);

    await assertFreshPlatformAppLoginRejected(primary);

    await existingClient.query("select 1");

    await primary.adminPool.query("ALTER ROLE platform_app LOGIN");
    noLoginAttempted = false;
    await assertFreshPlatformAppLogin(primary);

    const restoredRole = await primary.adminPool.query(
      "select rolcanlogin from pg_roles where rolname = 'platform_app'",
    );
    assert.equal(restoredRole.rows[0]?.rolcanlogin, true);
  } finally {
    existingClient?.release();
    if (noLoginAttempted) {
      await primary.adminPool.query("ALTER ROLE platform_app LOGIN");
    }
  }

  const finalFingerprint = await readOwnershipFingerprint(
    primary.adminPool,
    primary.databaseName,
  );
  assertExactFingerprint(finalFingerprint, baselineFingerprint);
}
function identifier(value) {
  assert.match(value, /^[a-z_][a-z0-9_$]{0,62}$/);
  return `"${value.replaceAll('"', '""')}"`;
}
