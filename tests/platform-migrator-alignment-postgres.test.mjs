import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { renameSync, unlinkSync, writeFileSync } from "node:fs";
import test from "node:test";
import { join } from "node:path";

import { access, readFile, writeFile } from "node:fs/promises";
import { Pool } from "pg";

import {
  inspectRuntimeDatabaseRoleAuthorityPosture,
} from "../dist/db/runtime-posture.js";
import {
  createDatabaseReadinessReport,
} from "../dist/db/readiness.js";
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
import { runDisposableRuntimeLifecycle } from "../scripts/disposable-runtime-lifecycle.mjs";

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
];
const ownershipFingerprintDefaultAclCreators = Object.freeze([
  "platform_app",
  "platform_migrator",
  "platform_runtime",
  "pg_database_owner",
]);
const allowedAclRoles = new Set([
  ...fixtureRoleNames,
  "cloud_admin",
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
    Object.keys(process.env).some((key) => {
      const comparisonKey = typeof key === "string" ? key.toUpperCase() : "";
      return (
        comparisonKey.startsWith("PG") ||
        comparisonKey === "NODE_PG_FORCE_NATIVE"
      );
    }) ||
    Object.hasOwn(process.env, "NODE_PG_FORCE_NATIVE")
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
const defaultPgpassControlTimeoutMs = 30_000;
const defaultPgpassControlFailureMessage = "C3 RED default-pgpass admission failed.";
const defaultPgpassControlTimeoutMessage = "C3 RED default-pgpass admission timed out.";

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
const isFocusedDisposableChild =
  typeof process.env.PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE === "string" &&
  process.env.PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE.length > 0 &&
  typeof process.env.PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE === "string" &&
  process.env.PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE.length > 0;
const a10CausalControlsEnabled = !isFocusedDisposableChild;
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
  "unrelated_default_acl_setup",
  "unrelated_default_acl_exact_equality",
  "unrelated_default_acl_cleanup",
  "post_unrelated_default_acl_exact_fingerprint",
  "C3_RED_DEFAULT_PGPASS_ADMISSION",
  "C3_HOSTILE_ENV_RETAINED",
  "C3_RUNNER_PGPASS_QUARANTINE",
  "C3_INHERITED_PG_STATE_SANITISED",
  "C3_OMITTED_PASSWORD_REJECTED",
  "C3_WRONG_PASSWORD_REJECTED",
  "C3_CORRECT_PASSWORD_ACCEPTED",
  "C3_CLEANUP_CONFIRMED",
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
  "c3_security_invariant",
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
if (a10CausalControlsEnabled) {
test("A10-H1-C1/C3 normal child failures remain deterministic under the watchdog", async () => {
  const child = new EventEmitter();
  const killSignals = [];
  child.kill = (signal) => {
    killSignals.push(signal);
    return true;
  };
  let watchdogCallback = null;
  const pending = runDefaultPgpassControl({}, {
    childScript: "process.exitCode = 23;",
    spawnImpl: () => child,
    setTimeoutImpl: (callback) => {
      watchdogCallback = callback;
      return {};
    },
    clearTimeoutImpl: () => {},
  });
  queueMicrotask(() => child.emit("close", 23, null));
  await assert.rejects(
    pending,
    (error) =>
      error instanceof Error &&
      error.message === defaultPgpassControlFailureMessage,
  );
  assert.equal(typeof watchdogCallback, "function");
  watchdogCallback();
  assert.deepEqual(killSignals, []);
});

test("A10-H1-C2 real stalled default-pgpass child is terminated and fails deterministically", async () => {
  let child = null;
  const startedAt = Date.now();
  await assert.rejects(
    runDefaultPgpassControl({}, {
      childScript: "setInterval(() => {}, 1000);",
      timeoutMs: 75,
      spawnImpl: (...args) => {
        child = spawn(...args);
        return child;
      },
    }),
    (error) =>
      error instanceof Error &&
      error.message === defaultPgpassControlTimeoutMessage,
  );
  assert.ok(child);
  assert.equal(child.killed, true);
  await new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("close", resolve);
  });
  assert.ok(child.exitCode !== null || child.signalCode !== null);
  assert.ok(Date.now() - startedAt < 3_000);
});

test("A10-H1-C3 timeout/error/close races settle once and clear the watchdog", async () => {
  const child = new EventEmitter();
  const killSignals = [];
  child.kill = (signal) => {
    killSignals.push(signal);
    child.emit("close", null, signal);
    return true;
  };
  let watchdogCallback = null;
  const watchdogHandle = {};
  let clearCount = 0;
  const pending = runDefaultPgpassControl({}, {
    childScript: "setInterval(() => {}, 1000);",
    spawnImpl: () => child,
    setTimeoutImpl: (callback) => {
      watchdogCallback = callback;
      return watchdogHandle;
    },
    clearTimeoutImpl: (handle) => {
      assert.equal(handle, watchdogHandle);
      clearCount += 1;
    },
  });
  assert.equal(typeof watchdogCallback, "function");
  watchdogCallback();
  child.emit("error", new Error("late error"));
  child.emit("close", 0, null);
  await assert.rejects(
    pending,
    (error) =>
      error instanceof Error &&
      error.message === defaultPgpassControlTimeoutMessage,
  );
  assert.deepEqual(killSignals, ["SIGTERM"]);
  assert.equal(clearCount, 1);
});

test("A10-H1-C4 timeout failure reaches disposable lifecycle cleanup and final absence", async () => {
  const residue = {
    container: true,
    volume: true,
    listener: true,
    passfile: true,
    receipt: true,
    sidecar: true,
  };
  const runnerOwnedResidue = [
    "container:owned",
    "volume:owned",
    "listener:127.0.0.1:56432",
    "passfile:owned",
    "receipt:owned",
    "sidecar:owned",
  ];
  let cleanupCalls = 0;
  let absenceCalls = 0;
  await assert.rejects(
    runDisposableRuntimeLifecycle({
      construct: (resources) => {
        for (const resource of runnerOwnedResidue) {
          resources.runnerOwned.add(resource);
        }
        return runDefaultPgpassControl({}, {
          childScript: "setInterval(() => {}, 1000);",
          timeoutMs: 75,
        });
      },
      admitConstruction: async () => null,
      deriveProvisioning: async () => null,
      provision: async () => {},
      admitConfigured: async () => null,
      runFocusedTests: async () => {},
      cleanup: async (resources) => {
        cleanupCalls += 1;
        resources.runnerOwned.clear();
        for (const resource of Object.keys(residue)) {
          residue[resource] = false;
        }
      },
      verifyAbsence: async (resources) => {
        absenceCalls += 1;
        assert.equal(resources.runnerOwned.size, 0);
        assert.deepEqual(residue, {
          container: false,
          volume: false,
          listener: false,
          passfile: false,
          receipt: false,
          sidecar: false,
        });
      },
    }),
  );
  assert.equal(cleanupCalls, 1);
  assert.equal(absenceCalls, 1);
  assert.deepEqual(residue, {
    container: false,
    volume: false,
    listener: false,
    passfile: false,
    receipt: false,
    sidecar: false,
  });
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

      await createMigratorRoleAsLegacyOwner(primary);

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
  "DL-128-REPO-011-A5: focused-child structural C3 default-pgpass proof",
  { skip: skipReason },
  async () => withStructuredFailureReceipt(
    "DL-128-REPO-011-A5-C3",
    async () => {
      let fixture = null;
      let roleCreationAttempted = false;
      let baseline = null;
      try {
        fixture = await openFixtures();
        const primary = fixture.primary;
        baseline = await readOwnershipFingerprint(
          primary.adminPool,
          primary.databaseName,
        );
        roleCreationAttempted = true;
        await createMigratorRoleAsLegacyOwner(primary);
        await primary.appPool.query(
          `grant connect on database ${identifier(primary.databaseName)} to platform_migrator`,
        );
        await primary.adminPool.query(
          `alter role platform_migrator login password '${syntheticMigratorPassword}'`,
        );
        await assertFocusedPassfileIsolation(primary);
      } finally {
        if (fixture) {
          markStructuredFailurePhase(
            "C3_CLEANUP_CONFIRMED",
            "c3_security_invariant",
          );
          try {
            await cleanupC3MigratorRole(
              fixture.primary.adminPool,
              roleCreationAttempted,
            );
            if (baseline) {
              assertExactFingerprint(
                await readOwnershipFingerprint(
                  fixture.primary.adminPool,
                  fixture.primary.databaseName,
                ),
                baseline,
              );
            }
          } finally {
            await closeFixtures(fixture);
          }
        }
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

      await createMigratorRoleAsLegacyOwner(primary);
      await primary.appPool.query(
        `grant connect on database ${identifier(primary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(primary.adminPool);
      const migratorDefaultAclFingerprint = await readOwnershipFingerprint(
        primary.adminPool,
        primary.databaseName,
      );
      assertDefaultAclCreatorPresent(
        migratorDefaultAclFingerprint.defaultAcl,
        "platform_migrator",
      );
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
        `grant create, usage on schema public to platform_migrator`,
      );
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
      assert.equal(forwardFingerprint.databaseOwner, "platform_app");
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
        "platform_app",
      );
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        true,
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        true,
      );
      await assertRuntimeGrantSetExact(primary.adminPool);
      await assertRuntimePosture(primary.adminPool);

      await primary.appPool.query(
        `revoke temporary on database ${identifier(primary.databaseName)} from public`,
      );
      const canonicalEnumNames = [
        "app_status",
        "entitlement_status",
        "invitation_status",
        "membership_status",
        "role",
        "user_status",
        "workspace_membership_approval_status",
        "workspace_status",
        "csrf_token_purpose",
      ];
      const createdCanonicalEnums = [];
      try {
        for (const enumName of canonicalEnumNames) {
          const existingEnum = await primary.adminPool.query(
            "select exists (" +
              "select 1 from pg_type type_record " +
              "join pg_namespace schema_record " +
              "on schema_record.oid = type_record.typnamespace " +
              "where schema_record.nspname = 'public' " +
              "and type_record.typname = $1 " +
              "and type_record.typtype = 'e') as present",
            [enumName],
          );
          if (existingEnum.rows[0].present) continue;
          await primary.migratorPasswordPool.query(
            `create type public.${identifier(enumName)} as enum ('fixture')`,
          );
          createdCanonicalEnums.push(enumName);
        }
        await withProviderBootstrapNamed(primary, async () => {
          const readinessInput = {
            env: {
              DATABASE_OPERATOR_URL:
                "postgres://platform_migrator@disposable.invalid/swooshz_platform",
            },
            requiredTables: [],
            clientFactory: async () => ({
              query: (...args) => primary.migratorPasswordPool.query(...args),
              end: async () => {},
            }),
          };
          const readinessReport = await createDatabaseReadinessReport(
            readinessInput,
          );
          assert.equal(readinessReport.status, "ready");
          assert.equal(readinessReport.checks.migratorPosture, "passed");

          const extensionClient = await primary.providerPool.connect();
          const tddRedFailures = [];
          const ledgerSequenceName = "__run178_drizzle_migrations_id_seq";
          let ledgerShapePrepared = false;
          let createdHstoreExtension = false;
          let ledgerAttachedToExtension = false;
          try {
            await primary.migratorPasswordPool.query(
              "create sequence drizzle.__run178_drizzle_migrations_id_seq",
            );
            ledgerShapePrepared = true;
            await primary.migratorPasswordPool.query(
              "alter sequence drizzle.__run178_drizzle_migrations_id_seq owned by drizzle.__drizzle_migrations.id",
            );
            await primary.migratorPasswordPool.query(
              "alter table drizzle.__drizzle_migrations alter column id set default nextval('drizzle.__run178_drizzle_migrations_id_seq'::regclass)",
            );
            await primary.migratorPasswordPool.query(
              "alter table drizzle.__drizzle_migrations add column created_at bigint not null default 0",
            );
            const extensionState = await extensionClient.query(
              "select exists (select 1 from pg_extension where extname = 'hstore') as present",
            );
            assert.equal(extensionState.rows[0].present, false);
            await extensionClient.query(
              "create extension hstore schema public",
            );
            createdHstoreExtension = true;
            await extensionClient.query(
              "create table public.__run176_extension_relation (id integer primary key, payload text)",
            );
            await extensionClient.query(
              "alter extension hstore add table public.__run176_extension_relation",
            );
            await extensionClient.query(
              "create index __run176_extension_index on public.__run176_extension_relation (payload)",
            );

            const extensionCatalog = await extensionClient.query(
              "select " +
                "extension_relation.oid as relation_oid, " +
                "extension_index.oid as index_oid, " +
                "hstore_type.oid as hstore_type_oid, " +
                "hstore_array.oid as hstore_array_oid, " +
                "exists (select 1 from pg_depend dependency_record " +
                "where dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = extension_relation.oid " +
                "and dependency_record.refclassid = 'pg_extension'::regclass " +
                "and dependency_record.deptype = 'e') as relation_direct_member, " +
                "exists (select 1 from pg_depend dependency_record " +
                "where dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = extension_index.oid " +
                "and dependency_record.refclassid = 'pg_extension'::regclass " +
                "and dependency_record.deptype = 'e') as index_direct_member, " +
                "exists (select 1 from pg_depend dependency_record " +
                "where dependency_record.classid = 'pg_type'::regclass " +
                "and dependency_record.objid = hstore_array.oid " +
                "and dependency_record.refclassid = 'pg_type'::regclass " +
                "and dependency_record.refobjid = hstore_type.oid " +
                "and dependency_record.deptype in ('a', 'i')) as array_internal_dependency " +
                "from pg_class extension_relation " +
                "join pg_namespace extension_namespace " +
                "on extension_namespace.oid = extension_relation.relnamespace " +
                "and extension_namespace.nspname = 'public' " +
                "and extension_relation.relname = '__run176_extension_relation' " +
                "join pg_class extension_index " +
                "on extension_index.relnamespace = extension_relation.relnamespace " +
                "and extension_index.relname = '__run176_extension_index' " +
                "join pg_type hstore_type " +
                "on hstore_type.typname = 'hstore' " +
                "and hstore_type.typnamespace = 'public'::regnamespace " +
                "join pg_type hstore_array " +
                "on hstore_array.typelem = hstore_type.oid " +
                "and hstore_array.typnamespace = 'public'::regnamespace",
            );
            assert.equal(extensionCatalog.rows.length, 1);
            assert.equal(extensionCatalog.rows[0].relation_direct_member, true);
            assert.equal(extensionCatalog.rows[0].index_direct_member, false);
            const ledgerRowTypeDependencyCatalog = await extensionClient.query(
              "select array_agg(distinct dependency_record.deptype::text order by dependency_record.deptype::text) as dependency_classes " +
                "from pg_type row_type " +
                "join pg_depend dependency_record " +
                "on dependency_record.classid = 'pg_type'::regclass " +
                "and dependency_record.objid = row_type.oid " +
                "and dependency_record.refclassid = 'pg_class'::regclass " +
                "and dependency_record.refobjid = row_type.typrelid " +
                "where row_type.typrelid = 'drizzle.__drizzle_migrations'::regclass",
            );
            const ledgerIndexDependencyCatalog = await extensionClient.query(
              "select count(*)::int as index_count, " +
                "array_agg(distinct dependency_record.deptype::text order by dependency_record.deptype::text) filter (where dependency_record.deptype is not null) as dependency_classes " +
                "from pg_index index_record " +
                "left join pg_depend dependency_record " +
                "on dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = index_record.indexrelid " +
                "where index_record.indrelid = 'drizzle.__drizzle_migrations'::regclass",
            );
            const ledgerSequenceDependencyCatalog = await extensionClient.query(
              "select array_agg(distinct dependency_record.deptype::text order by dependency_record.deptype::text) as dependency_classes " +
                "from pg_class sequence_record " +
                "join pg_depend dependency_record " +
                "on dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = sequence_record.oid " +
                "and dependency_record.refclassid = 'pg_class'::regclass " +
                "and dependency_record.refobjid = 'drizzle.__drizzle_migrations'::regclass " +
                "where sequence_record.relnamespace = 'drizzle'::regnamespace " +
                "and sequence_record.relname = '" + ledgerSequenceName + "'",
            );
            for (const [surface, dependencyCatalog] of [
              ["row_type", ledgerRowTypeDependencyCatalog],
              ["index", ledgerIndexDependencyCatalog],
              ["serial_sequence", ledgerSequenceDependencyCatalog],
            ]) {
              assert.equal(dependencyCatalog.rows.length, 1);
              const dependencyClasses =
                dependencyCatalog.rows[0].dependency_classes ?? [];
              assert.ok(
                Array.isArray(dependencyClasses),
                surface +
                  " dependency classes: " +
                  JSON.stringify(dependencyClasses),
              );
              if (surface === "index") {
                assert.ok(dependencyCatalog.rows[0].index_count > 0);
              } else {
                assert.ok(dependencyClasses.length > 0);
              }
            }

            assert.equal(extensionCatalog.rows[0].array_internal_dependency, true);

            await extensionClient.query(
              "alter extension hstore add table drizzle.__drizzle_migrations",
            );
            ledgerAttachedToExtension = true;
            const ledgerExtensionCatalog = await extensionClient.query(
              "select ledger.relkind as ledger_relkind, " +
                "pg_get_userbyid(ledger.relowner) as ledger_owner, " +
                "exists (select 1 from pg_depend dependency_record " +
                "where dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = ledger.oid " +
                "and dependency_record.refclassid = 'pg_extension'::regclass " +
                "and dependency_record.deptype = 'e') as ledger_direct_member, " +
                "exists (select 1 from pg_class sequence_record " +
                "join pg_depend dependency_record " +
                "on dependency_record.classid = 'pg_class'::regclass " +
                "and dependency_record.objid = sequence_record.oid " +
                "and dependency_record.refclassid = 'pg_class'::regclass " +
                "and dependency_record.refobjid = ledger.oid " +
                "and dependency_record.deptype in ('a', 'i') " +
                "where sequence_record.relnamespace = ledger.relnamespace " +
                "and sequence_record.relname = '" + ledgerSequenceName + "') as serial_sequence_present " +
                "from pg_class ledger " +
                "where ledger.relnamespace = 'drizzle'::regnamespace " +
                "and ledger.relname = '__drizzle_migrations'",
            );
            assert.equal(ledgerExtensionCatalog.rows.length, 1);
            assert.equal(ledgerExtensionCatalog.rows[0].ledger_relkind, "r");
            assert.equal(ledgerExtensionCatalog.rows[0].ledger_owner, "platform_migrator");
            assert.equal(ledgerExtensionCatalog.rows[0].ledger_direct_member, true);
            assert.equal(ledgerExtensionCatalog.rows[0].serial_sequence_present, true);

            const extensionReadinessReport = await createDatabaseReadinessReport(
              readinessInput,
            );
            try {
              assert.equal(extensionReadinessReport.status, "schema_not_ready");
              assert.equal(
                extensionReadinessReport.checks.migratorPosture,
                "failed",
              );
            } catch {
              tddRedFailures.push("canonical Drizzle ledger direct extension membership remained READY");
            }

            await extensionClient.query(
              "alter extension hstore drop table drizzle.__drizzle_migrations",
            );
            ledgerAttachedToExtension = false;
            const restoredLedgerReadinessReport =
              await createDatabaseReadinessReport(readinessInput);
            assert.equal(restoredLedgerReadinessReport.status, "ready");
            assert.equal(
              restoredLedgerReadinessReport.checks.migratorPosture,
              "passed",
            );

            await extensionClient.query(
              "create table public.__run176_user_dependency_relation (id integer references public.__run176_extension_relation(id))",
            );
            const ordinaryRelationDependencyCatalog = await extensionClient.query(
              "select array_agg(distinct dependency_record.deptype::text order by dependency_record.deptype::text) as dependency_classes " +
                "from pg_constraint constraint_record " +
                "join pg_depend dependency_record " +
                "on dependency_record.classid = 'pg_constraint'::regclass " +
                "and dependency_record.objid = constraint_record.oid " +
                "and dependency_record.refclassid = 'pg_class'::regclass " +
                "and dependency_record.refobjid = 'public.__run176_extension_relation'::regclass " +
                "where constraint_record.conrelid = 'public.__run176_user_dependency_relation'::regclass",
            );
            const ordinaryRelationDependencyClasses =
              ordinaryRelationDependencyCatalog.rows[0]?.dependency_classes ?? [];
            assert.ok(ordinaryRelationDependencyClasses.includes("n"));
            const ordinaryRelationDependencyReport =
              await createDatabaseReadinessReport(readinessInput);
            assert.equal(
              ordinaryRelationDependencyReport.status,
              "schema_not_ready",
            );
            assert.equal(
              ordinaryRelationDependencyReport.checks.migratorPosture,
              "failed",
            );
            await extensionClient.query(
              "drop table public.__run176_user_dependency_relation",
            );
            const relationRestoredReadinessReport =
              await createDatabaseReadinessReport(readinessInput);
            assert.equal(relationRestoredReadinessReport.status, "ready");
            assert.equal(
              relationRestoredReadinessReport.checks.migratorPosture,
              "passed",
            );

            await extensionClient.query(
              "create domain public.__run176_user_dependency as hstore",
            );
            const domainDependencyCatalog = await extensionClient.query(
              "select array_agg(distinct dependency_record.deptype::text order by dependency_record.deptype::text) as dependency_classes " +
                "from pg_depend dependency_record " +
                "where dependency_record.classid = 'pg_type'::regclass " +
                "and dependency_record.objid = 'public.__run176_user_dependency'::regtype " +
                "and dependency_record.refclassid = 'pg_type'::regclass " +
                "and dependency_record.refobjid = 'public.hstore'::regtype",
            );
            const domainDependencyClasses =
              domainDependencyCatalog.rows[0]?.dependency_classes ?? [];
            assert.ok(domainDependencyClasses.includes("n"));
            const isolatedDomainReadinessReport =
              await createDatabaseReadinessReport(readinessInput);
            assert.equal(
              isolatedDomainReadinessReport.status,
              "schema_not_ready",
            );
            assert.equal(
              isolatedDomainReadinessReport.checks.migratorPosture,
              "failed",
            );
            await extensionClient.query(
              "drop domain public.__run176_user_dependency",
            );
            const domainRestoredReadinessReport =
              await createDatabaseReadinessReport(readinessInput);
            assert.equal(domainRestoredReadinessReport.status, "ready");
            assert.equal(
              domainRestoredReadinessReport.checks.migratorPosture,
              "passed",
            );
          } finally {
            await extensionClient.query(
              "drop domain if exists public.__run176_user_dependency",
            ).catch(() => {});
            await extensionClient.query(
              "drop table if exists public.__run176_user_dependency_relation",
            ).catch(() => {});
            if (createdHstoreExtension) {
              if (ledgerAttachedToExtension) {
                await extensionClient.query(
                  "alter extension hstore drop table drizzle.__drizzle_migrations",
                ).catch(() => {});
              }
              await extensionClient.query(
                "alter extension hstore drop table public.__run176_extension_relation",
              ).catch(() => {});
              await extensionClient.query(
                "drop table if exists public.__run176_extension_relation",
              ).catch(() => {});
              await extensionClient.query("drop extension if exists hstore").catch(() => {});
            }
            extensionClient.release();
            if (ledgerShapePrepared) {
              await primary.migratorPasswordPool.query(
                "alter table drizzle.__drizzle_migrations alter column id drop default",
              ).catch(() => {});
              await primary.migratorPasswordPool.query(
                "alter table drizzle.__drizzle_migrations drop column created_at",
              ).catch(() => {});
              await primary.migratorPasswordPool.query(
                "drop sequence if exists drizzle.__run178_drizzle_migrations_id_seq",
              ).catch(() => {});
            }
          }

          const readinessClient = await primary.migratorPasswordPool.connect();
          assert.deepEqual(tddRedFailures, [], tddRedFailures.join("; "));

          const transactionalReadinessInput = {
            ...readinessInput,
            clientFactory: async () => ({
              query: (...args) => readinessClient.query(...args),
              end: async () => {},
            }),
          };
          try {
            await readinessClient.query("begin");
            await readinessClient.query("drop type public.role cascade");
            const missingEnumReport = await createDatabaseReadinessReport(
              transactionalReadinessInput,
            );
            assert.equal(missingEnumReport.status, "schema_not_ready");
            assert.equal(missingEnumReport.checks.migratorPosture, "failed");
            await readinessClient.query("rollback");

            await primary.providerPool.query(
              "alter type public.role owner to platform_app",
            );
            try {
              const wrongOwnerReport = await createDatabaseReadinessReport(
                readinessInput,
              );
              assert.equal(wrongOwnerReport.status, "schema_not_ready");
              assert.equal(
                wrongOwnerReport.checks.migratorPosture,
                "failed",
              );
            } finally {
              await primary.providerPool.query(
                "alter type public.role owner to platform_migrator",
              );
            }
          } finally {
            await readinessClient.query("rollback").catch(() => {});
            readinessClient.release();
          }


          await primary.migratorPasswordPool.query(
            "create type public.__run176_unrelated_type as enum ('fixture')",
          );
          try {
            const unrelatedTypeReport = await createDatabaseReadinessReport(
              readinessInput,
            );
            assert.equal(unrelatedTypeReport.status, "schema_not_ready");
            assert.equal(
              unrelatedTypeReport.checks.migratorPosture,
              "failed",
            );
          } finally {
            await primary.migratorPasswordPool.query(
              "drop type public.__run176_unrelated_type",
            );
          }

          await primary.migratorPasswordPool.query(
            "create table public.__run173_unknown_relation (id integer)",
          );
          try {
            const relationDriftReport = await createDatabaseReadinessReport(
              readinessInput,
            );
            assert.equal(relationDriftReport.status, "schema_not_ready");
            assert.equal(relationDriftReport.checks.migratorPosture, "failed");
          } finally {
            await primary.migratorPasswordPool.query(
              "drop table public.__run173_unknown_relation",
            );
          }

          await primary.migratorPasswordPool.query(
            "create function public.__run173_unknown_routine() returns integer language sql immutable as 'select 1'",
          );
          try {
            const routineDriftReport = await createDatabaseReadinessReport(
              readinessInput,
            );
            assert.equal(routineDriftReport.status, "schema_not_ready");
            assert.equal(routineDriftReport.checks.migratorPosture, "failed");
          } finally {
            await primary.migratorPasswordPool.query(
              "drop function public.__run173_unknown_routine()",
            );
          }
        });
      } finally {
        for (const enumName of [...createdCanonicalEnums].reverse()) {
          await primary.adminPool.query(
            `drop type if exists public.${identifier(enumName)} cascade`,
          ).catch(() => {});
        }
        await primary.appPool.query(
          `grant temporary on database ${identifier(primary.databaseName)} to public`,
        );
      }

      await primary.appPool.query(
        `grant platform_migrator to platform_app with set true, inherit false`,
      );
      assertExactTransferWindowEdges(await readMembershipEdges(primary.adminPool));
      await proveSelfGrantEscalation(primary.appPool);
      await primary.appPool.query(
        `revoke platform_migrator from platform_app granted by platform_app`,
      );
      await assertExactProtectedEdge(primary.adminPool);

      await assertExactProtectedEdge(primary.adminPool);

      // Pre-completion legacy-retirement guard: while the replacement and
      // rollback proof is still in progress, the legacy database owner cannot
      // be retired or dropped and remains available for rollback.
      await runReversibleLegacyNoLoginControl(primary);
      await assertQueryRejected(
        primary.adminPool,
        `drop role platform_app`,
        /depends on it|cannot be dropped/i,
      );
      await assertLegacyAuthorityAvailable(primary.appPool);

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
      assert.equal(finalFingerprint.databaseOwner, "platform_app");
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
      assert.equal(finalFingerprint.memberships.length, 1);

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
        true,
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
      assert.equal(migratedState.databaseOwner, "platform_app");
      assert.equal(
        await schemaOwner(primary.adminPool, primary.databaseName, "public"),
        "pg_database_owner",
      );
      await assertExactProtectedEdge(primary.adminPool);
      await assertCanCreateInPublic(
        primary.migratorPasswordPool,
        "platform_migrator",
        true,
      );
      await assertCanCreateInPublic(
        primary.appPool,
        "platform_app",
        true,
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
      await assertPgDatabaseOwnerDefaultAclResidueNegativeControls(
        primary.adminPool,
        primary.databaseName,
        preForwardBaseline,
      );
      await assertUnrelatedDefaultAclCreatorExcluded(
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
      assertBaselineFingerprint(secondaryBaseline, "pg_database_owner");

      await withProviderBootstrapNamed(primary, async () => {
        await primary.providerPool.query(
          `grant platform_runtime to platform_app with admin true, inherit false, set false`,
        );
        const runtimeEdge = (await readMembershipEdges(primary.providerPool))
          .filter((edge) => edge.granted_role === "platform_runtime");
        assert.equal(runtimeEdge.length, 1);
        assert.equal(runtimeEdge[0].granted_role, "platform_runtime");
        assert.equal(runtimeEdge[0].member, "platform_app");
        assert.equal(runtimeEdge[0].grantor, "cloud_admin");
        assert.equal(runtimeEdge[0].admin_option, true);
        assert.equal(runtimeEdge[0].inherit_option, false);
        assert.equal(runtimeEdge[0].set_option, false);
        const edgesWhereRuntimeIsMember = (await readMembershipEdges(primary.providerPool))
          .filter((edge) => edge.member === "platform_runtime");
        assert.equal(edgesWhereRuntimeIsMember.length, 0);
        await assertRuntimeGrantSetExact(primary.providerPool);
        const runtimeOwns = await runtimeOwnershipCounts(primary.providerPool);
        assert.deepEqual(runtimeOwns, {
          dbs: 0,
          relations: 0,
          routines: 0,
          schemas: 0,
          types: 0,
        });
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
      await createMigratorRoleAsLegacyOwner(secondary);
      await secondary.appPool.query(
        `grant connect on database ${identifier(secondary.databaseName)} to platform_migrator`,
      );
      await installMigratorDefaultPrivileges(secondary.adminPool);
      const migratorDefaultAclFingerprint = await readOwnershipFingerprint(
        secondary.adminPool,
        secondary.databaseName,
      );
      assertDefaultAclCreatorPresent(
        migratorDefaultAclFingerprint.defaultAcl,
        "platform_migrator",
      );
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
        "pg_database_owner",
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
      await createMigratorRoleAsLegacyOwner(primary);
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

async function withProviderBootstrapNamed(target, operation) {
  let renamed = false;
  await target.providerAdminPool.query(
    `alter role postgres rename to cloud_admin`,
  );
  renamed = true;
  try {
    return await operation();
  } finally {
    if (renamed) {
      await target.providerAdminPool.query(
        `alter role cloud_admin rename to postgres`,
      );
    }
  }
}

async function createMigratorRoleAsLegacyOwner(target) {
  await withProviderBootstrapNamed(target, async () => {
    await target.appPool.query(
      `create role platform_migrator nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls`,
    );
    await assertExactProtectedEdge(target.providerPool, "cloud_admin");
  });
}

async function cleanupC3MigratorRole(adminPool, creationAttempted) {
  if (!creationAttempted) return;
  const roleResult = await adminPool.query(
    "select 1 from pg_roles where rolname = 'platform_migrator'",
  );
  if (roleResult.rows.length === 0) return;
  await adminPool.query("drop owned by platform_migrator");
  const defaultPrivilegeResidue = await adminPool.query(
    `
      select count(*)::int as c
        from pg_default_acl default_record
        join pg_roles role_record on role_record.oid = default_record.defaclrole
       where role_record.rolname = 'platform_migrator'
    `,
  );
  assert.equal(defaultPrivilegeResidue.rows.length, 1);
  assert.equal(defaultPrivilegeResidue.rows[0].c, 0);
  await adminPool.query("drop role platform_migrator");
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
    `revoke create, usage on schema public from platform_migrator`,
    `revoke create on schema drizzle from platform_migrator`,
    `revoke create on schema appdata from platform_migrator`,
    `revoke connect on database ${identifier(databaseName)} from platform_migrator`,
    `revoke platform_migrator from platform_app`,
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

async function assertExactProtectedEdge(adminPool, expectedGrantor = "postgres") {
  const edges = await readMembershipEdges(adminPool);
  assert.equal(
    edges.length,
    1,
    "complete membership inventory must contain exactly the protected edge",
  );
  const edge = edges[0];
  assert.equal(edge.granted_role, "platform_migrator");
  assert.equal(edge.member, "platform_app");
  assert.equal(edge.grantor, expectedGrantor);
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
  await primaryAdmin.query(
    `do $fixture$
       begin
         if not exists (select 1 from pg_roles where rolname = 'provider_admin') then
           create role provider_admin login superuser noinherit
             nocreatedb nocreaterole noreplication nobypassrls;
         end if;
       end
       $fixture$`,
  );
  await primaryAdmin.query(
    `alter role provider_admin login superuser noinherit
      nocreatedb nocreaterole noreplication nobypassrls`,
  );
  await primaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke all privileges on tables from public`,
  );
  await primaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke all privileges on sequences from public`,
  );
  await primaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke execute on functions from public`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke all privileges on tables from public`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke all privileges on sequences from public`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role provider_admin
      revoke execute on functions from public`,
  );
  await secondaryAdmin.query(
    `alter schema public owner to pg_database_owner`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role pg_database_owner
      revoke all privileges on tables from public`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role pg_database_owner
      revoke all privileges on sequences from public`,
  );
  await secondaryAdmin.query(
    `alter default privileges for role pg_database_owner
      revoke execute on functions from public`,
  );
  const primaryProviderAdmin = new Pool({
    connectionString: roleUrl("provider_admin", primaryDatabaseName),
    max: 2,
  });
  const secondaryProviderAdmin = new Pool({
    connectionString: roleUrl("provider_admin", secondaryDatabaseName),
    max: 2,
  });
  const primaryProvider = new Pool({
    connectionString: roleUrl("cloud_admin", primaryDatabaseName),
    max: 2,
  });
  const secondaryProvider = new Pool({
    connectionString: roleUrl("cloud_admin", secondaryDatabaseName),
    max: 2,
  });
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
      primaryProviderAdmin,
      secondaryProviderAdmin,
      primaryProvider,
      secondaryProvider,
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
      providerAdminPool: primaryProviderAdmin,
      providerPool: primaryProvider,
      databaseName: primaryDatabaseName,
      migratorNoPasswordPool: primaryMigratorNoPassword,
      migratorPasswordPool: primaryMigratorPassword,
      migratorWrongPasswordPool: primaryMigratorWrongPassword,
    },
    secondary: {
      adminPool: secondaryAdmin,
      appPool: secondaryApp,
      providerAdminPool: secondaryProviderAdmin,
      providerPool: secondaryProvider,
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
    await fixture.primary.adminPool.query(
      `drop owned by provider_admin`,
    ).catch(() => {});
    await fixture.secondary.adminPool.query(
      `drop owned by provider_admin`,
    ).catch(() => {});
    await fixture.primary.adminPool.query(
      `drop role if exists provider_admin`,
    ).catch(() => {});
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
      select 'default', creator_role.rolname || ':'
             || coalesce(namespace_record.nspname, '<global>')
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
        join pg_roles creator_role on creator_role.oid = default_record.defaclrole
       where default_record.defaclrole in (
         select oid from pg_roles where rolname = any($2::text[])
       )
      order by surface, object_name, grantor, grantee, privilege_type
    `,
    [databaseName, ownershipFingerprintDefaultAclCreators],
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

  assertAclSurfaceBounded(fingerprint.databaseAcl, "database");
  assertAclSurfaceBounded(fingerprint.schemaAcls, "schema");
  assertAclSurfaceBounded(fingerprint.defaultAcl, "default");
  assert.ok(fingerprint.databaseAcl.length > 0);
  assert.ok(fingerprint.schemaAcls.length > 0);
  assert.ok(fingerprint.defaultAcl.length > 0);
  assertDefaultAclCreatorCoverage(fingerprint.defaultAcl, expectedPublicOwner);
}

function assertDefaultAclCreatorCoverage(records, expectedPublicOwner) {
  const creatorKinds = (creator) => new Set(
    records
      .map((record) => record.split("\u0000"))
      .filter((fields) => fields[0].startsWith(`${creator}:`))
      .map((fields) => fields[0].split(":").at(-1)),
  );
  for (const creator of ["platform_app"]) {
    assert.ok(
      creatorKinds(creator).size > 0,
      `expected ${creator} default-ACL state in the bounded fingerprint`,
    );
  }
  if (expectedPublicOwner === "pg_database_owner") {
    assert.ok(
      creatorKinds("pg_database_owner").has("f"),
      "primary fixture must fingerprint its pg_database_owner routine default posture",
    );
  }
}

function assertDefaultAclCreatorPresent(records, creator) {
  assert.ok(
    records.some((record) => record.startsWith(`${creator}:`)),
    `expected ${creator} default-ACL state in the bounded fingerprint`,
  );
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
    "platform_app:<global>:f",
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
async function assertPgDatabaseOwnerDefaultAclResidueNegativeControls(
  adminPool,
  databaseName,
  baseline,
) {
  const controls = [
    {
      kind: "r",
      privilege: "SELECT",
      grant: "grant select on tables to platform_runtime",
      revoke: "revoke select on tables from platform_runtime",
    },
    {
      kind: "S",
      privilege: "USAGE",
      grant: "grant usage on sequences to platform_runtime",
      revoke: "revoke usage on sequences from platform_runtime",
    },
    {
      kind: "f",
      privilege: "EXECUTE",
      grant: "grant execute on functions to platform_runtime",
      revoke: "revoke execute on functions from platform_runtime",
    },
  ];
  for (const control of controls) {
    const expectedResidue = [
      `pg_database_owner:<global>:${control.kind}`,
      "pg_database_owner",
      "platform_runtime",
      control.privilege,
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
        `alter default privileges for role pg_database_owner ${control.grant}`,
      );
      markStructuredFailurePhase(
        "default_acl_permissive_helper",
        "default_acl_residue_cleanup",
      );
      const perturbed = await readOwnershipFingerprint(adminPool, databaseName);
      const additions = perturbed.defaultAcl.filter(
        (record) => !baseline.defaultAcl.includes(record),
      );
      assert.ok(
        additions.includes(expectedResidue),
        `expected pg_database_owner ${control.kind} residue in the fingerprint`,
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
          `alter default privileges for role pg_database_owner ${control.revoke}`,
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
}

async function assertUnrelatedDefaultAclCreatorExcluded(
  adminPool,
  databaseName,
  baseline,
) {
  const roleName = "a13_unrelated_default_creator";
  let roleCreated = false;
  markStructuredFailurePhase(
    "unrelated_default_acl_setup",
    "default_acl_residue_cleanup",
  );
  try {
    await adminPool.query(
      `create role ${identifier(roleName)} nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls`,
    );
    roleCreated = true;
    await adminPool.query(
      `alter default privileges for role ${identifier(roleName)} grant select on tables to platform_runtime`,
    );
    markStructuredFailurePhase(
      "unrelated_default_acl_exact_equality",
      "default_acl_residue_cleanup",
    );
    assertExactFingerprint(
      await readOwnershipFingerprint(adminPool, databaseName),
      baseline,
    );
  } finally {
    if (roleCreated) {
      markStructuredFailurePhase(
        "unrelated_default_acl_cleanup",
        "default_acl_residue_cleanup",
      );
      await adminPool.query(`drop owned by ${identifier(roleName)}`);
      await adminPool.query(`drop role ${identifier(roleName)}`);
    }
  }
  markStructuredFailurePhase(
    "post_unrelated_default_acl_exact_fingerprint",
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
  return assertFocusedC3Proof(primary);
}

async function assertFocusedC3Proof(primary) {
  markStructuredFailurePhase(
    "C3_HOSTILE_ENV_RETAINED",
    "c3_security_invariant",
  );
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
  assert.equal(
    process.env.MIGRATOR_ALIGNMENT_TEST_C3_RUNNER_BOUNDARY,
    "runner-sanitised",
  );
  assert.equal(process.env.MIGRATOR_ALIGNMENT_TEST_C3_PGPASS_OWNER, "runner-test");
  await assertPrivateFilePresent(join(homeDirectory, ".pgpass"));
  await assertPrivateFilePresent(
    join(appDataDirectory, "postgresql", "pgpass.conf"),
  );
  let homePassfileContent;
  try {
    homePassfileContent = await readFile(
      join(homeDirectory, ".pgpass"),
      "utf8",
    );
  } catch {
    assert.fail("synthetic HOME .pgpass must be readable");
  }
  assert.equal(
    homePassfileContent.includes(
      `*:*:${primary.databaseName}:platform_migrator:${syntheticMigratorPassword}\n`,
    ),
    true,
  );
  markStructuredFailurePhase(
    "C3_RUNNER_PGPASS_QUARANTINE",
    "c3_security_invariant",
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
  assert.equal(
    controlledPassfilePath.includes("swooshz-platform-pgpass-isolation-"),
    true,
  );

  markStructuredFailurePhase(
    "C3_INHERITED_PG_STATE_SANITISED",
    "c3_security_invariant",
  );
  assert.equal(Object.hasOwn(process.env, "PGPASSWORD"), false);
  assert.equal(
    Object.keys(process.env).some(
      (key) => {
        const comparisonKey = typeof key === "string" ? key.toUpperCase() : "";
        return comparisonKey.startsWith("PG") && comparisonKey !== "PGPASSFILE";
      },
    ),
    false,
  );
  assert.equal(Object.hasOwn(process.env, "NODE_PG_FORCE_NATIVE"), false);
  assert.equal(process.env.PGPASSFILE === controlledPassfilePath, true);
  assert.equal(
    Object.keys(process.env).filter(
      (key) => (typeof key === "string" ? key.toUpperCase() : "") === "PGPASSFILE",
    ).length,
    1,
  );

  // RED/default-pgpass causal control: remove only the bounded child process's
  // quarantine so the parent retains the runner-owned passfile for every
  // subsequent control.
  markStructuredFailurePhase(
    "C3_RED_DEFAULT_PGPASS_ADMISSION",
    "c3_security_invariant",
  );
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
  assert.equal(
    Object.hasOwn(redEnvironment, "NODE_PG_FORCE_NATIVE"),
    false,
  );
  assert.equal(redEnvironment.HOME, homeDirectory);
  assert.equal(redEnvironment.APPDATA, appDataDirectory);
  await runDefaultPgpassControl(redEnvironment);
  assert.equal(
    process.env.PGPASSFILE,
    controlledPassfilePath,
    "runner-owned PGPASSFILE must remain active after RED",
  );

  markStructuredFailurePhase(
    "C3_OMITTED_PASSWORD_REJECTED",
    "c3_security_invariant",
  );
  await assertC3AuthenticationRejected(
    roleUrl("platform_migrator", primary.databaseName),
    /client password must be a string|no password supplied|password authentication failed/i,
  );

  markStructuredFailurePhase(
    "C3_WRONG_PASSWORD_REJECTED",
    "c3_security_invariant",
  );
  await assertC3AuthenticationRejected(
    roleUrl(
      "platform_migrator",
      primary.databaseName,
      wrongMigratorPassword,
    ),
    /password authentication failed/i,
    "28P01",
  );

  markStructuredFailurePhase(
    "C3_CORRECT_PASSWORD_ACCEPTED",
    "c3_security_invariant",
  );
  const correctPasswordPool = new Pool({
    connectionString: roleUrl(
      "platform_migrator",
      primary.databaseName,
      syntheticMigratorPassword,
    ),
    max: 1,
  });
  try {
    await validateMigratorLoginAdmission(
      correctPasswordPool,
      primary.databaseName,
    );
  } finally {
    await correctPasswordPool.end();
  }
}

export async function runDefaultPgpassControl(
  environment,
  {
    childScript = defaultPgpassControlScript,
    timeoutMs = defaultPgpassControlTimeoutMs,
    spawnImpl = spawn,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout,
  } = {},
) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timedOut = false;
    let watchdog = null;
    let child;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (watchdog !== null) {
        clearTimeoutImpl(watchdog);
        watchdog = null;
      }
      if (error) reject(error);
      else resolve();
    };
    const fail = () => finish(new Error(defaultPgpassControlFailureMessage));
    try {
      child = spawnImpl(
        process.execPath,
        ["--input-type=module", "--eval", childScript],
        {
          env: environment,
          stdio: "ignore",
          windowsHide: true,
        },
      );
    } catch {
      fail();
      return;
    }
    child.once("error", fail);
    child.once("close", (code, signal) => {
      if (timedOut) return;
      if (code === 0 && signal === null) finish();
      else fail();
    });
    watchdog = setTimeoutImpl(() => {
      if (settled) return;
      timedOut = true;
      try {
        if (typeof child?.kill !== "function") throw new Error();
        child.kill("SIGTERM");
      } catch {
        // The timeout remains the deterministic failure even if termination races.
      }
      finish(new Error(defaultPgpassControlTimeoutMessage));
    }, timeoutMs);
  });
}

async function assertC3AuthenticationRejected(
  connectionString,
  pattern,
  expectedCode = null,
) {
  const pool = new Pool({ connectionString, max: 1 });
  try {
    await assert.rejects(
      () => pool.query("select 1"),
      (error) =>
        pattern.test(String(error?.message ?? error)) &&
        (expectedCode === null || error?.code === expectedCode),
    );
  } finally {
    await pool.end();
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
