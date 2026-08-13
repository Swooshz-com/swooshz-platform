import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, open, readFile, rm, stat as statPath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";

import { Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresConstructionTargets,
  admitDisposablePostgresFixtures,
  createAuthorizedDatabaseCreationPool,
  createAuthorizedProvisioningPool,
  deriveDisposablePostgresDatabaseCreationAuthority,
  deriveDisposablePostgresProvisioningAuthority,
  invalidateDisposablePostgresAdmission,
  invalidateDisposablePostgresConstructionAdmission,
} from "../tests/support/disposable-postgres-fixture.mjs";
import { runDisposableRuntimeLifecycle } from "./disposable-runtime-lifecycle.mjs";

const databaseName = "migrator_alignment_test";
const secondaryDatabaseName = "migrator_alignment_test_secondary";
const ownedContainerName = "deepseek-platform128-pg17";
const ownedVolumeName = "deepseek-platform128-pg17-data";
const volumeOwnershipTokenLabelKey = "com.swooshz.platform.runner-token";
const ownedPort = 56432;
const maxChildOutputBytes = 64 * 1024;
const focusedCredentialIsolationDirectoryPrefix = "swooshz-platform-pgpass-isolation-";
const syntheticMigratorPassword = "synthetic-migrator-password";
const structuredFailureReceiptPrefix = "PLATFORM_MIGRATOR_FAILURE_V1=";
const structuredFailureReceiptFileEnvironmentVariable =
  "PLATFORM_MIGRATOR_FAILURE_RECEIPT_FILE";
const structuredFailureProgressFileEnvironmentVariable =
  "PLATFORM_MIGRATOR_FAILURE_PROGRESS_FILE";
const maxStructuredReceiptSidecarBytes = 16 * 1024;
const structuredReceiptSidecarDirectoryPrefix =
  "swooshz-platform-migrator-receipt-";
const structuredReceiptFingerprintFields = new Set([
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
]);
const structuredReceiptPhases = new Set([
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
const structuredReceiptAssertionCategories = new Set([
  "baseline_lifecycle",
  "forward_migration",
  "migrated_state_assertion",
  "exact_reverse_rollback",
  "acl_residue_cleanup",
  "default_acl_residue_cleanup",
  "membership_inventory",
  "focused_child_defect",
]);
const structuredReceiptCleanupPhases = new Set([
  "not_started",
  "started",
  "complete",
  "failed",
]);
const structuredReceiptTransportStates = new Set([
  "phase_armed",
  "failure_catch_entered",
  "failure_receipt_write_armed",
]);
const structuredReceiptTestIdPattern = /^[A-Za-z0-9._:-]{1,96}$/u;
const structuredReceiptTuplePattern = /^([A-Za-z][A-Za-z0-9]*):(0|[1-9]\d*)\/(0|[1-9]\d*)$/u;
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const loopbackHosts = new Set(["127.0.0.1", "::1"]);
const failurePhases = new Set([
  "construct",
  "admitConstruction",
  "deriveProvisioning",
  "provision",
  "admitConfigured",
  "runFocusedTests",
  "cleanup",
  "absenceVerification",
]);
const failureCategories = new Set([
  "container_preexistence",
  "volume_preexistence",
  "volume_create",
  "volume_mount_inspection",
  "listener_preexistence",
  "publish_binding_inspection",
  "container_start",
  "postgres_readiness",
  "password_auth_lockdown",
  "secondary_database_creation",
  "construction_target_admission",
  "provisioning_authority",
  "primary_provisioning",
  "secondary_provisioning",
  "configured_fixture_admission",
  "child_test_spawn",
  "child_test_failure",
  "structured_child_receipt_missing",
  "structured_child_failure_receipt_absent_with_progress",
  "structured_child_failure_receipt_invalid",
  "structured_child_context_missing",
  "structured_child_progress_invalid",
  "child_output_overflow",
  "child_signal",
  "cleanup",
  "absence_verification",
  "ci_environment_unclassified",
]);

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  run().catch((error) => {
    process.stderr.write(
      `${error?.runtimeFailureReceipt ?? formatDisposableRuntimeFailureReceipt()}` +
        "\n",
    );
    process.stderr.write("Disposable migrator alignment test runner failed.\n");
    process.exitCode = 1;
  });
}

export async function run({
  env = process.env,
  spawnImpl = spawn,
} = {}) {
  let resources = null;

  try {
    return await runDisposableRuntimeLifecycle({
    construct: async (lifecycleResources) => {
      resources = lifecycleResources;
      Object.assign(resources, {
        phase: "construct",
        failurePhase: null,
        failureCategory: null,
        childExitCode: null,
        childSignal: false,
        childOutputOverflow: false,
        childSummaryParsed: false,
        structuredChildReceipt: null,
        structuredChildProgress: null,
        containerStarted: false,
        postgresReady: false,
        constructionAdmission: false,
        provisioningComplete: false,
        configuredAdmission: false,
        childTestsStarted: false,
        cleanupComplete: false,
        absenceVerified: false,
        focusedCredentialIsolationSetupAttempted: false,
        focusedCredentialIsolationPreSanitization: false,
        focusedCredentialChildBoundary: false,
        focusedCredentialIsolationCleaned: false,
        focusedCredentialIsolationAbsent: false,
        focusedCredentialIsolation: null,
        containerStartAttempted: false,
        ownedContainer: false,
        containerRemoved: false,
        volumePreAbsenceVerified: false,
        volumeCreateAttempted: false,
        volumeCreated: false,
        volumeAttached: false,
        volumeOwned: false,
        volumeRemoved: false,
        volumeOwnershipToken: createVolumeOwnershipToken(),
        volumeAbsenceVerified: false,
        childProcess: null,
        childExited: true,
        databaseUrls: new Map(),
        ownedDatabases: new Set(),
        ownedRoles: new Set([
          "platform_app",
          "platform_migrator",
          "platform_runtime",
          "provider_owner",
        ]),
        ownedSchemas: new Set(["drizzle", "appdata"]),
        ownedObjects: new Set([
          "drizzle.__drizzle_migrations",
          "public.users",
          "appdata.widgets",
          "appdata.widgets_label_uidx",
          "appdata.widget_status",
          "appdata.counter_seq",
          "appdata.widget_summary",
          ...contractTableNames().map((name) => `public.${name}`),
        ]),
        runnerOwned: new Set(),
        callerManaged: new Set([
          "docker daemon",
          "postgres default database",
        ]),
      });
      await runAt(resources, "construct", "container_preexistence", async () => {
        assertNoCallerSuppliedFixture(env);
        await assertExactContainerAbsent(spawnImpl);
      });
      await runAt(resources, "construct", "volume_preexistence", async () => {
        await assertExactVolumeAbsent(spawnImpl);
        resources.volumePreAbsenceVerified = true;
      });
      await runAt(resources, "construct", "listener_preexistence", async () => {
        await assertOwnedListenerAbsent();
      });
      resources.volumeCreateAttempted = true;
      await runAt(resources, "construct", "volume_create", async () => {
        const createdVolume = await createOwnedVolume(
          spawnImpl,
          resources.volumeOwnershipToken,
        );
        resources.volumeCreated = true;
        if (createdVolume !== ownedVolumeName) throw new Error();
      });
      resources.containerStartAttempted = true;
      await runAt(resources, "construct", "container_start", () =>
        startOwnedContainer(spawnImpl));
      resources.ownedContainer = true;
      resources.containerStarted = true;
      resources.runnerOwned.add(`container:${ownedContainerName}`);
      resources.runnerOwned.add(`listener:127.0.0.1:${ownedPort}`);
      await runAt(resources, "construct", "publish_binding_inspection", () =>
        assertExactPublishedBinding(spawnImpl));
      await runAt(resources, "construct", "volume_mount_inspection", async () => {
        await assertExactVolumeMount(spawnImpl);
        resources.volumeAttached = true;
        resources.volumeOwned = true;
        resources.runnerOwned.add(`volume:${ownedVolumeName}`);
      });

      const urls = fixtureUrls();
      resources.databaseUrls = new Map([
        [databaseName, urls.primaryOperatorUrl],
        [secondaryDatabaseName, urls.secondaryOperatorUrl],
      ]);
      resources.ownedDatabases.add(databaseName);

      await runAt(resources, "construct", "postgres_readiness", async () => {
        await waitForPostgres(urls.primaryOperatorUrl);
        resources.postgresReady = true;
      });
      await runAt(resources, "construct", "password_auth_lockdown", () =>
        applyMigratorPasswordAuth(spawnImpl));
      return urls;
    },

    admitConstruction: async (urls) => runAt(
      resources,
      "admitConstruction",
      "construction_target_admission",
      async () => {
        const admission = await admitDisposablePostgresConstructionTargets([
          constructionTargetDefinition("primary", urls.primaryOperatorUrl),
          constructionTargetDefinition(
            "secondary",
            urls.secondaryOperatorUrl,
            urls.rootOperatorUrl,
          ),
        ]);
        resources.constructionAdmission = true;
        return admission;
      },
    ),

    deriveProvisioning: async (constructionAuthority) => runAt(
      resources,
      "deriveProvisioning",
      "provisioning_authority",
      async () => {
        const authorities = new Map();
        for (const targetName of ["primary", "secondary"]) {
          authorities.set(
            targetName,
            deriveDisposablePostgresProvisioningAuthority(
              constructionAuthority,
              targetName,
            ),
          );
        }
        return {
          authorities,
          creationAuthorities: new Map([
            [
              "secondary",
              deriveDisposablePostgresDatabaseCreationAuthority(
                constructionAuthority,
                "secondary",
              ),
            ],
          ]),
        };
      },
    ),

    provision: async (authorities, urls, lifecycleResources) => {
      await runAt(
        lifecycleResources,
        "provision",
        "secondary_database_creation",
        () => ensureDatabase(
          urls.rootOperatorUrl,
          secondaryDatabaseName,
          authorities.creationAuthorities.get("secondary"),
          lifecycleResources,
        ),
      );
      await runAt(
        lifecycleResources,
        "provision",
        "primary_provisioning",
        () => provisionFixture(
          urls.primaryOperatorUrl,
          databaseName,
          authorities.authorities.get("primary"),
          lifecycleResources,
          "pg-database-owner-public",
        ),
      );
      await runAt(
        lifecycleResources,
        "provision",
        "secondary_provisioning",
        () => provisionFixture(
          urls.secondaryOperatorUrl,
          secondaryDatabaseName,
          authorities.authorities.get("secondary"),
          lifecycleResources,
          "stable-provider-owner-public",
        ),
      );
      lifecycleResources.provisioningComplete = true;
    },

    admitConfigured: async (urls) => runAt(
      resources,
      "admitConfigured",
      "configured_fixture_admission",
      async () => {
        const admission = await admitDisposablePostgresFixtures([
          fixtureDefinition("primary", urls),
          fixtureDefinition("secondary", urls),
        ]);
        resources.configuredAdmission = true;
        return admission;
      },
    ),

    runFocusedTests: async (admission, lifecycleResources) => runAt(
      lifecycleResources,
      "runFocusedTests",
      "child_test_failure",
      () => runFocusedTests({
        admission,
        urls: lifecycleResources.construction,
        spawnImpl,
        resources: lifecycleResources,
        parentEnv: env,
      }),
    ),

    cleanup: async (lifecycleResources) => runAt(
      lifecycleResources,
      "cleanup",
      "cleanup",
      async () => {
        await cleanupRunnerResources(lifecycleResources, spawnImpl);
        lifecycleResources.cleanupComplete = true;
      },
    ),

    verifyAbsence: async (lifecycleResources) => runAt(
      lifecycleResources,
      "absenceVerification",
      "absence_verification",
      async () => {
        await verifyRunnerAbsence(lifecycleResources, spawnImpl);
        lifecycleResources.absenceVerified = true;
      },
    ),
    });
  } catch (error) {
    const failure = error instanceof Error ? error : new Error();
    Object.defineProperty(failure, "runtimeFailureReceipt", {
      configurable: true,
      value: formatDisposableRuntimeFailureReceipt(resources),
    });
    throw failure;
  }
}

export function formatDisposableRuntimeFailureReceipt(resources = {}) {
  const receipt = {
    phase: failurePhases.has(resources.failurePhase)
      ? resources.failurePhase
      : "construct",
    category: failureCategories.has(resources.failureCategory)
      ? resources.failureCategory
      : "ci_environment_unclassified",
    childExitCode: Number.isInteger(resources.childExitCode)
      ? resources.childExitCode
      : null,
    childSignal: resources.childSignal === true,
    outputOverflow: resources.childOutputOverflow === true,
    summaryParsed: resources.childSummaryParsed === true,
    structuredChildReceipt: projectStructuredChildReceipt(
      resources.structuredChildReceipt,
    ),
    structuredChildProgress: projectStructuredChildProgress(
      resources.structuredChildProgress,
    ),
    containerStarted: resources.containerStarted === true,
    volumePreAbsenceVerified: resources.volumePreAbsenceVerified === true,
    volumeCreateAttempted: resources.volumeCreateAttempted === true,
    volumeCreated: resources.volumeCreated === true,
    volumeAttached: resources.volumeAttached === true,
    volumeOwned: resources.volumeOwned === true,
    volumeOwnershipState: resources.volumeOwnershipState ?? "unknown",
    volumeRemoved: resources.volumeRemoved === true,
    volumeAbsenceVerified: resources.volumeAbsenceVerified === true,
    postgresReady: resources.postgresReady === true,
    constructionAdmission: resources.constructionAdmission === true,
    provisioningComplete: resources.provisioningComplete === true,
    configuredAdmission: resources.configuredAdmission === true,
    childTestsStarted: resources.childTestsStarted === true,
    cleanupComplete: resources.cleanupComplete === true,
    absenceVerified: resources.absenceVerified === true,
    focusedCredentialIsolationPreSanitization:
      resources.focusedCredentialIsolationPreSanitization === true,
    focusedCredentialChildBoundary:
      resources.focusedCredentialChildBoundary === true,
    focusedCredentialIsolationCleaned:
      resources.focusedCredentialIsolationCleaned === true,
    focusedCredentialIsolationAbsent:
      resources.focusedCredentialIsolationAbsent === true,
  };
  return `Disposable fixture failure receipt: ${JSON.stringify(receipt)}`;
}

function projectStructuredFailureReceipt(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.version !== 1 || typeof value.test_id !== "string") return null;
  if (!structuredReceiptTestIdPattern.test(value.test_id)) return null;
  if (!structuredReceiptPhases.has(value.phase)) return null;
  if (!structuredReceiptAssertionCategories.has(value.assertion_category)) {
    return null;
  }
  if (!Array.isArray(value.fingerprint_fields)) return null;
  if (value.fingerprint_fields.length > structuredReceiptFingerprintFields.size) {
    return null;
  }
  const fingerprintFields = [];
  for (const field of value.fingerprint_fields) {
    if (
      typeof field !== "string" ||
      !structuredReceiptFingerprintFields.has(field) ||
      fingerprintFields.includes(field)
    ) {
      return null;
    }
    fingerprintFields.push(field);
  }
  if (!Array.isArray(value.tuple_counts)) return null;
  const tupleCounts = [];
  for (const entry of value.tuple_counts) {
    if (typeof entry !== "string" || tupleCounts.includes(entry)) return null;
    const match = entry.match(structuredReceiptTuplePattern);
    if (!match || !structuredReceiptFingerprintFields.has(match[1])) {
      return null;
    }
    tupleCounts.push(entry);
  }
  if (!structuredReceiptCleanupPhases.has(value.cleanup_phase)) return null;
  return {
    version: 1,
    test_id: value.test_id,
    phase: value.phase,
    assertion_category: value.assertion_category,
    fingerprint_fields: fingerprintFields,
    tuple_counts: tupleCounts,
    cleanup_phase: value.cleanup_phase,
  };
}

export function parseStructuredFailureReceipt(output) {
  if (
    typeof output !== "string" ||
    Buffer.byteLength(output, "utf8") > maxStructuredReceiptSidecarBytes
  ) {
    return null;
  }
  const lines = output.replace(/\r\n?/gu, "\n").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (
    lines.length !== 1 ||
    !lines[0].startsWith(structuredFailureReceiptPrefix)
  ) {
    return null;
  }
  const payload = lines[0].slice(structuredFailureReceiptPrefix.length);
  if (payload.length === 0 || payload.trim() !== payload) return null;
  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }
  return projectStructuredFailureReceipt(parsed);
}

export async function createStructuredFailureReceiptSidecar() {
  const temporaryRoot = resolve(tmpdir());
  const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const temporaryRootRelativeToRepository = relative(
    repositoryRoot,
    temporaryRoot,
  );
  if (
    temporaryRootRelativeToRepository === "" ||
    (!temporaryRootRelativeToRepository.startsWith("..") &&
      !isAbsolute(temporaryRootRelativeToRepository))
  ) {
    throw new Error();
  }
  const directory = await mkdtemp(
    join(
      temporaryRoot,
      structuredReceiptSidecarDirectoryPrefix + randomUUID() + "-",
    ),
  );
  return Object.freeze({
    directory,
    progressFilePath: join(directory, "progress"),
    filePath: join(directory, "receipt"),
  });
}

export async function readStructuredFailureReceiptFile(filePath) {
  const result = await readStructuredSidecarFile(filePath, parseStructuredFailureReceipt);
  return result.status === "valid" ? result.value : null;
}

export async function readStructuredFailureProgressFile(filePath) {
  const result = await readStructuredSidecarFile(filePath, parseStructuredFailureProgress);
  return result.status === "valid" ? result.value : null;
}

export async function readStructuredChildFailureDiagnostics(sidecar) {
  const finalReceipt = await readStructuredSidecarFile(
    sidecar?.filePath,
    parseStructuredFailureReceipt,
  );
  if (finalReceipt.status === "valid") {
    return { kind: "final", receipt: finalReceipt.value };
  }
  if (finalReceipt.status === "invalid") {
    return { kind: "final_invalid" };
  }

  const progress = await readStructuredSidecarFile(
    sidecar?.progressFilePath,
    parseStructuredFailureProgress,
  );
  if (progress.status === "valid") {
    return { kind: "progress", progress: progress.value };
  }
  if (progress.status === "invalid") {
    return { kind: "progress_invalid" };
  }
  return { kind: "missing" };
}

async function readStructuredSidecarFile(filePath, parser) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    return { status: "missing" };
  }
  let handle = null;
  try {
    handle = await open(filePath, "r");
    const buffer = Buffer.allocUnsafe(maxStructuredReceiptSidecarBytes + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(
        buffer,
        bytesRead,
        buffer.length - bytesRead,
        null,
      );
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    if (bytesRead > maxStructuredReceiptSidecarBytes) {
      return { status: "invalid" };
    }
    const value = parser(buffer.subarray(0, bytesRead).toString("utf8"));
    return value ? { status: "valid", value } : { status: "invalid" };
  } catch (error) {
    return error?.code === "ENOENT"
      ? { status: "missing" }
      : { status: "invalid" };
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export async function cleanupStructuredFailureReceiptSidecar(sidecar) {
  let cleanupFailed = false;
  try {
    await rm(sidecar?.directory, { force: true, recursive: true });
  } catch {
    cleanupFailed = true;
  }
  for (const path of [sidecar?.filePath, sidecar?.progressFilePath, sidecar?.directory]) {
    if (typeof path !== "string") {
      cleanupFailed = true;
      continue;
    }
    try {
      await access(path);
      cleanupFailed = true;
    } catch (error) {
      if (error?.code !== "ENOENT") cleanupFailed = true;
    }
  }
  if (cleanupFailed) throw new Error();
}
function projectStructuredChildProgress(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.version !== 1 || typeof value.test_id !== "string") return null;
  if (!structuredReceiptTestIdPattern.test(value.test_id)) return null;
  if (!structuredReceiptPhases.has(value.phase)) return null;
  if (!structuredReceiptAssertionCategories.has(value.assertion_category)) {
    return null;
  }
  if (!Array.isArray(value.fingerprint_fields)) return null;
  if (value.fingerprint_fields.length > structuredReceiptFingerprintFields.size) return null;
  const fingerprintFields = [];
  for (const field of value.fingerprint_fields) {
    if (typeof field !== "string" || !structuredReceiptFingerprintFields.has(field) || fingerprintFields.includes(field)) {
      return null;
    }
    fingerprintFields.push(field);
  }
  if (!Array.isArray(value.tuple_counts)) return null;
  if (value.tuple_counts.length > structuredReceiptFingerprintFields.size) return null;
  const tupleCounts = [];
  for (const entry of value.tuple_counts) {
    if (typeof entry !== "string" || tupleCounts.includes(entry)) return null;
    const match = entry.match(structuredReceiptTuplePattern);
    if (!match || !structuredReceiptFingerprintFields.has(match[1])) return null;
    tupleCounts.push(entry);
  }
  if (!structuredReceiptCleanupPhases.has(value.cleanup_phase)) return null;
  if (!structuredReceiptTransportStates.has(value.transport_state)) return null;
  return {
    version: 1,
    test_id: value.test_id,
    phase: value.phase,
    assertion_category: value.assertion_category,
    fingerprint_fields: fingerprintFields,
    tuple_counts: tupleCounts,
    cleanup_phase: value.cleanup_phase,
    transport_state: value.transport_state,
  };
}
function parseStructuredFailureProgress(output) {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > maxStructuredReceiptSidecarBytes) {
    return null;
  }
  const lines = output.replaceAll(String.fromCharCode(13), "").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== 1 || lines[0].trim() !== lines[0]) return null;
  let parsed;
  try {
    parsed = JSON.parse(lines[0]);
  } catch {
    return null;
  }
  return projectStructuredChildProgress(parsed);
}

function projectStructuredChildReceipt(value) {
  const receipt = projectStructuredFailureReceipt(value);
  if (!receipt) return null;
  return {
    ...receipt,
    child_exit_code:
      Number.isSafeInteger(value.child_exit_code) &&
      value.child_exit_code >= 0 &&
      value.child_exit_code <= 255
        ? value.child_exit_code
        : null,
    child_signal:
      typeof value.child_signal === "string" &&
      /^[A-Z0-9_]{1,32}$/u.test(value.child_signal)
        ? value.child_signal
        : null,
    runner_category: failureCategories.has(value.runner_category)
      ? value.runner_category
      : null,
  };
}
async function runAt(resources, phase, category, operation) {
  resources.phase = phase;
  try {
    return await operation();
  } catch (error) {
    if (!resources.failureCategory) {
      resources.failurePhase = phase;
      resources.failureCategory = category;
    }
    throw error;
  }
}

function fixtureUrls() {
  return {
    rootOperatorUrl: buildUrl("postgres", "postgres"),
    primaryTargetUrl: buildUrl("platform_app", databaseName),
    primaryOperatorUrl: buildUrl("postgres", databaseName),
    secondaryTargetUrl: buildUrl("platform_app", secondaryDatabaseName),
    secondaryOperatorUrl: buildUrl("postgres", secondaryDatabaseName),
  };
}

function buildUrl(user, database) {
  if (!safeIdentifier.test(user) || !safeIdentifier.test(database)) {
    throw new Error();
  }
  return `postgres://${user}@127.0.0.1:${ownedPort}/${database}`;
}

function constructionTargetDefinition(
  name,
  connectionString,
  creationConnectionString,
) {
  const expectedDatabase = name === "primary"
    ? databaseName
    : secondaryDatabaseName;
  return {
    name,
    connectionString,
    ...(creationConnectionString
      ? {
          allowDatabaseCreation: true,
          creationConnectionString,
          databaseMayBeAbsent: true,
        }
      : {}),
    expectedDatabase,
    expectedUser: "postgres",
    phase: "initialization",
    transport: { kind: "loopback", phase: "initialization" },
  };
}

function fixtureDefinition(name, urls) {
  const secondary = name === "secondary";
  return {
    name,
    connectionString: secondary ? urls.secondaryTargetUrl : urls.primaryTargetUrl,
    expectedDatabase: secondary ? secondaryDatabaseName : databaseName,
    expectedUser: "platform_app",
    expectedRuntimeRole: "platform_runtime",
    expectedMutationUser: "postgres",
    operatorUrl: secondary ? urls.secondaryOperatorUrl : urls.primaryOperatorUrl,
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

async function ensureDatabase(
  operatorUrl,
  expectedDatabase,
  creationAuthority,
  resources,
) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    const authorizedPool = createAuthorizedDatabaseCreationPool(
      operatorPool,
      creationAuthority,
    );
    const result = await authorizedPool.query(
      "select 1 from pg_database where datname = $1",
      [expectedDatabase],
    );
    if (result.rows.length === 0) {
      await authorizedPool.query(`create database ${quoteIdentifier(expectedDatabase)}`);
      resources.ownedDatabases.add(expectedDatabase);
      resources.runnerOwned.add(`database:${expectedDatabase}`);
    } else {
      throw new Error();
    }
  } finally {
    await operatorPool.end();
  }
}

async function provisionFixture(
  operatorUrl,
  expectedDatabase,
  authority,
  resources,
  variant,
) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  const authorizedPool = createAuthorizedProvisioningPool(operatorPool, authority);
  try {
    await authorizedPool.query(`
      do $fixture$
      begin
        if not exists (select 1 from pg_roles where rolname = 'platform_app') then
          create role platform_app login nosuperuser createdb createrole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'platform_runtime') then
          create role platform_runtime nologin nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'provider_owner') then
          create role provider_owner nologin nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
      end
      $fixture$
    `);
    await authorizedPool.query(
      "alter role platform_app login inherit nosuperuser createdb createrole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role platform_runtime nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role provider_owner nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query("revoke platform_runtime from platform_app");
    await authorizedPool.query("revoke platform_app from platform_runtime");
    await authorizedPool.query("revoke provider_owner from platform_app");
    await authorizedPool.query("revoke platform_app from provider_owner");
    await authorizedPool.query("revoke provider_owner from platform_runtime");
    await authorizedPool.query("revoke platform_runtime from provider_owner");

    await authorizedPool.query(
      `alter database ${quoteIdentifier(expectedDatabase)} owner to platform_app`,
    );
    if (variant === "stable-provider-owner-public") {
      await authorizedPool.query(
        `alter schema public owner to provider_owner`,
      );
    } else if (variant === "pg-database-owner-public") {
      const publicOwner = await authorizedPool.query(
        `select pg_get_userbyid(nspowner)::text as owner
           from pg_namespace
          where nspname = 'public'`,
      );
      if (publicOwner.rows?.[0]?.owner !== "pg_database_owner") {
        throw new Error();
      }
      await authorizedPool.query(
        "alter default privileges for role pg_database_owner revoke all privileges on tables from public",
      );
      await authorizedPool.query(
        "alter default privileges for role pg_database_owner revoke all privileges on sequences from public",
      );
      await authorizedPool.query(
        "alter default privileges for role pg_database_owner revoke execute on functions from public",
      );
    } else {
      throw new Error();
    }
    await authorizedPool.query(
      "create schema appdata authorization platform_app",
    );
    await authorizedPool.query(
      "create schema drizzle authorization platform_app",
    );
    await authorizedPool.query("alter schema appdata owner to platform_app");
    await authorizedPool.query("alter schema drizzle owner to platform_app");
    await authorizedPool.query(
      "create table drizzle.__drizzle_migrations (id integer primary key, hash text not null)",
    );
    await authorizedPool.query(
      "alter table drizzle.__drizzle_migrations owner to platform_app",
    );
    await authorizedPool.query(
      `grant connect on database ${quoteIdentifier(expectedDatabase)} to platform_app`,
    );
    await authorizedPool.query(
      `revoke create on database ${quoteIdentifier(expectedDatabase)} from public`,
    );
    await authorizedPool.query("revoke create on schema public from public");
    await authorizedPool.query("grant usage on schema public to platform_app");
    await authorizedPool.query("grant usage on schema appdata to platform_app");

    await authorizedPool.query(
      "create type appdata.widget_status as enum ('active', 'disabled')",
    );
    await authorizedPool.query(
      "alter type appdata.widget_status owner to platform_app",
    );
    await authorizedPool.query(
      "create table appdata.widgets (id integer primary key, label text not null, status appdata.widget_status not null default 'active')",
    );
    await authorizedPool.query(
      "alter table appdata.widgets owner to platform_app",
    );
    await authorizedPool.query(
      "create unique index widgets_label_uidx on appdata.widgets (label)",
    );
    await authorizedPool.query(
      "create sequence appdata.counter_seq",
    );
    await authorizedPool.query(
      "alter sequence appdata.counter_seq owner to platform_app",
    );
    await authorizedPool.query(
      "create function appdata.widget_summary() returns bigint language sql as $$ select count(*)::bigint from appdata.widgets $$",
    );
    await authorizedPool.query(
      "alter function appdata.widget_summary() owner to platform_app",
    );

    for (const tableName of contractTableNames()) {
      await authorizedPool.query(
        `create table public.${quoteIdentifier(tableName)} (id integer)`,
      );
      await authorizedPool.query(
        `alter table public.${quoteIdentifier(tableName)} owner to platform_app`,
      );
      await authorizedPool.query(
        `revoke all privileges on table public.${quoteIdentifier(tableName)} from platform_runtime`,
      );
    }
    for (const [tableName, privileges] of privilegesByTable()) {
      await authorizedPool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema appdata from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema appdata from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema public from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema public from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema appdata from public",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema appdata from public",
    );
    await authorizedPool.query(
      "revoke execute on function appdata.widget_summary() from public",
    );
    await authorizedPool.query(
      "alter default privileges for role postgres revoke execute on functions from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke all privileges on tables from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke all privileges on sequences from public",
    );
    await authorizedPool.query(
      "alter default privileges for role platform_app revoke execute on functions from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke all privileges on tables from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke all privileges on sequences from public",
    );
    await authorizedPool.query(
      "alter default privileges for role provider_owner revoke execute on functions from public",
    );
    resources.runnerOwned.add(`role:platform_app:${expectedDatabase}`);
    resources.runnerOwned.add(`role:platform_migrator:${expectedDatabase}`);
    resources.runnerOwned.add(`role:platform_runtime:${expectedDatabase}`);
    resources.runnerOwned.add(`role:provider_owner:${expectedDatabase}`);
    resources.runnerOwned.add(`schema:drizzle:${expectedDatabase}`);
    resources.runnerOwned.add(`schema:appdata:${expectedDatabase}`);
    for (const object of resources.ownedObjects) {
      resources.runnerOwned.add(`${object}:${expectedDatabase}`);
    }
  } finally {
    await authorizedPool.end();
  }
}

async function runFocusedTests({ admission, urls, spawnImpl, resources, parentEnv }) {
  resources.focusedCredentialIsolationSetupAttempted = true;
  const isolation = await createFocusedCredentialIsolation(resources);
  resources.focusedCredentialIsolation = isolation;
  const originalSpawnImpl = spawnImpl;
  spawnImpl = (command, args, options = {}) => {
    const beforeSanitization = options.env ?? {};
    const childEnv = buildFocusedTestEnvironment(
      beforeSanitization,
      isolation.controlledPassfilePath,
    );
    assertFocusedCredentialBoundary(
      resources,
      beforeSanitization,
      childEnv,
      isolation,
    );
    return originalSpawnImpl(command, args, {
      ...options,
      env: childEnv,
    });
  };
  const env = {
    ...parentEnv,
    ...isolation.hostileEnvironment,
    MIGRATOR_ALIGNMENT_TEST_DATABASE_URL: urls.primaryTargetUrl,
    MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL: urls.primaryOperatorUrl,
    MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL: urls.secondaryTargetUrl,
    MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL: urls.secondaryOperatorUrl,
    MIGRATOR_ALIGNMENT_TEST_CONFIRM: "disposable-only",
  };
  let sidecar = null;
  try {
    sidecar = await createStructuredFailureReceiptSidecar();
    await new Promise((resolvePromise, reject) => {
      const childEnv = {
        ...env,
        [structuredFailureReceiptFileEnvironmentVariable]: sidecar.filePath,
        [structuredFailureProgressFileEnvironmentVariable]: sidecar.progressFilePath,
      };
      let outputLength = 0;
      let outputOverflow = false;
      let child;
      try {
        child = spawnImpl(
          process.execPath,
          [
            "--test",
            "tests/platform-migrator-alignment-postgres.test.mjs",
          ],
          {
            env: childEnv,
            stdio: ["ignore", "pipe", "pipe"],
            windowsHide: true,
          },
        );
      } catch (error) {
        markChildFailure(resources, "child_test_spawn");
        throw error;
      }
      resources.childProcess = child;
      resources.childExited = false;
      resources.childTestsStarted = true;
      child.stdout?.on("data", (chunk) => {
        outputLength += Buffer.from(chunk).length;
        if (outputLength > maxChildOutputBytes) outputOverflow = true;
      });
      child.stderr?.resume();
      child.once("error", (error) => {
        markChildFailure(resources, "child_test_spawn");
        reject(error);
      });
      child.once("close", (code, signal) => {
        resources.childExited = true;
        resources.childExitCode = Number.isInteger(code) ? code : null;
        resources.childSignal = signal !== null;
        if (code !== 0 || resources.childSignal) {
          void readStructuredChildFailureDiagnostics(sidecar).then((diagnostic) => {
            if (diagnostic.kind === "final") {
              resources.structuredChildReceipt = {
                ...diagnostic.receipt,
                child_exit_code: resources.childExitCode,
                child_signal: typeof signal === "string" ? signal : null,
                runner_category: "child_test_failure",
              };
              resources.childOutputOverflow = outputOverflow;
              markChildFailure(resources, "child_test_failure");
              reject(new Error("Focused child test failed."));
              return;
            }
            if (diagnostic.kind === "final_invalid") {
              markChildFailure(resources, "structured_child_failure_receipt_invalid");
              reject(new Error("Focused child test failed with an invalid structured receipt."));
              return;
            }
            if (diagnostic.kind === "progress") {
              resources.structuredChildProgress = diagnostic.progress;
              markChildFailure(
                resources,
                "structured_child_failure_receipt_absent_with_progress",
              );
              reject(new Error("Focused child test failed with durable progress."));
              return;
            }
            if (diagnostic.kind === "progress_invalid") {
              markChildFailure(resources, "structured_child_progress_invalid");
              reject(new Error("Focused child test failed with invalid durable progress."));
              return;
            }
            markChildFailure(resources, "structured_child_context_missing");
            reject(new Error("Focused child test failed without bounded context."));
          });
          return;
        }
        if (outputOverflow) {
          resources.childOutputOverflow = true;
          markChildFailure(resources, "child_output_overflow");
          reject(new Error());
          return;
        }
        if (code === 0 && signal === null) {
          // Retained as completion evidence for the existing lifecycle contract; no reporter text is parsed.
          resources.childSummaryParsed = true;
          process.stdout.write(
            "Disposable PostgreSQL 17 migrator alignment child exited successfully.\n",
          );
          resolvePromise();
        }
      });
    });
  } finally {
    if (sidecar) {
      await cleanupStructuredFailureReceiptSidecar(sidecar);
    }
  }
  void admission;
}

function markChildFailure(resources, category) {
  if (!resources.failureCategory) {
    resources.failurePhase = "runFocusedTests";
    resources.failureCategory = category;
  }
}

async function cleanupRunnerResources(resources, spawnImpl) {
  let firstError = null;
  try {
    if (resources.constructionAuthority) {
      invalidateDisposablePostgresConstructionAdmission(
        resources.constructionAuthority,
      );
    }
  } catch {
    firstError ??= new Error();
  }
  try {
    if (resources.configuredAdmission) {
      invalidateDisposablePostgresAdmission(resources.configuredAdmission);
    }
  } catch {
    firstError ??= new Error();
  }
  try {
    await terminateOwnedChild(resources);
  } catch {
    firstError ??= new Error();
  }
  try {
    await cleanupFocusedCredentialIsolation(resources);
  } catch {
    firstError ??= new Error();
  }
  try {
    await cleanupFixtureDatabases(resources);
  } catch {
    firstError ??= new Error();
  }
  if (resources.containerStartAttempted) {
    try {
      await runCommand(spawnImpl, "docker", [
        "rm",
        "--force",
        ownedContainerName,
      ]);
      resources.containerRemoved = true;
    } catch {
      firstError ??= new Error();
    }
  }
  if (resources.volumeCreateAttempted && !resources.volumeRemoved) {
    try {
      await cleanupOwnedVolumeAfterCreateAttempt(spawnImpl, resources);
    } catch {
      firstError ??= new Error();
    }
  }
  if (firstError) throw firstError;
}

async function cleanupFixtureDatabases(resources) {
  if (!resources.ownedContainer || resources.ownedDatabases.size === 0) {
    return;
  }
  const rootUrl = buildUrl("postgres", "postgres");
  for (const database of resources.ownedDatabases) {
    const pool = new Pool({ connectionString: buildUrl("postgres", database), max: 1 });
    try {
      for (const tableName of ["users", ...contractTableNames()]) {
        await pool.query(
          `drop table if exists public.${quoteIdentifier(tableName)} cascade`,
        );
      }
      await pool.query("drop schema if exists drizzle cascade");
      await pool.query("drop schema if exists appdata cascade");
    } finally {
      await pool.end();
    }
  }
  const rootPool = new Pool({ connectionString: rootUrl, max: 1 });
  try {
    for (const database of resources.ownedDatabases) {
      await rootPool.query(
        `drop database if exists ${quoteIdentifier(database)} with (force)`,
      );
    }
    const roleResult = await rootPool.query(
      "select rolname from pg_roles where rolname <> 'postgres' and rolname not like 'pg_%'",
    );
    const roleNames = new Set(resources.ownedRoles);
    for (const row of roleResult.rows) {
      if (typeof row.rolname !== "string" || !safeIdentifier.test(row.rolname)) {
        throw new Error();
      }
      roleNames.add(row.rolname);
    }
    for (const roleName of roleNames) {
      await rootPool.query(`drop role if exists ${quoteIdentifier(roleName)}`);
    }
  } finally {
    await rootPool.end();
  }
}

async function verifyRunnerAbsence(resources, spawnImpl) {
  if (resources.focusedCredentialIsolationSetupAttempted) {
    await verifyFocusedCredentialIsolationAbsence(resources);
  }
  if (resources.childProcess && !resources.childExited) throw new Error();
  if (!resources.containerStartAttempted) {
    if (resources.volumeCreateAttempted) {
      await assertExactVolumeAbsent(spawnImpl);
      resources.volumeAbsenceVerified = true;
      if (resources.volumeCreated && !resources.volumeRemoved) throw new Error();
    }
    return;
  }
  const names = await assertExactContainerAbsent(spawnImpl);
  if (names !== "") throw new Error();
  if (!resources.containerRemoved) throw new Error();
  if (resources.volumeCreateAttempted) {
    await assertExactVolumeAbsent(spawnImpl);
    resources.volumeAbsenceVerified = true;
    if (resources.volumeCreated && !resources.volumeRemoved) throw new Error();
  }
  await assertPortAbsent();
}

async function terminateOwnedChild(resources) {
  const child = resources.childProcess;
  if (!child || resources.childExited) return;
  if (typeof child.kill !== "function" || !child.kill("SIGTERM")) {
    throw new Error();
  }
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error()), 2_000);
    child.once("close", () => {
      clearTimeout(timer);
      resources.childExited = true;
      resolvePromise();
    });
  });
}

function ownedVolumeOwnershipMarker() {
  return {
    key: "com.swooshz.platform.runner",
    value: "deepseek-platform128-migrator",
  };
}

function createVolumeOwnershipToken() {
  return randomUUID();
}

function isVolumeOwnershipToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}

function volumeOwnershipLabels(ownershipToken) {
  if (!isVolumeOwnershipToken(ownershipToken)) throw new Error();
  const marker = ownedVolumeOwnershipMarker();
  return {
    [marker.key]: marker.value,
    [volumeOwnershipTokenLabelKey]: ownershipToken,
  };
}

function malformedOwnedVolumeState() {
  return { state: "ambiguous" };
}

export async function inspectOwnedVolumeOwnership(spawnImpl, ownershipToken) {
  let listedOutput;
  try {
    listedOutput = await runCommand(spawnImpl, "docker", [
      "volume",
      "ls",
      "--filter",
      `name=${ownedVolumeName}`,
      "--format",
      "{{.Name}}",
    ]);
  } catch {
    return malformedOwnedVolumeState();
  }

  const names = String(listedOutput ?? "")
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  if (names.length === 0) return { state: "absent" };
  if (names.length !== 1 || names[0] !== ownedVolumeName) {
    return malformedOwnedVolumeState();
  }

  let inspectedOutput;
  try {
    inspectedOutput = await runCommand(spawnImpl, "docker", [
      "volume",
      "inspect",
      "--format",
      "{{json .}}",
      ownedVolumeName,
    ]);
  } catch {
    return malformedOwnedVolumeState();
  }

  const inspectedLines = String(inspectedOutput ?? "")
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  if (inspectedLines.length !== 1) return malformedOwnedVolumeState();

  let details;
  try {
    details = JSON.parse(inspectedLines[0]);
  } catch {
    return malformedOwnedVolumeState();
  }
  if (!details || Array.isArray(details) || typeof details !== "object") {
    return malformedOwnedVolumeState();
  }
  if (details.Name !== ownedVolumeName) return { state: "unowned" };

  const marker = ownedVolumeOwnershipMarker();
  if (
    !details.Labels ||
    typeof details.Labels !== "object" ||
    Array.isArray(details.Labels)
  ) {
    return { state: "unowned" };
  }
  if (
    details.Labels[marker.key] !== marker.value ||
    details.Labels[volumeOwnershipTokenLabelKey] !== ownershipToken
  ) {
    return { state: "unowned" };
  }
  return { state: "owned" };
}

export async function cleanupOwnedVolumeAfterCreateAttempt(spawnImpl, resources) {
  if (!resources.volumeCreateAttempted || resources.volumeRemoved) {
    return "not-required";
  }
  if (resources.containerStartAttempted && !resources.containerRemoved) {
    throw new Error("volume cleanup requires container cleanup first");
  }

  const state = await inspectOwnedVolumeOwnership(
    spawnImpl,
    resources.volumeOwnershipToken,
  );
  resources.volumeOwnershipState = state.state;
  if (state.state === "absent") return state.state;
  if (state.state !== "owned") {
    throw new Error(`owned volume evidence was ${state.state}`);
  }

    await runCommand(spawnImpl, "docker", ["volume", "rm", ownedVolumeName]);
  resources.volumeCreated = true;
  resources.volumeOwned = true;
  resources.volumeRemoved = true;
  return "removed";
}

export async function createOwnedVolume(spawnImpl, ownershipToken) {
  const marker = ownedVolumeOwnershipMarker();
  const labels = volumeOwnershipLabels(ownershipToken);
  const output = await runCommand(spawnImpl, "docker", [
    "volume",
    "create",
    "--label",
    `${marker.key}=${marker.value}`,
    "--label",
    `${volumeOwnershipTokenLabelKey}=${labels[volumeOwnershipTokenLabelKey]}`,
    ownedVolumeName,
  ]);
  if (String(output ?? "").trim() && String(output).trim() !== ownedVolumeName) {
    throw new Error("docker volume create returned an unexpected name");
  }
  const state = await inspectOwnedVolumeOwnership(spawnImpl, ownershipToken);
  if (state.state !== "owned") {
    throw new Error(`created volume ownership evidence was ${state.state}`);
  }
  return ownedVolumeName;
}


async function startOwnedContainer(spawnImpl) {
  await runCommand(spawnImpl, "docker", [
    "run",
    "--detach",
    "--name",
    ownedContainerName,
    "--mount",
    `type=volume,source=${ownedVolumeName},destination=${ownedPgDataPath}`,
    "--publish",
    `127.0.0.1:${ownedPort}:5432`,
    "--env",
    `POSTGRES_DB=${databaseName}`,
    "--env",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "postgres:17",
  ]);
}

const ownedPgDataPath = "/var/lib/postgresql/data";

function migratorHbaContent() {
  return [
    "# managed by run-disposable-migrator-alignment-tests.mjs",
    "local   all             all                                        trust",
    "host    all             platform_migrator       127.0.0.1/32       scram-sha-256",
    "host    all             platform_migrator       ::1/128            scram-sha-256",
    "host    all             platform_migrator       all                scram-sha-256",
    "host    all             all                     127.0.0.1/32       trust",
    "host    all             all                     ::1/128            trust",
    "host    all             all                     all                trust",
    "",
  ].join("\n");
}

function assertMigratorHbaContent(content) {
  const lines = content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (lines.length !== 7) throw new Error();
  const scramRules = lines.filter(
    (line) => line.includes("platform_migrator") && line.includes("scram-sha-256"),
  );
  if (scramRules.length !== 3) throw new Error();
  for (const rule of scramRules) {
    if (!/^host\s+all\s+platform_migrator\s+(?:\d+\.\d+\.\d+\.\d+\/\d+|::1\/\d+|all)\s+scram-sha-256$/u.test(rule)) {
      throw new Error();
    }
  }
  const fallback = lines.find((line) =>
    /^host\s+all\s+all\s+(?:\d+\.\d+\.\d+\.\d+\/\d+|::1\/\d+|all)\s+trust$/u.test(line));
  if (!fallback) throw new Error();
  if (lines.some((line) => line.includes("platform_migrator") && line.includes("trust"))) {
    throw new Error();
  }
}

async function applyMigratorPasswordAuth(spawnImpl) {
  const content = migratorHbaContent();
  const quotedLines = content
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => `'${line}'`)
    .join(" ");
  await runCommand(spawnImpl, "docker", [
    "exec",
    ownedContainerName,
    "sh",
    "-c",
    `printf '%s\n' ${quotedLines} > ${ownedPgDataPath}/pg_hba.conf`,
  ]);
  const observed = await runCommand(spawnImpl, "docker", [
    "exec",
    ownedContainerName,
    "sh",
    "-c",
    `cat ${ownedPgDataPath}/pg_hba.conf`,
  ]);
  assertMigratorHbaContent(observed);
  const pool = new Pool({ connectionString: buildUrl("postgres", databaseName), max: 1 });
  try {
    const result = await pool.query("select pg_reload_conf() as ok");
    if (result.rows?.[0]?.ok !== true) throw new Error();
  } finally {
    await pool.end();
  }
}

export function parsePublishedBinding(output) {
  const text = typeof output === "string" ? output.trim() : "";
  if (text.length === 0) throw new Error();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error();
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error();
  }
  const keys = Object.keys(parsed);
  if (keys.length === 0) throw new Error();
  const binding = new Map();
  for (const key of keys) {
    if (!/^[0-9]+\/tcp$/u.test(key)) throw new Error();
    const entries = parsed[key];
    if (!Array.isArray(entries) || entries.length === 0) throw new Error();
    binding.set(
      key,
      entries.map((entry) => {
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          throw new Error();
        }
        const hostIp = entry.HostIp;
        const hostPort = entry.HostPort;
        if (typeof hostIp !== "string" || typeof hostPort !== "string") {
          throw new Error();
        }
        return { hostIp, hostPort };
      }),
    );
  }
  return binding;
}

export function assertSingleLoopbackPublishedBinding(binding, expectedHostPort) {
  if (!(binding instanceof Map)) throw new Error();
  if (binding.size !== 1) throw new Error();
  const entries = binding.get("5432/tcp");
  if (!Array.isArray(entries) || entries.length !== 1) throw new Error();
  const entry = entries[0];
  if (
    entry.hostIp !== "127.0.0.1" ||
    entry.hostPort !== String(expectedHostPort)
  ) {
    throw new Error();
  }
}

async function assertExactPublishedBinding(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "inspect",
    "--format",
    "{{json .NetworkSettings.Ports}}",
    ownedContainerName,
  ]);
  assertSingleLoopbackPublishedBinding(
    parsePublishedBinding(output),
    ownedPort,
  );
}

async function waitForPostgres(connectionString) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
    try {
      await pool.query("select 1");
      return;
    } catch {
      await delay(500);
    } finally {
      await pool.end();
    }
  }
  throw new Error();
}

export function parseContainerMounts(output) {
  const text = typeof output === "string" ? output.trim() : "";
  if (text.length === 0) throw new Error();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error();
  }
  if (!Array.isArray(parsed)) throw new Error();
  return parsed;
}

export function assertSingleOwnedVolumeMount(mounts) {
  if (!Array.isArray(mounts)) throw new Error();
  const ownedMounts = mounts.filter(
    (mount) => mount?.Name === ownedVolumeName,
  );
  if (ownedMounts.length !== 1) throw new Error();
  const dataMounts = mounts.filter(
    (mount) => mount?.Destination === ownedPgDataPath,
  );
  if (dataMounts.length !== 1) throw new Error();
  const mount = dataMounts[0];
  if (
    mount.Type !== "volume" ||
    mount.Name !== ownedVolumeName ||
    mount.Destination !== ownedPgDataPath ||
    mount.RW !== true
  ) {
    throw new Error();
  }
}

async function assertExactVolumeMount(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "inspect",
    "--format",
    "{{json .Mounts}}",
    ownedContainerName,
  ]);
  assertSingleOwnedVolumeMount(parseContainerMounts(output));
}

async function assertExactVolumeAbsent(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "volume",
    "ls",
    "--quiet",
    "--filter",
    `name=^${ownedVolumeName}$`,
  ]);
  const names = output
    .trim()
    .split(/\r?\n/u)
    .filter((name) => name.length > 0);
  if (names.some((name) => name !== ownedVolumeName)) throw new Error();
  if (names.length !== 0) throw new Error();
}

async function assertExactContainerAbsent(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${ownedContainerName}$`,
    "--format",
    "{{.Names}}",
  ]);
  return output.trim();
}

async function assertOwnedListenerAbsent() {
  await new Promise((resolvePromise, reject) => {
    const socket = net.createConnection({
      host: "127.0.0.1",
      port: ownedPort,
    });
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolvePromise();
    };
    socket.setTimeout(1_000, () => finish(new Error()));
    socket.once("connect", () => finish(new Error()));
    socket.once("error", (error) => {
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) {
        finish();
      } else {
        finish(new Error());
      }
    });
  });
}

async function assertPortAbsent() {
  await assertOwnedListenerAbsent();
}

async function runCommand(spawnImpl, command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawnImpl(command, args, {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    const output = [];
    let outputLength = 0;
    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      reject(new Error());
    };
    child.once("error", fail);
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      if (code !== 0 || signal !== null || outputLength > 1_024) {
        reject(new Error());
        return;
      }
      resolvePromise(Buffer.concat(output).toString("utf8"));
    });
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) output.push(Buffer.from(chunk));
    });
  });
}

function assertNoCallerSuppliedFixture(env) {
  const names = [
    "MIGRATOR_ALIGNMENT_TEST_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_OPERATOR_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_DATABASE_URL",
    "MIGRATOR_ALIGNMENT_TEST_SECONDARY_OPERATOR_URL",
  ];
  if (names.some((name) => typeof env?.[name] === "string" && env[name])) {
    throw new Error();
  }
}

function contractTableNames() {
  return [...new Set(
    RUNTIME_TABLE_GRANT_CONTRACT.map((record) => record.objectName),
  )];
}

function privilegesByTable() {
  const values = new Map();
  for (const record of RUNTIME_TABLE_GRANT_CONTRACT) {
    const privileges = values.get(record.objectName) ?? [];
    privileges.push(record.privilege);
    values.set(record.objectName, privileges);
  }
  return values;
}

const postgresqlConnectionEnvironmentKeys = Object.freeze([
  "PGUSER",
  "PGDATABASE",
  "PGHOST",
  "PGHOSTADDR",
  "PGPORT",
  "PGPASSWORD",
  "PGPASSFILE",
  "PGSERVICE",
  "PGSERVICEFILE",
  "PGOPTIONS",
  "PGAPPNAME",
  "PGCONNECT_TIMEOUT",
  "PGSSLMODE",
  "PGSSLNEGOTIATION",
  "PGSSLCERT",
  "PGSSLKEY",
  "PGSSLROOTCERT",
  "PGREQUIRESSL",
  "PGCHANNELBINDING",
  "PGTARGETSESSIONATTRS",
  "PGCLIENTENCODING",
  "PGDATESTYLE",
  "PGTZ",
  "PGGEQO",
  "PGSYSCONFDIR",
  "PGLOCALEDIR",
  "PGPASS_NO_DEESCAPE",
  "NODE_PG_FORCE_NATIVE",
]);

export function buildFocusedTestEnvironment(
  env = process.env,
  controlledPassfilePath,
) {
  if (
    typeof controlledPassfilePath !== "string" ||
    controlledPassfilePath.length === 0 ||
    !isAbsolute(controlledPassfilePath)
  ) {
    throw new Error();
  }
  const childEnv = { ...env };
  delete childEnv.PGPASSWORD;
  delete childEnv.PGPASSFILE;
  for (const key of postgresqlConnectionEnvironmentKeys) delete childEnv[key];
  for (const key of Object.keys(childEnv)) {
    if (key.startsWith("PG")) delete childEnv[key];
  }
  delete childEnv.NODE_PG_FORCE_NATIVE;
  childEnv.PGPASSFILE = controlledPassfilePath;
  return childEnv;
}

function assertFocusedCredentialBoundary(
  resources,
  beforeSanitization,
  childEnv,
  isolation,
) {
  const hostileNames = [
    "PGPASSWORD",
    "PGPASSFILE",
    "PGUSER",
    "PGDATABASE",
    "PGHOST",
    "PGPORT",
    "PGSERVICE",
    "HOME",
    "APPDATA",
  ];
  if (!hostileNames.every((name) => Object.hasOwn(beforeSanitization, name))) {
    throw new Error();
  }
  if (
    beforeSanitization.PGPASSWORD !== isolation.hostileEnvironment.PGPASSWORD ||
    beforeSanitization.PGPASSFILE !== isolation.hostileExplicitPassfilePath ||
    beforeSanitization.HOME !== isolation.hostileHomeDirectory ||
    beforeSanitization.APPDATA !== isolation.hostileAppDataDirectory
  ) {
    throw new Error();
  }
  resources.focusedCredentialIsolationPreSanitization = true;
  if (
    Object.hasOwn(childEnv, "PGPASSWORD") ||
    !Object.hasOwn(childEnv, "PGPASSFILE") ||
    childEnv.PGPASSFILE !== isolation.controlledPassfilePath ||
    childEnv.HOME !== beforeSanitization.HOME ||
    childEnv.APPDATA !== beforeSanitization.APPDATA
  ) {
    throw new Error();
  }
  if (
    Object.keys(childEnv).some(
      (key) => key.startsWith("PG") && key !== "PGPASSFILE",
    )
  ) {
    throw new Error();
  }
  resources.focusedCredentialChildBoundary = true;
}

async function createFocusedCredentialIsolation(resources) {
  const temporaryRoot = resolve(tmpdir());
  const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const temporaryRootRelativeToRepository = relative(
    repositoryRoot,
    temporaryRoot,
  );
  if (
    temporaryRootRelativeToRepository === "" ||
    (!temporaryRootRelativeToRepository.startsWith("..") &&
      !isAbsolute(temporaryRootRelativeToRepository))
  ) {
    throw new Error();
  }
  const directory = join(
    temporaryRoot,
    focusedCredentialIsolationDirectoryPrefix + randomUUID(),
  );
  let directoryCreated = false;
  try {
    await assertFocusedPathAbsent(directory);
    await mkdir(directory, { mode: 0o700 });
    directoryCreated = true;
    const hostileHomeDirectory = join(directory, "home");
    const hostileAppDataDirectory = join(directory, "appdata");
    const hostileAppDataPostgresDirectory = join(
      hostileAppDataDirectory,
      "postgresql",
    );
    const hostileHomePassfilePath = join(hostileHomeDirectory, ".pgpass");
    const hostileAppDataPassfilePath = join(
      hostileAppDataPostgresDirectory,
      "pgpass.conf",
    );
    const hostileExplicitPassfilePath = join(
      directory,
      "hostile-explicit-pgpass",
    );
    const controlledPassfilePath = join(directory, "controlled-empty-pgpass");
    const isolation = {
      directory,
      hostileHomeDirectory,
      hostileAppDataDirectory,
      hostileHomePassfilePath,
      hostileAppDataPassfilePath,
      hostileExplicitPassfilePath,
      controlledPassfilePath,
      hostileEnvironment: {
        HOME: hostileHomeDirectory,
        APPDATA: hostileAppDataDirectory,
        PGPASSWORD: "synthetic-hostile-password",
        PGPASSFILE: hostileExplicitPassfilePath,
        PGUSER: "platform_migrator",
        PGDATABASE: databaseName,
        PGHOST: "127.0.0.1",
        PGPORT: String(ownedPort),
        PGSERVICE: "hostile_service",
      },
    };
    resources.focusedCredentialIsolation = isolation;
    await mkdir(hostileHomeDirectory, { mode: 0o700 });
    await mkdir(hostileAppDataDirectory, { mode: 0o700 });
    await mkdir(hostileAppDataPostgresDirectory, { mode: 0o700 });
    const hostilePassfileContent =
      "*:*:" +
      databaseName +
      ":platform_migrator:" +
      syntheticMigratorPassword +
      "\n";
    for (const path of [
      hostileHomePassfilePath,
      hostileAppDataPassfilePath,
      hostileExplicitPassfilePath,
    ]) {
      await writeFile(path, hostilePassfileContent, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
    }
    await writeFile(controlledPassfilePath, "", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    if (process.platform !== "win32") {
      for (const path of [
        hostileHomePassfilePath,
        hostileAppDataPassfilePath,
        hostileExplicitPassfilePath,
        controlledPassfilePath,
      ]) {
        await chmod(path, 0o600);
      }
    }
    if ((await readFile(controlledPassfilePath, "utf8")) !== "") {
      throw new Error();
    }
    for (const path of [
      hostileHomePassfilePath,
      hostileAppDataPassfilePath,
      hostileExplicitPassfilePath,
      controlledPassfilePath,
    ]) {
      await assertFocusedCredentialFile(path);
    }
    return Object.freeze(isolation);
  } catch (error) {
    if (directoryCreated) {
      try {
        await cleanupFocusedCredentialIsolation(resources);
      } catch {
        throw new Error();
      }
    }
    throw error;
  }
}

async function assertFocusedCredentialFile(path) {
  const details = await statPath(path);
  if (!details.isFile()) throw new Error();
  if (
    typeof process.getuid === "function" &&
    details.uid !== process.getuid()
  ) {
    throw new Error();
  }
  if (process.platform !== "win32" && (details.mode & 0o077) !== 0) {
    throw new Error();
  }
}

async function assertFocusedPathAbsent(path) {
  try {
    await access(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw new Error();
  }
  throw new Error();
}

async function cleanupFocusedCredentialIsolation(resources) {
  const isolation = resources.focusedCredentialIsolation;
  if (!isolation || resources.focusedCredentialIsolationCleaned) return;
  await rm(isolation.directory, { recursive: true, force: true });
  for (const path of [
    isolation.hostileHomePassfilePath,
    isolation.hostileAppDataPassfilePath,
    isolation.hostileExplicitPassfilePath,
    isolation.controlledPassfilePath,
    isolation.hostileHomeDirectory,
    isolation.hostileAppDataDirectory,
    isolation.directory,
  ]) {
    await assertFocusedPathAbsent(path);
  }
  resources.focusedCredentialIsolationCleaned = true;
  resources.focusedCredentialIsolationAbsent = true;
  resources.focusedCredentialIsolation = null;
}

async function verifyFocusedCredentialIsolationAbsence(resources) {
  if (
    !resources.focusedCredentialIsolationCleaned ||
    !resources.focusedCredentialIsolationAbsent ||
    resources.focusedCredentialIsolation
  ) {
    throw new Error();
  }
}
function quoteIdentifier(value) {
  if (!safeIdentifier.test(value)) throw new Error();
  return `"${value.replaceAll('"', '""')}"`;
}
