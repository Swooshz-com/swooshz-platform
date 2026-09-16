#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client, Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresFixtures,
  invalidateDisposablePostgresAdmission,
} from "../tests/support/disposable-postgres-fixture.mjs";
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const databaseName = "runtime_posture_test";
const networkAlias =
  "ep-disposable-primary-001-pooler.us-east-2.aws.neon.tech";
const ownedNetworks = Object.freeze([
  "codex-platform169-activation-primary-net",
  "codex-platform169-activation-secondary-net",
]);
const ownedContainers = Object.freeze([
  "codex-platform169-activation-primary-pg17",
  "codex-platform169-activation-secondary-pg17",
]);
const expectedMigrationTags = Object.freeze([
  "0000_overconfident_onslaught",
  "0001_lovely_famine",
  "0002_futuristic_aaron_stack",
  "0003_worthless_scourge",
  "0004_illegal_william_stryker",
  "0005_sqag_app_key_migration",
  "0006_optimal_tomorrow_man",
  "0007_remove_legacy_kqag_tables",
  "0009_wonderful_star_brand",
]);
const excludedMigrationTag =
  "0010_admin_operator_viewer_role_collapse";
const identitiesSql = fileURLToPath(
  new URL("../tests/support/runtime-postgres-identities.sql", import.meta.url),
);
const expectedTestCount = 45;
const maxChildOutputBytes = 64 * 1024;
const maxDiagnosticBytes = 4_000;
const maxChildDurationMs = 180_000;
export const ACTIVATION_READINESS_MAX_ATTEMPTS = 240;
export const ACTIVATION_READINESS_CONNECTION_TIMEOUT_MS = 1_000;
export const ACTIVATION_READINESS_ERROR_BACKOFF_MS = 500;

const readinessProbeCategories = Object.freeze([
  "CONNECTION_REFUSED",
  "CONNECTION_TIMEOUT",
  "NETWORK_UNREACHABLE",
  "AUTH_REJECTED",
  "SERVER_STARTING",
  "PROTOCOL_OR_SERVER_ERROR",
  "QUERY_FAILED",
  "IDENTITY_OR_VERSION_MISMATCH",
  "UNKNOWN",
]);
export const ACTIVATION_READINESS_EVIDENCE_CONTRACT = Object.freeze({
  OUTCOME: Object.freeze(["READY", "TIMEOUT"]),
  AGGREGATE_PROBE: readinessProbeCategories,
  LAST_PROBE: readinessProbeCategories,
  CONTAINER_STATE: Object.freeze([
    "RUNNING", "RESTARTING", "EXITED", "DEAD", "OOM_KILLED", "UNKNOWN",
  ]),
  INTERNAL_PG_ISREADY: Object.freeze([
    "ACCEPTING", "REJECTING", "NO_RESPONSE", "COMMAND_FAILED",
  ]),
  HOST_TCP: Object.freeze([
    "CONNECTED", "REFUSED", "TIMEOUT", "NETWORK_ERROR",
  ]),
  TOPOLOGY_BINDING: Object.freeze(["EXACT", "CHANGED", "UNPROVEN"]),
  TARGET: Object.freeze(["PRIMARY", "SECONDARY"]),
});

export const ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS = Object.freeze([
  0, 250, 500, 750, 1_000,
]);
const topologyCommandCategories = Object.freeze([
  "COMMAND_SPAWN_FAILED", "COMMAND_NONZERO", "SIGNAL", "TIMEOUT",
  "OUTPUT_OVERFLOW",
]);
export const ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT = Object.freeze({
  ENGINE: Object.freeze([
    "GE_28", "LT_28", "UNPARSEABLE", ...topologyCommandCategories,
  ]),
  REQUEST: Object.freeze([
    "EXACT_DYNAMIC", "EXACT_ASSIGNED", "MISSING", "MALFORMED",
    "EXPECTED_PORT_MISSING", "UNEXPECTED_PORT_PRESENT",
    "BINDING_SHAPE_INVALID", "BINDING_MISSING", "BINDING_MULTIPLE",
    "HOST_WILDCARD_OR_MISSING", "HOST_NONLOOPBACK",
    "HOST_LOOPBACK_MISMATCH", "PORT_INVALID", ...topologyCommandCategories,
  ]),
  OPERATIONAL_FIRST: Object.freeze([
    "EXACT", "MISSING", "MALFORMED", "EXPECTED_PORT_MISSING",
    "UNEXPECTED_PORT_PRESENT", "BINDING_SHAPE_INVALID", "BINDING_MISSING",
    "BINDING_MULTIPLE", "HOST_WILDCARD_OR_MISSING", "HOST_NONLOOPBACK",
    "HOST_LOOPBACK_MISMATCH", "HOST_PORT_MISSING",
    "HOST_PORT_NONDECIMAL", "PORT_OUT_OF_RANGE", ...topologyCommandCategories,
  ]),
  OPERATIONAL_TERMINAL: Object.freeze([
    "EXACT", "MISSING", "MALFORMED", "EXPECTED_PORT_MISSING",
    "UNEXPECTED_PORT_PRESENT", "BINDING_SHAPE_INVALID", "BINDING_MISSING",
    "BINDING_MULTIPLE", "HOST_WILDCARD_OR_MISSING", "HOST_NONLOOPBACK",
    "HOST_LOOPBACK_MISMATCH", "HOST_PORT_MISSING",
    "HOST_PORT_NONDECIMAL", "PORT_OUT_OF_RANGE", ...topologyCommandCategories,
  ]),
  PORT_QUERY: Object.freeze([
    "EXACT", "MISSING", "MALFORMED", "MULTIPLE",
    "HOST_WILDCARD_OR_MISSING", "HOST_NONLOOPBACK",
    "HOST_LOOPBACK_MISMATCH", "PORT_INVALID", ...topologyCommandCategories,
  ]),
  TEMPORAL: Object.freeze([
    "NOT_SAMPLED", "STABLE", "CONVERGED_TO_EXACT", "CHANGED_NONEXACT",
  ]),
  PORT_MATCH: Object.freeze(["YES", "NO", "UNPROVABLE"]),
  TARGET: Object.freeze(["PRIMARY", "SECONDARY"]),
});

export const ACTIVATION_RUNNER_FAILURE_CONTRACT = Object.freeze({
  BOOTSTRAP_PREFLIGHT: Object.freeze([
    "CALLER_INPUT_REJECTED",
    "IDENTITY_SOURCE_UNAVAILABLE",
    "OWNED_RESOURCE_PREEXISTS",
  ]),
  MIGRATION_PREFIX: Object.freeze([
    "TEMP_ROOT_CREATE_FAILED",
    "JOURNAL_READ_OR_PARSE_FAILED",
    "PREFIX_SET_INVALID",
    "MIGRATION_COPY_OR_WRITE_FAILED",
    "PREFIX_VERIFY_FAILED",
  ]),
  NETWORK_CREATE: Object.freeze([
    "SPAWN_FAILED", "COMMAND_NONZERO", "SIGNAL", "TIMEOUT", "OUTPUT_OVERFLOW",
  ]),
  CONTAINER_START: Object.freeze([
    "SPAWN_FAILED", "COMMAND_NONZERO", "SIGNAL", "TIMEOUT", "OUTPUT_OVERFLOW",
    "CONTAINER_ID_MISSING",
  ]),
  TOPOLOGY_PORT_VERIFY: Object.freeze([
    "ENGINE_INVALID", "IMAGE_INVALID", "NETWORK_INVALID", "ALIAS_INVALID",
    "BINDING_INVALID", "PORT_INVALID", "PORTS_NOT_DISTINCT",
  ]),
  POSTGRES_READINESS: Object.freeze(["READINESS_TIMEOUT"]),
  FIXTURE_PROVISION: Object.freeze([
    "MIGRATION_FAILED", "ROLE_SETUP_FAILED", "CREATOR_EDGE_FAILED",
    "GRANT_CONTRACT_FAILED",
  ]),
  FIXTURE_IDENTITY: Object.freeze([
    "QUERY_FAILED", "IDENTITY_INVALID", "SYSTEM_IDENTIFIER_INVALID",
    "SYSTEM_IDENTIFIERS_NOT_DISTINCT",
  ]),
  DISPOSABLE_ADMISSION: Object.freeze(["ADMISSION_FAILED"]),
  ACTIVATION_CHILD: Object.freeze([
    "SPAWN_FAILED", "EXIT_NONZERO", "SIGNAL", "TIMEOUT", "STDOUT_OVERFLOW",
    "STDERR_OVERFLOW", "SUMMARY_MISSING", "SUMMARY_MALFORMED",
    "SUMMARY_DUPLICATE", "SUMMARY_COUNT_MISMATCH",
  ]),
  CLEANUP: Object.freeze([
    "CHILD_TERMINATION_FAILED", "ADMISSION_INVALIDATION_FAILED",
    "CONTAINER_REMOVAL_FAILED", "NETWORK_REMOVAL_FAILED",
    "MIGRATION_PREFIX_REMOVAL_FAILED", "CREDENTIAL_CLEAR_FAILED",
  ]),
  FINAL_ABSENCE: Object.freeze([
    "CONTAINER_PRESENT_OR_UNPROVEN", "NETWORK_PRESENT_OR_UNPROVEN",
    "TEMP_PATH_PRESENT_OR_UNPROVEN", "PORT_OPEN_OR_UNPROVEN",
  ]),
});
const activationTargets = Object.freeze(["NONE", "PRIMARY", "SECONDARY", "BOTH"]);

export function activationRunnerFailure(
  phase,
  category,
  target = "NONE",
  childDiagnostics = "",
  activationTopologyEvidence = null,
  activationReadinessEvidence = [],
) {
  if (
    !Object.hasOwn(ACTIVATION_RUNNER_FAILURE_CONTRACT, phase) ||
    !ACTIVATION_RUNNER_FAILURE_CONTRACT[phase].includes(category) ||
    !activationTargets.includes(target) ||
    !Array.isArray(activationReadinessEvidence) ||
    activationReadinessEvidence.length > 2
  ) {
    throw new TypeError("Invalid activation runner failure receipt");
  }
  const error = new Error();
  error.activationRunnerFailure = true;
  error.phase = phase;
  error.category = category;
  error.target = target;
  error.childDiagnostics = boundedChildDiagnostics(childDiagnostics);
  error.activationTopologyEvidence = activationTopologyEvidence;
  error.activationReadinessEvidence = activationReadinessEvidence;
  error.diagnostics = formatActivationRunnerFailure(error);
  return error;
}

export function formatActivationRunnerFailure(error) {
  const receipts = flattenActivationFailures(error);
  return receipts.map((failure) => {
    const receipt = `ACTIVATION_RUNNER_FAILURE phase=${failure.phase} ` +
      `category=${failure.category} target=${failure.target}`;
    const failureReceipt = failure.childDiagnostics
      ? `${receipt}\n${failure.childDiagnostics}`
      : receipt;
    const topologyReceipt = failure.activationTopologyEvidence
      ? `${failureReceipt}\n${formatActivationTopologyEvidence(
        failure.activationTopologyEvidence,
      )}`
      : failureReceipt;
    return failure.activationReadinessEvidence.length > 0
      ? `${topologyReceipt}\n${failure.activationReadinessEvidence.map(
        formatActivationReadinessEvidence,
      ).join("\n")}`
      : topologyReceipt;
  }).join("\n");
}

export async function executeActivationCleanupActions(actions, bodyError = null) {
  const failures = bodyError ? flattenActivationFailures(bodyError) : [];
  for (const action of actions) {
    try {
      await action.run();
    } catch {
      failures.push(activationRunnerFailure(
        action.phase,
        action.category,
        action.target ?? "NONE",
      ));
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures);
}

function flattenActivationFailures(error) {
  if (error instanceof AggregateError) {
    return error.errors.flatMap((value) => flattenActivationFailures(value));
  }
  if (error?.activationRunnerFailure === true) return [error];
  return [activationRunnerFailure("BOOTSTRAP_PREFLIGHT", "IDENTITY_SOURCE_UNAVAILABLE")];
}

function boundedChildDiagnostics(value) {
  if (typeof value !== "string" || value.length === 0) return "";
  return Buffer.from(value, "utf8")
    .subarray(0, maxDiagnosticBytes)
    .toString("utf8");
}

async function withActivationFailure(phase, category, target, operation) {
  try {
    return await operation();
  } catch (error) {
    if (error?.activationRunnerFailure === true) throw error;
    throw activationRunnerFailure(phase, category, target);
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  run().catch((error) => {
    process.stderr.write("Disposable activation PostgreSQL 17 runner failed.\n");
    const diagnostics = formatActivationRunnerFailure(error);
    if (diagnostics) process.stderr.write(`${diagnostics}\n`);
    process.exitCode = 1;
  });
}

export async function run({
  env = process.env,
  spawnImpl = spawn,
  assertPortAbsentImpl = assertPortAbsent,
  implementations = {},
} = {}) {
  try {
    assertNoCallerSuppliedActivationInputs(env);
  } catch {
    throw activationRunnerFailure(
      "BOOTSTRAP_PREFLIGHT", "CALLER_INPUT_REJECTED", "NONE",
    );
  }
  await withActivationFailure(
    "BOOTSTRAP_PREFLIGHT",
    "IDENTITY_SOURCE_UNAVAILABLE",
    "NONE",
    () => (implementations.access ?? access)(identitiesSql),
  );

  const operatorPasswordBuffer = randomBytes(32);
  const runtimePasswordBuffer = randomBytes(32);
  const resources = {
    admission: null,
    child: null,
    childExited: true,
    childEnvironment: null,
    containerStartAttempted: new Set(),
    networksCreated: new Set(),
    migrationPrefix: null,
    operatorPassword: `Operator_A1!${operatorPasswordBuffer.toString("base64url")}`,
    operatorPasswordBuffer,
    ports: [null, null],
    runtimePassword: `Runtime_A1!${runtimePasswordBuffer.toString("base64url")}`,
    runtimePasswordBuffer,
  };
  let bodyError = null;
  let summary = null;

  try {
    try {
      await (implementations.assertInitialAbsence ?? assertExactDockerResourcesAbsent)();
    } catch {
      throw activationRunnerFailure(
        "BOOTSTRAP_PREFLIGHT", "OWNED_RESOURCE_PREEXISTS", "BOTH",
      );
    }
    resources.migrationPrefix = await withActivationFailure(
      "MIGRATION_PREFIX", "PREFIX_VERIFY_FAILED", "NONE",
      () => (
        implementations.createMigrationPrefix ?? createActivationMigrationPrefix
      )(),
    );

    for (const networkName of ownedNetworks) {
      await requireSuccessfulCommand(
        spawnImpl,
        "docker",
        ownedNetworkCreateArguments(networkName),
        {},
        "NETWORK_CREATE",
        targetForIndex(ownedNetworks.indexOf(networkName)),
      );
      resources.networksCreated.add(networkName);
    }

    for (let index = 0; index < ownedContainers.length; index += 1) {
      const childEnvironment = {
        ...env,
        POSTGRES_PASSWORD: resources.operatorPassword,
      };
      resources.containerStartAttempted.add(ownedContainers[index]);
      let result;
      try {
        result = await requireSuccessfulCommand(
          spawnImpl,
          "docker",
          ownedContainerDockerArguments(
            ownedContainers[index],
            ownedNetworks[index],
          ),
          { env: childEnvironment },
          "CONTAINER_START",
          targetForIndex(index),
        );
      } finally {
        delete childEnvironment.POSTGRES_PASSWORD;
      }
      if (!result.stdout.trim()) {
        throw activationRunnerFailure(
          "CONTAINER_START", "CONTAINER_ID_MISSING", targetForIndex(index),
        );
      }
    }

    for (let index = 0; index < ownedContainers.length; index += 1) {
      resources.ports[index] = await withActivationFailure(
        "TOPOLOGY_PORT_VERIFY", "BINDING_INVALID", targetForIndex(index),
        () => (implementations.assertTopology ?? assertOwnedDockerTopology)(
          spawnImpl,
          ownedContainers[index],
          ownedNetworks[index],
          targetForIndex(index),
          { delayImpl: implementations.topologyDelay ?? delay },
        ),
      );
    }
    if (resources.ports[0] === resources.ports[1]) {
      throw activationRunnerFailure(
        "TOPOLOGY_PORT_VERIFY", "PORTS_NOT_DISTINCT", "BOTH",
      );
    }

    const operatorUrls = resources.ports.map((port) =>
      buildLoopbackUrl("platform_app", port));
    await executeActivationReadinessChecks({
      operatorUrls,
      operatorPassword: resources.operatorPassword,
      ports: resources.ports,
      spawnImpl,
      waitForPostgresImpl:
        implementations.waitForPostgres ?? waitForPostgresReadiness,
      collectTerminalEvidenceImpl:
        implementations.collectReadinessEvidence ??
          collectActivationReadinessEvidence,
    });
    await Promise.all(operatorUrls.map((url, index) => withActivationFailure(
      "FIXTURE_PROVISION", "GRANT_CONTRACT_FAILED", targetForIndex(index),
      () => (implementations.provisionFixture ?? provisionFixture)(
        url,
        resources.operatorPassword,
        resources.migrationPrefix.migrationsFolder,
        targetForIndex(index),
      ),
    )));
    const systemIdentifiers = await Promise.all(
      operatorUrls.map((url, index) => withActivationFailure(
        "FIXTURE_IDENTITY", "QUERY_FAILED", targetForIndex(index),
        () => (implementations.assertFixtureIdentity ?? assertFixtureIdentity)(
          url, resources.operatorPassword, targetForIndex(index),
        ),
      )),
    );
    if (systemIdentifiers[0] === systemIdentifiers[1]) {
      throw activationRunnerFailure(
        "FIXTURE_IDENTITY", "SYSTEM_IDENTIFIERS_NOT_DISTINCT", "BOTH",
      );
    }

    resources.admission = await withActivationFailure(
      "DISPOSABLE_ADMISSION", "ADMISSION_FAILED", "BOTH",
      () => (implementations.admitFixtures ?? admitDisposablePostgresFixtures)(
      operatorUrls.map((connectionString, index) => ({
        name: index === 0 ? "primary" : "secondary",
        connectionString,
        expectedDatabase: databaseName,
        expectedUser: "platform_app",
        expectedRuntimeRole: "platform_runtime",
        expectedObjects: {
          schemas: ["public", "drizzle"],
          relations: [
            { schema: "drizzle", name: "__drizzle_migrations", kind: "r" },
            { schema: "public", name: "users", kind: "r" },
          ],
          sequences: [],
          routines: [],
        },
        transport: { kind: "loopback", phase: "initialization" },
      })),
      {
        clientFactory: async (target) => {
          const client = new Client({
            ...parentPostgresClientConfig(
              target.connectionString,
              resources.operatorPassword,
            ),
          });
          await client.connect();
          return {
            query: (...args) => client.query(...args),
            end: () => client.end(),
          };
        },
      },
      ),
    );

    summary = await withActivationFailure(
      "ACTIVATION_CHILD", "SPAWN_FAILED", "BOTH",
      () => (implementations.runActivationChild ?? runActivationChild)(
        spawnImpl,
        resources,
        operatorUrls,
      ),
    );
  } catch (error) {
    bodyError = error?.activationRunnerFailure === true || error instanceof AggregateError
      ? error
      : activationRunnerFailure(
        "BOOTSTRAP_PREFLIGHT", "IDENTITY_SOURCE_UNAVAILABLE", "NONE",
      );
  }

  await executeActivationCleanupActions([
    cleanupAction("CLEANUP", "CHILD_TERMINATION_FAILED", "NONE", () =>
      (implementations.terminateChild ?? terminateChild)(resources)),
    cleanupAction("CLEANUP", "ADMISSION_INVALIDATION_FAILED", "BOTH", async () => {
      if (resources.admission) {
        (implementations.invalidateAdmission ?? invalidateDisposablePostgresAdmission)(
          resources.admission,
        );
        resources.admission = null;
      }
    }),
    ...ownedContainers.map((containerName, index) => cleanupAction(
      "CLEANUP", "CONTAINER_REMOVAL_FAILED", targetForIndex(index), async () => {
      if (resources.containerStartAttempted.has(containerName)) {
        await (implementations.removeContainer ?? removeOwnedContainer)(
          spawnImpl, containerName,
        );
      }
    })),
    ...ownedNetworks.map((networkName, index) => cleanupAction(
      "CLEANUP", "NETWORK_REMOVAL_FAILED", targetForIndex(index), async () => {
      if (resources.networksCreated.has(networkName)) {
        await (implementations.removeNetwork ?? removeOwnedNetwork)(
          spawnImpl, networkName,
        );
      }
    })),
    cleanupAction("CLEANUP", "MIGRATION_PREFIX_REMOVAL_FAILED", "NONE", async () => {
      if (resources.migrationPrefix?.temporaryRoot) {
        const temporaryRoot = resources.migrationPrefix.temporaryRoot;
        await rm(temporaryRoot, {
          recursive: true,
          force: true,
        });
        await assertPathAbsent(temporaryRoot);
        resources.migrationPrefix = null;
      }
    }),
    cleanupAction("CLEANUP", "CREDENTIAL_CLEAR_FAILED", "NONE", () =>
      (implementations.clearCredentials ?? clearCredentialState)(resources)),
    ...ownedContainers.map((containerName, index) => cleanupAction(
      "FINAL_ABSENCE",
      "CONTAINER_PRESENT_OR_UNPROVEN",
      targetForIndex(index),
      () => (implementations.assertFinalContainerAbsent ?? assertContainerAbsent)(
        containerName,
      ),
    )),
    ...ownedNetworks.map((networkName, index) => cleanupAction(
      "FINAL_ABSENCE",
      "NETWORK_PRESENT_OR_UNPROVEN",
      targetForIndex(index),
      () => (implementations.assertFinalNetworkAbsent ?? assertNetworkAbsent)(
        networkName,
      ),
    )),
    cleanupAction(
      "FINAL_ABSENCE", "TEMP_PATH_PRESENT_OR_UNPROVEN", "NONE", async () => {
        if (resources.migrationPrefix?.temporaryRoot) {
          await assertPathAbsent(resources.migrationPrefix.temporaryRoot);
        }
      },
    ),
    ...resources.ports.map((port, index) => cleanupAction(
      "FINAL_ABSENCE", "PORT_OPEN_OR_UNPROVEN", targetForIndex(index), async () => {
      if (Number.isInteger(port)) await assertPortAbsentImpl(port);
    })),
  ], bodyError);

  if (!summary) {
    throw activationRunnerFailure(
      "ACTIVATION_CHILD", "SUMMARY_MISSING", "BOTH",
    );
  }
  process.stdout.write(
    `Activation PostgreSQL 17 tests: ${summary.total} total / ` +
      `${summary.passed} passed / ${summary.failed} failed / ` +
      `${summary.skipped} skipped / ${summary.cancelled} cancelled / ` +
      `${summary.todo} todo.\n`,
  );
  return summary;
}

function targetForIndex(index) {
  return index === 0 ? "PRIMARY" : "SECONDARY";
}

function cleanupAction(phase, category, target, run) {
  return { phase, category, target, run };
}

export function assertNoCallerSuppliedActivationInputs(env) {
  if (!env || typeof env !== "object") throw new Error();
  if (
    Object.keys(env).some((name) =>
      name.startsWith("RUNTIME_ACTIVATION_TEST_"))
  ) {
    throw new Error();
  }
}

export function ownedNetworkCreateArguments(networkName) {
  if (!ownedNetworks.includes(networkName)) throw new Error();
  return ["network", "create", "--driver", "bridge", networkName];
}

export function ownedContainerDockerArguments(containerName, networkName) {
  const index = ownedContainers.indexOf(containerName);
  if (index < 0 || ownedNetworks[index] !== networkName) throw new Error();
  return [
    "run",
    "--detach",
    "--name",
    containerName,
    "--network",
    networkName,
    "--network-alias",
    networkAlias,
    "--publish",
    "127.0.0.1::5432",
    "--env",
    "POSTGRES_USER=platform_app",
    "--env",
    `POSTGRES_DB=${databaseName}`,
    "--env",
    "POSTGRES_PASSWORD",
    "--mount",
    `type=bind,source=${identitiesSql},target=/docker-entrypoint-initdb.d/runtime-postgres-identities.sql,readonly`,
    "postgres:17",
  ];
}

export async function createActivationMigrationPrefix({
  sourceRoot = rootDir,
  temporaryBase = tmpdir(),
} = {}) {
  let temporaryRoot;
  try {
    temporaryRoot = await withActivationFailure(
      "MIGRATION_PREFIX", "TEMP_ROOT_CREATE_FAILED", "NONE",
      () => mkdtemp(join(temporaryBase, "swooshz-activation-0009-")),
    );
    const sourceMigrations = join(sourceRoot, "drizzle", "migrations");
    const migrationsFolder = join(temporaryRoot, "drizzle", "migrations");
    await withActivationFailure(
      "MIGRATION_PREFIX", "MIGRATION_COPY_OR_WRITE_FAILED", "NONE",
      () => mkdir(join(migrationsFolder, "meta"), { recursive: true }),
    );
    const journal = await withActivationFailure(
      "MIGRATION_PREFIX", "JOURNAL_READ_OR_PARSE_FAILED", "NONE",
      async () => JSON.parse(
        await readFile(join(sourceMigrations, "meta", "_journal.json"), "utf8"),
      ),
    );
    if (!Array.isArray(journal.entries)) {
      throw activationRunnerFailure(
        "MIGRATION_PREFIX", "PREFIX_SET_INVALID", "NONE",
      );
    }
    const entries = journal.entries.filter((entry) => entry.idx <= 8);
    try {
      assertActivationMigrationEntries(entries);
    } catch {
      throw activationRunnerFailure(
        "MIGRATION_PREFIX", "PREFIX_SET_INVALID", "NONE",
      );
    }
    if (!journal.entries.some((entry) => entry.tag === excludedMigrationTag)) {
      throw activationRunnerFailure(
        "MIGRATION_PREFIX", "PREFIX_SET_INVALID", "NONE",
      );
    }
    await withActivationFailure(
      "MIGRATION_PREFIX", "MIGRATION_COPY_OR_WRITE_FAILED", "NONE", async () => {
        for (const entry of entries) {
          await copyFile(
            join(sourceMigrations, `${entry.tag}.sql`),
            join(migrationsFolder, `${entry.tag}.sql`),
          );
        }
        await writeFile(
          join(migrationsFolder, "meta", "_journal.json"),
          `${JSON.stringify({
            version: journal.version,
            dialect: journal.dialect,
            entries,
          }, null, 2)}\n`,
          "utf8",
        );
      },
    );
    const copiedFiles = await withActivationFailure(
      "MIGRATION_PREFIX", "PREFIX_VERIFY_FAILED", "NONE", async () => (
        await readdir(migrationsFolder, { withFileTypes: true })
      ).filter((entry) => entry.isFile()).map((entry) => entry.name).sort(),
    );
    if (
      copiedFiles.length !== 9 ||
      copiedFiles.some((name, index) =>
        name !== `${expectedMigrationTags[index]}.sql`) ||
      copiedFiles.includes(`${excludedMigrationTag}.sql`)
    ) {
      throw activationRunnerFailure(
        "MIGRATION_PREFIX", "PREFIX_VERIFY_FAILED", "NONE",
      );
    }
    return { entries, migrationsFolder, temporaryRoot };
  } catch (error) {
    if (temporaryRoot) {
      try {
        await rm(temporaryRoot, { recursive: true, force: true });
      } catch {
        throw new AggregateError([
          ...flattenActivationFailures(error),
          activationRunnerFailure(
            "CLEANUP", "MIGRATION_PREFIX_REMOVAL_FAILED", "NONE",
          ),
        ]);
      }
    }
    throw error;
  }
}

export function assertActivationMigrationEntries(entries) {
  if (
    !Array.isArray(entries) ||
    entries.length !== 9 ||
    entries.some((entry, index) =>
      !entry ||
      entry.idx !== index ||
      entry.tag !== expectedMigrationTags[index] ||
      entry.tag === excludedMigrationTag)
  ) {
    throw new Error();
  }
}

export function parseActivationTestSummary(output) {
  if (
    typeof output !== "string" ||
    Buffer.byteLength(output, "utf8") > maxChildOutputBytes
  ) {
    return null;
  }
  const lines = output
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\r\n?/gu, "\n")
    .split("\n");
  while (lines.at(-1) === "") lines.pop();
  const pattern = /^\s*([#ℹ])\s+(tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)\s+([^\s].*?)\s*$/u;
  const starts = lines
    .map((line, index) => [line.match(pattern), index])
    .filter(([match]) => match?.[2] === "tests")
    .map(([, index]) => index);
  if (starts.length !== 1) return null;
  const expectedFields = [
    "tests",
    "suites",
    "pass",
    "fail",
    "cancelled",
    "skipped",
    "todo",
    "duration_ms",
  ];
  const fields = new Map();
  let marker = null;
  for (let offset = 0; offset < expectedFields.length; offset += 1) {
    const lineIndex = starts[0] + offset;
    const match = lines[lineIndex]?.match(pattern);
    if (
      !match ||
      match[2] !== expectedFields[offset] ||
      fields.has(match[2]) ||
      (marker !== null && marker !== match[1])
    ) {
      return null;
    }
    marker ??= match[1];
    fields.set(match[2], match[3]);
  }
  if (starts[0] + expectedFields.length !== lines.length) return null;
  const counts = {};
  for (const field of expectedFields.slice(0, -1)) {
    const value = fields.get(field);
    if (!/^(?:0|[1-9]\d*)$/u.test(value)) return null;
    counts[field] = Number(value);
  }
  const durationText = fields.get("duration_ms");
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(durationText)) return null;
  const duration = Number(durationText);
  if (
    !Number.isFinite(duration) ||
    duration < 0 ||
    duration > maxChildDurationMs ||
    String(duration) !== durationText ||
    counts.tests !== expectedTestCount ||
    counts.pass !== expectedTestCount ||
    counts.fail !== 0 ||
    counts.cancelled !== 0 ||
    counts.skipped !== 0 ||
    counts.todo !== 0 ||
    counts.pass + counts.fail + counts.cancelled + counts.skipped +
      counts.todo !== counts.tests
  ) {
    return null;
  }
  return {
    total: counts.tests,
    passed: counts.pass,
    failed: counts.fail,
    cancelled: counts.cancelled,
    skipped: counts.skipped,
    todo: counts.todo,
  };
}

export function classifyActivationTestSummary(output) {
  if (typeof output !== "string") return { category: "SUMMARY_MALFORMED" };
  const normalized = output
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\r\n?/gu, "\n");
  const starts = normalized.split("\n")
    .filter((line) => /^\s*([#ℹ])\s+tests\s+/u.test(line)).length;
  if (starts === 0) return { category: "SUMMARY_MISSING" };
  if (starts > 1) return { category: "SUMMARY_DUPLICATE" };
  const summary = parseActivationTestSummary(output);
  if (summary) return { summary };
  const countFields = new Map();
  for (const line of normalized.split("\n")) {
    const match = line.match(
      /^\s*([#ℹ])\s+(tests|pass|fail|cancelled|skipped|todo)\s+([^\s]+)\s*$/u,
    );
    if (match && /^(?:0|[1-9]\d*)$/u.test(match[3])) {
      countFields.set(match[2], Number(match[3]));
    }
  }
  return countFields.size === 6
    ? { category: "SUMMARY_COUNT_MISMATCH" }
    : { category: "SUMMARY_MALFORMED" };
}

export function sanitizeActivationChildDiagnostics({
  stdout = "",
  stderr = "",
  secretValues = [],
} = {}) {
  let source = [stdout, stderr].filter(Boolean).join("\n");
  for (const secret of secretValues) {
    if (typeof secret === "string" && secret.length > 0) {
      source = source.replaceAll(secret, "<redacted>");
    }
  }
  source = source
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\b(?:postgres(?:ql)?|mysql|mssql):\/\/[^\s'"]+/giu, "<redacted-url>")
    .replace(/\bhttps?:\/\/[^\s'"]+/giu, "<redacted-url>")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+)\b/gu, "<redacted-token>")
    .replace(/\b(Bearer|Basic)\s+[^\s'"]+/giu, "$1 <redacted-token>")
    .replace(
      /\b(?:RUNTIME_ACTIVATION_TEST_[A-Z_]+|DATABASE_URL|DATABASE_OPERATOR_URL|PGPASSWORD|PGPASSFILE|PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|API_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|AUTHORIZATION|DSN)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;)]*)/giu,
      (match) => `${match.slice(0, match.search(/[:=]/u) + 1)}<redacted>`,
    )
    .replace(/[?&][A-Za-z0-9_-]+=[^&\s'"]*/gu, (match) =>
      `${match.slice(0, match.indexOf("=") + 1)}<redacted>`);
  const selected = source
    .replace(/\r\n?/gu, "\n")
    .split("\n")
    .filter((line) => {
      const value = line.trim();
      return /^(?:TAP version|# Subtest:|not ok |1\.\.|# (?:tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)|(?:Assertion)?Error|(?:failureType|error|code|name|operator|expected|actual|location|stack|message):|at\s)/u.test(value);
    })
    .join("\n");
  return Buffer.from(selected, "utf8")
    .subarray(0, maxDiagnosticBytes)
    .toString("utf8");
}

export async function assertExactDockerResourcesAbsent(
  commandImpl = runCommand,
) {
  await assertContainersAbsent(commandImpl);
  await assertNetworksAbsent(commandImpl);
}

export async function assertContainersAbsent(commandImpl = runCommand) {
  for (const containerName of ownedContainers) {
    await assertContainerAbsent(containerName, commandImpl);
  }
}

export async function assertContainerAbsent(
  containerName,
  commandImpl = runCommand,
) {
  const target = targetForIndex(ownedContainers.indexOf(containerName));
  const result = await commandImpl("docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${containerName}$`,
    "--format",
    "{{.Names}}",
  ]);
  if (
    result.code !== 0 || result.signal || result.timedOut ||
    result.outputOverflow || result.stdout.trim()
  ) {
    throw activationRunnerFailure(
      "FINAL_ABSENCE", "CONTAINER_PRESENT_OR_UNPROVEN", target,
    );
  }
}

export async function assertNetworksAbsent(commandImpl = runCommand) {
  for (const networkName of ownedNetworks) {
    await assertNetworkAbsent(networkName, commandImpl);
  }
}

export async function assertNetworkAbsent(
  networkName,
  commandImpl = runCommand,
) {
  const target = targetForIndex(ownedNetworks.indexOf(networkName));
  const result = await commandImpl("docker", [
    "network",
    "ls",
    "--filter",
    `name=^${networkName}$`,
    "--format",
    "{{.Name}}",
  ]);
  if (
    result.code !== 0 || result.signal || result.timedOut ||
    result.outputOverflow || result.stdout.trim()
  ) {
    throw activationRunnerFailure(
      "FINAL_ABSENCE", "NETWORK_PRESENT_OR_UNPROVEN", target,
    );
  }
}

async function provisionFixture(
  connectionString,
  operatorPassword,
  migrationsFolder,
  target,
) {
  const pool = new Pool({
    ...parentPostgresClientConfig(connectionString, operatorPassword),
    max: 1,
  });
  try {
    await withActivationFailure(
      "FIXTURE_PROVISION", "MIGRATION_FAILED", target,
      () => migrate(drizzle(pool), { migrationsFolder }),
    );
    await withActivationFailure(
      "FIXTURE_PROVISION", "ROLE_SETUP_FAILED", target, async () => {
        await pool.query(`
      do $fixture$
      begin
        if exists (
          select 1 from pg_roles
          where rolname in ('cloud_admin', 'platform_runtime')
        ) then
          raise exception 'unexpected fixture role';
        end if;
        create role cloud_admin nologin noinherit superuser nocreatedb
          nocreaterole noreplication nobypassrls;
        create role platform_runtime nologin noinherit nosuperuser nocreatedb
          nocreaterole noreplication nobypassrls;
      end
      $fixture$
        `);
        await pool.query("revoke platform_runtime from platform_app");
        await pool.query("revoke platform_app from platform_runtime");
      },
    );
    const creatorEdgeClient = await withActivationFailure(
      "FIXTURE_PROVISION", "CREATOR_EDGE_FAILED", target,
      () => pool.connect(),
    );
    let creatorEdgeError = null;
    try {
      await creatorEdgeClient.query("set session authorization cloud_admin");
      await creatorEdgeClient.query(
        "grant platform_runtime to platform_app with admin true, set false, inherit false granted by cloud_admin",
      );
    } catch (error) {
      creatorEdgeError = activationRunnerFailure(
        "FIXTURE_PROVISION", "CREATOR_EDGE_FAILED", target,
      );
    } finally {
      try {
        await executeActivationCleanupActions([
          cleanupAction(
            "FIXTURE_PROVISION", "CREATOR_EDGE_FAILED", target,
            () => creatorEdgeClient.query("reset session authorization"),
          ),
        ], creatorEdgeError);
      } finally {
        creatorEdgeClient.release(true);
      }
    }
    await withActivationFailure(
      "FIXTURE_PROVISION", "GRANT_CONTRACT_FAILED", target, async () => {
    await pool.query(
      `revoke create on database ${quoteIdentifier(databaseName)} from public`,
    );
    await pool.query("revoke create on schema public from public");
    await pool.query("revoke usage on schema drizzle from public");
    await pool.query("revoke create on schema drizzle from public");
    await pool.query("grant usage on schema public to platform_runtime");
    await pool.query(
      "revoke all privileges on all tables in schema public from platform_runtime",
    );
    if (RUNTIME_TABLE_GRANT_CONTRACT.length !== 39) throw new Error();
    for (const [tableName, privileges] of privilegesByTable()) {
      await pool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await pool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await pool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
      },
    );
  } finally {
    await pool.end();
  }
}

async function assertFixtureIdentity(connectionString, operatorPassword, target) {
  const pool = new Pool({
    ...parentPostgresClientConfig(connectionString, operatorPassword),
    max: 1,
  });
  try {
    const result = await withActivationFailure(
      "FIXTURE_IDENTITY", "QUERY_FAILED", target, () => pool.query(`
      select
        current_database() = 'runtime_posture_test' as database_matches,
        current_user = 'platform_app' as current_user_matches,
        session_user = 'platform_app' as session_user_matches,
        current_setting('server_version_num')::integer / 10000 = 17 as postgres17,
        (select rolsuper and rolcanlogin from pg_roles where rolname = 'platform_app')
          as operator_matches,
        (select rolsuper and rolcanlogin and not rolinherit from pg_roles where rolname = 'postgres')
          as postgres_matches,
        (select rolsuper and not rolcanlogin and not rolinherit from pg_roles where rolname = 'cloud_admin')
          as cloud_admin_matches,
        (select not rolcanlogin and not rolinherit and not rolsuper and not rolcreaterole
          from pg_roles where rolname = 'platform_runtime') as runtime_matches,
        (select system_identifier::text from pg_control_system())
          as system_identifier
      `),
    );
    const [row] = result.rows;
    if (
      !row?.database_matches ||
      !row.current_user_matches ||
      !row.session_user_matches ||
      !row.postgres17 ||
      !row.operator_matches ||
      !row.postgres_matches ||
      !row.cloud_admin_matches ||
      !row.runtime_matches
    ) {
      throw activationRunnerFailure(
        "FIXTURE_IDENTITY", "IDENTITY_INVALID", target,
      );
    }
    if (!/^[0-9]+$/u.test(row.system_identifier)) {
      throw activationRunnerFailure(
        "FIXTURE_IDENTITY", "SYSTEM_IDENTIFIER_INVALID", target,
      );
    }
    return row.system_identifier;
  } finally {
    await pool.end();
  }
}

export async function assertOwnedDockerTopology(
  spawnImpl,
  containerName,
  networkName,
  target,
  { delayImpl = delay } = {},
) {
  const engine = classifyEnginePosture(await topologyCommand(
    spawnImpl,
    ["version", "--format", "{{.Server.Version}}"],
    "ENGINE_INVALID",
    target,
  ));
  if (engine.category !== "GE_28") {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "ENGINE_INVALID", target,
    );
  }
  const image = await topologyCommand(
    spawnImpl,
    ["inspect", "--format", "{{.Config.Image}}", containerName],
    "IMAGE_INVALID",
    target,
  );
  if (image.stdout.trim() !== "postgres:17") {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "IMAGE_INVALID", target,
    );
  }
  const network = await topologyCommand(
    spawnImpl,
    [
      "network", "inspect", "--format", "{{json .}}",
      networkName,
    ],
    "NETWORK_INVALID",
    target,
  );
  const networkPosture = parseTopologyJson(network.stdout);
  if (
    networkPosture.category ||
    networkPosture.value.Driver !== "bridge" ||
    networkPosture.value.Internal !== false ||
    !networkPosture.value.Options ||
    typeof networkPosture.value.Options !== "object" ||
    Array.isArray(networkPosture.value.Options) ||
    Object.keys(networkPosture.value.Options).length !== 0
  ) {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "NETWORK_INVALID", target,
    );
  }
  const networks = await topologyCommand(
    spawnImpl,
    [
      "inspect", "--format", "{{json .NetworkSettings.Networks}}",
      containerName,
    ],
    "ALIAS_INVALID",
    target,
  );
  let networkMap;
  try {
    networkMap = JSON.parse(networks.stdout);
  } catch {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "ALIAS_INVALID", target,
    );
  }
  if (
    Object.keys(networkMap).length !== 1 ||
    !networkMap[networkName] ||
    !Array.isArray(networkMap[networkName].Aliases) ||
    !networkMap[networkName].Aliases.includes(networkAlias)
  ) {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "ALIAS_INVALID", target,
    );
  }
  const request = classifyRequestBinding(await topologyCommand(
    spawnImpl,
    [
      "inspect", "--format", "{{json .HostConfig.PortBindings}}",
      containerName,
    ],
    "BINDING_INVALID",
    target,
  ));
  if (request.category !== "EXACT_DYNAMIC") {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", "BINDING_INVALID", target,
    );
  }
  const operationalArguments = [
    "inspect", "--format", "{{json .NetworkSettings.Ports}}", containerName,
  ];
  const firstOperational = classifyOperationalBinding(
    await topologyEvidenceCommand(spawnImpl, operationalArguments),
  );
  if (firstOperational.category === "EXACT") {
    const portQuery = classifyPortQuery(await topologyEvidenceCommand(
      spawnImpl,
      ["port", containerName, "5432/tcp"],
    ));
    if (
      portQuery.category !== "EXACT" ||
      portQuery.port !== firstOperational.port
    ) {
      throw activationRunnerFailure(
        "TOPOLOGY_PORT_VERIFY", "PORT_INVALID", target,
      );
    }
    return firstOperational.port;
  }

  const evidence = await collectActivationTopologyEvidence({
    target,
    firstOperational,
    delayImpl,
    observeEngine: async () => engine,
    observeRequest: async () => request,
    observeOperational: async () => classifyOperationalBinding(
      await topologyEvidenceCommand(spawnImpl, operationalArguments),
    ),
    observePortQuery: async () => classifyPortQuery(
      await topologyEvidenceCommand(
        spawnImpl,
        ["port", containerName, "5432/tcp"],
      ),
    ),
  });
  throw activationRunnerFailure(
    "TOPOLOGY_PORT_VERIFY", "BINDING_INVALID", target, "", evidence,
  );
}

export function classifyEnginePosture(observation) {
  if (observation?.commandCategory) {
    return { category: requireTopologyCommandCategory(observation.commandCategory) };
  }
  const value = typeof observation?.stdout === "string"
    ? observation.stdout.trim()
    : "";
  const match = value.match(/^(\d+)\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/u);
  if (!match) return { category: "UNPARSEABLE" };
  return { category: Number(match[1]) >= 28 ? "GE_28" : "LT_28" };
}

export function classifyRequestBinding(observation) {
  if (observation?.commandCategory) {
    return { category: requireTopologyCommandCategory(observation.commandCategory) };
  }
  const parsed = parseTopologyJson(observation?.stdout);
  if (parsed.category) return parsed;
  const selected = classifyPortMap(parsed.value, { request: true });
  if (selected.category) return selected;
  if (selected.binding.HostPort === "") return { category: "EXACT_DYNAMIC" };
  if (!isValidPortText(selected.binding.HostPort)) return { category: "PORT_INVALID" };
  return { category: "EXACT_ASSIGNED", port: Number(selected.binding.HostPort) };
}

export function classifyOperationalBinding(observation) {
  if (observation?.commandCategory) {
    return { category: requireTopologyCommandCategory(observation.commandCategory) };
  }
  const parsed = parseTopologyJson(observation?.stdout);
  if (parsed.category) return parsed;
  const selected = classifyPortMap(parsed.value, { request: false });
  if (selected.category) return selected;
  if (!Object.hasOwn(selected.binding, "HostPort") || selected.binding.HostPort === "") {
    return { category: "HOST_PORT_MISSING" };
  }
  if (
    typeof selected.binding.HostPort !== "string" ||
    !/^[0-9]+$/u.test(selected.binding.HostPort)
  ) {
    return { category: "HOST_PORT_NONDECIMAL" };
  }
  if (!isValidPortText(selected.binding.HostPort)) {
    return { category: "PORT_OUT_OF_RANGE" };
  }
  return { category: "EXACT", port: Number(selected.binding.HostPort) };
}

export function classifyPortQuery(observation) {
  if (observation?.commandCategory) {
    return { category: requireTopologyCommandCategory(observation.commandCategory) };
  }
  if (typeof observation?.stdout !== "string" || !observation.stdout.trim()) {
    return { category: "MISSING" };
  }
  const lines = observation.stdout.replace(/\r\n?/gu, "\n")
    .split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length > 1) return { category: "MULTIPLE" };
  const match = lines[0].match(/^(.*):([^:]*)$/u);
  if (!match) return { category: "MALFORMED" };
  const host = match[1].replace(/^\[(.*)\]$/u, "$1");
  const hostCategory = classifyTopologyHost(host);
  if (hostCategory) return { category: hostCategory };
  if (!isValidPortText(match[2])) return { category: "PORT_INVALID" };
  return { category: "EXACT", port: Number(match[2]) };
}

export function isUnsafeInitialOperationalBinding(classification) {
  return [
    "UNEXPECTED_PORT_PRESENT",
    "BINDING_SHAPE_INVALID",
    "BINDING_MULTIPLE",
    "HOST_WILDCARD_OR_MISSING",
    "HOST_NONLOOPBACK",
    "HOST_PORT_NONDECIMAL",
    "PORT_OUT_OF_RANGE",
  ].includes(classification?.category);
}

export async function collectActivationTopologyEvidence({
  target,
  firstOperational,
  observeEngine,
  observeRequest,
  observeOperational,
  observePortQuery,
  delayImpl = delay,
}) {
  if (!ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT.TARGET.includes(target)) {
    throw new TypeError("Invalid activation topology target");
  }
  const [engine, request] = await Promise.all([
    safeTopologyObservation(observeEngine, "UNPARSEABLE"),
    safeTopologyObservation(observeRequest, "MALFORMED"),
  ]);
  const operational = [firstOperational];
  if (!isUnsafeInitialOperationalBinding(firstOperational)) {
    for (let index = 1; index < ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS.length; index += 1) {
      await delayImpl(
        ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS[index] -
          ACTIVATION_TOPOLOGY_SAMPLE_TIMES_MS[index - 1],
      );
      operational.push(await safeTopologyObservation(
        observeOperational,
        "MALFORMED",
      ));
    }
  }
  const terminalOperational = operational.at(-1);
  const portQuery = await safeTopologyObservation(observePortQuery, "MALFORMED");
  const temporal = operational.length === 1
    ? "NOT_SAMPLED"
    : terminalOperational.category === "EXACT"
      ? "CONVERGED_TO_EXACT"
      : operational.every((value) =>
        value.category === operational[0].category &&
        value.port === operational[0].port)
        ? "STABLE"
        : "CHANGED_NONEXACT";
  const portMatch = terminalOperational.category === "EXACT" &&
      portQuery.category === "EXACT"
    ? terminalOperational.port === portQuery.port ? "YES" : "NO"
    : "UNPROVABLE";
  return {
    ENGINE: engine.category,
    REQUEST: request.category,
    OPERATIONAL_FIRST: firstOperational.category,
    OPERATIONAL_TERMINAL: terminalOperational.category,
    PORT_QUERY: portQuery.category,
    TEMPORAL: temporal,
    PORT_MATCH: portMatch,
    TARGET: target,
  };
}

export function formatActivationTopologyEvidence(evidence) {
  for (const [field, allowed] of Object.entries(
    ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT,
  )) {
    if (!allowed.includes(evidence?.[field])) {
      throw new TypeError("Invalid activation topology evidence receipt");
    }
  }
  return "ACTIVATION_TOPOLOGY_EVIDENCE " + Object.keys(
    ACTIVATION_TOPOLOGY_EVIDENCE_CONTRACT,
  ).map((field) => `${field}=${evidence[field]}`).join(" ");
}

function parseTopologyJson(stdout) {
  if (typeof stdout !== "string" || !stdout.trim() || stdout.trim() === "null") {
    return { category: "MISSING" };
  }
  try {
    const value = JSON.parse(stdout);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { category: "MALFORMED" };
    }
    return { value };
  } catch {
    return { category: "MALFORMED" };
  }
}

function classifyPortMap(value, { request }) {
  const keys = Object.keys(value);
  if (keys.some((key) => key !== "5432/tcp")) {
    return { category: "UNEXPECTED_PORT_PRESENT" };
  }
  if (!Object.hasOwn(value, "5432/tcp")) {
    return { category: "EXPECTED_PORT_MISSING" };
  }
  const bindings = value["5432/tcp"];
  if (!Array.isArray(bindings)) return { category: "BINDING_SHAPE_INVALID" };
  if (bindings.length === 0) return { category: "BINDING_MISSING" };
  if (bindings.length > 1) return { category: "BINDING_MULTIPLE" };
  const binding = bindings[0];
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    return { category: "BINDING_SHAPE_INVALID" };
  }
  const hostCategory = classifyTopologyHost(binding.HostIp);
  if (hostCategory) return { category: hostCategory };
  if (request && !Object.hasOwn(binding, "HostPort")) {
    return { category: "PORT_INVALID" };
  }
  return { binding };
}

function classifyTopologyHost(host) {
  if (
    typeof host !== "string" || !host || host === "0.0.0.0" || host === "::"
  ) {
    return "HOST_WILDCARD_OR_MISSING";
  }
  if (host === "127.0.0.1") return null;
  if (/^127(?:\.\d{1,3}){3}$/u.test(host) || host === "::1") {
    return "HOST_LOOPBACK_MISMATCH";
  }
  return "HOST_NONLOOPBACK";
}

function isValidPortText(value) {
  if (typeof value !== "string" || !/^[0-9]+$/u.test(value)) return false;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65_535;
}

function requireTopologyCommandCategory(category) {
  if (!topologyCommandCategories.includes(category)) {
    throw new TypeError("Invalid topology command category");
  }
  return category;
}

async function safeTopologyObservation(observe, fallbackCategory) {
  try {
    return await observe();
  } catch {
    return { category: fallbackCategory };
  }
}

async function topologyEvidenceCommand(spawnImpl, args) {
  let result;
  try {
    result = await runCommand("docker", args, { spawnImpl });
  } catch {
    return { commandCategory: "COMMAND_SPAWN_FAILED", stdout: "" };
  }
  const category = classifyCommandOutcome(result);
  return {
    commandCategory: category,
    stdout: category ? "" : result.stdout,
  };
}

async function topologyCommand(spawnImpl, args, category, target) {
  try {
    const result = await runCommand("docker", args, { spawnImpl });
    if (
      result.code !== 0 || result.signal !== null || result.timedOut ||
      result.outputOverflow
    ) {
      throw new Error();
    }
    return result;
  } catch {
    throw activationRunnerFailure(
      "TOPOLOGY_PORT_VERIFY", category, target,
    );
  }
}

export function parentPostgresClientConfig(connectionString, operatorPassword) {
  const invalid = () => {
    throw new TypeError("Invalid parent PostgreSQL client configuration");
  };
  if (
    typeof connectionString !== "string" ||
    typeof operatorPassword !== "string" ||
    operatorPassword.length === 0
  ) {
    return invalid();
  }

  let parsed;
  try {
    parsed = new URL(connectionString);
  } catch {
    return invalid();
  }
  const port = Number(parsed.port);
  if (
    parsed.protocol !== "postgresql:" ||
    parsed.username !== "platform_app" ||
    parsed.password !== "" ||
    parsed.hostname !== "127.0.0.1" ||
    !/^[1-9][0-9]{0,4}$/u.test(parsed.port) ||
    !Number.isInteger(port) ||
    port > 65_535 ||
    parsed.pathname !== `/${databaseName}` ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.href !== connectionString
  ) {
    return invalid();
  }

  return {
    user: parsed.username,
    host: parsed.hostname,
    port,
    database: databaseName,
    password: operatorPassword,
  };
}

export async function waitForPostgresReadiness(
  connectionString,
  operatorPassword,
  { PoolImpl = Pool, delayImpl = delay } = {},
) {
  const probeCategories = [];
  for (
    let attempt = 0;
    attempt < ACTIVATION_READINESS_MAX_ATTEMPTS;
    attempt += 1
  ) {
    const pool = new PoolImpl({
      ...parentPostgresClientConfig(connectionString, operatorPassword),
      connectionTimeoutMillis: ACTIVATION_READINESS_CONNECTION_TIMEOUT_MS,
      max: 1,
    });
    let poolEndFailed = false;
    let ready = false;
    try {
      const result = await pool.query(
        "select current_user = 'platform_app' as admitted, current_setting('server_version_num')::integer / 10000 = 17 as postgres17",
      );
      ready = Boolean(
        result.rows[0]?.admitted && result.rows[0]?.postgres17,
      );
      if (!ready) probeCategories.push("IDENTITY_OR_VERSION_MISMATCH");
    } catch (error) {
      probeCategories.push(classifyReadinessProbeError(error));
      await delayImpl(ACTIVATION_READINESS_ERROR_BACKOFF_MS);
    } finally {
      try {
        await pool.end();
      } catch {
        poolEndFailed = true;
      }
    }
    if (poolEndFailed) {
      probeCategories.push("UNKNOWN");
      return readinessProbeResult("TIMEOUT", attempt + 1, probeCategories);
    }
    if (ready) {
      return readinessProbeResult("READY", attempt + 1, probeCategories);
    }
  }
  return readinessProbeResult(
    "TIMEOUT",
    ACTIVATION_READINESS_MAX_ATTEMPTS,
    probeCategories,
  );
}

function readinessProbeResult(outcome, attempts, categories) {
  return {
    outcome,
    attempts,
    aggregateProbe: aggregateReadinessProbeCategory(categories),
    lastProbe: categories.at(-1) ?? "UNKNOWN",
  };
}

export function classifyReadinessProbeError(error) {
  if (error?.message === "Connection terminated due to connection timeout") {
    return "CONNECTION_TIMEOUT";
  }
  const code = typeof error?.code === "string" ? error.code.toUpperCase() : "";
  if (code === "ECONNREFUSED") return "CONNECTION_REFUSED";
  if (["ETIMEDOUT", "ETIME"].includes(code)) return "CONNECTION_TIMEOUT";
  if (["ENETUNREACH", "EHOSTUNREACH", "EAI_AGAIN"].includes(code)) {
    return "NETWORK_UNREACHABLE";
  }
  if (["28P01", "28000"].includes(code)) return "AUTH_REJECTED";
  if (code === "57P03") return "SERVER_STARTING";
  if (
    code.startsWith("08") ||
    ["ECONNRESET", "EPIPE", "57P01", "57P02"].includes(code)
  ) {
    return "PROTOCOL_OR_SERVER_ERROR";
  }
  if (/^[0-9A-Z]{5}$/u.test(code)) return "QUERY_FAILED";
  return "UNKNOWN";
}

export function aggregateReadinessProbeCategory(categories) {
  const counts = new Map(readinessProbeCategories.map((category) => [category, 0]));
  for (const category of categories) {
    if (counts.has(category)) counts.set(category, counts.get(category) + 1);
    else counts.set("UNKNOWN", counts.get("UNKNOWN") + 1);
  }
  let selected = "UNKNOWN";
  let selectedCount = 0;
  for (const category of readinessProbeCategories) {
    if (counts.get(category) > selectedCount) {
      selected = category;
      selectedCount = counts.get(category);
    }
  }
  return selected;
}

export async function executeActivationReadinessChecks({
  operatorUrls,
  operatorPassword,
  ports,
  spawnImpl,
  waitForPostgresImpl = waitForPostgresReadiness,
  collectTerminalEvidenceImpl = collectActivationReadinessEvidence,
}) {
  const settled = await Promise.allSettled(operatorUrls.map((url) =>
    waitForPostgresImpl(url, operatorPassword)));
  const probeResults = settled.map((result) => {
    if (result.status === "fulfilled") {
      const value = result.value;
      if (
        ["READY", "TIMEOUT"].includes(value?.outcome) &&
        Number.isInteger(value?.attempts) &&
        value.attempts >= 1 &&
        value.attempts <= ACTIVATION_READINESS_MAX_ATTEMPTS &&
        readinessProbeCategories.includes(value.aggregateProbe) &&
        readinessProbeCategories.includes(value.lastProbe)
      ) {
        return value;
      }
    }
    return readinessProbeResult("TIMEOUT", 1, ["UNKNOWN"]);
  });
  const timedOutIndexes = probeResults.flatMap((result, index) =>
    result.outcome === "TIMEOUT" ? [index] : []);
  if (timedOutIndexes.length === 0) return probeResults;

  const evidence = await Promise.all(probeResults.map(async (probe, index) => {
    try {
      return await collectTerminalEvidenceImpl({
        probe,
        target: targetForIndex(index),
        containerName: ownedContainers[index],
        port: ports[index],
        spawnImpl,
      });
    } catch {
      return readinessEvidenceWithTerminalState(probe, targetForIndex(index), {
        containerState: "UNKNOWN",
        internalPgIsReady: "COMMAND_FAILED",
        hostTcp: "NETWORK_ERROR",
        topologyBinding: "UNPROVEN",
      });
    }
  }));
  const failureTarget = timedOutIndexes.length === 2
    ? "BOTH"
    : targetForIndex(timedOutIndexes[0]);
  throw activationRunnerFailure(
    "POSTGRES_READINESS",
    "READINESS_TIMEOUT",
    failureTarget,
    "",
    null,
    evidence,
  );
}

export async function collectActivationReadinessEvidence({
  probe,
  target,
  containerName,
  port,
  spawnImpl,
}) {
  const [containerState, internalPgIsReady, hostTcp, topologyBinding] =
    await Promise.all([
      observeReadinessContainerState(spawnImpl, containerName),
      observeInternalPgIsReady(spawnImpl, containerName),
      observeHostTcp(port),
      observeTerminalTopologyBinding(spawnImpl, containerName, port),
    ]);
  return readinessEvidenceWithTerminalState(probe, target, {
    containerState,
    internalPgIsReady,
    hostTcp,
    topologyBinding,
  });
}

function readinessEvidenceWithTerminalState(probe, target, terminal) {
  return {
    OUTCOME: probe.outcome,
    ATTEMPTS: probe.attempts,
    AGGREGATE_PROBE: probe.aggregateProbe,
    LAST_PROBE: probe.lastProbe,
    CONTAINER_STATE: terminal.containerState,
    INTERNAL_PG_ISREADY: terminal.internalPgIsReady,
    HOST_TCP: terminal.hostTcp,
    TOPOLOGY_BINDING: terminal.topologyBinding,
    TARGET: target,
  };
}

export function formatActivationReadinessEvidence(evidence) {
  if (
    !Number.isInteger(evidence?.ATTEMPTS) ||
    evidence.ATTEMPTS < 1 ||
    evidence.ATTEMPTS > ACTIVATION_READINESS_MAX_ATTEMPTS
  ) {
    throw new TypeError("Invalid activation readiness evidence receipt");
  }
  for (const [field, allowed] of Object.entries(
    ACTIVATION_READINESS_EVIDENCE_CONTRACT,
  )) {
    if (!allowed.includes(evidence?.[field])) {
      throw new TypeError("Invalid activation readiness evidence receipt");
    }
  }
  const fields = [
    "OUTCOME", "ATTEMPTS", "AGGREGATE_PROBE", "LAST_PROBE",
    "CONTAINER_STATE", "INTERNAL_PG_ISREADY", "HOST_TCP",
    "TOPOLOGY_BINDING", "TARGET",
  ];
  return "ACTIVATION_READINESS_EVIDENCE " + fields.map(
    (field) => `${field}=${evidence[field]}`,
  ).join(" ");
}

async function observeReadinessContainerState(spawnImpl, containerName) {
  const observation = await topologyEvidenceCommand(spawnImpl, [
    "inspect", "--format", "{{json .State}}", containerName,
  ]);
  if (observation.commandCategory) return "UNKNOWN";
  try {
    return classifyReadinessContainerState(JSON.parse(observation.stdout));
  } catch {
    return "UNKNOWN";
  }
}

export function classifyReadinessContainerState(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) return "UNKNOWN";
  if (state.OOMKilled === true) return "OOM_KILLED";
  const status = typeof state.Status === "string" ? state.Status.toLowerCase() : "";
  if (status === "running") return "RUNNING";
  if (status === "restarting") return "RESTARTING";
  if (status === "exited") return "EXITED";
  if (status === "dead") return "DEAD";
  return "UNKNOWN";
}

async function observeInternalPgIsReady(spawnImpl, containerName) {
  let result;
  try {
    result = await runCommand("docker", [
      "exec", containerName, "pg_isready", "-U", "platform_app",
      "-d", databaseName, "-t", "1",
    ], { spawnImpl, timeoutMs: 5_000 });
  } catch {
    return "COMMAND_FAILED";
  }
  return classifyInternalPgIsReady(result);
}

export function classifyInternalPgIsReady(result) {
  if (result?.timedOut || result?.outputOverflow || result?.signal) {
    return "COMMAND_FAILED";
  }
  if (result?.code === 0) return "ACCEPTING";
  if (result?.code === 1) return "REJECTING";
  if (result?.code === 2) return "NO_RESPONSE";
  return "COMMAND_FAILED";
}

async function observeHostTcp(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    return "NETWORK_ERROR";
  }
  return new Promise((resolvePromise) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (category) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(category);
    };
    socket.setTimeout(ACTIVATION_READINESS_CONNECTION_TIMEOUT_MS, () =>
      finish("TIMEOUT"));
    socket.once("connect", () => finish("CONNECTED"));
    socket.once("error", (error) => finish(classifyHostTcpError(error)));
  });
}

export function classifyHostTcpError(error) {
  if (error?.code === "ECONNREFUSED") return "REFUSED";
  if (error?.code === "ETIMEDOUT") return "TIMEOUT";
  return "NETWORK_ERROR";
}

async function observeTerminalTopologyBinding(spawnImpl, containerName, port) {
  const [request, operational, portQuery] = await Promise.all([
    topologyEvidenceCommand(spawnImpl, [
      "inspect", "--format", "{{json .HostConfig.PortBindings}}", containerName,
    ]).then(classifyRequestBinding),
    topologyEvidenceCommand(spawnImpl, [
      "inspect", "--format", "{{json .NetworkSettings.Ports}}", containerName,
    ]).then(classifyOperationalBinding),
    topologyEvidenceCommand(spawnImpl, [
      "port", containerName, "5432/tcp",
    ]).then(classifyPortQuery),
  ]);
  return classifyTerminalTopologyBinding({
    request,
    operational,
    portQuery,
    expectedPort: port,
  });
}

export function classifyTerminalTopologyBinding({
  request,
  operational,
  portQuery,
  expectedPort,
}) {
  if (
    request?.category === "EXACT_DYNAMIC" &&
    operational?.category === "EXACT" &&
    portQuery?.category === "EXACT" &&
    operational.port === expectedPort &&
    portQuery.port === expectedPort
  ) {
    return "EXACT";
  }
  const unproven = [request, operational, portQuery].some((value) =>
    !value?.category ||
    topologyCommandCategories.includes(value.category) ||
    ["MISSING", "MALFORMED"].includes(value.category));
  return unproven ? "UNPROVEN" : "CHANGED";
}

export async function runActivationChild(
  spawnImpl,
  resources,
  operatorUrls,
  { timeoutMs = maxChildDurationMs } = {},
) {
  const childEnvironment = { ...process.env };
  for (const name of Object.keys(childEnvironment)) {
    if (name.startsWith("RUNTIME_ACTIVATION_TEST_")) {
      delete childEnvironment[name];
    }
  }
  Object.assign(childEnvironment, {
    PGPASSWORD: resources.operatorPassword,
    RUNTIME_ACTIVATION_TEST_OPERATOR_URL: operatorUrls[0],
    RUNTIME_ACTIVATION_TEST_SECOND_OPERATOR_URL: operatorUrls[1],
    RUNTIME_ACTIVATION_TEST_DOCKER_NETWORK: ownedNetworks[0],
    RUNTIME_ACTIVATION_TEST_SECOND_DOCKER_NETWORK: ownedNetworks[1],
    RUNTIME_ACTIVATION_TEST_RUNTIME_PASSWORD: resources.runtimePassword,
    RUNTIME_ACTIVATION_TEST_CONFIRM: "disposable-only",
  });
  resources.childEnvironment = childEnvironment;
  const result = await new Promise((resolvePromise, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;
    let timedOut = false;
    let child;
    try {
      child = spawnImpl(
        process.execPath,
        ["--test", "tests/platform-runtime-activation-postgres.test.mjs"],
        {
          cwd: rootDir,
          env: childEnvironment,
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        },
      );
    } catch {
      reject(activationRunnerFailure(
        "ACTIVATION_CHILD", "SPAWN_FAILED", "BOTH",
      ));
      return;
    }
    resources.child = child;
    resources.childExited = false;
    const timer = setTimeout(() => {
      if (!settled) {
        timedOut = true;
        child.kill("SIGTERM");
      }
    }, timeoutMs);
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolvePromise(value);
    };
    child.once("error", () => finish(null, activationRunnerFailure(
      "ACTIVATION_CHILD", "SPAWN_FAILED", "BOTH",
    )));
    child.stdout?.on("data", (chunk) => {
      stdoutLength += chunk.length;
      if (stdoutLength <= maxChildOutputBytes) stdout.push(Buffer.from(chunk));
    });
    child.stderr?.on("data", (chunk) => {
      stderrLength += chunk.length;
      if (stderrLength <= maxChildOutputBytes) stderr.push(Buffer.from(chunk));
    });
    child.once("close", (code, signal) => {
      resources.childExited = true;
      const stdoutText = Buffer.concat(stdout).toString("utf8");
      const stderrText = Buffer.concat(stderr).toString("utf8");
      for (const chunk of [...stdout, ...stderr]) chunk.fill(0);
      let category = null;
      if (timedOut) category = "TIMEOUT";
      else if (stdoutLength > maxChildOutputBytes) category = "STDOUT_OVERFLOW";
      else if (stderrLength > maxChildOutputBytes) category = "STDERR_OVERFLOW";
      else if (signal !== null) category = "SIGNAL";
      else if (code !== 0) category = "EXIT_NONZERO";
      if (category) {
        const childDiagnostics = sanitizeActivationChildDiagnostics({
          stdout: stdoutText,
          stderr: stderrText,
          secretValues: [
            resources.operatorPassword,
            resources.runtimePassword,
            ...operatorUrls,
            ...Object.values(childEnvironment),
          ],
        });
        finish(null, activationRunnerFailure(
          "ACTIVATION_CHILD", category, "BOTH", childDiagnostics,
        ));
        return;
      }
      finish({ stdout: stdoutText, stderr: stderrText });
    });
  });
  const classified = classifyActivationTestSummary(result.stdout);
  if (!classified.summary) {
    const childDiagnostics = sanitizeActivationChildDiagnostics({
      stdout: result.stdout,
      stderr: result.stderr,
      secretValues: [
        resources.operatorPassword,
        resources.runtimePassword,
        ...operatorUrls,
        ...Object.values(childEnvironment),
      ],
    });
    throw activationRunnerFailure(
      "ACTIVATION_CHILD", classified.category, "BOTH", childDiagnostics,
    );
  }
  result.stdout = "";
  result.stderr = "";
  return classified.summary;
}

async function terminateChild(resources) {
  if (!resources.child || resources.childExited) return;
  if (!resources.child.kill("SIGTERM")) throw new Error();
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error()), 2_000);
    resources.child.once("close", () => {
      clearTimeout(timer);
      resources.childExited = true;
      resolvePromise();
    });
  });
}

async function removeOwnedContainer(spawnImpl, containerName) {
  const result = await runCommand("docker", ["rm", "--force", containerName], {
    spawnImpl,
  });
  if (result.code === 0) return;
  const absent = await runCommand("docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${containerName}$`,
    "--format",
    "{{.Names}}",
  ], { spawnImpl });
  if (absent.code !== 0 || absent.stdout.trim()) throw new Error();
}

async function removeOwnedNetwork(spawnImpl, networkName) {
  const result = await runCommand("docker", ["network", "rm", networkName], {
    spawnImpl,
  });
  if (result.code === 0) return;
  const absent = await runCommand("docker", [
    "network",
    "ls",
    "--filter",
    `name=^${networkName}$`,
    "--format",
    "{{.Name}}",
  ], { spawnImpl });
  if (absent.code !== 0 || absent.stdout.trim()) throw new Error();
}

async function clearCredentialState(resources) {
  resources.operatorPasswordBuffer.fill(0);
  resources.runtimePasswordBuffer.fill(0);
  resources.operatorPassword = null;
  resources.runtimePassword = null;
  if (resources.childEnvironment) {
    for (const name of Object.keys(resources.childEnvironment)) {
      if (
        name.startsWith("RUNTIME_ACTIVATION_TEST_") ||
        name === "POSTGRES_PASSWORD" ||
        name === "PGPASSWORD"
      ) {
        delete resources.childEnvironment[name];
      }
    }
    resources.childEnvironment = null;
  }
}

async function assertPathAbsent(path) {
  try {
    await access(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error();
}

async function assertPortAbsent(port) {
  await new Promise((resolvePromise, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
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
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) finish();
      else finish(new Error());
    });
  });
}

async function requireSuccessfulCommand(
  spawnImpl,
  command,
  args,
  options = {},
  phase,
  target,
) {
  let result;
  try {
    result = await runCommand(command, args, { ...options, spawnImpl });
  } catch {
    throw activationRunnerFailure(phase, "SPAWN_FAILED", target);
  }
  const category = classifyCommandOutcome(result);
  if (category) throw activationRunnerFailure(phase, category, target);
  return result;
}

export function classifyCommandOutcome(result) {
  if (result?.timedOut) return "TIMEOUT";
  if (result?.outputOverflow) return "OUTPUT_OVERFLOW";
  if (result?.signal !== null && result?.signal !== undefined) return "SIGNAL";
  if (result?.code !== 0) return "COMMAND_NONZERO";
  return null;
}

async function runCommand(command, args, {
  cwd = rootDir,
  env = process.env,
  spawnImpl = spawn,
  timeoutMs = 30_000,
} = {}) {
  return new Promise((resolvePromise, reject) => {
    const stdout = [];
    const stderr = [];
    let outputLength = 0;
    let settled = false;
    let timedOut = false;
    let child;
    try {
      child = spawnImpl(command, args, {
        cwd,
        env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch {
      reject(new Error());
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolvePromise(value);
    };
    child.once("error", () => finish(null, new Error()));
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) stdout.push(Buffer.from(chunk));
    });
    child.stderr?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) stderr.push(Buffer.from(chunk));
    });
    child.once("close", (code, signal) => finish({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      outputOverflow: outputLength > maxChildOutputBytes,
      timedOut,
    }));
  });
}

function buildLoopbackUrl(user, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error();
  return `postgresql://${user}@127.0.0.1:${port}/${databaseName}`;
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

function quoteIdentifier(value) {
  if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(value)) throw new Error();
  return `"${value.replaceAll('"', '""')}"`;
}
