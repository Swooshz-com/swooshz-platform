#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  createDatabaseReadinessReport,
  formatDatabaseReadinessReport,
} from "../dist/db/readiness.js";
import {
  BROKER_EXPECTED_FINAL_MIGRATION_STATE,
  canonicalSerializeBrokerBundle,
  normalizeBrokerObservationEvidence,
} from "../dist/db/brokered-migration.js";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultJournalPath = path.join(
  rootDir,
  "drizzle",
  "migrations",
  "meta",
  "_journal.json",
);

const EXPECTED_MIGRATION_STATE_KEYS = [
  "latestTag",
  "latestCreatedAt",
  "migrationCount",
];
const JOURNAL_KEYS = ["version", "dialect", "entries"];
const JOURNAL_ENTRY_KEYS = ["idx", "version", "when", "tag", "breakpoints"];

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, keys) {
  if (!isRecord(value)) throw new Error("Migration journal is not readable.");
  const expected = new Set(keys);
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== expected.size ||
    actual.some((key) => typeof key !== "string" || !expected.has(key))
  ) {
    throw new Error("Migration journal is not readable.");
  }
}

function captureExpectedMigrationState(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Migration journal is not readable.");
  }
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new Error("Migration journal is not readable.");
  }
  const expected = new Set(EXPECTED_MIGRATION_STATE_KEYS);
  const actual = Reflect.ownKeys(descriptors);
  if (
    actual.length !== expected.size ||
    actual.some((key) => typeof key !== "string" || !expected.has(key))
  ) {
    throw new Error("Migration journal is not readable.");
  }
  const snapshot = {};
  for (const key of EXPECTED_MIGRATION_STATE_KEYS) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      descriptor.enumerable !== true ||
      !Object.hasOwn(descriptor, "value") ||
      !Object.hasOwn(descriptor, "writable") ||
      Object.hasOwn(descriptor, "get") ||
      Object.hasOwn(descriptor, "set")
    ) {
      throw new Error("Migration journal is not readable.");
    }
    snapshot[key] = descriptor.value;
  }
  if (
    snapshot.latestTag !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestTag ||
    snapshot.latestCreatedAt !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestCreatedAt ||
    snapshot.migrationCount !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.migrationCount
  ) {
    throw new Error("Migration journal is not readable.");
  }
  return Object.freeze(snapshot);
}

function canonicalJournalSummary(journal) {
  assertExactKeys(journal, JOURNAL_KEYS);
  if (
    journal.version !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.version ||
    journal.dialect !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.dialect ||
    !Array.isArray(journal.entries) ||
    journal.entries.length !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.migrationCount
  ) {
    throw new Error("Migration journal is not readable.");
  }
  journal.entries.forEach((entry, index) => {
    assertExactKeys(entry, JOURNAL_ENTRY_KEYS);
    const expected = BROKER_EXPECTED_FINAL_MIGRATION_STATE.entries[index];
    if (
      !expected ||
      entry.idx !== expected.idx ||
      entry.version !== expected.version ||
      entry.when !== expected.when ||
      entry.tag !== expected.tag ||
      entry.breakpoints !== expected.breakpoints
    ) {
      throw new Error("Migration journal is not readable.");
    }
  });
  return Object.freeze({
    latestTag: BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestTag,
    latestCreatedAt: BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestCreatedAt,
    migrationCount: BROKER_EXPECTED_FINAL_MIGRATION_STATE.migrationCount,
  });
}

export async function readExpectedMigrationState(journalPath = defaultJournalPath) {
  const journal = JSON.parse(await readFile(journalPath, "utf8"));
  return canonicalJournalSummary(journal);
}

export async function runPlatformDatabaseReadinessCheck({
  env = process.env,
  expectedMigrationState,
  clientFactory,
  broker,
  observationBundle,
  writeLine = console.log,
  writeError = console.error,
} = {}) {
  if (env.DATABASE_OPERATOR_URL?.trim()) {
    writeError("Swooshz Platform database readiness_check=fail");
    writeError("status=direct_database_credential_prohibited");
    return { ok: false, status: "db_config_invalid", checks: { config: "invalid", reachability: "not_checked", schema: "not_checked", migrations: "not_checked", migratorPosture: "not_checked" }, requiredTables: [], missingTables: [] };
  }
  let migrationState;

  try {
    migrationState = expectedMigrationState === undefined
      ? await readExpectedMigrationState()
      : captureExpectedMigrationState(expectedMigrationState);
  } catch {
    const report = {
      ok: false,
      status: "schema_not_ready",
      checks: {
        config: "not_checked",
        reachability: "not_checked",
        schema: "failed",
        migrations: "failed",
        migratorPosture: "not_checked",
      },
      requiredTables: [],
      missingTables: [],
    };

    writeError("Swooshz Platform database readiness_check=fail");
    writeError("status=schema_not_ready");
    writeError("database_config=not_checked");
    writeError("database_reachability=not_checked");
    writeError("schema_state=failed");
    writeError("migrator_posture=not_checked");
    writeError("migration_state=expected_state_unavailable");
    return report;
  }

  if (broker && observationBundle) {
    try {
      const rawEvidence = await broker.observe(
        canonicalSerializeBrokerBundle(observationBundle),
        observationBundle.bundle_digest,
      );
      const evidence = normalizeBrokerObservationEvidence(rawEvidence, observationBundle, "FINAL");
      if (
        migrationState.migrationCount !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.migrationCount ||
        migrationState.latestTag !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestTag ||
        migrationState.latestCreatedAt !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.latestCreatedAt ||
        evidence.ledger.row_count !== BROKER_EXPECTED_FINAL_MIGRATION_STATE.migrationCount ||
        evidence.ledger.migration_0010_absent !== false
      ) {
        throw new Error("Broker final migration state rejected.");
      }
      const report = { ok: true, status: "ready", checks: { config: "present", reachability: "passed", schema: "passed", migrations: "passed", migratorPosture: "passed" }, requiredTables: [], missingTables: [], expectedMigrationState: migrationState };
      for (const line of formatDatabaseReadinessReport(report)) writeLine(line);
      writeLine("migrations=passed");
      return report;
    } catch {
      writeError("Swooshz Platform database readiness_check=fail");
      writeError("status=broker_observation_rejected");
      writeError("migrations=failed");
      return { ok: false, status: "schema_not_ready", checks: { config: "present", reachability: "failed", schema: "not_checked", migrations: "failed", migratorPosture: "failed" }, requiredTables: [], missingTables: [], expectedMigrationState: migrationState };
    }
  }

  const report = await createDatabaseReadinessReport({
    env,
    expectedMigrationState: migrationState,
    ...(clientFactory ? { clientFactory } : {}),
  });
  const write = report.ok ? writeLine : writeError;

  for (const line of formatDatabaseReadinessReport(report)) {
    write(line);
  }

  return report;
}

async function main() {
  if (!process.env.DATABASE_OPERATOR_URL?.trim()) {
    process.stderr.write("Swooshz Platform database readiness_check=fail\nstatus=broker_adapter_unavailable\n");
    process.exitCode = 1;
    return;
  }
  const report = await runPlatformDatabaseReadinessCheck();
  process.exitCode = report.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
