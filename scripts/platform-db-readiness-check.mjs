#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  createDatabaseReadinessReport,
  formatDatabaseReadinessReport,
} from "../dist/db/readiness.js";
import {
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

export async function readExpectedMigrationState(journalPath = defaultJournalPath) {
  const journal = JSON.parse(await readFile(journalPath, "utf8"));
  const entries = Array.isArray(journal.entries) ? journal.entries : [];
  const latest = entries.at(-1);

  if (!latest || typeof latest.tag !== "string" || typeof latest.when !== "number") {
    throw new Error("Migration journal is not readable.");
  }

  return {
    latestTag: latest.tag,
    latestCreatedAt: latest.when,
    migrationCount: entries.length,
  };
}

export async function runPlatformDatabaseReadinessCheck({
  env = process.env,
  expectedMigrationState,
  clientFactory,
  runnerOwnedFixture,
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
    migrationState = expectedMigrationState ?? (await readExpectedMigrationState());
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
      normalizeBrokerObservationEvidence(rawEvidence, observationBundle);
      const report = { ok: true, status: "ready", checks: { config: "present", reachability: "passed", schema: "passed", migrations: "passed", migratorPosture: "passed" }, requiredTables: [], missingTables: [], expectedMigrationState: migrationState };
      for (const line of formatDatabaseReadinessReport(report)) writeLine(line);
      return report;
    } catch {
      writeError("Swooshz Platform database readiness_check=fail");
      writeError("status=broker_observation_rejected");
      return { ok: false, status: "schema_not_ready", checks: { config: "present", reachability: "failed", schema: "not_checked", migrations: "not_checked", migratorPosture: "failed" }, requiredTables: [], missingTables: [], expectedMigrationState: migrationState };
    }
  }

  const report = await createDatabaseReadinessReport({
    env,
    expectedMigrationState: migrationState,
    ...(runnerOwnedFixture ? { runnerOwnedFixture } : {}),
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
