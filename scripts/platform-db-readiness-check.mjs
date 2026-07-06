#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  createDatabaseReadinessReport,
  formatDatabaseReadinessReport,
} from "../dist/db/readiness.js";

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
  writeLine = console.log,
  writeError = console.error,
} = {}) {
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
      },
      requiredTables: [],
      missingTables: [],
    };

    writeError("Swooshz Platform database readiness_check=fail");
    writeError("status=schema_not_ready");
    writeError("database_config=not_checked");
    writeError("database_reachability=not_checked");
    writeError("schema_state=failed");
    writeError("migration_state=expected_state_unavailable");
    return report;
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
  const report = await runPlatformDatabaseReadinessCheck();
  process.exitCode = report.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
