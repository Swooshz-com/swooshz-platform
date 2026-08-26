#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";


import {
  assertMigrationExecutionAllowed,
  createDatabaseClient,
} from "../dist/db/client.js";
import { runCanonicalMigrationPrimitive } from "../dist/db/durable-operations.js";
// The shared primitive preserves the canonical Drizzle migrate(...) behavior.

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsFolder = path.join(rootDir, "drizzle", "migrations");

let client;

try {
  const config = assertMigrationExecutionAllowed(process.env);
  client = createDatabaseClient(config);

  await runCanonicalMigrationPrimitive({
    pool: client.pool,
    migrationsFolder,
  });
  console.log("Database migrations applied.");
} catch (error) {
  const message = error instanceof Error ? error.message : "Database migration failed.";
  if (message.startsWith("DATABASE_")) {
    console.error(message);
  } else {
    console.error(
      "Database migration failed. Details were not printed because they may include connection information.",
    );
  }
  process.exitCode = 1;
} finally {
  await client?.pool.end();
}
