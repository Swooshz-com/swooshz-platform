import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import { createDrizzlePlatformRepositories, type DrizzleDatabase } from "./repositories.js";
import * as schema from "./schema.js";
import type { PlatformRepositories } from "../platform/repositories.js";

export const DATABASE_MIGRATIONS_CONFIRM_VALUE = "apply-reviewed-migrations";

export interface DatabaseEnvironment {
  DATABASE_URL?: string;
  DATABASE_SSL_MODE?: string;
  DATABASE_MIGRATIONS_CONFIRM?: string;
}

export interface DatabaseConfig {
  databaseUrl: string;
  sslMode?: "disable" | "require";
}

export interface DatabaseClient {
  pool: Pool;
  db: NodePgDatabase<typeof schema>;
}

export interface DatabaseRepositoryClient extends DatabaseClient {
  repositories: PlatformRepositories;
}

export function readDatabaseConfig(env: DatabaseEnvironment): DatabaseConfig {
  const databaseUrl = env.DATABASE_URL?.trim();

  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required for database connections.");
  }

  const sslMode = readDatabaseSslMode(env);

  return {
    databaseUrl,
    ...(sslMode ? { sslMode } : {}),
  };
}

export function assertMigrationExecutionAllowed(env: DatabaseEnvironment): DatabaseConfig {
  const config = readDatabaseConfig(env);

  if (env.DATABASE_MIGRATIONS_CONFIRM !== DATABASE_MIGRATIONS_CONFIRM_VALUE) {
    throw new Error(
      `DATABASE_MIGRATIONS_CONFIRM must be set to ${DATABASE_MIGRATIONS_CONFIRM_VALUE} to run database migrations.`,
    );
  }

  return config;
}

export function createDatabasePool(config: DatabaseConfig): Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    ...(config.sslMode ? { ssl: config.sslMode === "require" } : {}),
  });
}

export function createDatabaseClient(config: DatabaseConfig): DatabaseClient {
  const pool = createDatabasePool(config);
  const db = drizzle(pool, { schema });

  return { pool, db };
}

export function createDatabaseRepositories(
  env: DatabaseEnvironment,
): DatabaseRepositoryClient {
  const client = createDatabaseClient(readDatabaseConfig(env));

  return {
    ...client,
    repositories: createDrizzlePlatformRepositories(
      client.db as unknown as DrizzleDatabase,
    ),
  };
}

function readDatabaseSslMode(env: DatabaseEnvironment): DatabaseConfig["sslMode"] {
  const sslMode = env.DATABASE_SSL_MODE?.trim();

  if (!sslMode) {
    return undefined;
  }

  if (sslMode === "disable" || sslMode === "require") {
    return sslMode;
  }

  throw new Error("DATABASE_SSL_MODE must be either 'disable' or 'require' when set.");
}
