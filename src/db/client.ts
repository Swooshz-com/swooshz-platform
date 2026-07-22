import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import { createDrizzlePlatformRepositories, type DrizzleDatabase } from "./repositories.js";
import * as schema from "./schema.js";
import type { PlatformRepositories } from "../platform/repositories.js";

export const DATABASE_MIGRATIONS_CONFIRM_VALUE = "apply-reviewed-migrations";

export type DatabaseConfigErrorCode =
  | "missing_database_url"
  | "missing_database_operator_url"
  | "invalid_database_url"
  | "invalid_database_ssl_mode";

export class DatabaseConfigError extends Error {
  readonly code: DatabaseConfigErrorCode;
  readonly publicMessage = "Database configuration is invalid.";

  constructor(code: DatabaseConfigErrorCode) {
    super(readDatabaseConfigErrorMessage(code));
    this.name = "DatabaseConfigError";
    this.code = code;
  }
}

export interface DatabaseEnvironment {
  NODE_ENV?: string;
  DATABASE_OPERATOR_URL?: string;
  DATABASE_EXPECTED_RUNTIME_ROLE?: string;
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
    throw new DatabaseConfigError("missing_database_url");
  }

  assertValidDatabaseUrl(databaseUrl);
  const sslMode = readDatabaseSslMode(env);

  return {
    databaseUrl,
    ...(sslMode ? { sslMode } : {}),
  };
}

export function assertMigrationExecutionAllowed(env: DatabaseEnvironment): DatabaseConfig {
  const config = readOperatorDatabaseConfig(env);

  if (env.DATABASE_MIGRATIONS_CONFIRM !== DATABASE_MIGRATIONS_CONFIRM_VALUE) {
    throw new Error(
      `DATABASE_MIGRATIONS_CONFIRM must be set to ${DATABASE_MIGRATIONS_CONFIRM_VALUE} to run database migrations.`,
    );
  }

  return config;
}

export function readOperatorDatabaseConfig(
  env: DatabaseEnvironment,
): DatabaseConfig {
  const operatorUrl = env.DATABASE_OPERATOR_URL?.trim();
  if (operatorUrl) {
    return readDatabaseConfig({
      ...env,
      DATABASE_URL: operatorUrl,
    });
  }
  if (env.NODE_ENV?.trim() === "production") {
    throw new DatabaseConfigError("missing_database_operator_url");
  }
  return readDatabaseConfig(env);
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

  throw new DatabaseConfigError("invalid_database_ssl_mode");
}

function assertValidDatabaseUrl(value: string): void {
  try {
    const parsed = new URL(value);
    const supportedProtocol =
      parsed.protocol === "postgres:" || parsed.protocol === "postgresql:";
    const hasHost = Boolean(parsed.hostname);
    const hasDatabaseName = parsed.pathname.length > 1;

    if (!supportedProtocol || !hasHost || !hasDatabaseName) {
      throw new Error("invalid database url");
    }
  } catch {
    throw new DatabaseConfigError("invalid_database_url");
  }
}

function readDatabaseConfigErrorMessage(code: DatabaseConfigErrorCode): string {
  switch (code) {
    case "missing_database_url":
      return "DATABASE_URL is required for database connections.";
    case "missing_database_operator_url":
      return "DATABASE_OPERATOR_URL is required for production operator database connections.";
    case "invalid_database_url":
      return "DATABASE_URL must be a valid Postgres connection string.";
    case "invalid_database_ssl_mode":
      return "DATABASE_SSL_MODE must be either 'disable' or 'require' when set.";
  }
}
