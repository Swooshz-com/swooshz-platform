import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import { createDrizzlePlatformRepositories, type DrizzleDatabase } from "./repositories.js";
import * as schema from "./schema.js";
import type { PlatformRepositories } from "../platform/repositories.js";

export const DATABASE_MIGRATIONS_CONFIRM_VALUE = "apply-reviewed-migrations";

export type DatabaseConfigErrorCode =
  | "missing_database_url"
  | "direct_database_credential_prohibited"
  | "runner_owned_fixture_required"
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
  RUNNER_OWNED_DATABASE_FIXTURE?: string;
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

export interface RunnerOwnedDatabaseFixtureV1 {
  readonly version: "runner-owned-database-fixture-v1";
  readonly owner: "disposable-postgres-runner";
  readonly databaseUrl: string;
}

export function assertRunnerOwnedFixtureMigrationExecutionAllowed(
  env: DatabaseEnvironment,
  fixture: RunnerOwnedDatabaseFixtureV1,
): DatabaseConfig {
  const config = readRunnerOwnedFixtureDatabaseConfig(env, fixture);

  if (env.DATABASE_MIGRATIONS_CONFIRM !== DATABASE_MIGRATIONS_CONFIRM_VALUE) {
    throw new Error(
      `DATABASE_MIGRATIONS_CONFIRM must be set to ${DATABASE_MIGRATIONS_CONFIRM_VALUE} to run database migrations.`,
    );
  }

  return config;
}

export function readRunnerOwnedFixtureDatabaseConfig(
  env: DatabaseEnvironment,
  fixture: RunnerOwnedDatabaseFixtureV1,
): DatabaseConfig {
  if (env.DATABASE_OPERATOR_URL?.trim()) {
    throw new DatabaseConfigError("direct_database_credential_prohibited");
  }
  if (
    env.NODE_ENV !== "test" ||
    env.RUNNER_OWNED_DATABASE_FIXTURE !== "disposable-postgres-runner" ||
    fixture?.version !== "runner-owned-database-fixture-v1" ||
    fixture.owner !== "disposable-postgres-runner"
  ) throw new DatabaseConfigError("runner_owned_fixture_required");
  const config = readDatabaseConfig({ ...env, DATABASE_URL: fixture.databaseUrl });
  const parsed = new URL(config.databaseUrl);
  if (
    !["127.0.0.1", "::1"].includes(parsed.hostname) ||
    !parsed.port ||
    !parsed.username ||
    parsed.pathname.length <= 1
  ) throw new DatabaseConfigError("runner_owned_fixture_required");
  return config;
}

export function createDatabasePool(config: DatabaseConfig): Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    ...(config.sslMode ? { ssl: config.sslMode === "require" } : {}),
    enableChannelBinding: true,
  } as NonNullable<ConstructorParameters<typeof Pool>[0]> & {
    enableChannelBinding: true;
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
    case "direct_database_credential_prohibited":
      return "Direct production database operator credentials are prohibited.";
    case "runner_owned_fixture_required":
      return "A runner-owned disposable database fixture is required.";
    case "invalid_database_url":
      return "DATABASE_URL must be a valid Postgres connection string.";
    case "invalid_database_ssl_mode":
      return "DATABASE_SSL_MODE must be either 'disable' or 'require' when set.";
  }
}
