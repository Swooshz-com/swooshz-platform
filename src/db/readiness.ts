import {
  createDatabasePool,
  DatabaseConfigError,
  readOperatorDatabaseConfig,
  type DatabaseConfig,
  type DatabaseEnvironment,
} from "./client.js";

export const REQUIRED_PLATFORM_TABLES = [
  "users",
  "provider_identities",
  "workspaces",
  "memberships",
  "workspace_membership_approvals",
  "invitations",
  "sessions",
  "csrf_tokens",
  "auth_states",
  "audit_events",
  "apps",
  "app_launch_tokens",
  "app_entitlements",
  "access_validation_grants",
] as const;

export type DatabaseReadinessStatus =
  | "db_config_missing"
  | "db_config_invalid"
  | "db_unreachable"
  | "schema_not_ready"
  | "ready";

export type DatabaseReadinessCheckState =
  | "missing"
  | "invalid"
  | "present"
  | "not_checked"
  | "passed"
  | "failed";

export interface ExpectedMigrationState {
  latestTag: string;
  latestCreatedAt: number;
  migrationCount: number;
}

export interface DatabaseReadinessChecks {
  config: DatabaseReadinessCheckState;
  reachability: DatabaseReadinessCheckState;
  schema: DatabaseReadinessCheckState;
  migrations: DatabaseReadinessCheckState;
}

export interface DatabaseReadinessReport {
  ok: boolean;
  status: DatabaseReadinessStatus;
  checks: DatabaseReadinessChecks;
  requiredTables: readonly string[];
  missingTables: string[];
  expectedMigrationState?: ExpectedMigrationState;
}

export interface DatabaseReadinessQueryResult {
  rows: Array<Record<string, unknown>>;
}

export interface DatabaseReadinessClient {
  query(
    text: string,
    values?: readonly unknown[],
  ): Promise<DatabaseReadinessQueryResult>;
  end?(): Promise<void> | void;
}

export interface DatabaseReadinessInput {
  env: DatabaseEnvironment;
  expectedMigrationState?: ExpectedMigrationState;
  requiredTables?: readonly string[];
  clientFactory?: (
    config: DatabaseConfig,
  ) => DatabaseReadinessClient | Promise<DatabaseReadinessClient>;
}

const reachabilitySql = "select 1 as readiness_ok";
const requiredTablesSql = `
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name = any($1::text[])
`;
const migrationStateSql = `
select count(*)::int as applied_count, max(created_at)::bigint as latest_created_at
from drizzle.__drizzle_migrations
`;

export async function createDatabaseReadinessReport(
  input: DatabaseReadinessInput,
): Promise<DatabaseReadinessReport> {
  const requiredTables = input.requiredTables ?? REQUIRED_PLATFORM_TABLES;
  const checks: DatabaseReadinessChecks = {
    config: "not_checked",
    reachability: "not_checked",
    schema: "not_checked",
    migrations: "not_checked",
  };
  let config: DatabaseConfig;
  let client: DatabaseReadinessClient | null = null;

  try {
    config = readOperatorDatabaseConfig(input.env);
    checks.config = "present";
  } catch (error) {
    checks.config = readConfigFailureState(error);
    return report({
      status: checks.config === "missing" ? "db_config_missing" : "db_config_invalid",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  }

  try {
    const clientFactory = input.clientFactory ?? createDatabaseReadinessClient;
    client = await clientFactory(config);
    await client.query(reachabilitySql);
    checks.reachability = "passed";
  } catch {
    checks.reachability = "failed";
    return report({
      status: "db_unreachable",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } finally {
    if (checks.reachability === "failed") {
      await closeClientQuietly(client);
    }
  }

  let missingTables: string[] | undefined;

  try {
    missingTables = await readMissingRequiredTables(client, requiredTables);
    checks.schema = missingTables.length === 0 ? "passed" : "failed";

    const migrationReady = await readMigrationReadiness(
      client,
      input.expectedMigrationState,
    );

    checks.migrations = migrationReady ? "passed" : "failed";

    if (checks.schema !== "passed" || checks.migrations !== "passed") {
      return report({
        status: "schema_not_ready",
        checks,
        requiredTables,
        missingTables,
        expectedMigrationState: input.expectedMigrationState,
      });
    }

    return report({
      status: "ready",
      checks,
      requiredTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } catch {
    checks.schema =
      typeof missingTables === "undefined"
        ? "failed"
        : missingTables.length === 0
          ? "passed"
          : "failed";
    checks.migrations =
      input.expectedMigrationState && checks.migrations === "not_checked"
        ? "failed"
        : checks.migrations;
    return report({
      status: "schema_not_ready",
      checks,
      requiredTables,
      missingTables,
      expectedMigrationState: input.expectedMigrationState,
    });
  } finally {
    await closeClientQuietly(client);
  }
}

export function createDatabaseReadinessClient(
  config: DatabaseConfig,
): DatabaseReadinessClient {
  const pool = createDatabasePool(config);

  return {
    query(text, values) {
      return values ? pool.query(text, [...values]) : pool.query(text);
    },
    end() {
      return pool.end();
    },
  };
}

export function formatDatabaseReadinessReport(
  readinessReport: DatabaseReadinessReport,
): string[] {
  const lines = [
    `Swooshz Platform database readiness_check=${readinessReport.ok ? "pass" : "fail"}`,
    `status=${readinessReport.status}`,
    `database_config=${readinessReport.checks.config}`,
    `database_reachability=${readinessReport.checks.reachability}`,
    `schema_state=${readinessReport.checks.schema}`,
  ];

  if (shouldReportRequiredTables(readinessReport)) {
    lines.push(
      `required_tables_present=${
        readinessReport.requiredTables.length - readinessReport.missingTables.length
      }/${readinessReport.requiredTables.length}`,
    );
  }

  if (readinessReport.missingTables.length > 0) {
    lines.push(`missing_tables=${readinessReport.missingTables.join(",")}`);
  }

  if (readinessReport.expectedMigrationState) {
    lines.push(`migration_state=${formatMigrationState(readinessReport)}`);
    lines.push(
      `expected_latest_migration=${readinessReport.expectedMigrationState.latestTag}`,
    );
  }

  return lines;
}

function shouldReportRequiredTables(
  readinessReport: DatabaseReadinessReport,
): boolean {
  if (readinessReport.requiredTables.length === 0) {
    return false;
  }

  return (
    readinessReport.checks.schema === "passed" ||
    readinessReport.missingTables.length > 0
  );
}

async function readMissingRequiredTables(
  client: DatabaseReadinessClient,
  requiredTables: readonly string[],
): Promise<string[]> {
  const result = await client.query(requiredTablesSql, [requiredTables]);
  const existingTables = new Set(
    result.rows
      .map((row) => row.table_name)
      .filter((value): value is string => typeof value === "string"),
  );

  return requiredTables.filter((tableName) => !existingTables.has(tableName));
}

async function readMigrationReadiness(
  client: DatabaseReadinessClient,
  expectedMigrationState: ExpectedMigrationState | undefined,
): Promise<boolean> {
  if (!expectedMigrationState) {
    return true;
  }

  const result = await client.query(migrationStateSql);
  const row = result.rows[0] ?? {};
  const appliedCount = Number(row.applied_count ?? 0);
  const latestCreatedAt = Number(row.latest_created_at ?? 0);

  return (
    Number.isFinite(appliedCount) &&
    Number.isFinite(latestCreatedAt) &&
    appliedCount >= expectedMigrationState.migrationCount &&
    latestCreatedAt >= expectedMigrationState.latestCreatedAt
  );
}

function readConfigFailureState(error: unknown): "missing" | "invalid" {
  if (
    error instanceof DatabaseConfigError &&
    ["missing_database_url", "missing_database_operator_url"].includes(error.code)
  ) {
    return "missing";
  }

  return "invalid";
}

function formatMigrationState(readinessReport: DatabaseReadinessReport): string {
  if (readinessReport.checks.migrations === "passed") {
    return "ready";
  }

  if (readinessReport.checks.migrations === "failed") {
    return "behind";
  }

  return "not_checked";
}

function report({
  status,
  checks,
  requiredTables,
  missingTables = [],
  expectedMigrationState,
}: {
  status: DatabaseReadinessStatus;
  checks: DatabaseReadinessChecks;
  requiredTables: readonly string[];
  missingTables?: string[];
  expectedMigrationState?: ExpectedMigrationState;
}): DatabaseReadinessReport {
  return {
    ok: status === "ready",
    status,
    checks: { ...checks },
    requiredTables,
    missingTables,
    ...(expectedMigrationState ? { expectedMigrationState } : {}),
  };
}

async function closeClientQuietly(
  client: DatabaseReadinessClient | null,
): Promise<void> {
  try {
    await client?.end?.();
  } catch {
    // Readiness output stays category-only; close errors may include connection details.
  }
}
