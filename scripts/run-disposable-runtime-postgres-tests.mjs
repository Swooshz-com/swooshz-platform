import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresFixtures,
  parseDisposablePostgresUrl,
} from "../tests/support/disposable-postgres-fixture.mjs";

const databaseName = "runtime_posture_test";
const secondaryDatabaseName = "runtime_posture_test_secondary";
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;
const loopbackHosts = new Set(["127.0.0.1", "::1"]);

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  run().catch(() => {
    process.stderr.write("Disposable fixture test runner failed.\n");
    process.exitCode = 1;
  });
}

export async function run({
  env = process.env,
  spawnImpl = spawn,
} = {}) {
  const primaryTargetUrl = requiredEnv(env, "RUNTIME_POSTURE_TEST_DATABASE_URL");
  const primaryOperatorUrl = requiredEnv(
    env,
    "RUNTIME_POSTURE_TEST_OPERATOR_URL",
  );
  const secondaryTargetUrl =
    env.RUNTIME_POSTURE_TEST_SECONDARY_DATABASE_URL ??
    replaceDatabase(primaryTargetUrl, secondaryDatabaseName);
  const secondaryOperatorUrl =
    env.RUNTIME_POSTURE_TEST_SECONDARY_OPERATOR_URL ??
    replaceDatabase(primaryOperatorUrl, secondaryDatabaseName);

  assertLoopbackUrl(primaryTargetUrl, "platform_app", databaseName);
  assertLoopbackUrl(primaryOperatorUrl, "postgres", databaseName);
  assertLoopbackUrl(secondaryTargetUrl, "platform_app", secondaryDatabaseName);
  assertLoopbackUrl(secondaryOperatorUrl, "postgres", secondaryDatabaseName);
  parseDisposablePostgresUrl(primaryTargetUrl, {
    expectedDatabase: databaseName,
    expectedUser: "platform_app",
    phase: "final_start",
    transport: { kind: "loopback", phase: "final_start" },
  });
  parseDisposablePostgresUrl(secondaryTargetUrl, {
    expectedDatabase: secondaryDatabaseName,
    expectedUser: "platform_app",
    phase: "final_start",
    transport: { kind: "loopback", phase: "final_start" },
  });

  await ensureDatabase(primaryOperatorUrl, secondaryDatabaseName);
  await provisionFixture(primaryOperatorUrl, databaseName);
  await provisionFixture(secondaryOperatorUrl, secondaryDatabaseName);

  await admitDisposablePostgresFixtures([
    fixtureDefinition("primary", primaryTargetUrl, databaseName),
    fixtureDefinition("secondary", secondaryTargetUrl, secondaryDatabaseName),
  ]);

  await runFocusedTests({
    env: {
      ...env,
      RUNTIME_POSTURE_TEST_DATABASE_URL: primaryTargetUrl,
      RUNTIME_POSTURE_TEST_OPERATOR_URL: primaryOperatorUrl,
      RUNTIME_POSTURE_TEST_CONFIRM: "disposable-only",
    },
    spawnImpl,
  });
}

function fixtureDefinition(name, connectionString, expectedDatabase) {
  return {
    name,
    connectionString,
    expectedDatabase,
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
    transport: { kind: "loopback", phase: "final_start" },
  };
}

async function ensureDatabase(operatorUrl, expectedDatabase) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    const result = await operatorPool.query(
      "select 1 from pg_database where datname = $1",
      [expectedDatabase],
    );
    if (result.rows.length === 0) {
      await operatorPool.query(`create database ${quoteIdentifier(expectedDatabase)}`);
    }
  } finally {
    await operatorPool.end();
  }
}

async function provisionFixture(operatorUrl, expectedDatabase) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    await operatorPool.query(`
      do $fixture$
      begin
        if not exists (select 1 from pg_roles where rolname = 'platform_app') then
          create role platform_app login nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
        if not exists (select 1 from pg_roles where rolname = 'platform_runtime') then
          create role platform_runtime nologin nosuperuser nocreatedb nocreaterole
            noreplication nobypassrls;
        end if;
      end
      $fixture$
    `);
    await operatorPool.query(
      "alter role platform_app login nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await operatorPool.query(
      "alter role platform_runtime nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await operatorPool.query(
      "revoke platform_runtime from platform_app",
    );
    await operatorPool.query(
      "revoke platform_app from platform_runtime",
    );
    await operatorPool.query(
      "alter schema public owner to postgres",
    );
    await operatorPool.query(
      "create schema if not exists drizzle authorization postgres",
    );
    await operatorPool.query("alter schema drizzle owner to postgres");
    await operatorPool.query(
      "create table if not exists drizzle.__drizzle_migrations (id integer primary key)",
    );
    await operatorPool.query(
      "alter table drizzle.__drizzle_migrations owner to postgres",
    );
    await operatorPool.query(
      `grant connect on database ${quoteIdentifier(expectedDatabase)} to platform_app`,
    );
    await operatorPool.query(
      `revoke create on database ${quoteIdentifier(expectedDatabase)} from public`,
    );
    await operatorPool.query(
      "revoke create on schema public from public",
    );
    await operatorPool.query(
      "revoke create on schema drizzle from public",
    );
    await operatorPool.query(
      "revoke usage on schema drizzle from public",
    );
    await operatorPool.query(
      "grant usage on schema public to platform_app",
    );
    await operatorPool.query(
      "alter default privileges for role postgres revoke execute on functions from public",
    );

    for (const tableName of contractTableNames()) {
      await operatorPool.query(
        `create table if not exists public.${quoteIdentifier(tableName)} (id integer)`,
      );
      await operatorPool.query(
        `alter table public.${quoteIdentifier(tableName)} owner to postgres`,
      );
      await operatorPool.query(
        `revoke all privileges on table public.${quoteIdentifier(tableName)} from platform_runtime`,
      );
    }
    for (const [tableName, privileges] of privilegesByTable()) {
      await operatorPool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await operatorPool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await operatorPool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
  } finally {
    await operatorPool.end();
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

async function runFocusedTests({ env, spawnImpl }) {
  await new Promise((resolve, reject) => {
    const child = spawnImpl(
      process.execPath,
      [
        "--test",
        "tests/disposable-postgres-fixture.test.mjs",
        "tests/runtime-database-posture-postgres.test.mjs",
      ],
      {
        env,
        stdio: "inherit",
        windowsHide: true,
      },
    );
    child.once("error", () => reject(new Error()));
    child.once("close", (code, signal) => {
      if (code === 0 && signal === null) {
        resolve();
      } else {
        reject(new Error());
      }
    });
  });
}

function assertLoopbackUrl(connectionString, expectedUser, expectedDatabase) {
  try {
    const parsed = new URL(connectionString);
    if (
      !["postgres:", "postgresql:"].includes(parsed.protocol) ||
      parsed.username !== expectedUser ||
      parsed.password ||
      parsed.hostname === "localhost" ||
      !loopbackHosts.has(parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase()) ||
      parsed.pathname !== `/${expectedDatabase}` ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error();
    }
  } catch {
    throw new Error();
  }
}

function replaceDatabase(connectionString, database) {
  if (!safeIdentifier.test(database)) {
    throw new Error();
  }
  const parsed = new URL(connectionString);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

function requiredEnv(env, name) {
  const value = env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error();
  }
  return value;
}

function quoteIdentifier(value) {
  if (!safeIdentifier.test(value)) {
    throw new Error();
  }
  return `"${value.replaceAll('"', '""')}"`;
}
