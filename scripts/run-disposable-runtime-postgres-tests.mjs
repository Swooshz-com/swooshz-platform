import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";

import { Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresConstructionTargets,
  admitDisposablePostgresFixtures,
  createAuthorizedProvisioningPool,
  deriveDisposablePostgresProvisioningAuthority,
  invalidateDisposablePostgresAdmission,
} from "../tests/support/disposable-postgres-fixture.mjs";
import { runDisposableRuntimeLifecycle } from "./disposable-runtime-lifecycle.mjs";

const databaseName = "runtime_posture_test";
const secondaryDatabaseName = "runtime_posture_test_secondary";
const ownedContainerName = "codex-platform127-pg17";
const ownedPort = 55432;
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
  let resources = null;

  return runDisposableRuntimeLifecycle({
    construct: async (lifecycleResources) => {
      resources = lifecycleResources;
      Object.assign(resources, {
        containerStartAttempted: false,
        ownedContainer: false,
        containerRemoved: false,
        childProcess: null,
        childExited: true,
        databaseUrls: new Map(),
        ownedDatabases: new Set(),
        ownedRoles: new Set(["platform_app", "platform_runtime"]),
        ownedSchemas: new Set(["drizzle"]),
        ownedObjects: new Set([
          "drizzle.__drizzle_migrations",
          "public.users",
          ...contractTableNames().map((name) => `public.${name}`),
        ]),
        runnerOwned: new Set(),
        callerManaged: new Set([
          "docker daemon",
          "postgres default database",
        ]),
      });
      assertNoCallerSuppliedFixture(env);
      await assertExactContainerAbsent(spawnImpl);
      resources.containerStartAttempted = true;
      await startOwnedContainer(spawnImpl);
      resources.ownedContainer = true;
      resources.runnerOwned.add(`container:${ownedContainerName}`);
      resources.runnerOwned.add(`listener:127.0.0.1:${ownedPort}`);

      const urls = fixtureUrls();
      resources.databaseUrls = new Map([
        [databaseName, urls.primaryOperatorUrl],
        [secondaryDatabaseName, urls.secondaryOperatorUrl],
      ]);
      resources.ownedDatabases.add(databaseName);

      await waitForPostgres(urls.primaryOperatorUrl);
      await ensureDatabase(
        urls.primaryOperatorUrl,
        secondaryDatabaseName,
        resources,
      );
      return urls;
    },

    admitConstruction: async (urls) =>
      admitDisposablePostgresConstructionTargets([
        constructionTargetDefinition("primary", urls.primaryOperatorUrl),
        constructionTargetDefinition("secondary", urls.secondaryOperatorUrl),
      ]),

    deriveProvisioning: async (constructionAuthority) => {
      const authorities = new Map();
      for (const targetName of ["primary", "secondary"]) {
        authorities.set(
          targetName,
          deriveDisposablePostgresProvisioningAuthority(
            constructionAuthority,
            targetName,
          ),
        );
      }
      return authorities;
    },

    provision: async (authorities, urls, lifecycleResources) => {
      await provisionFixture(
        urls.primaryOperatorUrl,
        databaseName,
        authorities.get("primary"),
        lifecycleResources,
      );
      await provisionFixture(
        urls.secondaryOperatorUrl,
        secondaryDatabaseName,
        authorities.get("secondary"),
        lifecycleResources,
      );
    },

    admitConfigured: async (urls) =>
      admitDisposablePostgresFixtures([
        fixtureDefinition("primary", urls),
        fixtureDefinition("secondary", urls),
      ]),

    runFocusedTests: async (admission, lifecycleResources) =>
      runFocusedTests({
        admission,
        urls: lifecycleResources.construction,
        spawnImpl,
        resources: lifecycleResources,
      }),

    cleanup: async (lifecycleResources) =>
      cleanupRunnerResources(lifecycleResources, spawnImpl),

    verifyAbsence: async (lifecycleResources) =>
      verifyRunnerAbsence(lifecycleResources, spawnImpl),
  });
}

function fixtureUrls() {
  return {
    primaryTargetUrl: buildUrl("platform_app", databaseName),
    primaryOperatorUrl: buildUrl("postgres", databaseName),
    secondaryTargetUrl: buildUrl("platform_app", secondaryDatabaseName),
    secondaryOperatorUrl: buildUrl("postgres", secondaryDatabaseName),
  };
}

function buildUrl(user, database) {
  if (!safeIdentifier.test(user) || !safeIdentifier.test(database)) {
    throw new Error();
  }
  return `postgres://${user}@127.0.0.1:${ownedPort}/${database}`;
}

function constructionTargetDefinition(name, connectionString) {
  const expectedDatabase = name === "primary"
    ? databaseName
    : secondaryDatabaseName;
  return {
    name,
    connectionString,
    expectedDatabase,
    expectedUser: "postgres",
    phase: "initialization",
    transport: { kind: "loopback", phase: "initialization" },
  };
}

function fixtureDefinition(name, urls) {
  const secondary = name === "secondary";
  return {
    name,
    connectionString: secondary ? urls.secondaryTargetUrl : urls.primaryTargetUrl,
    expectedDatabase: secondary ? secondaryDatabaseName : databaseName,
    expectedUser: "platform_app",
    expectedRuntimeRole: "platform_runtime",
    expectedMutationUser: "postgres",
    operatorUrl: secondary ? urls.secondaryOperatorUrl : urls.primaryOperatorUrl,
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
    operatorTransport: { kind: "loopback", phase: "final_start" },
  };
}

async function ensureDatabase(operatorUrl, expectedDatabase, resources) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  try {
    const result = await operatorPool.query(
      "select 1 from pg_database where datname = $1",
      [expectedDatabase],
    );
    if (result.rows.length === 0) {
      await operatorPool.query(`create database ${quoteIdentifier(expectedDatabase)}`);
      resources.ownedDatabases.add(expectedDatabase);
      resources.runnerOwned.add(`database:${expectedDatabase}`);
    } else {
      throw new Error();
    }
  } finally {
    await operatorPool.end();
  }
}

async function provisionFixture(operatorUrl, expectedDatabase, authority, resources) {
  const operatorPool = new Pool({ connectionString: operatorUrl, max: 1 });
  const authorizedPool = createAuthorizedProvisioningPool(operatorPool, authority);
  try {
    await authorizedPool.query(`
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
    await authorizedPool.query(
      "alter role platform_app login nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query(
      "alter role platform_runtime nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls",
    );
    await authorizedPool.query("revoke platform_runtime from platform_app");
    await authorizedPool.query("revoke platform_app from platform_runtime");
    await authorizedPool.query("alter schema public owner to postgres");
    await authorizedPool.query(
      "create schema if not exists drizzle authorization postgres",
    );
    await authorizedPool.query("alter schema drizzle owner to postgres");
    await authorizedPool.query(
      "create table if not exists drizzle.__drizzle_migrations (id integer primary key)",
    );
    await authorizedPool.query(
      "alter table drizzle.__drizzle_migrations owner to postgres",
    );
    await authorizedPool.query(
      `grant connect on database ${quoteIdentifier(expectedDatabase)} to platform_app`,
    );
    await authorizedPool.query(
      `revoke create on database ${quoteIdentifier(expectedDatabase)} from public`,
    );
    await authorizedPool.query("revoke create on schema public from public");
    await authorizedPool.query("revoke create on schema drizzle from public");
    await authorizedPool.query("revoke usage on schema drizzle from public");
    await authorizedPool.query("grant usage on schema public to platform_app");
    await authorizedPool.query(
      "alter default privileges for role postgres revoke execute on functions from public",
    );

    for (const tableName of contractTableNames()) {
      await authorizedPool.query(
        `create table if not exists public.${quoteIdentifier(tableName)} (id integer)`,
      );
      await authorizedPool.query(
        `alter table public.${quoteIdentifier(tableName)} owner to postgres`,
      );
      await authorizedPool.query(
        `revoke all privileges on table public.${quoteIdentifier(tableName)} from platform_runtime`,
      );
    }
    await authorizedPool.query(
      "create table if not exists public.users (id integer)",
    );
    await authorizedPool.query("alter table public.users owner to postgres");
    for (const [tableName, privileges] of privilegesByTable()) {
      await authorizedPool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await authorizedPool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await authorizedPool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
    resources.runnerOwned.add(`role:platform_app:${expectedDatabase}`);
    resources.runnerOwned.add(`role:platform_runtime:${expectedDatabase}`);
    resources.runnerOwned.add(`schema:drizzle:${expectedDatabase}`);
    for (const object of resources.ownedObjects) {
      resources.runnerOwned.add(`${object}:${expectedDatabase}`);
    }
  } finally {
    await authorizedPool.end();
  }
}

async function runFocusedTests({ admission, urls, spawnImpl, resources }) {
  const env = {
    ...process.env,
    RUNTIME_POSTURE_TEST_DATABASE_URL: urls.primaryTargetUrl,
    RUNTIME_POSTURE_TEST_OPERATOR_URL: urls.primaryOperatorUrl,
    RUNTIME_POSTURE_TEST_SECONDARY_DATABASE_URL: urls.secondaryTargetUrl,
    RUNTIME_POSTURE_TEST_SECONDARY_OPERATOR_URL: urls.secondaryOperatorUrl,
    RUNTIME_POSTURE_TEST_CONFIRM: "disposable-only",
  };
  await new Promise((resolvePromise, reject) => {
    const output = [];
    let outputLength = 0;
    let outputOverflow = false;
    const child = spawnImpl(
      process.execPath,
      [
        "--test",
        "tests/disposable-postgres-fixture.test.mjs",
        "tests/disposable-runtime-lifecycle.test.mjs",
        "tests/runtime-database-posture-postgres.test.mjs",
      ],
      { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
    );
    resources.childProcess = child;
    resources.childExited = false;
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= 64 * 1024) {
        output.push(Buffer.from(chunk));
      } else {
        outputOverflow = true;
      }
    });
    child.stderr?.resume();
    child.once("error", () => reject(new Error()));
    child.once("close", (code, signal) => {
      resources.childExited = true;
      if (code === 0 && signal === null && !outputOverflow) {
        const summary = Buffer.concat(output).toString("utf8");
        const match = summary.match(
          /ℹ tests (\d+)[\s\S]*?ℹ pass (\d+)[\s\S]*?ℹ skipped (\d+)/u,
        );
        if (!match) {
          reject(new Error());
          return;
        }
        process.stdout.write(
          `Disposable PostgreSQL 17 tests: ${match[1]} total, ${match[2]} passed, ${match[3]} skipped.\n`,
        );
        resolvePromise();
      } else {
        reject(new Error());
      }
    });
  });
  void admission;
}

async function cleanupRunnerResources(resources, spawnImpl) {
  let firstError = null;
  try {
    if (resources.configuredAdmission) {
      invalidateDisposablePostgresAdmission(resources.configuredAdmission);
    }
  } catch {
    firstError ??= new Error();
  }
  try {
    await terminateOwnedChild(resources);
  } catch {
    firstError ??= new Error();
  }
  try {
    await cleanupFixtureDatabases(resources);
  } catch {
    firstError ??= new Error();
  }
  if (resources.containerStartAttempted) {
    try {
      await runCommand(spawnImpl, "docker", [
        "rm",
        "--force",
        ownedContainerName,
      ]);
      resources.containerRemoved = true;
    } catch {
      firstError ??= new Error();
    }
  }
  if (firstError) throw firstError;
}

async function cleanupFixtureDatabases(resources) {
  if (!resources.ownedContainer || resources.ownedDatabases.size === 0) {
    return;
  }
  const rootUrl = buildUrl("postgres", "postgres");
  for (const database of resources.ownedDatabases) {
    const pool = new Pool({ connectionString: buildUrl("postgres", database), max: 1 });
    try {
      for (const tableName of ["users", ...contractTableNames()]) {
        await pool.query(
          `drop table if exists public.${quoteIdentifier(tableName)} cascade`,
        );
      }
      await pool.query("drop schema if exists drizzle cascade");
    } finally {
      await pool.end();
    }
  }
  const rootPool = new Pool({ connectionString: rootUrl, max: 1 });
  try {
    for (const database of resources.ownedDatabases) {
      await rootPool.query(
        `drop database if exists ${quoteIdentifier(database)} with (force)`,
      );
    }
    const roleResult = await rootPool.query(
      "select rolname from pg_roles where rolname <> 'postgres' and rolname not like 'pg_%'",
    );
    const roleNames = new Set(resources.ownedRoles);
    for (const row of roleResult.rows) {
      if (typeof row.rolname !== "string" || !safeIdentifier.test(row.rolname)) {
        throw new Error();
      }
      roleNames.add(row.rolname);
    }
    for (const roleName of roleNames) {
      await rootPool.query(`drop role if exists ${quoteIdentifier(roleName)}`);
    }
  } finally {
    await rootPool.end();
  }
}

async function verifyRunnerAbsence(resources, spawnImpl) {
  if (resources.childProcess && !resources.childExited) throw new Error();
  if (!resources.containerStartAttempted) return;
  const names = await assertExactContainerAbsent(spawnImpl);
  if (names !== "") throw new Error();
  if (!resources.containerRemoved) throw new Error();
  await assertPortAbsent();
}

async function terminateOwnedChild(resources) {
  const child = resources.childProcess;
  if (!child || resources.childExited) return;
  if (typeof child.kill !== "function" || !child.kill("SIGTERM")) {
    throw new Error();
  }
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error()), 2_000);
    child.once("close", () => {
      clearTimeout(timer);
      resources.childExited = true;
      resolvePromise();
    });
  });
}

async function startOwnedContainer(spawnImpl) {
  await runCommand(spawnImpl, "docker", [
    "run",
    "--detach",
    "--name",
    ownedContainerName,
    "--publish",
    `${ownedPort}:5432`,
    "--env",
    "POSTGRES_DB=runtime_posture_test",
    "--env",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "postgres:17",
  ]);
}

async function waitForPostgres(connectionString) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
    try {
      await pool.query("select 1");
      return;
    } catch {
      await delay(500);
    } finally {
      await pool.end();
    }
  }
  throw new Error();
}

async function assertExactContainerAbsent(spawnImpl) {
  const output = await runCommand(spawnImpl, "docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${ownedContainerName}$`,
    "--format",
    "{{.Names}}",
  ]);
  return output.trim();
}

async function assertPortAbsent() {
  await new Promise((resolvePromise, reject) => {
    const socket = net.createConnection({
      host: "127.0.0.1",
      port: ownedPort,
    });
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
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) {
        finish();
      } else {
        finish(new Error());
      }
    });
  });
}

async function runCommand(spawnImpl, command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawnImpl(command, args, {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    const output = [];
    let outputLength = 0;
    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      reject(new Error());
    };
    child.once("error", fail);
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      if (code !== 0 || signal !== null || outputLength > 1_024) {
        reject(new Error());
        return;
      }
      resolvePromise(Buffer.concat(output).toString("utf8"));
    });
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= 1_024) output.push(Buffer.from(chunk));
    });
  });
}

function assertNoCallerSuppliedFixture(env) {
  const names = [
    "RUNTIME_POSTURE_TEST_DATABASE_URL",
    "RUNTIME_POSTURE_TEST_OPERATOR_URL",
    "RUNTIME_POSTURE_TEST_SECONDARY_DATABASE_URL",
    "RUNTIME_POSTURE_TEST_SECONDARY_OPERATOR_URL",
  ];
  if (names.some((name) => typeof env?.[name] === "string" && env[name])) {
    throw new Error();
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

function quoteIdentifier(value) {
  if (!safeIdentifier.test(value)) throw new Error();
  return `"${value.replaceAll('"', '""')}"`;
}
