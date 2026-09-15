#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client, Pool } from "pg";

import {
  RUNTIME_TABLE_GRANT_CONTRACT,
} from "../dist/db/runtime-grant-contract.js";
import {
  admitDisposablePostgresFixtures,
  invalidateDisposablePostgresAdmission,
} from "../tests/support/disposable-postgres-fixture.mjs";
import {
  executeDisposableCleanupActions,
} from "./run-disposable-runtime-postgres-tests.mjs";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const databaseName = "runtime_posture_test";
const networkAlias =
  "ep-disposable-primary-001-pooler.us-east-2.aws.neon.tech";
const ownedNetworks = Object.freeze([
  "codex-platform169-activation-primary-net",
  "codex-platform169-activation-secondary-net",
]);
const ownedContainers = Object.freeze([
  "codex-platform169-activation-primary-pg17",
  "codex-platform169-activation-secondary-pg17",
]);
const expectedMigrationTags = Object.freeze([
  "0000_overconfident_onslaught",
  "0001_lovely_famine",
  "0002_futuristic_aaron_stack",
  "0003_worthless_scourge",
  "0004_illegal_william_stryker",
  "0005_sqag_app_key_migration",
  "0006_optimal_tomorrow_man",
  "0007_remove_legacy_kqag_tables",
  "0009_wonderful_star_brand",
]);
const excludedMigrationTag =
  "0010_admin_operator_viewer_role_collapse";
const identitiesSql = fileURLToPath(
  new URL("../tests/support/runtime-postgres-identities.sql", import.meta.url),
);
const expectedTestCount = 45;
const maxChildOutputBytes = 64 * 1024;
const maxDiagnosticBytes = 4_000;
const maxChildDurationMs = 180_000;

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  run().catch((error) => {
    process.stderr.write("Disposable activation PostgreSQL 17 runner failed.\n");
    const diagnostics = typeof error?.diagnostics === "string"
      ? error.diagnostics
      : "";
    if (diagnostics) process.stderr.write(`${diagnostics}\n`);
    process.exitCode = 1;
  });
}

export async function run({
  env = process.env,
  spawnImpl = spawn,
  assertPortAbsentImpl = assertPortAbsent,
} = {}) {
  assertNoCallerSuppliedActivationInputs(env);
  await access(identitiesSql);

  const operatorPasswordBuffer = randomBytes(32);
  const runtimePasswordBuffer = randomBytes(32);
  const resources = {
    admission: null,
    child: null,
    childExited: true,
    childEnvironment: null,
    containerStartAttempted: new Set(),
    networksCreated: new Set(),
    migrationPrefix: null,
    operatorPassword: `Operator_A1!${operatorPasswordBuffer.toString("base64url")}`,
    operatorPasswordBuffer,
    ports: [null, null],
    runtimePassword: `Runtime_A1!${runtimePasswordBuffer.toString("base64url")}`,
    runtimePasswordBuffer,
  };
  let bodyError = null;
  let summary = null;

  try {
    await assertExactDockerResourcesAbsent();
    resources.migrationPrefix = await createActivationMigrationPrefix();

    for (const networkName of ownedNetworks) {
      await requireSuccessfulCommand(
        spawnImpl,
        "docker",
        ownedNetworkCreateArguments(networkName),
      );
      resources.networksCreated.add(networkName);
    }

    for (let index = 0; index < ownedContainers.length; index += 1) {
      const childEnvironment = {
        ...env,
        POSTGRES_PASSWORD: resources.operatorPassword,
      };
      resources.containerStartAttempted.add(ownedContainers[index]);
      let result;
      try {
        result = await requireSuccessfulCommand(
          spawnImpl,
          "docker",
          ownedContainerDockerArguments(
            ownedContainers[index],
            ownedNetworks[index],
          ),
          { env: childEnvironment },
        );
      } finally {
        delete childEnvironment.POSTGRES_PASSWORD;
      }
      if (!result.stdout.trim()) throw new Error();
    }

    for (let index = 0; index < ownedContainers.length; index += 1) {
      resources.ports[index] = await assertOwnedDockerTopology(
        spawnImpl,
        ownedContainers[index],
        ownedNetworks[index],
      );
    }
    if (resources.ports[0] === resources.ports[1]) throw new Error();

    const operatorUrls = resources.ports.map((port) =>
      buildLoopbackUrl("platform_app", port));
    await Promise.all(operatorUrls.map((url) =>
      waitForPostgres(url, resources.operatorPassword)));
    await Promise.all(operatorUrls.map((url) => provisionFixture(
      url,
      resources.operatorPassword,
      resources.migrationPrefix.migrationsFolder,
    )));
    const systemIdentifiers = await Promise.all(
      operatorUrls.map((url) =>
        assertFixtureIdentity(url, resources.operatorPassword)),
    );
    if (systemIdentifiers[0] === systemIdentifiers[1]) throw new Error();

    resources.admission = await admitDisposablePostgresFixtures(
      operatorUrls.map((connectionString, index) => ({
        name: index === 0 ? "primary" : "secondary",
        connectionString,
        expectedDatabase: databaseName,
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
        transport: { kind: "loopback", phase: "initialization" },
      })),
      {
        clientFactory: async (target) => {
          const client = new Client({
            connectionString: target.connectionString,
            password: resources.operatorPassword,
          });
          await client.connect();
          return {
            query: (...args) => client.query(...args),
            end: () => client.end(),
          };
        },
      },
    );

    summary = await runActivationChild(
      spawnImpl,
      resources,
      operatorUrls,
    );
  } catch (error) {
    bodyError = error instanceof Error ? error : new Error();
  }

  await executeDisposableCleanupActions([
    () => terminateChild(resources),
    async () => {
      if (resources.admission) {
        invalidateDisposablePostgresAdmission(resources.admission);
        resources.admission = null;
      }
    },
    ...ownedContainers.map((containerName) => async () => {
      if (resources.containerStartAttempted.has(containerName)) {
        await removeOwnedContainer(spawnImpl, containerName);
      }
    }),
    ...ownedNetworks.map((networkName) => async () => {
      if (resources.networksCreated.has(networkName)) {
        await removeOwnedNetwork(spawnImpl, networkName);
      }
    }),
    async () => {
      if (resources.migrationPrefix?.temporaryRoot) {
        const temporaryRoot = resources.migrationPrefix.temporaryRoot;
        await rm(temporaryRoot, {
          recursive: true,
          force: true,
        });
        await assertPathAbsent(temporaryRoot);
        resources.migrationPrefix = null;
      }
    },
    async () => clearCredentialState(resources),
    () => assertExactDockerResourcesAbsent(),
    ...resources.ports.map((port) => async () => {
      if (Number.isInteger(port)) await assertPortAbsentImpl(port);
    }),
  ], bodyError);

  if (!summary) throw new Error();
  process.stdout.write(
    `Activation PostgreSQL 17 tests: ${summary.total} total / ` +
      `${summary.passed} passed / ${summary.failed} failed / ` +
      `${summary.skipped} skipped / ${summary.cancelled} cancelled / ` +
      `${summary.todo} todo.\n`,
  );
  return summary;
}

export function assertNoCallerSuppliedActivationInputs(env) {
  if (!env || typeof env !== "object") throw new Error();
  if (
    Object.keys(env).some((name) =>
      name.startsWith("RUNTIME_ACTIVATION_TEST_"))
  ) {
    throw new Error();
  }
}

export function ownedNetworkCreateArguments(networkName) {
  if (!ownedNetworks.includes(networkName)) throw new Error();
  return ["network", "create", "--driver", "bridge", "--internal", networkName];
}

export function ownedContainerDockerArguments(containerName, networkName) {
  const index = ownedContainers.indexOf(containerName);
  if (index < 0 || ownedNetworks[index] !== networkName) throw new Error();
  return [
    "run",
    "--detach",
    "--name",
    containerName,
    "--network",
    networkName,
    "--network-alias",
    networkAlias,
    "--publish",
    "127.0.0.1::5432",
    "--env",
    "POSTGRES_USER=platform_app",
    "--env",
    `POSTGRES_DB=${databaseName}`,
    "--env",
    "POSTGRES_PASSWORD",
    "--mount",
    `type=bind,source=${identitiesSql},target=/docker-entrypoint-initdb.d/runtime-postgres-identities.sql,readonly`,
    "postgres:17",
  ];
}

export async function createActivationMigrationPrefix({
  sourceRoot = rootDir,
  temporaryBase = tmpdir(),
} = {}) {
  const temporaryRoot = await mkdtemp(
    join(temporaryBase, "swooshz-activation-0009-"),
  );
  try {
    const sourceMigrations = join(sourceRoot, "drizzle", "migrations");
    const migrationsFolder = join(temporaryRoot, "drizzle", "migrations");
    await mkdir(join(migrationsFolder, "meta"), { recursive: true });
    const journal = JSON.parse(
      await readFile(join(sourceMigrations, "meta", "_journal.json"), "utf8"),
    );
    if (!Array.isArray(journal.entries)) throw new Error();
    const entries = journal.entries.filter((entry) => entry.idx <= 8);
    assertActivationMigrationEntries(entries);
    if (!journal.entries.some((entry) => entry.tag === excludedMigrationTag)) {
      throw new Error();
    }
    for (const entry of entries) {
      await copyFile(
        join(sourceMigrations, `${entry.tag}.sql`),
        join(migrationsFolder, `${entry.tag}.sql`),
      );
    }
    await writeFile(
      join(migrationsFolder, "meta", "_journal.json"),
      `${JSON.stringify({
        version: journal.version,
        dialect: journal.dialect,
        entries,
      }, null, 2)}\n`,
      "utf8",
    );
    const copiedFiles = (await readdir(migrationsFolder, {
      withFileTypes: true,
    }))
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();
    if (
      copiedFiles.length !== 9 ||
      copiedFiles.some((name, index) =>
        name !== `${expectedMigrationTags[index]}.sql`) ||
      copiedFiles.includes(`${excludedMigrationTag}.sql`)
    ) {
      throw new Error();
    }
    return { entries, migrationsFolder, temporaryRoot };
  } catch (error) {
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}

export function assertActivationMigrationEntries(entries) {
  if (
    !Array.isArray(entries) ||
    entries.length !== 9 ||
    entries.some((entry, index) =>
      !entry ||
      entry.idx !== index ||
      entry.tag !== expectedMigrationTags[index] ||
      entry.tag === excludedMigrationTag)
  ) {
    throw new Error();
  }
}

export function parseActivationTestSummary(output) {
  if (
    typeof output !== "string" ||
    Buffer.byteLength(output, "utf8") > maxChildOutputBytes
  ) {
    return null;
  }
  const lines = output
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\r\n?/gu, "\n")
    .split("\n");
  while (lines.at(-1) === "") lines.pop();
  const pattern = /^\s*([#ℹ])\s+(tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)\s+([^\s].*?)\s*$/u;
  const starts = lines
    .map((line, index) => [line.match(pattern), index])
    .filter(([match]) => match?.[2] === "tests")
    .map(([, index]) => index);
  if (starts.length !== 1) return null;
  const expectedFields = [
    "tests",
    "suites",
    "pass",
    "fail",
    "cancelled",
    "skipped",
    "todo",
    "duration_ms",
  ];
  const fields = new Map();
  let marker = null;
  for (let offset = 0; offset < expectedFields.length; offset += 1) {
    const lineIndex = starts[0] + offset;
    const match = lines[lineIndex]?.match(pattern);
    if (
      !match ||
      match[2] !== expectedFields[offset] ||
      fields.has(match[2]) ||
      (marker !== null && marker !== match[1])
    ) {
      return null;
    }
    marker ??= match[1];
    fields.set(match[2], match[3]);
  }
  if (starts[0] + expectedFields.length !== lines.length) return null;
  const counts = {};
  for (const field of expectedFields.slice(0, -1)) {
    const value = fields.get(field);
    if (!/^(?:0|[1-9]\d*)$/u.test(value)) return null;
    counts[field] = Number(value);
  }
  const durationText = fields.get("duration_ms");
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(durationText)) return null;
  const duration = Number(durationText);
  if (
    !Number.isFinite(duration) ||
    duration < 0 ||
    duration > maxChildDurationMs ||
    String(duration) !== durationText ||
    counts.tests !== expectedTestCount ||
    counts.pass !== expectedTestCount ||
    counts.fail !== 0 ||
    counts.cancelled !== 0 ||
    counts.skipped !== 0 ||
    counts.todo !== 0 ||
    counts.pass + counts.fail + counts.cancelled + counts.skipped +
      counts.todo !== counts.tests
  ) {
    return null;
  }
  return {
    total: counts.tests,
    passed: counts.pass,
    failed: counts.fail,
    cancelled: counts.cancelled,
    skipped: counts.skipped,
    todo: counts.todo,
  };
}

export function sanitizeActivationChildDiagnostics({
  stdout = "",
  stderr = "",
  secretValues = [],
} = {}) {
  let source = [stdout, stderr].filter(Boolean).join("\n");
  for (const secret of secretValues) {
    if (typeof secret === "string" && secret.length > 0) {
      source = source.replaceAll(secret, "<redacted>");
    }
  }
  source = source
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\b(?:postgres(?:ql)?|mysql|mssql):\/\/[^\s'"]+/giu, "<redacted-url>")
    .replace(/\bhttps?:\/\/[^\s'"]+/giu, "<redacted-url>")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+)\b/gu, "<redacted-token>")
    .replace(/\b(Bearer|Basic)\s+[^\s'"]+/giu, "$1 <redacted-token>")
    .replace(
      /\b(?:RUNTIME_ACTIVATION_TEST_[A-Z_]+|DATABASE_URL|DATABASE_OPERATOR_URL|PGPASSWORD|PGPASSFILE|PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|API_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|AUTHORIZATION|DSN)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;)]*)/giu,
      (match) => `${match.slice(0, match.search(/[:=]/u) + 1)}<redacted>`,
    )
    .replace(/[?&][A-Za-z0-9_-]+=[^&\s'"]*/gu, (match) =>
      `${match.slice(0, match.indexOf("=") + 1)}<redacted>`);
  const selected = source
    .replace(/\r\n?/gu, "\n")
    .split("\n")
    .filter((line) => {
      const value = line.trim();
      return /^(?:TAP version|# Subtest:|not ok |1\.\.|# (?:tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)|(?:Assertion)?Error|(?:failureType|error|code|name|operator|expected|actual|location|stack|message):|at\s)/u.test(value);
    })
    .join("\n");
  return Buffer.from(selected, "utf8")
    .subarray(0, maxDiagnosticBytes)
    .toString("utf8");
}

export async function assertExactDockerResourcesAbsent(
  commandImpl = runCommand,
) {
  for (const containerName of ownedContainers) {
    const result = await commandImpl("docker", [
      "ps",
      "--all",
      "--filter",
      `name=^/${containerName}$`,
      "--format",
      "{{.Names}}",
    ]);
    if (result.code !== 0 || result.signal || result.stdout.trim()) {
      throw new Error();
    }
  }
  for (const networkName of ownedNetworks) {
    const result = await commandImpl("docker", [
      "network",
      "ls",
      "--filter",
      `name=^${networkName}$`,
      "--format",
      "{{.Name}}",
    ]);
    if (result.code !== 0 || result.signal || result.stdout.trim()) {
      throw new Error();
    }
  }
}

async function provisionFixture(
  connectionString,
  operatorPassword,
  migrationsFolder,
) {
  const pool = new Pool({
    connectionString,
    password: operatorPassword,
    max: 1,
  });
  try {
    await migrate(drizzle(pool), { migrationsFolder });
    await pool.query(`
      do $fixture$
      begin
        if exists (
          select 1 from pg_roles
          where rolname in ('cloud_admin', 'platform_runtime')
        ) then
          raise exception 'unexpected fixture role';
        end if;
        create role cloud_admin nologin noinherit superuser nocreatedb
          nocreaterole noreplication nobypassrls;
        create role platform_runtime nologin noinherit nosuperuser nocreatedb
          nocreaterole noreplication nobypassrls;
      end
      $fixture$
    `);
    await pool.query("revoke platform_runtime from platform_app");
    await pool.query("revoke platform_app from platform_runtime");
    const creatorEdgeClient = await pool.connect();
    let creatorEdgeError = null;
    try {
      await creatorEdgeClient.query("set session authorization cloud_admin");
      await creatorEdgeClient.query(
        "grant platform_runtime to platform_app with admin true, set false, inherit false granted by cloud_admin",
      );
    } catch (error) {
      creatorEdgeError = error;
    } finally {
      try {
        await executeDisposableCleanupActions([
          () => creatorEdgeClient.query("reset session authorization"),
        ], creatorEdgeError);
      } finally {
        creatorEdgeClient.release(true);
      }
    }
    await pool.query(
      `revoke create on database ${quoteIdentifier(databaseName)} from public`,
    );
    await pool.query("revoke create on schema public from public");
    await pool.query("revoke usage on schema drizzle from public");
    await pool.query("revoke create on schema drizzle from public");
    await pool.query("grant usage on schema public to platform_runtime");
    await pool.query(
      "revoke all privileges on all tables in schema public from platform_runtime",
    );
    if (RUNTIME_TABLE_GRANT_CONTRACT.length !== 39) throw new Error();
    for (const [tableName, privileges] of privilegesByTable()) {
      await pool.query(
        `grant ${privileges.join(", ")} on table public.${quoteIdentifier(tableName)} to platform_runtime`,
      );
    }
    await pool.query(
      "revoke all privileges on all sequences in schema public from platform_runtime",
    );
    await pool.query(
      "revoke all privileges on all functions in schema public from platform_runtime",
    );
  } finally {
    await pool.end();
  }
}

async function assertFixtureIdentity(connectionString, operatorPassword) {
  const pool = new Pool({
    connectionString,
    password: operatorPassword,
    max: 1,
  });
  try {
    const result = await pool.query(`
      select
        current_database() = 'runtime_posture_test' as database_matches,
        current_user = 'platform_app' as current_user_matches,
        session_user = 'platform_app' as session_user_matches,
        current_setting('server_version_num')::integer / 10000 = 17 as postgres17,
        (select rolsuper and rolcanlogin from pg_roles where rolname = 'platform_app')
          as operator_matches,
        (select rolsuper and rolcanlogin and not rolinherit from pg_roles where rolname = 'postgres')
          as postgres_matches,
        (select rolsuper and not rolcanlogin and not rolinherit from pg_roles where rolname = 'cloud_admin')
          as cloud_admin_matches,
        (select not rolcanlogin and not rolinherit and not rolsuper and not rolcreaterole
          from pg_roles where rolname = 'platform_runtime') as runtime_matches,
        (select system_identifier::text from pg_control_system())
          as system_identifier
    `);
    const [row] = result.rows;
    if (
      !row?.database_matches ||
      !row.current_user_matches ||
      !row.session_user_matches ||
      !row.postgres17 ||
      !row.operator_matches ||
      !row.postgres_matches ||
      !row.cloud_admin_matches ||
      !row.runtime_matches ||
      !/^[0-9]+$/u.test(row.system_identifier)
    ) {
      throw new Error();
    }
    return row.system_identifier;
  } finally {
    await pool.end();
  }
}

async function assertOwnedDockerTopology(
  spawnImpl,
  containerName,
  networkName,
) {
  const image = await requireSuccessfulCommand(spawnImpl, "docker", [
    "inspect",
    "--format",
    "{{.Config.Image}}",
    containerName,
  ]);
  if (image.stdout.trim() !== "postgres:17") throw new Error();
  const network = await requireSuccessfulCommand(spawnImpl, "docker", [
    "network",
    "inspect",
    "--format",
    "{{.Driver}} {{.Internal}}",
    networkName,
  ]);
  if (network.stdout.trim() !== "bridge true") throw new Error();
  const networks = await requireSuccessfulCommand(spawnImpl, "docker", [
    "inspect",
    "--format",
    "{{json .NetworkSettings.Networks}}",
    containerName,
  ]);
  const networkMap = JSON.parse(networks.stdout);
  if (
    Object.keys(networkMap).length !== 1 ||
    !networkMap[networkName] ||
    !Array.isArray(networkMap[networkName].Aliases) ||
    !networkMap[networkName].Aliases.includes(networkAlias)
  ) {
    throw new Error();
  }
  const binding = await requireSuccessfulCommand(spawnImpl, "docker", [
    "inspect",
    "--format",
    "{{json .NetworkSettings.Ports}}",
    containerName,
  ]);
  const parsed = JSON.parse(binding.stdout);
  if (
    Object.keys(parsed).length !== 1 ||
    !Array.isArray(parsed["5432/tcp"]) ||
    parsed["5432/tcp"].length !== 1 ||
    parsed["5432/tcp"][0].HostIp !== "127.0.0.1" ||
    !/^[0-9]+$/u.test(parsed["5432/tcp"][0].HostPort)
  ) {
    throw new Error();
  }
  const port = Number(parsed["5432/tcp"][0].HostPort);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error();
  return port;
}

async function waitForPostgres(connectionString, operatorPassword) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const pool = new Pool({
      connectionString,
      password: operatorPassword,
      connectionTimeoutMillis: 1_000,
      max: 1,
    });
    try {
      const result = await pool.query(
        "select current_user = 'platform_app' as admitted, current_setting('server_version_num')::integer / 10000 = 17 as postgres17",
      );
      if (result.rows[0]?.admitted && result.rows[0]?.postgres17) return;
    } catch {
      await delay(500);
    } finally {
      await pool.end();
    }
  }
  throw new Error();
}

async function runActivationChild(spawnImpl, resources, operatorUrls) {
  const childEnvironment = { ...process.env };
  for (const name of Object.keys(childEnvironment)) {
    if (name.startsWith("RUNTIME_ACTIVATION_TEST_")) {
      delete childEnvironment[name];
    }
  }
  Object.assign(childEnvironment, {
    PGPASSWORD: resources.operatorPassword,
    RUNTIME_ACTIVATION_TEST_OPERATOR_URL: operatorUrls[0],
    RUNTIME_ACTIVATION_TEST_SECOND_OPERATOR_URL: operatorUrls[1],
    RUNTIME_ACTIVATION_TEST_DOCKER_NETWORK: ownedNetworks[0],
    RUNTIME_ACTIVATION_TEST_SECOND_DOCKER_NETWORK: ownedNetworks[1],
    RUNTIME_ACTIVATION_TEST_RUNTIME_PASSWORD: resources.runtimePassword,
    RUNTIME_ACTIVATION_TEST_CONFIRM: "disposable-only",
  });
  resources.childEnvironment = childEnvironment;
  const result = await new Promise((resolvePromise, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;
    const child = spawnImpl(
      process.execPath,
      ["--test", "tests/platform-runtime-activation-postgres.test.mjs"],
      {
        cwd: rootDir,
        env: childEnvironment,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    resources.child = child;
    resources.childExited = false;
    const timer = setTimeout(() => {
      if (!settled) child.kill("SIGTERM");
    }, maxChildDurationMs);
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolvePromise(value);
    };
    child.once("error", () => finish(null, new Error()));
    child.stdout?.on("data", (chunk) => {
      stdoutLength += chunk.length;
      if (stdoutLength <= maxChildOutputBytes) stdout.push(Buffer.from(chunk));
    });
    child.stderr?.on("data", (chunk) => {
      stderrLength += chunk.length;
      if (stderrLength <= maxChildOutputBytes) stderr.push(Buffer.from(chunk));
    });
    child.once("close", (code, signal) => {
      resources.childExited = true;
      const stdoutText = Buffer.concat(stdout).toString("utf8");
      const stderrText = Buffer.concat(stderr).toString("utf8");
      for (const chunk of [...stdout, ...stderr]) chunk.fill(0);
      const overflow =
        stdoutLength > maxChildOutputBytes ||
        stderrLength > maxChildOutputBytes;
      if (code !== 0 || signal !== null || overflow) {
        const error = new Error();
        error.diagnostics = sanitizeActivationChildDiagnostics({
          stdout: stdoutText,
          stderr: stderrText,
          secretValues: [
            resources.operatorPassword,
            resources.runtimePassword,
            ...operatorUrls,
          ],
        });
        finish(null, error);
        return;
      }
      finish({ stdout: stdoutText, stderr: stderrText });
    });
  });
  const summary = parseActivationTestSummary(result.stdout);
  if (!summary) {
    const error = new Error();
    error.diagnostics = sanitizeActivationChildDiagnostics({
      stdout: result.stdout,
      stderr: result.stderr,
      secretValues: [
        resources.operatorPassword,
        resources.runtimePassword,
        ...operatorUrls,
      ],
    });
    throw error;
  }
  result.stdout = "";
  result.stderr = "";
  return summary;
}

async function terminateChild(resources) {
  if (!resources.child || resources.childExited) return;
  if (!resources.child.kill("SIGTERM")) throw new Error();
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error()), 2_000);
    resources.child.once("close", () => {
      clearTimeout(timer);
      resources.childExited = true;
      resolvePromise();
    });
  });
}

async function removeOwnedContainer(spawnImpl, containerName) {
  const result = await runCommand("docker", ["rm", "--force", containerName], {
    spawnImpl,
  });
  if (result.code === 0) return;
  const absent = await runCommand("docker", [
    "ps",
    "--all",
    "--filter",
    `name=^/${containerName}$`,
    "--format",
    "{{.Names}}",
  ], { spawnImpl });
  if (absent.code !== 0 || absent.stdout.trim()) throw new Error();
}

async function removeOwnedNetwork(spawnImpl, networkName) {
  const result = await runCommand("docker", ["network", "rm", networkName], {
    spawnImpl,
  });
  if (result.code === 0) return;
  const absent = await runCommand("docker", [
    "network",
    "ls",
    "--filter",
    `name=^${networkName}$`,
    "--format",
    "{{.Name}}",
  ], { spawnImpl });
  if (absent.code !== 0 || absent.stdout.trim()) throw new Error();
}

async function clearCredentialState(resources) {
  resources.operatorPasswordBuffer.fill(0);
  resources.runtimePasswordBuffer.fill(0);
  resources.operatorPassword = null;
  resources.runtimePassword = null;
  if (resources.childEnvironment) {
    for (const name of Object.keys(resources.childEnvironment)) {
      if (
        name.startsWith("RUNTIME_ACTIVATION_TEST_") ||
        name === "POSTGRES_PASSWORD" ||
        name === "PGPASSWORD"
      ) {
        delete resources.childEnvironment[name];
      }
    }
    resources.childEnvironment = null;
  }
}

async function assertPathAbsent(path) {
  try {
    await access(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error();
}

async function assertPortAbsent(port) {
  await new Promise((resolvePromise, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
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
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) finish();
      else finish(new Error());
    });
  });
}

async function requireSuccessfulCommand(
  spawnImpl,
  command,
  args,
  options = {},
) {
  const result = await runCommand(command, args, { ...options, spawnImpl });
  if (
    result.code !== 0 ||
    result.signal !== null ||
    result.timedOut ||
    result.outputOverflow
  ) {
    throw new Error();
  }
  return result;
}

async function runCommand(command, args, {
  cwd = rootDir,
  env = process.env,
  spawnImpl = spawn,
  timeoutMs = 30_000,
} = {}) {
  return new Promise((resolvePromise, reject) => {
    const stdout = [];
    const stderr = [];
    let outputLength = 0;
    let settled = false;
    let timedOut = false;
    let child;
    try {
      child = spawnImpl(command, args, {
        cwd,
        env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch {
      reject(new Error());
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolvePromise(value);
    };
    child.once("error", () => finish(null, new Error()));
    child.stdout?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) stdout.push(Buffer.from(chunk));
    });
    child.stderr?.on("data", (chunk) => {
      outputLength += chunk.length;
      if (outputLength <= maxChildOutputBytes) stderr.push(Buffer.from(chunk));
    });
    child.once("close", (code, signal) => finish({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      outputOverflow: outputLength > maxChildOutputBytes,
      timedOut,
    }));
  });
}

function buildLoopbackUrl(user, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error();
  return `postgresql://${user}@127.0.0.1:${port}/${databaseName}`;
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
  if (!/^[a-z_][a-z0-9_$]{0,62}$/u.test(value)) throw new Error();
  return `"${value.replaceAll('"', '""')}"`;
}
