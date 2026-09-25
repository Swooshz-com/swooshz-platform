import { spawn } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";
import { Pool } from "pg";
import { join, resolve } from "node:path";

import { withDisposablePostgresFixtureMigration } from "../tests/support/disposable-postgres-fixture.mjs";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const ownedContainerName = "codex-platform153-role-collapse-pg17";
const migrationDatabaseName = "role_collapse_migration_test";
const concurrencyDatabaseName = "role_collapse_concurrency_test";
const databaseNames = [migrationDatabaseName, concurrencyDatabaseName];
const maxChildOutputBytes = 64 * 1024;
const childTimeoutMs = 180_000;
const safeIdentifier = /^[a-z_][a-z0-9_$]{0,62}$/u;

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  run().catch((error) => {
    const phase = typeof error?.phase === "string" ? error.phase : "unknown";
    process.stderr.write(
      "Disposable PostgreSQL 17 role-collapse proof runner failed (" +
        phase +
        ").\n",
    );
    process.exitCode = 1;
  });
}

export async function run({ spawnImpl = spawn } = {}) {
  let startAttempted = false;
  let containerStarted = false;
  let observedPort = null;
  let primaryError = null;
  let cleanupError = null;
  let phase = "container-preflight";

  try {
    phase = "container-preflight";
    await assertExactContainerAbsent(spawnImpl);
    startAttempted = true;
    phase = "container-start";
    const started = await runCommand(
      spawnImpl,
      "docker",
      [
        "run",
        "--detach",
        "--name",
        ownedContainerName,
        "--env",
        "POSTGRES_HOST_AUTH_METHOD=trust",
        "--env",
        "POSTGRES_USER=cloud_admin",
        "--env",
        "POSTGRES_DB=postgres",
        "--publish",
        "127.0.0.1::5432",
        "postgres:17",
      ],
      rootDir,
    );
    if (started.code !== 0 || !started.stdout.trim()) {
      throw new Error();
    }
    containerStarted = true;
    phase = "port-discovery";
    observedPort = await readPublishedPort(spawnImpl);
    phase = "postgres-readiness";
    await waitForPostgres(observedPort);
    phase = "database-creation";
    await createDatabases(observedPort);
    phase = "focused-child";
    await runFocusedChild(spawnImpl, observedPort);
  } catch {
    primaryError = Object.assign(new Error(), { phase });
  }

  try {
    if (startAttempted) {
      await cleanupOwnedResources(spawnImpl, observedPort, containerStarted);
    }
  } catch {
    cleanupError = Object.assign(new Error(), { phase: "cleanup" });
  }

  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return {
    container: ownedContainerName,
    databases: databaseNames.slice(),
    postgresMajor: 17,
  };
}

async function assertExactContainerAbsent(spawnImpl) {
  const result = await runCommand(
    spawnImpl,
    "docker",
    [
      "ps",
      "--all",
      "--filter",
      "name=^/" + ownedContainerName + "$",
      "--format",
      "{{.Names}}",
    ],
    rootDir,
  );
  if (result.code !== 0 || result.stdout.trim() !== "") {
    throw new Error();
  }
}

async function readPublishedPort(spawnImpl) {
  const result = await runCommand(
    spawnImpl,
    "docker",
    ["port", ownedContainerName, "5432/tcp"],
    rootDir,
  );
  if (result.code !== 0) throw new Error();
  const match = result.stdout.match(/127\.0\.0\.1:(\d+)/u);
  if (!match) throw new Error();
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error();
  }
  return port;
}

async function waitForPostgres(port) {
  const connectionString = buildUrl("cloud_admin", port, "postgres");
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const pool = new Pool({ connectionString, max: 1 });
    try {
      const result = await pool.query(
        "select current_setting('server_version_num') as version_num",
      );
      const versionNumber = Number(result.rows[0]?.version_num);
      if (versionNumber >= 170000 && versionNumber < 180000) {
        return;
      }
    } catch {
      // The disposable server may still be starting.
    } finally {
      await pool.end().catch(() => {});
    }
    await delay(250);
  }
  throw new Error();
}

async function createDatabases(port) {
  const pool = new Pool({
    connectionString: buildUrl("cloud_admin", port, "postgres"),
    max: 1,
  });
  try {
    for (const databaseName of databaseNames) {
      await pool.query("create database " + quoteIdentifier(databaseName));
    }
  } finally {
    await pool.end();
  }
}

export async function migrateTo0009(databaseUrl) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "swooshz-role-collapse-0009-"));
  const temporaryMigrations = join(temporaryRoot, "migrations");

  try {
    await cp(join(rootDir, "drizzle", "migrations"), temporaryMigrations, {
      recursive: true,
    });
    await rm(
      join(
        temporaryMigrations,
        "0010_admin_operator_viewer_role_collapse.sql",
      ),
    );
    await rm(join(temporaryMigrations, "meta", "0010_snapshot.json"));

    const journalPath = join(temporaryMigrations, "meta", "_journal.json");
    const journal = JSON.parse(await readFile(journalPath, "utf8"));
    journal.entries = journal.entries.filter(
      (entry) => entry.tag !== "0010_admin_operator_viewer_role_collapse",
    );
    await writeFile(journalPath, JSON.stringify(journal, null, 2) + "\n");

    await withDisposablePostgresFixtureMigration(
      {
        connectionString: databaseUrl,
        expectedDatabase: databaseNameFromUrl(databaseUrl),
        expectedUser: "cloud_admin",
        migrationsFolder: temporaryMigrations,
      },
      async () => {},
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

export async function migrateToLatest(databaseUrl) {
  const result = await runRepositoryMigrator(databaseUrl);
  if (result.code !== 0 || result.timedOut !== false) throw new Error();
}

export async function runRepositoryMigrator(databaseUrl) {
  try {
    await withDisposablePostgresFixtureMigration(
      {
        connectionString: databaseUrl,
        expectedDatabase: databaseNameFromUrl(databaseUrl),
        expectedUser: "cloud_admin",
        migrationsFolder: join(rootDir, "drizzle", "migrations"),
      },
      async () => {},
    );
    return { code: 0, timedOut: false };
  } catch {
    return { code: 1, timedOut: false };
  }
}

export function parseRoleCollapseTestSummary(output) {
  if (
    typeof output !== "string" ||
    Buffer.byteLength(output, "utf8") > maxChildOutputBytes
  ) {
    return null;
  }
  const normalised = output
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\r\n?/gu, "\n");
  const lines = normalised.split("\n");
  while (lines.at(-1) === "") lines.pop();
  if (lines.length === 0) return null;

  const fieldPattern =
    /^\s*([#ℹ])\s+(tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)(?:\s+([^\s].*?))?\s*$/u;
  const summaryStarts = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(fieldPattern);
    if (match?.[2] === "tests") summaryStarts.push(index);
  }
  if (summaryStarts.length !== 1) return null;

  const start = summaryStarts[0];
  const fields = new Map();
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
  let marker = null;
  let expectedIndex = 0;
  for (let index = start; index < lines.length; index += 1) {
    const match = lines[index].match(fieldPattern);
    if (!match || (marker !== null && match[1] !== marker)) return null;
    marker ??= match[1];
    if (match[2] !== expectedFields[expectedIndex] || fields.has(match[2])) {
      return null;
    }
    if (typeof match[3] !== "string" || match[3].length === 0) return null;
    fields.set(match[2], match[3]);
    expectedIndex += 1;
    if (match[2] === "duration_ms") {
      if (index !== lines.length - 1) return null;
      break;
    }
  }
  if (expectedIndex !== expectedFields.length) return null;
  for (const line of lines.slice(0, start)) {
    if (fieldPattern.test(line)) return null;
  }

  const counts = {};
  for (const field of [
    "tests",
    "suites",
    "pass",
    "fail",
    "cancelled",
    "skipped",
    "todo",
  ]) {
    const value = fields.get(field);
    if (!/^(?:0|[1-9]\d*)$/u.test(value)) return null;
    const count = Number(value);
    if (!Number.isSafeInteger(count)) return null;
    counts[field] = count;
  }
  if (
    counts.tests <= 0 ||
    counts.pass !== counts.tests ||
    counts.fail !== 0 ||
    counts.skipped !== 0 ||
    counts.cancelled !== 0 ||
    counts.todo !== 0 ||
    counts.pass +
      counts.fail +
      counts.skipped +
      counts.cancelled +
      counts.todo !==
      counts.tests
  ) {
    return null;
  }

  const durationText = fields.get("duration_ms");
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(durationText)) return null;
  const durationMs = Number(durationText);
  if (
    !Number.isFinite(durationMs) ||
    durationMs < 0 ||
    durationMs > childTimeoutMs ||
    String(durationMs) !== durationText
  ) {
    return null;
  }
  return {
    cancelled: counts.cancelled,
    failed: counts.fail,
    passed: counts.pass,
    skipped: counts.skipped,
    suites: counts.suites,
    todo: counts.todo,
    total: counts.tests,
    durationMs,
  };
}

export function validateRoleCollapseChildResult(result) {
  if (
    result?.code !== 0 ||
    result.signal !== null ||
    result.timedOut !== false ||
    result.outputOverflow !== false
  ) {
    return null;
  }
  return parseRoleCollapseTestSummary(result.stdout);
}

export function formatRoleCollapseSuccess(summary) {
  return (
    "Disposable PostgreSQL 17 role-collapse proofs: " +
    summary.passed +
    " passed, " +
    summary.failed +
    " failed, " +
    summary.skipped +
    " skipped.\n"
  );
}

async function runFocusedChild(_spawnImpl, port) {
  const { runRoleCollapseProofs } = await import(
    "../tests/role-collapse-postgres.test.mjs"
  );
  const proof = await runRoleCollapseProofs({
    migrationDatabaseUrl: buildUrl(
      "cloud_admin",
      port,
      migrationDatabaseName,
    ),
    concurrencyDatabaseUrl: buildUrl(
      "cloud_admin",
      port,
      concurrencyDatabaseName,
    ),
    migrateTo0009Impl: migrateTo0009,
    migrateToLatestImpl: migrateToLatest,
    runRepositoryMigratorImpl: runRepositoryMigrator,
  });
  const result = {
    code: proof.failed === 0 ? 0 : 1,
    signal: null,
    timedOut: false,
    outputOverflow: false,
    stdout: formatRoleCollapseNodeSummary(proof),
    stderr: "",
  };
  const summary = validateRoleCollapseChildResult(result);
  if (!summary) {
    if (result.stdout) {
      process.stderr.write(result.stdout.slice(-8_000));
    }
    if (result.stderr) {
      process.stderr.write(result.stderr.slice(-8_000));
    }
    throw new Error();
  }
  process.stdout.write(formatRoleCollapseSuccess(summary));
}

function formatRoleCollapseNodeSummary(summary) {
  return [
    "# tests " + summary.total,
    "# suites " + summary.suites,
    "# pass " + summary.passed,
    "# fail " + summary.failed,
    "# cancelled " + summary.cancelled,
    "# skipped " + summary.skipped,
    "# todo " + summary.todo,
    "# duration_ms " + summary.durationMs,
  ].join("\n") + "\n";
}

async function cleanupOwnedResources(spawnImpl, port, containerStarted) {
  let firstError = null;
  if (containerStarted && Number.isInteger(port)) {
    try {
      const pool = new Pool({
        connectionString: buildUrl("cloud_admin", port, "postgres"),
        max: 1,
      });
      try {
        for (const databaseName of databaseNames) {
          await pool.query(
            "drop database if exists " +
              quoteIdentifier(databaseName) +
              " with (force)",
          );
        }
      } finally {
        await pool.end();
      }
    } catch (error) {
      firstError ??= error;
    }
  }

  if (containerStarted) {
    try {
      const removed = await runCommand(
        spawnImpl,
        "docker",
        ["rm", "--force", ownedContainerName],
        rootDir,
      );
      if (removed.code !== 0) throw new Error();
    } catch (error) {
      firstError ??= error;
    }
  }

  try {
    await assertExactContainerAbsent(spawnImpl);
  } catch (error) {
    firstError ??= error;
  }

  if (Number.isInteger(port)) {
    try {
      await assertPortAbsent(port);
    } catch (error) {
      firstError ??= error;
    }
  }

  if (firstError) throw firstError;
}

async function assertPortAbsent(port) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const listenerPresent = await probePort(port);
    if (!listenerPresent) return;
    await delay(100);
  }
  throw new Error();
}

async function probePort(port) {
  return new Promise((resolvePromise) => {
    let settled = false;
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const settle = (listenerPresent) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(listenerPresent);
    };
    socket.once("connect", () => settle(true));
    socket.once("error", () => settle(false));
    socket.setTimeout(1_000, () => settle(false));
  });
}

function buildUrl(user, port, databaseName) {
  if (
    !safeIdentifier.test(user) ||
    !safeIdentifier.test(databaseName) ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  ) {
    throw new Error();
  }
  return "postgres://" + user + "@127.0.0.1:" + port + "/" + databaseName;
}

function databaseNameFromUrl(databaseUrl) {
  return decodeURIComponent(new URL(databaseUrl).pathname.slice(1));
}

function quoteIdentifier(value) {
  if (!safeIdentifier.test(value)) throw new Error();
  return '"' + value + '"';
}

function runCommand(
  spawnImpl,
  command,
  args,
  cwd,
  { env, timeoutMs } = {},
) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawnImpl(command, args, {
        cwd,
        env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      rejectPromise(error);
      return;
    }

    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let timer = null;
    const append = (target, chunk, currentBytes) => {
      const bytes = Buffer.byteLength(chunk);
      if (currentBytes + bytes <= maxChildOutputBytes) {
        target.push(Buffer.from(chunk));
      }
      return currentBytes + bytes;
    };

    child.stdout?.on("data", (chunk) => {
      stdoutBytes = append(stdout, chunk, stdoutBytes);
    });
    child.stderr?.on("data", (chunk) => {
      stderrBytes = append(stderr, chunk, stderrBytes);
    });
    if (Number.isInteger(timeoutMs)) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill?.("SIGTERM");
      }, timeoutMs);
    }
    child.once("error", (error) => {
      if (timer) clearTimeout(timer);
      rejectPromise(error);
    });
    child.once("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      resolvePromise({
        code,
        signal,
        timedOut,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        outputOverflow:
          stdoutBytes > maxChildOutputBytes || stderrBytes > maxChildOutputBytes,
      });
    });
  });
}
