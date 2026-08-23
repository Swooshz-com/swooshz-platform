import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";
import { Pool } from "pg";
import { resolve } from "node:path";

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
  const connectionString = buildUrl("postgres", port, "postgres");
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
    connectionString: buildUrl("postgres", port, "postgres"),
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

async function runFocusedChild(spawnImpl, port) {
  const childEnv = { ...process.env };
  delete childEnv.DATABASE_URL;
  delete childEnv.DATABASE_OPERATOR_URL;
  delete childEnv.DATABASE_MIGRATIONS_CONFIRM;
  childEnv.ROLE_COLLAPSE_TEST_MIGRATION_OPERATOR_URL = buildUrl(
    "postgres",
    port,
    migrationDatabaseName,
  );
  childEnv.ROLE_COLLAPSE_TEST_CONCURRENCY_OPERATOR_URL = buildUrl(
    "postgres",
    port,
    concurrencyDatabaseName,
  );
  childEnv.ROLE_COLLAPSE_TEST_CONFIRM = "disposable-only";

  const result = await runCommand(
    spawnImpl,
    process.execPath,
    ["--test", "tests/role-collapse-postgres.test.mjs"],
    rootDir,
    { env: childEnv, timeoutMs: childTimeoutMs },
  );
  if (
    result.code !== 0 ||
    result.timedOut ||
    !/(?:#|\u2139)\s+pass 2\b/u.test(result.stdout) ||
    !/(?:#|\u2139)\s+fail 0\b/u.test(result.stdout) ||
    !/(?:#|\u2139)\s+skipped 0\b/u.test(result.stdout)
  ) {
    if (result.stdout) {
      process.stderr.write(result.stdout.slice(-8_000));
    }
    if (result.stderr) {
      process.stderr.write(result.stderr.slice(-8_000));
    }
    throw new Error();
  }
  process.stdout.write(
    "Disposable PostgreSQL 17 role-collapse proofs: 2 passed, 0 failed, 0 skipped.\n",
  );
}

async function cleanupOwnedResources(spawnImpl, port, containerStarted) {
  let firstError = null;
  if (containerStarted && Number.isInteger(port)) {
    try {
      const pool = new Pool({
        connectionString: buildUrl("postgres", port, "postgres"),
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
