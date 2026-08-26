#!/usr/bin/env node

import { spawn } from "node:child_process";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { resolve } from "node:path";
import { Pool } from "pg";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const containerName = "codex-platform185-durable-db-operations-pg17";
const databaseName = "durable_operations_test";
const maxOutputBytes = 64 * 1024;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((error) => {
    const phase = typeof error?.phase === "string" ? error.phase : "unknown";
    process.stderr.write(`Disposable PostgreSQL 17 durable-operation runner failed (${phase}).\n`);
    process.exitCode = 1;
  });
}

export async function run({ spawnImpl = spawn } = {}) {
  assertNoCallerSuppliedFixture(process.env);
  let port = null;
  let started = false;
  let primaryError = null;
  let phase = "container-preflight";
  try {
    await assertExactContainerAbsent(spawnImpl);
    phase = "container-start";
    const startedResult = await runCommand(spawnImpl, "docker", [
      "run", "--detach", "--name", containerName,
      "--publish", "127.0.0.1::5432",
      "--env", "POSTGRES_DB=postgres",
      "--env", "POSTGRES_USER=cloud_admin",
      "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
      "postgres:17",
    ]);
    if (startedResult.code !== 0 || !startedResult.stdout.trim()) throw new Error();
    started = true;
    phase = "port-discovery";
    port = await readPublishedPort(spawnImpl);
    phase = "postgres-readiness";
    await waitForPostgres(port);
    phase = "database-creation";
    await createDatabase(port);
    phase = "focused-tests";
    await runFocusedTests(spawnImpl, port);
  } catch (error) {
    primaryError = Object.assign(new Error(), { phase });
    if (error?.stdout) process.stderr.write(String(error.stdout).slice(-8_000));
  }

  let cleanupError = null;
  try {
    await cleanup(spawnImpl, port, started);
  } catch {
    cleanupError = Object.assign(new Error(), { phase: "cleanup" });
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  process.stdout.write("Disposable PostgreSQL 17 durable-operation proofs: passed.\n");
  return { container: containerName, database: databaseName, postgresMajor: 17 };
}

async function runFocusedTests(spawnImpl, port) {
  const childEnv = { ...process.env };
  for (const key of Object.keys(childEnv)) {
    if (/DATABASE_URL|DATABASE_OPERATOR_URL|DURABLE_OPERATIONS_TEST/u.test(key)) delete childEnv[key];
  }
  childEnv.DURABLE_OPERATIONS_TEST_DATABASE_URL = `postgres://cloud_admin@127.0.0.1:${port}/${databaseName}`;
  const result = await runCommand(spawnImpl, process.execPath, ["--test", "tests/durable-database-operations-postgres.test.mjs"], {
    cwd: rootDir,
    env: childEnv,
    timeoutMs: 180_000,
  });
  if (result.code !== 0 || result.timedOut || result.stdout.includes("fail 1")) {
    throw Object.assign(new Error(), { stdout: result.stdout, stderr: result.stderr });
  }
  if (!/(?:#|ℹ)\s+fail 0\b/u.test(result.stdout)) throw new Error();
  process.stdout.write(result.stdout.slice(-8_000));
}

async function createDatabase(port) {
  const pool = new Pool({ connectionString: `postgres://cloud_admin@127.0.0.1:${port}/postgres`, max: 1 });
  try {
    await pool.query(`create database "${databaseName}"`);
  } finally {
    await pool.end();
  }
}

async function waitForPostgres(port) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const pool = new Pool({ connectionString: `postgres://cloud_admin@127.0.0.1:${port}/postgres`, max: 1, connectionTimeoutMillis: 1_000 });
    try {
      const result = await pool.query("select current_setting('server_version_num') as version_num");
      const version = Number(result.rows[0]?.version_num);
      if (version >= 170000 && version < 180000) return;
    } catch {
      // The owned disposable server may still be starting.
    } finally {
      await pool.end().catch(() => {});
    }
    await delay(250);
  }
  throw new Error();
}

async function readPublishedPort(spawnImpl) {
  const result = await runCommand(spawnImpl, "docker", ["port", containerName, "5432/tcp"]);
  if (result.code !== 0) throw new Error();
  const match = result.stdout.match(/^127\.0\.0\.1:(\d+)$/mu);
  const port = Number(match?.[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error();
  return port;
}

async function cleanup(spawnImpl, port, started) {
  if (started && Number.isInteger(port)) {
    const pool = new Pool({ connectionString: `postgres://cloud_admin@127.0.0.1:${port}/postgres`, max: 1 });
    try {
      await pool.query(`drop database if exists "${databaseName}" with (force)`);
    } finally {
      await pool.end().catch(() => {});
    }
  }
  if (started) {
    const result = await runCommand(spawnImpl, "docker", ["rm", "--force", containerName]);
    if (result.code !== 0) throw new Error();
  }
  await assertExactContainerAbsent(spawnImpl);
  if (Number.isInteger(port)) await assertPortAbsent(port);
}

async function assertExactContainerAbsent(spawnImpl) {
  const result = await runCommand(spawnImpl, "docker", ["ps", "--all", "--filter", `name=^/${containerName}$`, "--format", "{{.Names}}"]);
  if (result.code !== 0 || result.stdout.trim() !== "") throw new Error();
}

async function assertPortAbsent(port) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const present = await new Promise((resolvePromise) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      let settled = false;
      const settle = (value) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolvePromise(value);
      };
      socket.once("connect", () => settle(true));
      socket.once("error", () => settle(false));
      socket.setTimeout(1_000, () => settle(false));
    });
    if (!present) return;
    await delay(100);
  }
  throw new Error();
}

function assertNoCallerSuppliedFixture(env) {
  if (Object.keys(env ?? {}).some((key) => /DURABLE_OPERATIONS_TEST_DATABASE_URL/u.test(key))) throw new Error();
}

function runCommand(spawnImpl, command, args, { cwd = rootDir, env, timeoutMs } = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawnImpl(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    } catch (error) {
      rejectPromise(error);
      return;
    }
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    const timer = Number.isInteger(timeoutMs) ? setTimeout(() => { timedOut = true; child.kill?.("SIGTERM"); }, timeoutMs) : null;
    const append = (target, chunk, current) => {
      const next = current + Buffer.byteLength(chunk);
      if (next <= maxOutputBytes) target.push(Buffer.from(chunk));
      return next;
    };
    child.stdout?.on("data", (chunk) => { stdoutBytes = append(stdout, chunk, stdoutBytes); });
    child.stderr?.on("data", (chunk) => { stderrBytes = append(stderr, chunk, stderrBytes); });
    child.once("error", (error) => { if (timer) clearTimeout(timer); rejectPromise(error); });
    child.once("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      resolvePromise({ code, signal, timedOut, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), outputOverflow: stdoutBytes > maxOutputBytes || stderrBytes > maxOutputBytes });
    });
  });
}
