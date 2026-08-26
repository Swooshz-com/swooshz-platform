#!/usr/bin/env node

import { spawn } from "node:child_process";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { resolve } from "node:path";
import { Pool } from "pg";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const containerNames = [
  "codex-platform190-durable-db-operations-pg17-a",
  "codex-platform190-durable-db-operations-pg17-b",
];
const databaseName = "durable_operations_test";
const maxOutputBytes = 64 * 1024;
const maxDiagnosticChars = 2_000;
const SAFE_TEST_TITLE = "Run-190 durable database operations on two disposable PostgreSQL 17 clusters";
const SAFE_FAILURE_CODES = new Set([
  "ERR_ASSERTION",
  "ERR_MODULE_NOT_FOUND",
  "ERR_TEST_FAILURE",
  "ERR_TEST_TIMEOUT",
  "ADMISSION_FAILED",
  "CONTRACT_DIGEST_MISMATCH",
  "FINAL_VERIFICATION_FAILED",
  "MUTATION_FAILED",
  "PREWRITE_DRIFT",
  "RESTORATION_FAILED",
  "RESTORE_CAPABILITY_REQUIRED",
  "TARGET_MISMATCH",
  "UNEXPECTED_FAILURE",
]);
const SAFE_POSTGRES_CODES = new Set(["25006", "23505", "42501", "42703", "42P01", "55006", "57P01", "57P02", "57P03"]);
const SAFE_FAILURE_TYPES = new Set(["testCodeFailure", "uncaughtException", "unhandledRejection", "testTimeout"]);
const SAFE_ASSERT_OPERATORS = new Set(["deepEqual", "deepStrictEqual", "doesNotMatch", "doesNotReject", "doesNotThrow", "equal", "match", "notDeepEqual", "notEqual", "ok", "rejects", "strictEqual", "throws"]);
const SAFE_ASSERT_MESSAGES = new Set([
  "index direct forward owner",
  "index direct mutation",
  "index inverse mutation",
  "index durable execution",
  "index drift execution",
  "index drift restore",
  "index after capture",
  "index restored capture",
  "index race baseline capture",
  "sequence direct forward owner",
  "sequence direct mutation",
  "sequence inverse mutation",
  "sequence durable execution",
  "sequence drift execution",
  "sequence drift restore",
  "sequence after capture",
  "sequence restored capture",
  "sequence race baseline capture",
  "database direct forward privilege",
  "database plan creation",
  "database inverse creation",
  "database direct mutation",
  "database inverse mutation",
  "database drift execution",
  "database drift restore",
  "database after capture",
  "database restored capture",
  "database restored digest",
  "database race baseline capture",
  "source drift assertion failed: injected",
  "source drift assertion failed: outcome",
  "source drift assertion failed: phase",
  "source drift assertion failed: code",
  "source drift assertion failed: mutation",
]);
const SAFE_ASSERT_SCALARS = new Set([
  "PASS",
  "FAIL",
  "BLOCKED",
  "SUCCESS",
  "PREWRITE",
  "PREWRITE_DRIFT",
  "FINAL_VERIFY",
  "COMMITTED",
  "NOT_STARTED",
  "NOT_COMMITTED",
  "MUTATION_FAILED",
  "platform_migrator",
  "platform_app",
  "cloud_admin",
  "public.users_pkey",
  "drizzle.__drizzle_migrations_id_seq",
  "durable_operations_test",
  "true",
  "false",
]);

function unquoteDiagnosticScalar(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2 &&
    ((trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith("\"") && trimmed.endsWith("\"")))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function projectDiagnosticLine(line) {
  const compact = line.trim();
  if (/^TAP version \d+$/u.test(compact)) return compact;
  const testLine = compact.match(/^not ok (\d+) - (.+)$/u);
  if (testLine && testLine[2] === SAFE_TEST_TITLE) return "not ok " + testLine[1] + " - " + SAFE_TEST_TITLE;
  if (/^(?:#|\u2139)\s+(?:tests|suites|pass|fail|cancelled|skipped|todo|duration|duration_ms)\b[ A-Za-z0-9_.,:=()/+-]{0,240}$/u.test(compact)) return compact;
  const sourceLocation = compact.match(/durable-database-operations-postgres\.test\.mjs:(\d+):(\d+)/u);
  if (sourceLocation) return "source: durable-database-operations-postgres.test.mjs:" + sourceLocation[1] + ":" + sourceLocation[2];
  const safeMessage = [...SAFE_ASSERT_MESSAGES]
    .sort((left, right) => right.length - left.length)
    .find((message) => compact.includes(message));
  if (safeMessage) return "message: " + safeMessage;
  const errorType = compact.match(/^(?:Error|AssertionError|DurableOperationError)(?:\s|\[|:)/u)?.[0].replace(/[\s[:\[]+$/u, "");
  if (errorType) return "error_type: " + errorType;
  const postgresCode = compact.match(/\b(?:25006|23505|42501|42703|42P01|55006|57P01|57P02|57P03)\b/u)?.[0];
  if (postgresCode && SAFE_POSTGRES_CODES.has(postgresCode)) return "postgres_code: " + postgresCode;
  if (/^(?:[+-]|actual|expected|error|name):/u.test(compact)) {
    const observed = [...SAFE_ASSERT_SCALARS]
      .sort((left, right) => right.length - left.length)
      .find((scalar) => compact.includes("'" + scalar + "'") || compact.includes("\"" + scalar + "\"") || compact.endsWith(": " + scalar));
    if (observed) return "assertion_value: " + observed;
    const numeric = compact.match(/(?:^|[:\s])(-?\d+(?:\.\d+)?)(?:['"])?$/u)?.[1];
    if (numeric) return "assertion_value: " + numeric;
  }
  const detail = compact.match(/^(?:#\s*)?(reason|status|code|failureType|operator|expected|actual|location|at|message|name):\s*(.*)$/u);
  if (!detail) {
    const errorCode = compact.match(/\b(ERR_[A-Z0-9_]+)\b/u)?.[1];
    if (errorCode && SAFE_FAILURE_CODES.has(errorCode)) return "error_code: " + errorCode;
    return null;
  }
  const key = detail[1];
  const value = unquoteDiagnosticScalar(detail[2]);
  if (key === "location" || key === "at") {
    const location = value.match(/(?:^|[/\\\\])durable-database-operations-postgres\.test\.mjs:(\d+):(\d+)$/u);
    return location ? "source: durable-database-operations-postgres.test.mjs:" + location[1] + ":" + location[2] : null;
  }
  if (key === "code") return SAFE_FAILURE_CODES.has(value) ? "code: " + value : null;
  if (key === "failureType") return SAFE_FAILURE_TYPES.has(value) ? "failureType: " + value : null;
  if (key === "operator") return SAFE_ASSERT_OPERATORS.has(value) ? "operator: " + value : null;
  if (key === "message") return SAFE_ASSERT_MESSAGES.has(value) ? "message: " + value : null;
  if (key === "name") return ["AssertionError", "DurableOperationError", "Error"].includes(value) ? "name: " + value : null;
  if (key === "expected" || key === "actual") {
    if (/^(?:true|false|null|undefined|-?\d+(?:\.\d+)?)$/u.test(value) || SAFE_ASSERT_SCALARS.has(value)) return key + ": " + value;
    if (value.length === 0) return key + ": <empty>";
    return key + ": <" + (value.startsWith("[") ? "array" : value.startsWith("{") ? "object" : "value") + ">";
  }
  if (key === "reason" || key === "status") {
    return /^expected status [01]$/u.test(value) ? key + ": " + value : null;
  }
  return null;
}

export function sanitizeDisposableDiagnostics({
  stdout = "",
  stderr = "",
  outputOverflow = false,
} = {}) {
  const source = [String(stdout), String(stderr)].join("\n")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\b(?:postgres(?:ql)?|mysql|mssql):\/\/[^\s"'<>]+/giu, "[REDACTED]")
    .replace(/\b(?:DATABASE_URL|DATABASE_OPERATOR_URL|DURABLE_OPERATIONS_TEST_DATABASE_URL_[A-Z])\s*=\s*[^\s]+/giu, "[REDACTED]")
    .replace(/\b(?:DSN|PASSWORD|PASSWD|TOKEN|SECRET|API[_-]?KEY|PROVIDER[_-]?ID|PROJECT[_-]?ID|WORKSPACE[_-]?ID)\s*[:=]\s*[^\s]+/giu, "[REDACTED]");
  const lines = [];
  for (const line of source.split(/\r?\n/u)) {
    const projected = projectDiagnosticLine(line);
    if (projected) lines.push(projected);
  }
  const suffix = outputOverflow ? "\n[diagnostic_output_truncated]" : "";
  const bounded = lines.join("\n");
  if (bounded.length + suffix.length <= maxDiagnosticChars) return bounded + suffix;
  return bounded.slice(0, Math.max(0, maxDiagnosticChars - "\n[diagnostic_output_truncated]".length)) + "\n[diagnostic_output_truncated]";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((error) => {
    const phase = typeof error?.phase === "string" ? error.phase : "unknown";
    const diagnostics = typeof error?.diagnostics === "string"
      ? error.diagnostics
      : sanitizeDisposableDiagnostics({ stdout: error?.stdout, stderr: error?.stderr, outputOverflow: error?.outputOverflow });
    process.stderr.write("Disposable PostgreSQL 17 durable-operation runner failed (" + phase + ")." + (diagnostics ? "\n" + diagnostics + "\n" : "\n"));
    process.exitCode = 1;
  });
}

export async function run({ spawnImpl = spawn } = {}) {
  assertNoCallerSuppliedFixture(process.env);
  const ports = [null, null];
  const started = [false, false];
  let primaryError = null;
  let phase = "container-preflight";
  try {
    await Promise.all(containerNames.map((containerName) => assertExactContainerAbsent(spawnImpl, containerName)));
    phase = "container-start";
    for (const [index, containerName] of containerNames.entries()) {
      const startedResult = await runCommand(spawnImpl, "docker", [
        "run", "--detach", "--name", containerName,
        "--publish", "127.0.0.1::5432",
        "--env", "POSTGRES_DB=postgres",
        "--env", "POSTGRES_USER=cloud_admin",
        "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
        "postgres:17",
      ]);
      if (startedResult.code !== 0 || !startedResult.stdout.trim()) throw new Error();
      started[index] = true;
    }
    phase = "port-discovery";
    for (const [index, containerName] of containerNames.entries()) ports[index] = await readPublishedPort(spawnImpl, containerName);
    phase = "postgres-readiness";
    await Promise.all(ports.map((port) => waitForPostgres(port)));
    phase = "database-creation";
    await Promise.all(ports.map((port) => createDatabase(port)));
    phase = "focused-tests";
    await runFocusedTests(spawnImpl, ports);
  } catch (error) {
    primaryError = Object.assign(new Error(), {
      phase,
      diagnostics: typeof error?.diagnostics === "string"
        ? error.diagnostics
        : sanitizeDisposableDiagnostics(),
    });
  }

  let cleanupError = null;
  try {
    await cleanup(spawnImpl, ports, started);
  } catch {
    cleanupError = Object.assign(new Error(), { phase: "cleanup" });
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  process.stdout.write("Disposable PostgreSQL 17 durable-operation proofs: passed.\n");
  return { containers: containerNames, database: databaseName, postgresMajor: 17 };
}

async function runFocusedTests(spawnImpl, ports) {
  const childEnv = { ...process.env };
  for (const key of Object.keys(childEnv)) {
    if (/DATABASE_URL|DATABASE_OPERATOR_URL|DURABLE_OPERATIONS_TEST/u.test(key)) delete childEnv[key];
  }
  childEnv.DURABLE_OPERATIONS_TEST_DATABASE_URL_A = `postgres://cloud_admin@127.0.0.1:${ports[0]}/${databaseName}`;
  childEnv.DURABLE_OPERATIONS_TEST_DATABASE_URL_B = `postgres://cloud_admin@127.0.0.1:${ports[1]}/${databaseName}`;
  const result = await runCommand(spawnImpl, process.execPath, ["--test", "tests/durable-database-operations-postgres.test.mjs"], {
    cwd: rootDir,
    env: childEnv,
    timeoutMs: 180_000,
  });
  if (result.code !== 0 || result.timedOut || result.stdout.includes("fail 1")) {
    throw Object.assign(new Error(), {
      phase: "focused-tests",
      diagnostics: sanitizeDisposableDiagnostics({
        stdout: result.stdout,
        stderr: result.stderr,
        outputOverflow: result.outputOverflow,
      }),
    });
  }
  if (!/(?:#|ℹ)\s+fail 0\b/u.test(result.stdout)) {
    throw Object.assign(new Error(), {
      phase: "focused-tests",
      diagnostics: sanitizeDisposableDiagnostics({
        stdout: result.stdout,
        stderr: result.stderr,
        outputOverflow: result.outputOverflow,
      }),
    });
  }
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

async function readPublishedPort(spawnImpl, containerName) {
  const result = await runCommand(spawnImpl, "docker", ["port", containerName, "5432/tcp"]);
  if (result.code !== 0) throw new Error();
  const match = result.stdout.match(/^127\.0\.0\.1:(\d+)$/mu);
  const port = Number(match?.[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error();
  return port;
}

async function cleanup(spawnImpl, ports, started) {
  for (const [index, port] of ports.entries()) {
    if (started[index] && Number.isInteger(port)) {
      const pool = new Pool({ connectionString: `postgres://cloud_admin@127.0.0.1:${port}/postgres`, max: 1 });
      try {
        await pool.query(`drop database if exists "${databaseName}" with (force)`);
      } finally {
        await pool.end().catch(() => {});
      }
    }
    if (started[index]) {
      const result = await runCommand(spawnImpl, "docker", ["rm", "--force", containerNames[index]]);
      if (result.code !== 0) throw new Error();
    }
  }
  await Promise.all(containerNames.map((containerName) => assertExactContainerAbsent(spawnImpl, containerName)));
  for (const port of ports) if (Number.isInteger(port)) await assertPortAbsent(port);
}

async function assertExactContainerAbsent(spawnImpl, containerName) {
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
