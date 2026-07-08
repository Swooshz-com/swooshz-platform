import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  formatPlatformSqagSmokeReadinessReport,
  platformSqagSmokeReadinessSchema,
  platformSqagSmokeReadinessTestFiles,
  runPlatformSqagSmokeReadinessCheck,
} from "../scripts/verify-platform-sqag-smoke-readiness.mjs";

test("package exposes a deterministic SQAG synthetic smoke readiness command", async () => {
  const pkg = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(
    pkg.scripts["platform:sqag-smoke-readiness"],
    "npm run build && node scripts/verify-platform-sqag-smoke-readiness.mjs",
  );
});

test("SQAG synthetic smoke readiness command covers launch consume seed docs and migration", () => {
  assert.deepEqual(platformSqagSmokeReadinessTestFiles, [
    "tests/http-node-adapter.test.mjs",
    "tests/platform-seed-internal-access-cli.test.mjs",
    "tests/sqag-integration-contract.test.mjs",
    "tests/db-schema.test.mjs",
  ]);
});

test("SQAG synthetic smoke readiness success output is sanitized and keeps production not ready", () => {
  const stdout = [];
  const stderr = [];
  const result = runPlatformSqagSmokeReadinessCheck({
    runner: () => ({ ok: true, exitCode: 0 }),
    stdout: (line) => stdout.push(line),
    stderr: (line) => stderr.push(line),
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.report.schema, platformSqagSmokeReadinessSchema);
  assert.equal(result.report.status, "passed");
  assert.equal(result.report.synthetic_smoke_readiness_supported, true);
  assert.equal(result.report.launch_open_sqag_covered, true);
  assert.equal(result.report.old_app_key_rejection_covered, true);
  assert.equal(result.report.header_only_token_covered, true);
  assert.equal(result.report.safe_consume_context_covered, true);
  assert.equal(result.report.seed_app_identity_override_rejection_covered, true);
  assert.equal(result.report.migration_rewires_sqag_app_key_covered, true);
  assert.equal(result.report.live_services_used, false);
  assert.equal(result.report.hosted_platform_sqag_smoke_passed, false);
  assert.equal(result.report.production_ready, false);
  assert.deepEqual(result.report.blockers, []);
  assert.deepEqual(stderr, []);

  const output = stdout.join("\n");
  assert.match(output, /status=passed/);
  assert.match(output, /production_ready=false/);
  assert.match(output, /blockers=none/);
  assertSanitized(output);
});

test("SQAG synthetic smoke readiness failure output is sanitized and blocked from readiness", () => {
  const stdout = [];
  const stderr = [];
  const result = runPlatformSqagSmokeReadinessCheck({
    runner: () => ({ ok: false, exitCode: 1 }),
    stdout: (line) => stdout.push(line),
    stderr: (line) => stderr.push(line),
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.report.status, "failed");
  assert.equal(result.report.synthetic_smoke_readiness_supported, false);
  assert.equal(result.report.production_ready, false);
  assert.deepEqual(result.report.blockers, [
    "synthetic_platform_sqag_smoke_readiness_tests_failed",
  ]);
  assert.deepEqual(stdout, []);

  const output = stderr.join("\n");
  assert.match(output, /status=failed/);
  assert.match(output, /hosted_platform_sqag_smoke_passed=false/);
  assert.match(output, /production_ready=false/);
  assertSanitized(output);
});

test("SQAG synthetic smoke readiness script does not print child test output", async () => {
  const script = await readFile(
    "scripts/verify-platform-sqag-smoke-readiness.mjs",
    "utf8",
  );

  assert.match(script, /stdio: \["ignore", "pipe", "pipe"\]/);
  assert.doesNotMatch(script, /console\.log\(result\.stdout|console\.error\(result\.stderr/);
  assertSanitized(script);
});

function assertSanitized(value) {
  assert.doesNotMatch(value, /postgres(?:ql)?:\/\/[^\s]+/i);
  assert.doesNotMatch(value, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(value, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(value, /github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(value, /ghp_[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(value, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /cookie[=:][A-Za-z0-9._=-]{20,}/i);
  assert.doesNotMatch(value, /C:\\Users\\|\/Users\/|\/home\//i);
}
