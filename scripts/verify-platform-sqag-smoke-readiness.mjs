#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const platformSqagSmokeReadinessSchema =
  "platform_sqag_synthetic_smoke_readiness_v1";

export const platformSqagSmokeReadinessTestFiles = Object.freeze([
  "tests/http-node-adapter.test.mjs",
  "tests/platform-seed-internal-access-cli.test.mjs",
  "tests/sqag-integration-contract.test.mjs",
  "tests/db-schema.test.mjs",
]);

const coveredChecks = Object.freeze({
  launch_open_sqag_covered: true,
  old_app_key_rejection_covered: true,
  header_only_token_covered: true,
  safe_consume_context_covered: true,
  seed_app_identity_override_rejection_covered: true,
  migration_rewires_sqag_app_key_covered: true,
});

export function runPlatformSqagSmokeReadinessCheck({
  runner = runNodeTestFiles,
  cwd = process.cwd(),
  stdout = console.log,
  stderr = console.error,
} = {}) {
  const result = runner(platformSqagSmokeReadinessTestFiles, { cwd });
  const passed = result.ok === true;
  const report = {
    schema: platformSqagSmokeReadinessSchema,
    status: passed ? "passed" : "failed",
    synthetic_smoke_readiness_supported: passed,
    test_files_checked: platformSqagSmokeReadinessTestFiles.length,
    ...coveredChecks,
    live_services_used: false,
    hosted_oauth_configured: false,
    hosted_platform_sqag_smoke_passed: false,
    production_ready: false,
    blockers: passed ? [] : ["synthetic_platform_sqag_smoke_readiness_tests_failed"],
  };

  for (const line of formatPlatformSqagSmokeReadinessReport(report)) {
    if (passed) {
      stdout(line);
    } else {
      stderr(line);
    }
  }

  return {
    exitCode: passed ? 0 : 1,
    report,
  };
}

export function runNodeTestFiles(testFiles, { cwd = process.cwd() } = {}) {
  const result = spawnSync(process.execPath, ["--test", ...testFiles], {
    cwd,
    encoding: "utf8",
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  return {
    ok: result.status === 0,
    exitCode: typeof result.status === "number" ? result.status : 1,
  };
}

export function formatPlatformSqagSmokeReadinessReport(report) {
  return [
    `schema=${report.schema}`,
    `status=${report.status}`,
    `synthetic_smoke_readiness_supported=${String(report.synthetic_smoke_readiness_supported)}`,
    `test_files_checked=${String(report.test_files_checked)}`,
    `launch_open_sqag_covered=${String(report.launch_open_sqag_covered)}`,
    `old_app_key_rejection_covered=${String(report.old_app_key_rejection_covered)}`,
    `header_only_token_covered=${String(report.header_only_token_covered)}`,
    `safe_consume_context_covered=${String(report.safe_consume_context_covered)}`,
    `seed_app_identity_override_rejection_covered=${String(
      report.seed_app_identity_override_rejection_covered,
    )}`,
    `migration_rewires_sqag_app_key_covered=${String(
      report.migration_rewires_sqag_app_key_covered,
    )}`,
    `live_services_used=${String(report.live_services_used)}`,
    `hosted_oauth_configured=${String(report.hosted_oauth_configured)}`,
    `hosted_platform_sqag_smoke_passed=${String(
      report.hosted_platform_sqag_smoke_passed,
    )}`,
    `production_ready=${String(report.production_ready)}`,
    `blockers=${report.blockers.length === 0 ? "none" : report.blockers.join(",")}`,
  ];
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { exitCode } = runPlatformSqagSmokeReadinessCheck();
  process.exitCode = exitCode;
}
