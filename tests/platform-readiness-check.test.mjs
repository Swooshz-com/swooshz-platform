import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createPlatformReadinessReport,
  runPlatformReadinessCheck,
} from "../scripts/platform-readiness-check.mjs";

const privateValues = [
  "<private-database-url-placeholder>",
  "private-session-secret-value-32-chars",
  "private-client-secret-value-32-chars",
  "private-csrf-secret-value-32-chars",
  "private-auth-state-secret-value-32-chars",
  "private-launch-secret-value-32-chars",
];

const privateOutputProbeValues = [
  ["postgres", "ql://private-user:private-pass@private-host/private-db"].join(""),
  ["private-oauth-access-token-", "abcdefghijklmnopqrstuvwxyz"].join(""),
  ["private-cookie-session-", "abcdefghijklmnopqrstuvwxyz"].join(""),
  ["provider-subject-", "abcdefghijklmnopqrstuvwxyz"].join(""),
  ["private.staff", "@example.invalid"].join(""),
  ["https://platform.private.invalid/api/platform/auth/callback", "?code=private-code"].join(""),
];

test("platform readiness check package script exists", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(packageJson.scripts["platform:readiness-check"], "node scripts/platform-readiness-check.mjs");
});

test("readiness check passes for complete hosted internal-alpha env without printing values", () => {
  const lines = [];
  const result = runPlatformReadinessCheck({
    env: completeEnv(),
    writeLine(line) {
      lines.push(line);
    },
    writeError(line) {
      lines.push(line);
    },
  });

  assert.equal(result.ok, true);
  assert.match(lines.join("\n"), /readiness_check=pass/);
  assert.match(lines.join("\n"), /manual_migrations=explicit/);
  assertNoPrivateMaterial(lines.join("\n"));
});

test("readiness check accepts multiple HTTPS origin entries with optional ports", () => {
  const result = createPlatformReadinessReport({
    ...completeEnv(),
    PLATFORM_ALLOWED_ORIGINS: [
      "https://platform.placeholder.invalid",
      "https://platform.placeholder.invalid:8443",
    ].join(","),
  });

  assert.equal(result.ok, true);
});

test("readiness check fails with safe missing and invalid env names only", () => {
  const lines = [];
  const result = runPlatformReadinessCheck({
    env: {
      NODE_ENV: "production",
      DATABASE_URL: privateValues[0],
      SESSION_SECRET: "short",
      AUTH_CLIENT_SECRET: privateValues[2],
      PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    },
    writeLine(line) {
      lines.push(line);
    },
    writeError(line) {
      lines.push(line);
    },
  });

  const output = lines.join("\n");

  assert.equal(result.ok, false);
  assert.match(output, /readiness_check=fail/);
  assert.match(output, /missing required env: PLATFORM_PUBLIC_BASE_URL/);
  assert.match(output, /invalid secret env: SESSION_SECRET/);
  assert.match(output, /missing conditional env: PLATFORM_KQAG_APP_BASE_URL/);
  assertNoPrivateMaterial(output);
});

test("hosted readiness requires production NODE_ENV", () => {
  for (const mode of ["development", "test"]) {
    const report = reportWithOverride({ NODE_ENV: mode });

    assert.equal(report.ok, false);
    assertInvalid(report, "NODE_ENV", "hosted_requires_production");
  }
});

test("hosted browser and provider URLs must use https without echoing values", () => {
  const httpsOnlyCases = [
    ["PLATFORM_PUBLIC_BASE_URL", "http://platform.placeholder.invalid"],
    ["PLATFORM_ALLOWED_ORIGINS", "http://platform.placeholder.invalid"],
    ["AUTH_REDIRECT_URI", "http://platform.placeholder.invalid/api/platform/auth/callback"],
    ["AUTH_ISSUER_URL", "http://issuer.placeholder.invalid"],
    ["AUTH_AUTHORIZATION_URL", "http://issuer.placeholder.invalid/oauth2/authorize"],
    ["AUTH_TOKEN_URL", "http://issuer.placeholder.invalid/oauth2/token"],
    ["AUTH_JWKS_URL", "http://issuer.placeholder.invalid/.well-known/jwks.json"],
    ["AUTH_USERINFO_URL", "http://issuer.placeholder.invalid/oauth2/userinfo"],
    ["PLATFORM_KQAG_APP_BASE_URL", "http://kqag.placeholder.invalid"],
  ];

  for (const [name, value] of httpsOnlyCases) {
    const lines = [];
    const result = runPlatformReadinessCheck({
      env: reportEnvWithOverride({ [name]: value }),
      writeLine(line) {
        lines.push(line);
      },
      writeError(line) {
        lines.push(line);
      },
    });
    const output = lines.join("\n");

    assert.equal(result.ok, false);
    assertInvalid(result, name, "must_be_https");
    assert.match(output, new RegExp(`invalid env: ${name}`));
    assert.doesNotMatch(output, new RegExp(escapeRegExp(value)));
    assertNoPrivateMaterial(output);
  }
});

test("hosted readiness rejects unsafe URL and origin shapes", () => {
  const callbackBase = "https://platform.placeholder.invalid/api/platform/auth/callback";
  const shapeCases = [
    [
      "PLATFORM_ALLOWED_ORIGINS",
      "https://platform.placeholder.invalid/path",
      "must_be_origin",
    ],
    [
      "PLATFORM_ALLOWED_ORIGINS",
      "https://platform.placeholder.invalid?debug=1",
      "must_be_origin",
    ],
    [
      "PLATFORM_ALLOWED_ORIGINS",
      "https://platform.placeholder.invalid#fragment",
      "must_be_origin",
    ],
    [
      "PLATFORM_PUBLIC_BASE_URL",
      "https://platform.placeholder.invalid?debug=1",
      "query_or_fragment_not_allowed",
    ],
    [
      "PLATFORM_PUBLIC_BASE_URL",
      "https://platform.placeholder.invalid#fragment",
      "query_or_fragment_not_allowed",
    ],
    [
      "AUTH_REDIRECT_URI",
      [callbackBase, "?code=private-code"].join(""),
      "query_or_fragment_not_allowed",
    ],
    [
      "AUTH_REDIRECT_URI",
      [callbackBase, "#fragment"].join(""),
      "query_or_fragment_not_allowed",
    ],
    [
      "AUTH_REDIRECT_URI",
      "https://platform.placeholder.invalid/api/platform/auth/wrong-callback",
      "must_end_with_platform_auth_callback",
    ],
  ];

  for (const [name, value, reason] of shapeCases) {
    const report = reportWithOverride({ [name]: value });

    assert.equal(report.ok, false);
    assertInvalid(report, name, reason);
  }
});

test("readiness report treats KQAG base URL as conditional on server handoff", () => {
  const manual = createPlatformReadinessReport({
    ...completeEnv(),
    PLATFORM_KQAG_LAUNCH_MODE: "manual",
    PLATFORM_KQAG_APP_BASE_URL: "",
  });
  const handoff = createPlatformReadinessReport({
    ...completeEnv(),
    PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_KQAG_APP_BASE_URL: "",
  });

  assert.equal(manual.ok, true);
  assert.equal(handoff.ok, false);
  assert.deepEqual(
    handoff.missingConditional.map((entry) => entry.name),
    ["PLATFORM_KQAG_APP_BASE_URL"],
  );
});

test("server handoff requires an HTTPS KQAG base URL without query or fragment", () => {
  const http = reportWithOverride({
    PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_KQAG_APP_BASE_URL: "http://kqag.placeholder.invalid",
  });
  const query = reportWithOverride({
    PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_KQAG_APP_BASE_URL: "https://kqag.placeholder.invalid?debug=1",
  });
  const fragment = reportWithOverride({
    PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_KQAG_APP_BASE_URL: "https://kqag.placeholder.invalid#fragment",
  });

  assert.equal(http.ok, false);
  assertInvalid(http, "PLATFORM_KQAG_APP_BASE_URL", "must_be_https");
  assert.equal(query.ok, false);
  assertInvalid(query, "PLATFORM_KQAG_APP_BASE_URL", "query_or_fragment_not_allowed");
  assert.equal(fragment.ok, false);
  assertInvalid(fragment, "PLATFORM_KQAG_APP_BASE_URL", "query_or_fragment_not_allowed");
});

test("readiness output never prints private-looking env values", () => {
  const lines = [];
  const result = runPlatformReadinessCheck({
    env: reportEnvWithOverride({
      DATABASE_URL: privateOutputProbeValues[0],
      SESSION_SECRET: privateOutputProbeValues[1],
      AUTH_CLIENT_SECRET: privateOutputProbeValues[2],
      AUTH_ALLOWED_EMAILS: privateOutputProbeValues[4],
      AUTH_REDIRECT_URI: privateOutputProbeValues[5],
    }),
    writeLine(line) {
      lines.push(line);
    },
    writeError(line) {
      lines.push(line);
    },
  });
  const output = lines.join("\n");

  assert.equal(result.ok, false);
  assertNoPrivateMaterial(output);
});

test("readiness check reports optional bootstrap env without failing runtime readiness", () => {
  const report = createPlatformReadinessReport({
    ...completeEnv(),
    PLATFORM_SEED_CONFIRM: "",
    PLATFORM_SEED_USER_EMAIL: "",
    PLATFORM_SEED_MEMBERSHIP_ROLE: "",
  });

  assert.equal(report.ok, true);
  assert.ok(report.missingOptional.some((entry) => entry.name === "PLATFORM_SEED_CONFIRM"));
  assert.ok(report.missingOptional.some((entry) => entry.name === "PLATFORM_SEED_USER_EMAIL"));
});

test("readiness script stays dry-run and does not import migration server or network code", async () => {
  const source = await readFile("scripts/platform-readiness-check.mjs", "utf8");

  assert.doesNotMatch(source, /db-migrate|platform-start|createPlatformNodeBootstrap/i);
  assert.doesNotMatch(source, /createDatabaseClient|createDatabasePool|drizzle|pg\b|migrate\(/i);
  assert.doesNotMatch(source, /node:http|node:https|listen\(|fetch\(/i);
  assert.doesNotMatch(source, /process\.env\.DATABASE_URL/);
});

function completeEnv() {
  return {
    NODE_ENV: "production",
    PLATFORM_HTTP_HOST: "0.0.0.0",
    PLATFORM_HTTP_PORT: "4317",
    PLATFORM_PUBLIC_BASE_URL: "https://platform.placeholder.invalid",
    PLATFORM_ALLOWED_ORIGINS: "https://platform.placeholder.invalid",
    PLATFORM_COOKIE_SECURE: "true",
    DATABASE_URL: privateValues[0],
    DATABASE_SSL_MODE: "require",
    DATABASE_MIGRATIONS_CONFIRM: "apply-reviewed-migrations",
    SESSION_SECRET: privateValues[1],
    CSRF_TOKEN_HASH_SECRET: privateValues[3],
    AUTH_STATE_HASH_SECRET: privateValues[4],
    APP_LAUNCH_TOKEN_HASH_SECRET: privateValues[5],
    PLATFORM_AUTH_PROVIDER_MODE: "generic_oidc",
    AUTH_PROVIDER_KEY: "google",
    AUTH_ISSUER_URL: "https://issuer.placeholder.invalid",
    AUTH_AUTHORIZATION_URL: "https://issuer.placeholder.invalid/oauth2/authorize",
    AUTH_TOKEN_URL: "https://issuer.placeholder.invalid/oauth2/token",
    AUTH_JWKS_URL: "https://issuer.placeholder.invalid/.well-known/jwks.json",
    AUTH_USERINFO_URL: "https://issuer.placeholder.invalid/oauth2/userinfo",
    AUTH_CLIENT_ID: "placeholder-client-id",
    AUTH_CLIENT_SECRET: privateValues[2],
    AUTH_REDIRECT_URI: "https://platform.placeholder.invalid/api/platform/auth/callback",
    AUTH_ALLOWED_EMAILS: "<comma-separated-allowlisted-emails>",
    AUTH_ALLOWED_DOMAINS: "",
    PLATFORM_KQAG_LAUNCH_MODE: "server_handoff",
    PLATFORM_KQAG_APP_BASE_URL: "https://kqag.placeholder.invalid",
    PLATFORM_SEED_CONFIRM: "seed-reviewed-internal-access",
    PLATFORM_SEED_USER_EMAIL: "<hosted-owner-admin-email-after-login>",
    PLATFORM_SEED_MEMBERSHIP_ROLE: "owner",
  };
}

function reportEnvWithOverride(overrides) {
  return {
    ...completeEnv(),
    ...overrides,
  };
}

function reportWithOverride(overrides) {
  return createPlatformReadinessReport(reportEnvWithOverride(overrides));
}

function assertInvalid(report, name, reason) {
  const entry = report.invalid.find((item) => item.name === name);

  assert.ok(entry, `${name} should be invalid`);
  assert.equal(entry.reason, reason);
}

function assertNoPrivateMaterial(output) {
  for (const value of [...privateValues, ...privateOutputProbeValues]) {
    assert.doesNotMatch(output, new RegExp(escapeRegExp(value)));
  }

  assert.doesNotMatch(output, /private-user|private-pass|private-host|private-db/);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
