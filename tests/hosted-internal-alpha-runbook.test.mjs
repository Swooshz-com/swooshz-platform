import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const runbookPath = "docs/hosted-internal-alpha-runbook.md";

test("hosted internal alpha runbook covers deployment operations", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "# Hosted Internal Alpha Runbook",
    "<hosted-platform-base-url>",
    "<hosted-kqag-base-url>",
    "<hosted-oidc-redirect-uri>",
    "PostgreSQL",
    "npm run db:migrate",
    "DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations",
    "Migrations are never automatic on app startup",
    "backup",
    "restore",
    "rollback",
    "`GET /healthz`",
    "log review",
    "process manager",
    "container",
    "TLS",
    "reverse proxy",
    "Secrets And Env Checklist",
    "Hosted readiness requires `NODE_ENV=production`",
    "HTTPS browser/provider-facing URLs",
    "origin-only allowed origins",
    "`AUTH_REDIRECT_URI` ends with `/api/platform/auth/callback`",
    "cross-host session and cookie behavior remains an operator review",
    "first owner/admin bootstrap",
    "add-existing-user",
    "KQAG entitlement",
    "audit/activity verification",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted internal alpha runbook has an env checklist with safe examples and secret classification", async () => {
  const runbook = await readRunbook();

  assert.match(
    runbook,
    /\|\s*Env var\s*\|\s*Purpose\s*\|\s*Required\s*\|\s*Safe example\s*\|\s*Secret\s*\|\s*Validation \/ failure behavior\s*\|/i,
  );

  const expectedRows = [
    ["NODE_ENV", "Required", "No"],
    ["PLATFORM_HTTP_HOST", "Required", "No"],
    ["PLATFORM_HTTP_PORT", "Required", "No"],
    ["PLATFORM_PUBLIC_BASE_URL", "Required", "No"],
    ["PLATFORM_ALLOWED_ORIGINS", "Required", "No"],
    ["PLATFORM_COOKIE_SECURE", "Required", "No"],
    ["DATABASE_URL", "Required", "Yes"],
    ["DATABASE_SSL_MODE", "Optional", "No"],
    ["DATABASE_MIGRATIONS_CONFIRM", "Required for migrations only", "No"],
    ["SESSION_SECRET", "Required", "Yes"],
    ["CSRF_TOKEN_HASH_SECRET", "Required", "Yes"],
    ["AUTH_STATE_HASH_SECRET", "Required", "Yes"],
    ["APP_LAUNCH_TOKEN_HASH_SECRET", "Required", "Yes"],
    ["PLATFORM_AUTH_PROVIDER_MODE", "Required", "No"],
    ["AUTH_PROVIDER_KEY", "Required", "No"],
    ["AUTH_ISSUER_URL", "Required", "No"],
    ["AUTH_AUTHORIZATION_URL", "Required", "No"],
    ["AUTH_TOKEN_URL", "Required", "No"],
    ["AUTH_JWKS_URL", "Required", "No"],
    ["AUTH_USERINFO_URL", "Optional", "No"],
    ["AUTH_CLIENT_ID", "Required", "No"],
    ["AUTH_CLIENT_SECRET", "Required", "Yes"],
    ["AUTH_REDIRECT_URI", "Required", "No"],
    ["AUTH_ALLOWED_EMAILS", "Required", "No"],
    ["AUTH_ALLOWED_DOMAINS", "Optional", "No"],
    ["PLATFORM_KQAG_LAUNCH_MODE", "Required", "No"],
    ["PLATFORM_KQAG_APP_BASE_URL", "Required when server_handoff", "No"],
    ["PLATFORM_SEED_CONFIRM", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_USER_EMAIL", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_MEMBERSHIP_ROLE", "Optional", "No"],
  ];

  for (const [name, required, secret] of expectedRows) {
    assertEnvRow(runbook, name, required, secret);
  }

  assert.match(runbook, /<strong-random-placeholder>/);
  assert.match(runbook, /<database-url-from-secret-store>/);
  assert.match(runbook, /<hosted-owner-admin-email-after-login>/);
  assert.match(runbook, /<comma-separated-allowlisted-emails>/);
});

test("hosted internal alpha smoke checklist covers fail-closed access and token privacy", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "server starts without importing/listening side effects",
    "`/healthz`",
    "auth start/callback shape",
    "without printing secrets",
    "login session context",
    "`/app`",
    "`/app/admin`",
    "add existing user by email after teammate signs in once",
    "role change",
    "membership disable",
    "membership reactivation",
    "KQAG entitlement enable/disable",
    "audit/activity shows admin events",
    "no raw token in browser URL, storage, or logs",
    "logout",
    "denied member/viewer admin access",
    "missing, expired, or disabled session fail closed",
    "what not to paste into tickets/screenshots/logs",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("hosted internal alpha docs are linked from repo docs", async () => {
  const readme = await readFile("README.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");
  const contract = await readFile("docs/internal-alpha-platform-contract.md", "utf8");

  assert.match(readme, /docs\/hosted-internal-alpha-runbook\.md/);
  assert.match(roadmap, /hosted internal-alpha deployment runbook/i);
  assert.match(roadmap, /readiness check hardened for production mode, HTTPS browser\/provider URLs/i);
  assert.match(contract, /hosted deployment runbook and smoke checklist are now documented/i);
  assert.match(contract, /hardened hosted-readiness guardrails/i);
  assert.match(contract, /Actual hosted deployment execution still requires reviewed infra\/operator approval/i);
});

test("hosted internal alpha runbook avoids private material and unsafe callback examples", async () => {
  const runbook = await readRunbook();

  assert.doesNotMatch(runbook, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(runbook, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(runbook, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(runbook, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(runbook, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(runbook, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(runbook, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(runbook, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(runbook, /raw claims|raw provider claims|provider payload/i);
  assert.doesNotMatch(runbook, /quote session|quote artifact|pricing file|quotation\.xlsx/i);
  assert.doesNotMatch(runbook, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(runbook, /127\.0\.0\.1/);
});

async function readRunbook() {
  return readFile(runbookPath, "utf8");
}

function assertEnvRow(runbook, name, required, secret) {
  assert.match(
    runbook,
    new RegExp(
      `\\|\\s*\`${escapeRegExp(name)}\`\\s*\\|[^\\n]*\\|\\s*${escapeRegExp(required)}\\s*\\|[^\\n]*\\|\\s*${escapeRegExp(secret)}\\s*\\|`,
      "i",
    ),
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
