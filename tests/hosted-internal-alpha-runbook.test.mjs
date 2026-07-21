import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const runbookPath = "docs/hosted-internal-alpha-runbook.md";

test("hosted internal alpha runbook covers deployment operations", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "# Hosted Internal Alpha Runbook",
    "https://swooshz.com",
    "https://www.swooshz.com",
    "https://quote.swooshz.com",
    "https://swooshz.com/api/platform/auth/callback",
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
    "Hostinger VPS And Coolify Deployment Readiness",
    "https://swooshz.com",
    "Platform PR #79 landed at merge commit `c65bf67078031921f5b4ce73f03455804eb2fd07`",
    "Build command: `npm run build`",
    "Start command: `npm run platform:start`",
    "Health check path: `/healthz`",
    "Do not add Coolify build hooks, deploy hooks, startup hooks",
    "TLS",
    "reverse proxy",
    "Secrets And Env Checklist",
    "Hosted readiness requires `NODE_ENV=production`",
    "HTTPS browser/provider-facing URLs",
    "origin-only allowed origins",
    "Neon Hosted Postgres Readiness",
    "Project: `swooshz-platform`",
    "Region: `Singapore / aws-ap-southeast-1`",
    "Database: `swooshz_platform`",
    "Role/user: `platform_app`",
    "pooled `DATABASE_URL`",
    "`npm run platform:db-readiness-check`",
    "`db_config_missing`",
    "`db_unreachable`",
    "`schema_not_ready`",
    "`ready`",
    "Direct URL only if migration tooling genuinely needs it",
    "readiness only, not full production readiness",
    "`AUTH_REDIRECT_URI` ends with `/api/platform/auth/callback`",
    "host-only cookie/finalization flow is smoke tested",
    "Sanitized Neon Migration Evidence",
    "Pre-migration DB readiness: `schema_not_ready`",
    "guarded manual migration through `npm run db:migrate`",
    "Post-migration DB readiness: `ready`",
    "This evidence does not approve hosted deployment or full production readiness",
    "first owner/admin bootstrap",
    "pending workspace approval",
    "SQAG entitlement",
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
    ["PLATFORM_SQAG_LAUNCH_MODE", "Required", "No"],
    ["PLATFORM_SQAG_APP_BASE_URL", "Required when server_handoff", "No"],
    ["PLATFORM_SEED_CONFIRM", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_USER_EMAIL", "Required for bootstrap only", "No"],
    ["PLATFORM_SEED_BOOTSTRAP_MODE", "Optional bootstrap only", "No"],
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

test("hosted internal alpha runbook covers Hostinger Coolify readiness without deployment config", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "future Hostinger VPS plus Coolify execution window",
    "does not buy or create VPS resources",
    "does not buy or create VPS resources, configure DNS, deploy the app",
    "already migrated Neon target",
    "pooled `DATABASE_URL`",
    "Deploy-time env categories",
    "Non-secret operator choices",
    "Secret values",
    "Private allowlist values",
    "Migration-only values",
    "Bootstrap-only values",
    "Product handoff configuration",
    "`PLATFORM_COOKIE_SECURE=true`",
    "explicit origins, not wildcard values",
    "one-off manual migration command",
    "must not become env-controlled business/admin state",
    "product workflow/runtime data remains outside Platform",
    "sanitized status `ready`",
    "Do not keep on the long-running Coolify app service",
    "Prefer redeploying the previous reviewed app build",
    "Use database restore only after backup/restore owner approval",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(runbook, /coolify\.ya?ml|docker-compose\.ya?ml|Dockerfile/i);
  assert.doesNotMatch(runbook, /coolify deploy --|hostinger deploy --|dns record type/i);
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
    "create pending workspace approval before teammate sign-in",
    "real OIDC sign-in activates the pending approval",
    "role change",
    "membership disable",
    "membership reactivation",
    "SQAG entitlement enable/disable",
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
