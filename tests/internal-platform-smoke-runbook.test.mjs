import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const runbookPath = "docs/internal-platform-smoke-runbook.md";

test("internal platform smoke runbook covers the existing service assumptions", async () => {
  const runbook = await readRunbook();

  assert.match(runbook, /existing Postgres-compatible database service/i);
  assert.match(runbook, /DATABASE_URL/);
  assert.match(runbook, /does not create or host its own database service/i);
  assert.match(runbook, /does not run migrations automatically/i);
  assert.match(runbook, /npm run db:migrate/);
  assert.match(runbook, /DATABASE_MIGRATIONS_CONFIRM=apply-reviewed-migrations/);
  assert.match(runbook, /existing OIDC provider/i);
  assert.match(runbook, /seed CLI writes records into the already-configured platform database/i);
});

test("internal platform smoke runbook documents the full smoke sequence", async () => {
  const runbook = await readRunbook();
  const requiredPhrases = [
    "npm run build",
    "npm run typecheck",
    "npm test",
    "DATABASE_SSL_MODE",
    "PLATFORM_HTTP_HOST",
    "PLATFORM_PUBLIC_BASE_URL",
    "CSRF_TOKEN_HASH_SECRET",
    "APP_LAUNCH_TOKEN_HASH_SECRET",
    "AUTH_STATE_HASH_SECRET",
    "AUTH_PROVIDER_KEY",
    "AUTH_AUTHORIZATION_URL",
    "AUTH_TOKEN_URL",
    "AUTH_CLIENT_ID",
    "AUTH_CLIENT_SECRET",
    "AUTH_REDIRECT_URI",
    "PLATFORM_AUTH_PROVIDER_MODE=generic_oidc",
    "AUTH_ISSUER_URL",
    "AUTH_JWKS_URL",
    "PLATFORM_SEED_CONFIRM=seed-reviewed-internal-access",
    "PLATFORM_SEED_USER_EMAIL=<email-used-for-login>",
    "PLATFORM_KQAG_LAUNCH_MODE=server_handoff",
    "PLATFORM_KQAG_APP_BASE_URL=<kqag-local-base-url>",
    "Visit `/`",
    "redirects to `/app`",
    "npm run platform:seed-internal-access",
    "Refresh `/app`",
    "Use `127.0.0.1` consistently",
    "open `/app/admin`",
    "Add Existing User",
    "role change",
    "membership disable",
    "entitlement change",
    "Audit/activity browsing remains future scope",
    "existing active provider-backed Platform user",
    "set role to `member` for quote operators",
    "no invitation email is sent",
    "workspace appears",
    "Click the KQAG launch button",
    "without any launch",
    "x-app-launch-token",
    "not in the query string",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase)));
  }
});

test("internal platform smoke runbook documents the explicit start CLI", async () => {
  const runbook = await readRunbook();
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(packageJson.scripts.start, undefined);
  assert.equal(packageJson.scripts["platform:start"], "node scripts/platform-start.mjs");
  assert.match(runbook, /npm run platform:start/);
  assert.match(runbook, /existing Node bootstrap\/runtime boundary/i);
  assert.match(runbook, /does not run migrations/i);
  assert.match(runbook, /does not seed access/i);
  assert.match(runbook, /does not call provider token, JWKS, or userinfo endpoints during startup/i);
  assert.match(runbook, /does not call KQAG during startup/i);
});

test("internal platform smoke runbook covers troubleshooting and hard boundaries", async () => {
  const runbook = await readRunbook();
  const troubleshooting = [
    "DATABASE_URL is required",
    "missing migrations",
    "auth config invalid",
    "auth_start_failure category=<category>",
    "callback state/nonce failures",
    "no session in `/app`",
    "user not found",
    "missing provider identity",
    "`/app` shows no workspace",
    "launch denied",
    "CSRF/origin failure",
    "consumed/expired launch token",
    "KQAG browser launch is not configured",
    "KQAG browser launch could not be completed",
  ];

  for (const phrase of troubleshooting) {
    assert.match(runbook, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.match(runbook, /no fake login/i);
  assert.match(runbook, /no KQAG-owned auth/i);
  assert.match(runbook, /no broad app proxy or open proxy/i);
  assert.match(runbook, /does not create users, provider identities, or sessions/i);
  assert.match(runbook, /does not provision a database service/i);
  assert.match(runbook, /does not deploy/i);
});

test("internal platform smoke runbook uses placeholders and avoids private material", async () => {
  const runbook = await readRunbook();

  assert.doesNotMatch(runbook, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(runbook, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(runbook, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(runbook, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(runbook, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(runbook, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(runbook, /logo_data_url|data:image|pricing file|quote export/i);
  assert.doesNotMatch(runbook, /@[A-Za-z0-9.-]+\.(?:com|net|org|io|co)\b/);
  assert.match(runbook, /<database-url-from-existing-service>/);
  assert.match(runbook, /<strong-random-placeholder>/);
  assert.match(runbook, /<email-used-for-login>/);
  assert.match(runbook, /<kqag-local-base-url>/);
  assert.match(runbook, /<launch-token-from-immediate-handoff>/);
});

test("README and roadmap link the internal smoke runbook", async () => {
  const readme = await readFile("README.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");

  assert.match(readme, /docs\/internal-platform-smoke-runbook\.md/);
  assert.match(roadmap, /internal platform smoke runbook/i);
  assert.match(roadmap, /operational smoke/i);
});

test("runbook change does not add forbidden scope imports or scripts", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const scripts = JSON.stringify(packageJson.scripts);

  assert.doesNotMatch(scripts, /deploy|provision|docker|stripe|kqag/i);
  assert.doesNotMatch(scripts, /start:platform/i);

  const runbook = await readRunbook();
  assert.doesNotMatch(runbook, /next\.js|vite|react|express|fastify|hono/i);
  assert.doesNotMatch(runbook, /clerk|auth0|supabase|stripe/i);
});

async function readRunbook() {
  return readFile(runbookPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
