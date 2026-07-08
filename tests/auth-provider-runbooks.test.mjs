import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const providerSelectionPath = "docs/auth-provider-selection.md";
const googleRunbookPath = "docs/google-oidc-setup-runbook.md";
const workosNotesPath = "docs/workos-authkit-fit-notes.md";

test("external auth provider docs exist and are linked", async () => {
  const readme = await readFile("README.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");

  for (const path of [providerSelectionPath, googleRunbookPath, workosNotesPath]) {
    await assert.doesNotReject(() => readFile(path, "utf8"));
    assert.match(readme, new RegExp(escapeRegExp(path)));
    assert.match(roadmap, new RegExp(escapeRegExp(path)));
  }
});

test("provider selection doc preserves platform ownership and one-provider runtime boundaries", async () => {
  const doc = await readFile(providerSelectionPath, "utf8");

  assert.match(doc, /external auth provider proves identity/i);
  assert.match(doc, /Swooshz Platform owns users/i);
  assert.match(doc, /platform sessions/i);
  assert.match(doc, /workspaces, memberships, roles/i);
  assert.match(doc, /app access decisions/i);
  assert.match(doc, /app launch tokens/i);
  assert.match(doc, /one active generic OIDC provider through environment configuration/i);
  assert.match(doc, /Do not implement true active multi-provider login/i);
  assert.match(doc, /Do not build platform-owned email\/password auth/i);
  assert.match(doc, /Do not add fake login/i);
  assert.match(doc, /Google OIDC is the first practical smoke target/i);
  assert.match(doc, /WorkOS\/AuthKit is a strong future B2B\/hosted-auth candidate/i);
  assert.match(doc, /provider subject ids differ/i);
  assert.match(doc, /Future active multi-provider login should be a separate architecture PR/i);
});

test("Google OIDC runbook documents exact endpoint env mapping with placeholders", async () => {
  const doc = await readFile(googleRunbookPath, "utf8");
  const requiredEnv = [
    "PLATFORM_AUTH_PROVIDER_MODE=generic_oidc",
    "AUTH_PROVIDER_KEY=google",
    "AUTH_ISSUER_URL=https://accounts.google.com",
    "AUTH_AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth",
    "AUTH_TOKEN_URL=https://oauth2.googleapis.com/token",
    "AUTH_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs",
    "AUTH_USERINFO_URL=https://openidconnect.googleapis.com/v1/userinfo",
    "AUTH_CLIENT_ID=<google-oauth-client-id>",
    "AUTH_CLIENT_SECRET=<google-oauth-client-secret>",
    "AUTH_REDIRECT_URI=<platform-base-url>/api/platform/auth/callback",
    "AUTH_ALLOWED_EMAILS=<comma-separated-invited-emails>",
    "AUTH_ALLOWED_DOMAINS=<comma-separated-allowed-domains>",
  ];

  for (const envLine of requiredEnv) {
    assert.match(doc, new RegExp(escapeRegExp(envLine)));
  }

  assert.match(doc, /DATABASE_URL=<database-url-from-existing-service>/);
  assert.match(doc, /SESSION_SECRET=<strong-random-placeholder>/);
  assert.match(doc, /CSRF_TOKEN_HASH_SECRET=<strong-random-placeholder>/);
  assert.match(doc, /APP_LAUNCH_TOKEN_HASH_SECRET=<strong-random-placeholder>/);
  assert.match(doc, /AUTH_STATE_HASH_SECRET=<strong-random-placeholder>/);
});

test("Google OIDC runbook covers setup, security posture, smoke flow, and troubleshooting", async () => {
  const doc = await readFile(googleRunbookPath, "utf8");
  const requiredPhrases = [
    "Google proves identity through OIDC",
    "Swooshz Platform still owns users, sessions, workspaces, memberships, roles, app access, app entitlements, invitations, and app launch tokens",
    "Google does not own workspace roles or SQAG access",
    "Use External audience if personal Google accounts or Gmail accounts need to log in",
    "Use Internal audience only if testing is limited to Google Workspace organization accounts",
    "openid",
    "email",
    "profile",
    "With personal Gmail, Swooshz cannot enforce the user's Google 2FA policy",
    "Google Workspace, administrators can enforce 2-Step Verification",
    "exact `AUTH_ALLOWED_EMAILS` is preferred over open domain allow",
    "Do not use broad domain allow unless intentionally approved",
    "Do not commit `.env` files or real provider secrets",
    "docs/internal-platform-smoke-runbook.md",
    "npm run platform:start",
    "Complete Google login",
    "redirects to `/app`",
    "npm run platform:seed-internal-access",
    "redirect_uri_mismatch",
    "callback state or nonce failure",
    "Seed says user not found",
    "Seed says missing provider identity",
    "`/app` has a session but no workspace or app access",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("WorkOS/AuthKit notes keep WorkOS future-only and require provider fit review", async () => {
  const doc = await readFile(workosNotesPath, "utf8");
  const requiredPhrases = [
    "potential future hosted-auth provider candidate",
    "stronger than plain Google OAuth for B2B",
    "Do not wire WorkOS runtime integration in this PR",
    "Do not implement active multi-provider login in this PR",
    "A future provider-fit PR should verify",
    "OIDC/OAuth endpoints",
    "issuer URL",
    "authorization URL",
    "token URL",
    "JWKS URL",
    "userinfo or claims shape",
    "provider subject stability",
    "verified email semantics",
    "MFA policy support",
    "organization and team model interaction with the Swooshz-owned workspace model",
    "redirect and callback constraints",
    "local and internal smoke steps",
    "pricing and plan assumptions at decision time",
    "Swooshz Platform should still own users, sessions, workspaces, memberships, roles, app access, app entitlements, invitations, and app launch tokens",
    "provider subject ids differ",
    "matching email address is not enough",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("external auth docs avoid real secrets private data and provider payload examples", async () => {
  const docs = await readExternalAuthDocs();
  const combined = docs.join("\n");

  assert.doesNotMatch(combined, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(combined, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(combined, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(combined, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(combined, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(combined, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(combined, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(combined, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(combined, /auth_code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(combined, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  const dataUrlPrefix = "data:" + "image";
  assert.doesNotMatch(combined, new RegExp(`logo_data_url|${dataUrlPrefix}|pricing file|quote export`, "i"));
  assert.doesNotMatch(combined, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(combined, /C:\\Users\\|\/Users\/|\/home\//i);
  assert.match(combined, /<platform-base-url>/);
  assert.match(combined, /<google-oauth-client-secret>/);
  assert.match(combined, /<database-url-from-existing-service>/);
});

test("external auth docs state deferred runtime boundaries instead of adding implementation scope", async () => {
  const combined = (await readExternalAuthDocs()).join("\n");
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const scripts = JSON.stringify(packageJson.scripts);

  assert.match(combined, /does not add runtime behavior/i);
  assert.match(combined, /does not add platform-owned email\/password auth/i);
  assert.match(combined, /fake login/i);
  assert.match(combined, /active multi-provider runtime behavior/i);
  assert.match(combined, /provider SDKs/i);
  assert.match(combined, /SQAG integration/i);
  assert.match(combined, /deployment/i);
  assert.match(combined, /database provisioning/i);
  assert.match(combined, /migration automation/i);
  assert.match(combined, /billing, or Stripe/i);
  assert.doesNotMatch(scripts, /deploy|provision|stripe/i);
});

test("source tree still has no forbidden provider or frontend dependencies", async () => {
  const sourceFiles = await listFiles("src");
  const allSource = (await Promise.all(sourceFiles.map((file) => readFile(file, "utf8")))).join("\n");
  const packageJson = await readFile("package.json", "utf8");
  const combined = `${packageJson}\n${allSource}`;

  assert.doesNotMatch(combined, /from ["'](?:@workos|workos|google-auth-library|next|react|vite|express|fastify|hono|stripe)/i);
  assert.doesNotMatch(combined, /require\(["'](?:@workos|workos|google-auth-library|next|react|vite|express|fastify|hono|stripe)/i);
  assert.doesNotMatch(combined, /fake login|email\/password auth implementation|multi-provider runtime/i);
});

async function readExternalAuthDocs() {
  return Promise.all(
    [providerSelectionPath, googleRunbookPath, workosNotesPath].map((path) => readFile(path, "utf8")),
  );
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        return listFiles(path);
      }
      return path.endsWith(".ts") || path.endsWith(".mjs") || path.endsWith(".js") ? [path] : [];
    }),
  );

  return nested.flat();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
