import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const providerSelectionPath = "docs/auth-provider-selection.md";
const auth0RunbookPath = "docs/auth0-passwordless-email-otp-runbook.md";
const workosNotesPath = "docs/workos-authkit-fit-notes.md";
const retiredConnectionSelector = ["AUTH0", "PASSWORDLESS", "CONNECTION"].join("_");

test("external auth provider docs exist and are linked", async () => {
  const readme = await readFile("README.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");

  for (const path of [providerSelectionPath, auth0RunbookPath, workosNotesPath]) {
    await assert.doesNotReject(() => readFile(path, "utf8"));
    assert.match(readme, new RegExp(escapeRegExp(path)));
    assert.match(roadmap, new RegExp(escapeRegExp(path)));
  }
});

test("provider selection preserves Platform ownership and accepted Auth0 boundaries", async () => {
  const doc = await readFile(providerSelectionPath, "utf8");

  assert.match(doc, /external auth provider proves identity/i);
  assert.match(doc, /Swooshz Platform owns users/i);
  assert.match(doc, /platform sessions/i);
  assert.match(doc, /workspaces, memberships, roles/i);
  assert.match(doc, /app access decisions/i);
  assert.match(doc, /app launch tokens/i);
  assert.match(doc, /one active generic OIDC provider through environment configuration/i);
  assert.match(doc, /AUTH_PROVIDER_KEY=auth0/i);
  assert.match(doc, /Auth0 Universal Login with passwordless email OTP/i);
  assert.match(doc, /fixed `connection=email` parameter/i);
  assert.match(doc, /Do not implement true active multi-provider login/i);
  assert.match(doc, /Do not build platform-owned email\/password auth/i);
  assert.match(doc, /Do not add fake login/i);
  assert.match(doc, /WorkOS\/AuthKit is a strong future B2B\/hosted-auth candidate/i);
  assert.match(doc, /provider subject ids differ/i);
  assert.match(doc, /Future active multi-provider login should be a separate architecture PR/i);
});

test("Auth0 passwordless runbook documents synthetic endpoint mapping and fixed selector", async () => {
  const doc = await readFile(auth0RunbookPath, "utf8");
  const requiredEnv = [
    "PLATFORM_AUTH_PROVIDER_MODE=generic_oidc",
    "AUTH_PROVIDER_KEY=auth0",
    "AUTH_ISSUER_URL=https://auth0.example.invalid/",
    "AUTH_AUTHORIZATION_URL=https://auth0.example.invalid/authorize",
    "AUTH_TOKEN_URL=https://auth0.example.invalid/oauth/token",
    "AUTH_USERINFO_URL=https://auth0.example.invalid/userinfo",
    "AUTH_JWKS_URL=https://auth0.example.invalid/.well-known/jwks.json",
    "OIDC_CLIENT_ID=<oidc-client-id-placeholder>",
    "OIDC_CLIENT_SECRET=<oidc-client-secret-placeholder>",
    "AUTH_REDIRECT_URI=https://swooshz.com/api/platform/auth/callback",
    "SESSION_SECRET=<session-secret-placeholder>",
    "AUTH_STATE_HASH_SECRET=<auth-state-hash-secret-placeholder>",
    "CSRF_TOKEN_HASH_SECRET=<csrf-token-hash-secret-placeholder>",
    "APP_LAUNCH_TOKEN_HASH_SECRET=<app-launch-token-hash-secret-placeholder>",
  ];

  for (const envLine of requiredEnv) {
    assert.match(doc, new RegExp(escapeRegExp(envLine)));
  }

  assert.match(doc, /fixed provider parameter `connection=email`/i);
  assert.doesNotMatch(doc, new RegExp(escapeRegExp(retiredConnectionSelector)));
  assert.match(doc, /no second auth-method or connection selector/i);
  assert.match(doc, /does not add an Auth0 SDK/i);
  assert.match(doc, /platform-owned passwords/i);
  assert.match(doc, /OTP generation/i);
  assert.match(doc, /platform-owned OTP email delivery/i);
});

test("Auth0 passwordless runbook covers identity, authorization, fail-closed security, and no live calls", async () => {
  const doc = await readFile(auth0RunbookPath, "utf8");
  const requiredPhrases = [
    "Auth0 Universal Login with passwordless email OTP owns human authentication",
    "sole authority for pending approval, active workspace membership, role, app entitlement, Platform session, and app-launch authority",
    "verified, mutable attribute",
    "approved provider authority plus provider subject (`sub`)",
    "exact configured issuer",
    "audience and authorized party",
    "RS256 signatures",
    "exp`/`nbf`/`iat",
    "nonce",
    "exact-sub userinfo",
    "State remains hashed, expiring, browser-bound, and one-time",
    "Session cookies, CSRF, Origin/Referer checks",
    "authenticated but unapproved identity receives no Platform session",
    "different subject or provider authority cannot merge or hijack",
    "short-lived, hashed, one-time, header-only",
    "intercepted provider fixtures only",
    "Synthetic evidence must never be described as live Auth0 validation",
    "passwordless email OTP flow",
    "approval-required denial",
    "No application access after sign-in",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(doc, /https:\/\/(?:[a-z0-9-]+\.)*auth0\.com/i);
  assert.doesNotMatch(doc, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(doc, new RegExp(escapeRegExp(retiredConnectionSelector)));
});

test("WorkOS/AuthKit notes keep WorkOS future-only and preserve subject/email identity rules", async () => {
  const doc = await readFile(workosNotesPath, "utf8");
  const requiredPhrases = [
    "potential future hosted-auth provider candidate",
    "current Auth0 passwordless OIDC authority",
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

test("external auth docs avoid real secrets, private data, and provider payload examples", async () => {
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
  assert.match(combined, /<oidc-client-secret-placeholder>/);
  assert.match(combined, /<session-secret-placeholder>/);
  assert.doesNotMatch(combined, /<google-oauth-client-secret>|accounts\.google\.com|google-auth-library/i);
});

test("external auth docs state deferred runtime boundaries instead of adding implementation scope", async () => {
  const combined = (await readExternalAuthDocs()).join("\n");
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const scripts = JSON.stringify(packageJson.scripts);

  assert.match(combined, /does not add runtime behavior/i);
  assert.match(combined, /platform-owned email\/password auth/i);
  assert.match(combined, /fake login/i);
  assert.match(combined, /active multi-provider/i);
  assert.match(combined, /Auth0 SDK/i);
  assert.match(combined, /SQAG/i);
  assert.match(combined, /hosted execution/i);
  assert.match(combined, /database provisioning/i);
  assert.match(combined, /migration automation/i);
  assert.doesNotMatch(scripts, /deploy|provision|stripe/i);
});

test("source tree still has no forbidden provider or frontend dependencies", async () => {
  const sourceFiles = await listFiles("src");
  const allSource = (await Promise.all(sourceFiles.map((file) => readFile(file, "utf8")))).join("\n");
  const packageJson = await readFile("package.json", "utf8");
  const combined = `${packageJson}\n${allSource}`;

  assert.doesNotMatch(combined, /from ["'](?:@workos|workos|google-auth-library|next|react|vite|express|fastify|hono|stripe)["']/i);
  assert.doesNotMatch(combined, /require\(["'](?:@workos|workos|google-auth-library|next|react|vite|express|fastify|hono|stripe)["']/i);
  assert.doesNotMatch(combined, /fake login|email\/password auth implementation|multi-provider runtime/i);
});

async function readExternalAuthDocs() {
  return Promise.all(
    [providerSelectionPath, auth0RunbookPath, workosNotesPath].map((path) => readFile(path, "utf8")),
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
