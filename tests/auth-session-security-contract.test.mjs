import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractPath = "docs/auth-session-security-contract.md";

const implementedBehaviors = [
  "Generic OIDC login path",
  "Provider-backed user requirement",
  "Pending workspace approval activation",
  "Server-side session records",
  "HttpOnly/SameSite cookie usage",
  "Secure cookie requirement for production",
  "Session expiry behavior",
  "Logout/session revocation behavior",
  "Fail-closed session context behavior",
  "CSRF token handling for browser state-changing routes",
  "Origin/Referer checks for state-changing admin routes",
  "App-launch token properties",
  "one-time",
  "hashed at rest",
  "header-only raw token",
  "no browser URL/storage token",
  "Read-only browser-session routes that do not require CSRF",
  "Header-token app launch consume route",
  "Audit events for workspace/app-access admin actions",
  "membership approval create/revoke/accept",
];

const deferredItems = [
  "Workspace-wide active-session viewer",
  "Revoke other sessions",
  "Account security page",
  "Auth failure dashboard",
  "Full invitation acceptance flow",
  "Password auth and 2FA",
  "SSO/SAML/AuthKit/WorkOS runtime integration",
  "Device/session metadata enrichment",
  "Rate limiting/lockout",
];

const alphaMinimumPosture = [
  "single provider-backed login",
  "allowlisted users",
  "secure cookie in hosted production",
  "fail-closed sessions",
  "owner/admin audit browsing",
  "no raw token exposure",
  "manual/operator incident process",
];

test("auth/session security contract exists and documents implemented behavior", async () => {
  const contract = await readContract();

  assert.match(contract, /# Auth\/Session Security Contract/i);

  for (const behavior of implementedBehaviors) {
    assert.match(contract, new RegExp(escapeRegExp(behavior), "i"));
  }

  for (const posture of alphaMinimumPosture) {
    assert.match(contract, new RegExp(escapeRegExp(posture), "i"));
  }
});

test("auth/session security contract documents deferred items honestly", async () => {
  const contract = await readContract();

  for (const item of deferredItems) {
    assert.match(contract, new RegExp(escapeRegExp(item), "i"));
  }

  assert.match(contract, /no password auth or 2FA added/i);
  assert.match(contract, /no session-management UI added/i);
  assert.match(contract, /no hosted deployment approval/i);
});

test("auth/session security contract includes the gap inventory table", async () => {
  const contract = await readContract();

  assert.match(
    contract,
    /\|\s*Security\/session capability\s*\|\s*Current status\s*\|\s*Evidence\/source file\/doc\s*\|\s*Alpha requirement\s*\|\s*Future production enhancement\s*\|/i,
  );

  for (const item of [...implementedBehaviors, ...deferredItems]) {
    assert.match(contract, new RegExp(escapeRegExp(item), "i"));
  }
});

test("auth/session security contract separates read-only CSRF exemptions from launch-token consume", async () => {
  const contract = await readContract();

  assert.match(
    contract,
    /Read-only browser-session routes that do not require CSRF: session context, session app-access checks, workspace member listing, pending approval listing, app-entitlement listing, and workspace audit browsing/i,
  );
  assert.match(
    contract,
    /Header-token app launch consume route: `POST \/api\/platform\/apps\/launch\/consume` does not require browser CSRF because it does not use the browser session cookie/i,
  );
  assert.match(contract, /requires the raw one-time launch token in the request header/i);
  assert.match(contract, /consumes it once/i);
  assert.match(
    contract,
    /\| Header-token app launch consume route \| Implemented \|[^|]+\| `POST \/api\/platform\/apps\/launch\/consume` is state-changing because it consumes a one-time launch token/i,
  );
  assert.match(
    contract,
    /CSRF-exempt because it uses header-token auth and no browser session cookie/i,
  );
  assert.doesNotMatch(contract, /read-only[^.\n|]*app launch consume/i);
  assert.doesNotMatch(contract, /app launch consume[^.\n|]*read-only/i);
  assert.doesNotMatch(contract, /app launch consume[^.\n|]*idempotent/i);
});

test("auth/session security contract aligns runbooks and roadmap", async () => {
  const contract = await readContract();
  const platformContract = await readFile("docs/internal-alpha-platform-contract.md", "utf8");
  const hostedRunbook = await readFile("docs/hosted-internal-alpha-runbook.md", "utf8");
  const operatorDecisions = await readFile(
    "docs/hosted-internal-alpha-operator-decisions.md",
    "utf8",
  );
  const roadmap = await readFile("docs/roadmap.md", "utf8");
  const readme = await readFile("README.md", "utf8");

  assert.match(contract, /docs\/internal-alpha-platform-contract\.md/);
  assert.match(contract, /docs\/hosted-internal-alpha-runbook\.md/);
  assert.match(contract, /docs\/hosted-internal-alpha-operator-decisions\.md/);
  assert.match(contract, /docs\/roadmap\.md/);

  assert.match(platformContract, /auth\/session security contract/i);
  assert.match(hostedRunbook, /auth\/session security contract/i);
  assert.match(operatorDecisions, /auth\/session security contract/i);
  assert.match(roadmap, /auth\/session security contract/i);
  assert.match(readme, /docs\/auth-session-security-contract\.md/);

  assert.match(platformContract, /This PR does not add a session-management UI/i);
  assert.match(hostedRunbook, /This PR does not approve hosted deployment/i);
});

test("auth/session security contract confirms Platform and KQAG boundaries", async () => {
  const contract = await readContract();

  assert.match(contract, /Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events/i);
  assert.match(contract, /Platform does not own KQAG quote data/i);
  assert.match(contract, /KQAG owns quote generation, profiles, pricing references, quote sessions, generated artifacts, and quote dashboard\/history/i);
  assert.match(contract, /No KQAG app-data editing, KQAG profiles\/pricing, quote history, generated artifacts, or quote sessions move into Platform/i);
});

test("auth/session security contract avoids private material and real hosted values", async () => {
  const contract = await readContract();

  assert.doesNotMatch(contract, /https?:\/\/(?!<)[^\s>)]+/i);
  assert.doesNotMatch(contract, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(contract, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(contract, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(contract, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(contract, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(contract, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(contract, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(contract, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(contract, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(contract, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(contract, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(contract, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(contract, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(contract, /quote session payload|quote artifact payload|pricing payload/i);
  assert.doesNotMatch(contract, /127\.0\.0\.1/);
});

async function readContract() {
  return readFile(contractPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
