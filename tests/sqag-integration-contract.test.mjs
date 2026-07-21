import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractPath = "docs/sqag-integration-contract.md";

test("repo ignore rules protect local env and secret files while allowing templates", async () => {
  const gitignore = await readFile(".gitignore", "utf8");

  for (const pattern of [".env", ".env.*"]) {
    assert.match(gitignore, new RegExp(`^${escapeRegExp(pattern)}$`, "m"));
  }

  for (const exception of [
    "!.env.example",
    "!.env.sample",
    "!.env.template",
    "!.env.*.example",
    "!.env.*.sample",
    "!.env.*.template",
  ]) {
    assert.match(gitignore, new RegExp(`^${escapeRegExp(exception)}$`, "m"));
  }
});

test("SQAG integration contract documents current platform launch handoff", async () => {
  const doc = await readFile(contractPath, "utf8");
  const requiredPhrases = [
    "current platform code implements the launch-token issue and consume endpoints plus a narrow browser-safe SQAG handoff route",
    "SQAG-side PR #122 and Platform PR #79 established the historical `appKey=sqag` baseline",
    "Before enabling `server_handoff`, operators must record and jointly review the exact Platform and SQAG revisions that implement this contract",
    "Browser user signs in to Swooshz Platform through OIDC",
    "Swooshz Platform owns the browser session, platform user, workspace membership, membership role, app entitlement, and app access decision",
    "POST /api/platform/apps/launch?workspaceId=<platform-workspace-id>&appKey=sqag",
    "disabled for raw-token delivery",
    "POST /api/platform/apps/launch/open?workspaceId=<platform-workspace-id>&appKey=sqag",
    "requires an active browser session cookie plus Origin/Referer and CSRF validation",
    "stores only a versioned hash of the launch token",
    "must not be placed in browser response bodies, URL query parameters, browser storage, cookies, logs, docs, screenshots, committed files, or app telemetry",
    "x-app-launch-token",
    "POST <sqag-local-base-url>/api/platform/launch",
    "POST /api/platform/apps/launch/consume?appKey=sqag",
    "requires no browser cookie and no CSRF token",
    "hashes the submitted token before lookup",
    "rejects missing, invalid, expired, consumed, revoked, and app-mismatched tokens safely",
    "re-checks app access",
    "consumes the token once",
    "returns only safe user/workspace/app context",
    "PLATFORM_SQAG_LAUNCH_MODE=server_handoff",
    "PLATFORM_SQAG_APP_BASE_URL=<sqag-local-base-url>",
    "npm run platform:sqag-smoke-readiness",
    "Passing it only confirms local synthetic readiness",
    "The browser-safe launch response does not include the raw launch token",
    "does not call SQAG during startup",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("SQAG integration contract keeps SQAG adapter scope and private material out", async () => {
  const doc = await readFile(contractPath, "utf8");
  const forbiddenPhrases = [
    "mechanism is undecided",
    "Launch-token or backend exchange mechanism",
    "This may include signed launch context, backend session exchange, or another approved mechanism",
  ];

  for (const phrase of forbiddenPhrases) {
    assert.doesNotMatch(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(doc, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(doc, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(doc, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(doc, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(doc, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(doc, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /auth_code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(doc, /C:\\Users\\|\/Users\/|\/home\//i);
  assert.match(doc, /<one-time-raw-launch-token>/);
  assert.match(doc, /<platform-user-email-placeholder>/);
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
