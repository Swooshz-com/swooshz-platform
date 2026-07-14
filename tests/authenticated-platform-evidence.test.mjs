import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assertAllowedEvidenceRequest,
  assertSyntheticIdentitySafety,
  requiredAuthenticatedInteractions,
  requiredAuthenticatedScreenshots,
  validateAuthenticatedEvidenceSummary,
  validateEvidenceHeadSha,
} from "../scripts/authenticated-platform-evidence-contract.mjs";

const validHead = "a".repeat(40);

function validSummary() {
  return {
    headSha: validHead,
    browser: "Chromium 149.0.0.0",
    screenshots: [...requiredAuthenticatedScreenshots],
    interactions: requiredAuthenticatedInteractions.map((id) => ({ id, passed: true, detail: "synthetic check passed" })),
    captures: requiredAuthenticatedScreenshots.map((name) => ({ name, horizontalOverflow: false })),
    consoleErrors: [],
    pageErrors: [],
    blockedExternalRequests: [],
    syntheticFixtureSummary: { email: "alex@example.invalid" },
  };
}

test("authenticated evidence requires an exact checked-out head SHA", () => {
  assert.equal(validateEvidenceHeadSha(validHead), validHead);
  for (const value of [undefined, "", "local-uncommitted", "a".repeat(39), "g".repeat(40)]) {
    assert.throws(() => validateEvidenceHeadSha(value), /exact 40-character checked-out commit SHA/);
  }
});

test("authenticated evidence blocks external network calls", () => {
  assert.equal(assertAllowedEvidenceRequest("http://127.0.0.1:43123/api/platform/session/context", "http://127.0.0.1:43123").pathname, "/api/platform/session/context");
  assert.throws(() => assertAllowedEvidenceRequest("https://accounts.google.com/", "http://127.0.0.1:43123"), /External network request blocked/);
  assert.throws(() => assertAllowedEvidenceRequest("https://database.example.invalid/", "http://127.0.0.1:43123"), /External network request blocked/);
});

test("authenticated evidence accepts only synthetic identity domains and rejects sensitive material", () => {
  assert.equal(assertSyntheticIdentitySafety({ name: "Alex Example", email: "alex@example.invalid" }), true);
  assert.throws(() => assertSyntheticIdentitySafety({ email: "person@gmail.com" }), /non-synthetic identity domain/);
  assert.throws(() => assertSyntheticIdentitySafety({ connection: "postgresql://private-host/db" }), /secret-, credential-, or private-runtime-like material/);
});

test("authenticated evidence summary rejects missing screenshots, browser errors, and failed interactions", () => {
  assert.equal(validateAuthenticatedEvidenceSummary(validSummary()), true);
  const missingScreenshot = validSummary();
  missingScreenshot.screenshots.pop();
  assert.throws(() => validateAuthenticatedEvidenceSummary(missingScreenshot), /missing required screenshots/);
  const consoleFailure = validSummary();
  consoleFailure.consoleErrors.push("synthetic console failure");
  assert.throws(() => validateAuthenticatedEvidenceSummary(consoleFailure), /browser errors/);
  const pageFailure = validSummary();
  pageFailure.pageErrors.push("synthetic page failure");
  assert.throws(() => validateAuthenticatedEvidenceSummary(pageFailure), /browser errors/);
  const failedInteraction = validSummary();
  failedInteraction.interactions[0].passed = false;
  assert.throws(() => validateAuthenticatedEvidenceSummary(failedInteraction), /interaction checks failed/);
  const overflow = validSummary();
  overflow.captures[0].horizontalOverflow = true;
  assert.throws(() => validateAuthenticatedEvidenceSummary(overflow), /horizontal overflow/);
});

test("capture script covers current authenticated API contracts without a production auth bypass", async () => {
  const script = await readFile("scripts/capture-authenticated-platform-evidence.mjs", "utf8");
  for (const endpoint of [
    "/api/platform/session/context",
    "/api/platform/session/csrf",
    "/members",
    "/member-approvals",
    "/app-entitlements",
    "/audit-events",
    "/api/platform/apps/launch/open",
  ]) assert.match(script, new RegExp(endpoint.replaceAll("/", "\\/")));
  assert.match(script, /context\.route\("\*\*\/\*"/);
  assert.match(script, /assertAllowedEvidenceRequest/);
  assert.match(script, /unexpectedApiRequests/);
  assert.match(script, /validateAuthenticatedEvidenceSummary/);
  assert.doesNotMatch(script, /FAKE_AUTH|BYPASS_AUTH|ALLOW_FAKE_LOGIN|process\.env\.(?:AUTH|SESSION|LOGIN)_/i);
  assert.doesNotMatch(script, /@gmail\.com|@outlook\.com|@hotmail\.com|@yahoo\.com/i);
});

test("workflow checks out and uploads an artifact named for the exact PR head", async () => {
  const workflow = await readFile(".github/workflows/authenticated-platform-evidence.yml", "utf8");
  assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  assert.match(workflow, /EVIDENCE_HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  assert.match(workflow, /name: authenticated-platform-evidence-\$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  assert.match(workflow, /node --test tests\/authenticated-platform-evidence\.test\.mjs/);
  assert.match(workflow, /if-no-files-found: error/);
});