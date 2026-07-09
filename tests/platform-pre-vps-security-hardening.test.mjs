import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const hardeningPath = "docs/platform-pre-vps-security-hardening.md";
const rotationPath = "docs/platform-secret-rotation-runbook.md";
const backupPath = "docs/platform-backup-restore-evidence-template.md";
const goNoGoPath = "docs/platform-final-go-no-go-checklist.md";
const roadmapPath = "docs/production-readiness-roadmap.md";

test("pre-VPS hardening plan documents security posture without hosted or production claims", async () => {
  const doc = await readFile(hardeningPath, "utf8");

  const requiredPhrases = [
    "# Platform Pre-VPS Security Hardening Plan",
    "Production readiness is not approved",
    "The shared Hostinger/Coolify foundation does not exist yet",
    "shared across Swooshz Platform, Swooshz Quote Auto Generator, and SKR",
    "Platform must not own Swooshz Quote Auto Generator product workflow/runtime data",
    "That local evidence is not hosted evidence",
    "Hosted deployment, hosted OAuth/provider setup, hosted security header review",
    "CSRF Smoke Plan",
    "Origin And Referer Expectations",
    "Session And Cookie Posture",
    "Security Header Posture",
    "Rate Limiting Posture",
    "Dependency And Security Audit Cadence",
    "Secret Rotation And Emergency Revoke",
    "Backup And Restore Evidence",
    "Monitoring, Logging, And Incident Placeholders",
    "Legal And Compliance Placeholders",
    "Final Go/No-Go Ownership",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assertNoOverclaimsOrPrivateMaterial(doc);
});

test("CSRF origin session rate limit and security-header posture are documented honestly", async () => {
  const doc = await readFile(hardeningPath, "utf8");

  const requiredPhrases = [
    "Valid admin mutation with fresh CSRF token and allowed Origin",
    "Missing CSRF token on the same mutation",
    "Invalid CSRF token on the same mutation",
    "Missing Origin and Referer on browser-cookie mutation",
    "Unapproved Origin on browser-cookie mutation",
    "exact Platform origins only",
    "Wildcards, path-shaped values, query strings, and fragments are not acceptable",
    "Session context, admin authorization, app access, and launch checks reject missing, expired, revoked, inactive-user, and missing-user sessions",
    "Workspace member removal revokes active Platform sessions for the removed user",
    "Revoke-other-sessions is not a general user-facing or admin-facing workflow yet",
    "Current implementation posture",
    "Application-level rate limiting and lockout remain deferred",
    "No naive in-memory production rate limiter is considered complete for hosted production",
    "Review hosted response headers after the reverse proxy and app are configured",
    "No runtime header behavior is changed by this plan",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("secret rotation runbook uses env names only and no secret values", async () => {
  const doc = await readFile(rotationPath, "utf8");

  const requiredEnvNames = [
    "DATABASE_URL",
    "SESSION_SECRET",
    "CSRF_TOKEN_HASH_SECRET",
    "AUTH_STATE_HASH_SECRET",
    "APP_LAUNCH_TOKEN_HASH_SECRET",
    "AUTH_CLIENT_SECRET",
    "AUTH_ALLOWED_EMAILS",
    "DATABASE_MIGRATIONS_CONFIRM",
    "PLATFORM_SEED_CONFIRM",
    "PLATFORM_SEED_USER_EMAIL",
    "PLATFORM_SEED_MEMBERSHIP_ROLE",
    "PLATFORM_ALLOWED_ORIGINS",
    "PLATFORM_COOKIE_SECURE",
    "AUTH_REDIRECT_URI",
    "PLATFORM_SQAG_LAUNCH_MODE",
    "PLATFORM_SQAG_APP_BASE_URL",
  ];

  for (const name of requiredEnvNames) {
    assert.match(doc, new RegExp(`\\b${escapeRegExp(name)}\\b`));
  }

  assert.match(doc, /does not create, request, store, rotate, print, or validate real secrets/i);
  assert.match(doc, /Emergency Revoke/i);
  assert.match(doc, /Allowed in repo notes/i);
  assert.match(doc, /Not allowed in repo notes/i);
  assertNoOverclaimsOrPrivateMaterial(doc);
});

test("backup restore template is sanitized and is not fake evidence", async () => {
  const doc = await readFile(backupPath, "utf8");

  const requiredPhrases = [
    "# Platform Backup/Restore Evidence Template",
    "This template is not backup evidence",
    "Evidence id",
    "<evidence-id>",
    "<opaque-backup-artifact-reference>",
    "<isolated-restore-target-category>",
    "Restore result",
    "not become fake backup evidence",
    "must not include fake timestamps",
    "Backup/restore execution remains unchecked until real sanitized restore evidence exists",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(doc, /\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}/);
  assert.doesNotMatch(doc, /\b\d{1,3}(?:\.\d{1,3}){3}\b/);
  assertNoOverclaimsOrPrivateMaterial(doc);
});

test("final go no-go checklist remains unchecked with owner placeholders only", async () => {
  const doc = await readFile(goNoGoPath, "utf8");

  const requiredPhrases = [
    "# Platform Final Go/No-Go Checklist",
    "Production readiness is not approved",
    "Required Owner Placeholders",
    "<final-launch-approver-role>",
    "<shared-hosting-owner-role>",
    "<secret-rotation-owner-role>",
    "<backup-restore-owner-role>",
    "<monitoring-logging-owner-role>",
    "<legal-compliance-reviewer-role>",
    "Go/No-Go Gates",
    "Non-Go Conditions",
    "Final launch decision is recorded by the final launch approver outside repo",
    "If SQAG and SKR are both hosting-ready, proceed to shared Hostinger/Coolify foundation planning",
    "Otherwise continue only non-hosted Platform governance work or return to the app that still blocks shared hosting",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.match(doc, /- \[ \] Shared Hostinger\/Coolify foundation exists/i);
  assert.match(doc, /- \[ \] Hosted Platform app is created/i);
  assert.match(doc, /- \[ \] Hosted OAuth\/provider configuration is completed outside repo/i);
  assert.match(doc, /- \[ \] Sanitized backup\/restore test evidence exists/i);
  assert.match(doc, /- \[ \] Final launch decision is recorded/i);
  assert.doesNotMatch(doc, /- \[x\]/i);
  assertNoOverclaimsOrPrivateMaterial(doc);
});

test("roadmap records docs-only pre-VPS progress while hosted and final gates stay unchecked", async () => {
  const roadmap = await readFile(roadmapPath, "utf8");

  const checkedPlanningItems = [
    "Backup/restore evidence template drafted",
    "Monitoring/logging/incident planning placeholders drafted",
    "Pre-VPS security hardening plan documented",
    "Secret rotation runbook drafted with env names only",
    "Dependency/security audit cadence planning documented",
    "Legal/compliance and final go/no-go placeholders drafted",
  ];

  for (const item of checkedPlanningItems) {
    assert.match(roadmap, new RegExp(`- \\[x\\] ${escapeRegExp(item)}`, "i"));
  }

  const uncheckedLaunchItems = [
    "Hosted visual evidence complete",
    "Coolify Platform app created",
    "Hosted Google OAuth client/redirect configured outside repo",
    "CSRF smoke",
    "Rate limiting review",
    "Security headers review",
    "Dependency/security audit cadence",
    "Secret rotation plan",
    "Restore test evidence",
    "Uptime monitoring",
    "Error monitoring or equivalent",
    "Privacy policy",
    "Terms",
    "Final launch checklist completed",
  ];

  for (const item of uncheckedLaunchItems) {
    assert.match(roadmap, new RegExp(`- \\[ \\] ${escapeRegExp(item)}(?:\\.|\\r?\\n)`, "i"));
    assert.doesNotMatch(roadmap, new RegExp(`- \\[x\\] ${escapeRegExp(item)}(?:\\.|\\r?\\n)`, "i"));
  }

  assert.match(roadmap, /docs-only readiness is not deployed evidence/i);
  assert.match(roadmap, /Pre-VPS planning templates now exist, but they are not hosted evidence or production approval/i);
  assertNoOverclaimsOrPrivateMaterial(roadmap);
});

function assertNoOverclaimsOrPrivateMaterial(value) {
  assert.doesNotMatch(value, /production readiness\s+(?:is|has been)\s+(?:approved|achieved|complete)/i);
  assert.doesNotMatch(value, /\b(?:is|are|now|fully)\s+production[- ]ready\b/i);
  assert.doesNotMatch(value, /hosted smoke\s+(?:passed|complete|completed|succeeded)/i);
  assert.doesNotMatch(value, /backup\/restore evidence\s+(?:exists|complete|completed|approved)/i);
  assert.doesNotMatch(value, /monitoring evidence\s+(?:exists|complete|completed|approved)/i);
  assert.doesNotMatch(value, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(value, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(value, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(value, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(value, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(value, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(value, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(value, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(value, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(value, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(value, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(value, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(value, /\b\d{1,3}(?:\.\d{1,3}){3}\b/);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
