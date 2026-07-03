import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const checklistPath = "docs/internal-alpha-go-no-go-checklist.md";

const requiredCategories = [
  "Product/admin surface",
  "Auth/session security",
  "Workspace/team management",
  "App entitlement/KQAG launch",
  "Audit/activity",
  "Hosted readiness",
  "Operator approvals",
  "Platform/KQAG boundary",
  "Privacy/logging/secrets",
  "Known deferred items",
];

const deferredItems = [
  "full invitation acceptance flow",
  "disabled existing membership reactivation",
  "audit export/filtering/retention",
  "security/session management UI",
  "revoke-other-sessions",
  "active-session viewer",
  "auth failure dashboard",
  "rate limiting/lockout",
  "first-class `operator` role",
  "Google Stitch / UI polish",
  "billing/credits",
  "production observability/alerts",
  "actual hosted deployment execution",
];

const linkedDocs = [
  "docs/internal-alpha-platform-contract.md",
  "docs/hosted-internal-alpha-runbook.md",
  "docs/hosted-internal-alpha-operator-decisions.md",
  "docs/auth-session-security-contract.md",
  "docs/internal-platform-smoke-runbook.md",
  "docs/kqag-integration-contract.md",
  "docs/roadmap.md",
];

const approvedStatuses = new Set([
  "Implemented",
  "Documented",
  "Deferred",
  "Blocked until operator approval",
  "Future",
]);

test("internal-alpha go/no-go checklist doc exists and has required categories", async () => {
  const checklist = await readChecklist();

  assert.match(checklist, /# Internal Alpha Go\/No-Go Checklist/i);
  assert.match(
    checklist,
    /\|\s*Checklist item\s*\|\s*Current status\s*\|\s*Evidence\/source doc or source file\s*\|\s*Go\/no-go decision\s*\|\s*Notes\s*\|/i,
  );

  for (const category of requiredCategories) {
    assert.match(checklist, new RegExp(`## ${escapeRegExp(category)}`, "i"));
  }
});

test("internal-alpha go/no-go checklist separates local and hosted readiness decisions", async () => {
  const checklist = await readChecklist();

  assert.match(checklist, /## Readiness Decision Summary/i);
  assert.match(checklist, /### Local\/internal UAT readiness/i);
  assert.match(checklist, /local\/internal UAT platform-admin foundation is mostly implemented\/documented/i);
  assert.match(checklist, /### Hosted internal-alpha readiness/i);
  assert.match(
    checklist,
    /hosted execution is still blocked until operator approvals, real infra choices, real OIDC config, hosted KQAG handoff\/session strategy, and smoke execution/i,
  );
  assert.match(checklist, /does not claim production readiness/i);
  assert.match(checklist, /Do not deploy until every required operator decision is approved outside repo and hosted smoke testing is complete/i);
});

test("internal-alpha go/no-go checklist lists required deferred items", async () => {
  const checklist = await readChecklist();

  for (const item of deferredItems) {
    assert.match(checklist, new RegExp(escapeRegExp(item), "i"));
  }
});

test("internal-alpha go/no-go checklist confirms Platform and KQAG boundaries", async () => {
  const checklist = await readChecklist();

  assert.match(checklist, /Platform owns auth, users, sessions, workspaces, roles, memberships, app entitlements, app launch checks, and audit events/i);
  assert.match(checklist, /Platform does not own KQAG quote data/i);
  assert.match(checklist, /KQAG owns quote generation, profiles, pricing references, quote sessions, generated artifacts, and quote dashboard\/history/i);
  assert.match(checklist, /No KQAG app-data editing, KQAG profiles\/pricing, quote history, generated artifacts, or quote sessions move into Platform/i);
});

test("internal-alpha go/no-go checklist links source docs and is linked from repo docs", async () => {
  const checklist = await readChecklist();
  const platformContract = await readFile("docs/internal-alpha-platform-contract.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");
  const readme = await readFile("README.md", "utf8");

  for (const linkedDoc of linkedDocs) {
    assert.match(checklist, new RegExp(escapeRegExp(linkedDoc), "i"));
  }

  assert.match(platformContract, /docs\/internal-alpha-go-no-go-checklist\.md/);
  assert.match(roadmap, /internal-alpha go\/no-go checklist/i);
  assert.match(readme, /docs\/internal-alpha-go-no-go-checklist\.md/);
});

test("internal-alpha go/no-go checklist uses only approved status vocabulary", async () => {
  const checklist = await readChecklist();
  const statusValues = extractStatusColumnValues(checklist);

  assert.ok(statusValues.length > 0, "expected checklist rows with status values");

  for (const status of statusValues) {
    assert.ok(approvedStatuses.has(status), `unexpected checklist status: ${status}`);
  }
});

test("internal-alpha go/no-go checklist avoids private material and real hosted values", async () => {
  const checklist = await readChecklist();

  assert.doesNotMatch(checklist, /https?:\/\/(?!<)[^\s>)]+/i);
  assert.doesNotMatch(checklist, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(checklist, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(checklist, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(checklist, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(checklist, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(checklist, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(checklist, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(checklist, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(checklist, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(checklist, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(checklist, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(checklist, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(checklist, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(checklist, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(checklist, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(checklist, /raw claims|raw provider claims|provider payload/i);
  assert.doesNotMatch(checklist, /quote session payload|quote artifact payload|pricing payload/i);
});

async function readChecklist() {
  return readFile(checklistPath, "utf8");
}

function extractStatusColumnValues(markdown) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.includes("---") && !line.includes("Current status"))
    .map((line) => line.split("|").map((cell) => cell.trim())[2])
    .filter(Boolean);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
