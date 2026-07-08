import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const briefingPath = "docs/hosted-internal-alpha-operator-briefing.md";

const requiredSections = [
  "Purpose and non-goals",
  "Current local/internal UAT readiness summary",
  "Hosted internal-alpha no-go blockers",
  "Required operator approvals before execution",
  "Recommended hosted topology options",
  "SQAG handoff/session strategy options",
  "Secret/config handling requirements",
  "Migration/backup/restore decision requirements",
  "Logging/privacy/incident handling requirements",
  "First owner/admin identity approval requirements",
  "Hosted smoke evidence requirements",
  "Final go/no-go decision template",
];

test("hosted operator briefing exists and has the required operator-facing sections", async () => {
  const briefing = await readBriefing();

  assert.match(briefing, /# Hosted Internal Alpha Operator Briefing/i);

  for (const section of requiredSections) {
    assert.match(briefing, new RegExp(`## ${escapeRegExp(section)}`, "i"));
  }
});

test("hosted operator briefing compares planning-only topology options", async () => {
  const briefing = await readBriefing();

  assert.match(briefing, /Single VPS\/process manager reverse-proxy setup/i);
  assert.match(briefing, /Containerised VPS setup/i);
  assert.match(briefing, /Managed app\/database provider setup/i);
  assert.match(briefing, /planning guidance only/i);
  assert.match(briefing, /does not add Docker, Caddy, Traefik, Nginx, Coolify, process manager, or deployment config/i);
});

test("hosted operator briefing keeps hosted execution blocked and avoids production-readiness claims", async () => {
  const briefing = await readBriefing();

  assert.match(briefing, /No-go until approved/i);
  assert.match(briefing, /does not approve hosted execution/i);
  assert.match(briefing, /does not claim production readiness/i);
  assert.match(briefing, /hosted execution remains blocked/i);
  assert.doesNotMatch(briefing, /hosted deployment is approved/i);
  assert.doesNotMatch(briefing, /hosted execution is approved/i);
  assert.doesNotMatch(briefing, /\b(?:is|are|now|fully)\s+production[- ]ready\b/i);
});

test("hosted operator briefing preserves Platform and SQAG ownership boundaries", async () => {
  const briefing = await readBriefing();

  assert.match(briefing, /Platform handles identity, workspace, membership, entitlement, and launch checks/i);
  assert.match(briefing, /SQAG owns quote\/session\/profile\/pricing\/generated-artifact data/i);
  assert.match(briefing, /hosted SQAG handoff\/session\/cookie decision must be approved and smoke-tested/i);
  assert.match(briefing, /Do not move SQAG quote data into Platform/i);
  assert.match(briefing, /SQAG owns quote generation, profiles, pricing references, quote sessions\/history\/dashboard, generated artifacts, and runtime\/app data/i);
});

test("hosted operator briefing is cross-linked from readiness docs", async () => {
  const runbook = await readFile("docs/hosted-internal-alpha-runbook.md", "utf8");
  const decisions = await readFile("docs/hosted-internal-alpha-operator-decisions.md", "utf8");
  const checklist = await readFile("docs/internal-alpha-go-no-go-checklist.md", "utf8");
  const readme = await readFile("README.md", "utf8");

  assert.match(runbook, /docs\/hosted-internal-alpha-operator-briefing\.md/);
  assert.match(decisions, /docs\/hosted-internal-alpha-operator-briefing\.md/);
  assert.match(checklist, /docs\/hosted-internal-alpha-operator-briefing\.md/);
  assert.match(readme, /docs\/hosted-internal-alpha-operator-briefing\.md/);
});

test("hosted operator briefing avoids private material and real hosted values", async () => {
  const briefing = await readBriefing();

  assert.doesNotMatch(briefing, /https?:\/\/(?!<)[^\s>)]+/i);
  assert.doesNotMatch(briefing, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(briefing, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(briefing, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(briefing, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(briefing, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(briefing, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(briefing, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(briefing, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(briefing, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(briefing, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(briefing, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(briefing, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(briefing, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(briefing, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(briefing, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(briefing, /raw claims|raw provider claims|provider payload/i);
  assert.doesNotMatch(briefing, /quote session payload|quote artifact payload|pricing payload/i);
});

async function readBriefing() {
  return readFile(briefingPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
