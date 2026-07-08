import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const decisionRecordPath = "docs/hosted-internal-alpha-operator-decisions.md";

const requiredDecisionItems = [
  "Platform host/provider choice",
  "SQAG host/provider choice",
  "TLS/reverse proxy approach",
  "Process manager/container approach",
  "PostgreSQL provider and backup/restore owner",
  "Migration approver and rollback approver",
  "OIDC provider/client owner",
  "Exact hosted redirect URI placeholder approval process",
  "Secret storage owner and rotation owner",
  "Log retention/access owner",
  "First owner/admin identity approval outside repo",
  "Add-existing-user internal alpha process owner",
  "SQAG handoff mode decision: `manual` first vs `server_handoff`",
  "Cross-host SQAG session/cookie strategy decision before `server_handoff`",
  "Incident contact/escalation path",
  "Go/no-go approver",
];

test("hosted operator decision record exists and lists every required decision", async () => {
  const record = await readDecisionRecord();

  assert.match(record, /# Hosted Internal Alpha Operator Decisions/i);

  for (const item of requiredDecisionItems) {
    assert.match(record, new RegExp(escapeRegExp(item), "i"));
  }
});

test("hosted operator decision record has approval checklist table and no-approval gate", async () => {
  const record = await readDecisionRecord();

  assert.match(
    record,
    /\|\s*Decision item\s*\|\s*Required owner\/approver placeholder\s*\|\s*Evidence required\s*\|\s*Repo impact\s*\|\s*Status placeholder\s*\|/i,
  );
  assert.match(record, /not approved by this PR/i);
  assert.match(record, /do not deploy until every required decision is approved outside repo/i);
  assert.match(record, /<owner-or-approver-placeholder>/);
  assert.match(record, /<status-placeholder>/);
});

test("hosted operator decision record aligns the readiness gate and linked docs", async () => {
  const record = await readDecisionRecord();
  const runbook = await readFile("docs/hosted-internal-alpha-runbook.md", "utf8");
  const contract = await readFile("docs/internal-alpha-platform-contract.md", "utf8");
  const roadmap = await readFile("docs/roadmap.md", "utf8");
  const readme = await readFile("README.md", "utf8");

  assert.match(record, /docs\/hosted-internal-alpha-runbook\.md/);
  assert.match(record, /docs\/internal-alpha-platform-contract\.md/);
  assert.match(record, /docs\/roadmap\.md/);
  assert.match(record, /PR #55 readiness check only validates env shape and dry-run safety/i);
  assert.match(record, /does not approve actual deployment/i);
  assert.match(
    record,
    /does not prove OIDC, database, SQAG, backups, rollback, logs, session cookies, or cross-host handoff work/i,
  );
  assert.match(record, /require operator approval and smoke testing/i);

  assert.match(runbook, /docs\/hosted-internal-alpha-operator-decisions\.md/);
  assert.match(contract, /hosted operator decision record/i);
  assert.match(roadmap, /hosted operator decision record/i);
  assert.match(readme, /docs\/hosted-internal-alpha-operator-decisions\.md/);
});

test("hosted operator decision record confirms Platform and SQAG boundaries", async () => {
  const record = await readDecisionRecord();

  assert.match(record, /Platform does not own SQAG quote data/i);
  assert.match(
    record,
    /SQAG deployment\/runtime\/data decisions remain outside this Platform PR except for Platform handoff placeholders/i,
  );
  assert.match(
    record,
    /No SQAG app-data editing, SQAG profiles\/pricing, quote history, generated artifacts, or quote sessions move into Platform/i,
  );
});

test("hosted operator decision record uses placeholders and avoids private material", async () => {
  const record = await readDecisionRecord();

  assert.doesNotMatch(record, /https?:\/\/(?!<)[^\s>)]+/i);
  assert.doesNotMatch(record, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  assert.doesNotMatch(record, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(record, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(record, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(record, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(record, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(record, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(record, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(record, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(record, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(record, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(record, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(record, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(record, /\/api\/platform\/auth\/callback\?/i);
  assert.doesNotMatch(record, /provider_subject[=:][A-Za-z0-9._-]{8,}/i);
  assert.doesNotMatch(record, /raw claims|raw provider claims|provider payload/i);
  assert.doesNotMatch(record, /quote session payload|quote artifact payload|pricing payload/i);
  assert.doesNotMatch(record, /127\.0\.0\.1/);
});

async function readDecisionRecord() {
  return readFile(decisionRecordPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
