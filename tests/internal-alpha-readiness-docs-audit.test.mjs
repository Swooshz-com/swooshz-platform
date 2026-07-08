import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readinessDocPaths = [
  "README.md",
  "docs/internal-alpha-platform-contract.md",
  "docs/internal-alpha-go-no-go-checklist.md",
  "docs/auth-session-security-contract.md",
  "docs/internal-platform-smoke-runbook.md",
  "docs/sqag-integration-contract.md",
  "docs/hosted-internal-alpha-runbook.md",
  "docs/hosted-internal-alpha-operator-decisions.md",
  "docs/hosted-internal-alpha-operator-briefing.md",
  "docs/production-readiness-roadmap.md",
  "docs/frontend-design-readiness.md",
  "docs/roadmap.md",
];

test("internal-alpha readiness docs include the hosted operator briefing", () => {
  assert.ok(
    readinessDocPaths.includes("docs/hosted-internal-alpha-operator-briefing.md"),
    "hosted operator briefing must stay in the readiness docs audit set",
  );
});

test("internal-alpha readiness docs avoid stale PR-scoped framing and readiness overclaims", async () => {
  const docs = await readDocs();

  for (const [path, doc] of docs) {
    assert.doesNotMatch(doc, /in this initial contract PR/i, `${path} has stale initial-PR wording`);
    assertProductionReadyIsNotOverclaimed(path, doc);
    assert.doesNotMatch(doc, /production readiness\s+(?:is|has been)\s+(?:approved|achieved|complete)/i, `${path} claims production readiness`);
    assert.doesNotMatch(doc, /hosted deployment is approved/i, `${path} approves hosted deployment`);
    assert.doesNotMatch(doc, /hosted execution is approved/i, `${path} approves hosted execution`);
    assert.doesNotMatch(doc, /approved for hosted/i, `${path} approves hosted rollout`);
  }
});

test("internal-alpha readiness docs keep local UAT and hosted planning separated", async () => {
  const docs = await readDocs();
  const joinedDocs = [...docs.values()].join("\n");

  assert.match(joinedDocs, /local\/internal UAT platform-admin foundation is mostly implemented\/documented/i);
  assert.match(joinedDocs, /hosted execution is still blocked until operator approvals/i);
  assert.match(joinedDocs, /Do not deploy until every required operator decision is approved outside repo and hosted smoke testing is complete/i);
  assert.match(joinedDocs, /Actual hosted deployment execution still requires reviewed infra\/operator approval/i);
});

async function readDocs() {
  return new Map(
    await Promise.all(
      readinessDocPaths.map(async (path) => [path, await readFile(path, "utf8")]),
    ),
  );
}

function assertProductionReadyIsNotOverclaimed(path, doc) {
  const productionReadyOverclaim = /\b(?:is|are|now|fully)\s+production[- ]ready\b/i;
  const allowedCaution = /(?:not|do not assume).*production[- ]ready/i;

  for (const line of doc.split(/\r?\n/)) {
    assert.ok(
      !productionReadyOverclaim.test(line) || allowedCaution.test(line),
      `${path} claims production-ready posture`,
    );
  }
}
