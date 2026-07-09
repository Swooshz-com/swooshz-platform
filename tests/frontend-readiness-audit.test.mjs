import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const auditPath = "docs/frontend-readiness-audit.md";

test("frontend readiness audit records implemented local surfaces without hosted claims", async () => {
  const audit = await readAudit();
  const normalizedAudit = normalizeWhitespace(audit);

  const requiredPhrases = [
    "Production readiness is not approved",
    "after PR #90",
    "Home",
    "Solutions",
    "Resources",
    "Resource article",
    "About",
    "Contact",
    "Request Access",
    "Login/access entry",
    "Portal/app launcher",
    "Workspace admin",
    "implemented locally",
    "Local route tests and local screenshots are not hosted visual evidence",
    "No hosted smoke was run",
    "Production copy is not approved",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(normalizedAudit, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(audit, /production readiness\s+(?:is|has been)\s+(?:approved|achieved|complete)/i);
  assert.doesNotMatch(audit, /\b(?:is|are|now|fully)\s+production[- ]ready\b/i);
  assert.doesNotMatch(audit, /hosted smoke (?:passed|complete)|hosted visual evidence complete/i);
});

test("frontend readiness audit preserves Platform SQAG and vendor-pending boundaries", async () => {
  const audit = await readAudit();
  const normalizedAudit = normalizeWhitespace(audit);

  const requiredPhrases = [
    "Swooshz Quote Auto Generator is presented as a separate app launched from Platform",
    "Platform does not own Swooshz Quote Auto Generator product workflow/runtime data",
    "SEO/GEO/Seozilla remains unavailable until confirmed and vendor workflow pending",
    "No SEO/GEO/Seozilla integration is added",
    "SKR content is absent from the Platform frontend",
    "Billing, payment, upgrade, and plan flows remain absent",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(normalizedAudit, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("frontend readiness audit locks static safe public page status", async () => {
  const audit = await readAudit();
  const normalizedAudit = normalizeWhitespace(audit);

  const requiredPhrases = [
    "Request access, contact, and resources remain static safe pages",
    "They do not create accounts",
    "send email",
    "submit public forms",
    "create CRM records",
    "run intake workflows",
    "CMS, content admin, editor workflows, public comments, newsletter signup, email capture, and dynamic publishing remain out of scope",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(normalizedAudit, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("frontend readiness audit records the fixed SQAG abbreviation blocker", async () => {
  const audit = await readAudit();

  assert.match(audit, /Audit Finding Fixed/i);
  assert.match(audit, /Swooshz Quote Auto Generator access/);
  assert.match(audit, /tests\/platform-shell\.test\.mjs/);
  assert.match(audit, /No fake enabled search control/i);
});

test("frontend readiness audit recommends pausing new Platform frontend feature work", async () => {
  const audit = await readAudit();
  const normalizedAudit = normalizeWhitespace(audit);

  assert.match(normalizedAudit, /pause new Platform frontend feature work/i);
  assert.match(normalizedAudit, /return to SQAG\/SKR hosting readiness/i);
  assert.match(normalizedAudit, /shared hosting foundation prerequisites/i);
  assert.doesNotMatch(audit, /deploy now|DNS configured|TLS configured|OAuth configured|hosted smoke passed/i);
});

async function readAudit() {
  return readFile(auditPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeWhitespace(value) {
  return value.replace(/\s+/g, " ");
}
