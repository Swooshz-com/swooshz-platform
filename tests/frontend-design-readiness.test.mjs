import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readinessPath = "docs/frontend-design-readiness.md";

test("frontend design readiness doc records required Stitch gate and scope language", async () => {
  const doc = await readReadinessDoc();

  const requiredPhrases = [
    "Public Swooshz website",
    "Blog/resources",
    "Google Stitch Design Gate",
    "Codex must not freestyle a broad visual redesign",
    "approved Stitch",
    "workspace/product portal",
    "customer workspace admin",
    "Swooshz internal admin",
    "content admin",
    "static/Git-backed blog",
    "Seozilla-assisted publishing",
    "blocked until vendor confirms workflow",
    "local visual success is not hosted evidence",
    "Design docs are not implemented UI",
    "production readiness is not approved",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("frontend design readiness doc keeps checklist evidence gated", async () => {
  const doc = await readReadinessDoc();

  assert.match(doc, /- \[ \] Home/i);
  assert.match(doc, /- \[ \] Blog\/resources index/i);
  assert.match(doc, /- \[ \] Login/i);
  assert.match(doc, /- \[ \] Workspace home/i);
  assert.match(doc, /- \[ \] Members list/i);
  assert.match(doc, /- \[ \] Internal overview/i);
  assert.match(doc, /Do not tick checklist items without evidence/i);
  assert.match(doc, /Evidence can be:/i);
  assert.doesNotMatch(doc, /- \[x\]/i);
});

test("frontend design readiness doc avoids secrets and readiness overclaims", async () => {
  const doc = await readReadinessDoc();

  assert.doesNotMatch(doc, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(doc, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(doc, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(doc, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(doc, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(doc, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(doc, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(doc, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(doc, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(doc, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(doc, /production readiness\s+(?:is|has been)\s+(?:approved|achieved|complete)/i);
  assert.doesNotMatch(doc, /\b(?:is|are|now|fully)\s+production[- ]ready\b/i);
});

async function readReadinessDoc() {
  return readFile(readinessPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
