import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const roadmapPath = "docs/production-readiness-roadmap.md";

test("production readiness roadmap records required launch gates and Codex rules", async () => {
  const roadmap = await readRoadmap();

  const requiredPhrases = [
    "prod-ready, not just MVP",
    "Production readiness is not yet approved",
    "Checklist Update Rules For Codex",
    "Hostinger/Coolify shared hosting foundation gate",
    "hosted deployment gate",
    "hosted OAuth/auth/member smoke gate",
    "backup/restore gate",
    "logging/monitoring/incident gate",
    "security hardening gate",
    "KQAG/SQAG launch handoff gate",
    "legal/compliance gate",
    "final go/no-go",
    "Codex must not tick a checkbox without evidence",
    "local success is not hosted evidence",
    "docs-only readiness is not deployed evidence",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(roadmap, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("production readiness roadmap keeps blocked items unchecked with evidence requirements", async () => {
  const roadmap = await readRoadmap();

  assert.match(roadmap, /\|\s*Status\s*\|\s*Count \/ notes\s*\|/i);
  assert.match(roadmap, /Blocked until VPS\/shared hosting foundation/i);
  assert.match(roadmap, /Blocked until SQAG\/SKR hosting readiness/i);
  assert.match(roadmap, /Can be worked before VPS/i);
  assert.match(roadmap, /Next recommended pre-VPS work/i);
  assert.match(roadmap, /Blocker:/i);
  assert.match(roadmap, /Next action:/i);
  assert.match(roadmap, /Evidence required:/i);
});

test("production readiness roadmap avoids secrets and readiness overclaims", async () => {
  const roadmap = await readRoadmap();

  assert.doesNotMatch(roadmap, /sk-[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(roadmap, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(roadmap, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(roadmap, /postgres(?:ql)?:\/\/[^\s>]+@/i);
  assert.doesNotMatch(roadmap, /ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
  assert.doesNotMatch(roadmap, /access_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(roadmap, /refresh_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(roadmap, /id_token[=:][A-Za-z0-9._-]{20,}/i);
  assert.doesNotMatch(roadmap, /auth[_-]?code[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(roadmap, /state[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(roadmap, /nonce[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(roadmap, /cookie[=:][A-Za-z0-9._-]{12,}/i);
  assert.doesNotMatch(roadmap, /production readiness\s+(?:is|has been)\s+(?:approved|achieved|complete)/i);
  assert.doesNotMatch(roadmap, /\b(?:is|are|now|fully)\s+production[- ]ready\b/i);
});

async function readRoadmap() {
  return readFile(roadmapPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
