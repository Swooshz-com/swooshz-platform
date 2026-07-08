import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readinessPath = "docs/frontend-design-readiness.md";
const parityPlanPath = "docs/frontend-stitch-visual-freeze-parity-plan.md";
const roadmapPath = "docs/production-readiness-roadmap.md";

const requiredStitchScreens = [
  "swooshz_homepage_desktop_freeze_final",
  "swooshz_homepage_mobile_freeze_final",
  "solutions_products_desktop_freeze_final",
  "solutions_products_mobile_freeze_final",
  "blog_resources_desktop_freeze_final",
  "blog_resources_mobile_freeze_final",
  "blog_article_detail_desktop_freeze_final",
  "blog_article_detail_mobile_freeze_final",
  "about_swooshz_desktop_freeze_final",
  "about_swooshz_mobile_freeze_final",
  "contact_desktop_freeze_final",
  "contact_mobile_freeze_final",
  "request_access_desktop_freeze_final",
  "request_access_mobile_freeze_final",
  "login_desktop_freeze_final",
  "login_mobile_freeze_final",
  "access_status_desktop_freeze_final",
  "access_status_mobile_freeze_final",
  "portal_home_desktop_freeze_final",
  "portal_home_mobile_freeze_final",
  "app_launcher_desktop_freeze_final",
  "app_launcher_mobile_freeze_final",
  "product_unavailable_desktop_freeze_final",
  "product_unavailable_mobile_freeze_final",
  "workspace_members_desktop_freeze_final",
  "workspace_members_mobile_freeze_final",
  "pending_approvals_desktop_freeze_final",
  "pending_approvals_mobile_freeze_final",
  "add_member_modal_desktop_freeze_final",
  "add_member_modal_mobile_freeze_final",
  "member_actions_desktop_freeze_final",
  "member_actions_mobile_freeze_final",
  "activity_log_desktop_freeze_final",
  "activity_log_mobile_freeze_final",
];

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
    "docs/frontend-stitch-visual-freeze-parity-plan.md",
    "34 required screens",
    "visual/layout freeze candidate only",
    "Raw Stitch copy is not production copy",
    "canonical copy corrections",
    "Codex must not freestyle a broad visual redesign",
    "preserve existing auth, provider identity, membership, DB, entitlement, CSRF/origin, session, audit, and SQAG launch logic",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(doc, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("Stitch visual freeze parity plan records the required 34-screen inventory", async () => {
  const plan = await readParityPlan();

  assert.match(plan, /# Frontend Stitch Visual Freeze Parity Plan/i);
  assert.match(plan, /34-screen inventory/i);
  assert.match(plan, /Inventory count: 17 surfaces x 2 breakpoints = 34 required screens/i);
  assert.match(plan, /visual\/layout freeze candidate only/i);

  for (const screenName of requiredStitchScreens) {
    assert.match(plan, new RegExp(escapeRegExp(screenName), "i"));
  }
});

test("Stitch visual freeze parity plan requires canonical copy overrides", async () => {
  const plan = await readParityPlan();

  const requiredPhrases = [
    "Raw Stitch copy is not production copy",
    "Canonical Copy Override Rules",
    "SQAG means Swooshz Quote Auto Generator",
    "Swooshz Quote Auto Generator is a separate app launched from Platform",
    "Do not use Split-Pane Auto Generator",
    "Do not use Structured Query Auto Generator",
    "Do not use query, data, vector, search, or data-lake language",
    "SEO/GEO/Seozilla coming soon, unavailable, vendor workflow pending, or planning-only",
    "Do not present SEO/GEO/Seozilla as a live module",
    "Do not say \"upgrade your plan\" unless billing/plan upgrades are explicitly approved",
    "Owner",
    "Admin",
    "Member",
    "Pending",
    "Do not imply email invitation delivery unless implemented",
    "Member removal copy should describe workspace access only",
    "Member added",
    "Member removed",
    "Role changed",
    "App launch allowed",
    "App launch denied",
    "Login blocked for unapproved user",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(plan, new RegExp(escapeRegExp(phrase), "i"));
  }

  assert.doesNotMatch(plan, /C:\\Users\\/i);
  assert.doesNotMatch(plan, /stitch_[a-z0-9_]+_portal/i);
  assert.doesNotMatch(plan, /screen\.png/i);
});

test("Stitch visual freeze parity plan preserves platform logic and avoids implementation claims", async () => {
  const plan = await readParityPlan();

  const requiredPhrases = [
    "Preserve existing auth, provider identity, session, CSRF/origin, membership, entitlement, audit, and Swooshz Quote Auto Generator launch logic",
    "Platform must not own Swooshz Quote Auto Generator product workflow/runtime data",
    "Do not implement the frontend redesign in this PR",
    "Do not deploy",
    "Do not integrate SEO/GEO/Seozilla",
    "Do not claim production readiness",
    "Hosted visual evidence does not exist",
    "Live Platform-to-Swooshz Quote Auto Generator smoke remains unchecked",
  ];

  for (const phrase of requiredPhrases) {
    assert.match(plan, new RegExp(escapeRegExp(phrase), "i"));
  }
});

test("production roadmap keeps frontend implementation and hosted visual evidence unchecked", async () => {
  const roadmap = await readRoadmap();

  assert.match(roadmap, /34-screen Stitch visual\/layout freeze candidate exists/i);
  assert.match(roadmap, /visual\/layout reference only/i);
  assert.match(roadmap, /Raw Stitch copy is not production copy/i);
  assert.match(roadmap, /- \[ \] Frontend implementation complete/i);
  assert.match(roadmap, /- \[ \] Hosted visual evidence complete/i);
  assert.match(roadmap, /Hosted OAuth\/provider configuration remains unchecked/i);
  assert.doesNotMatch(roadmap, /- \[x\] Frontend implementation complete/i);
  assert.doesNotMatch(roadmap, /- \[x\] Hosted visual evidence complete/i);
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

async function readParityPlan() {
  return readFile(parityPlanPath, "utf8");
}

async function readRoadmap() {
  return readFile(roadmapPath, "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
