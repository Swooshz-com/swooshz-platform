import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  renderAuthErrorPage,
  renderAdminShellPage,
  renderAppShellPage,
  renderLandingPage,
} from "../dist/index.js";

test("landing page renders the platform name and login link", () => {
  const html = renderLandingPage();

  assert.match(html, /Swooshz Platform/);
  assert.match(html, /\/api\/platform\/auth\/start/);
  assert.doesNotMatch(html, /SESSION_SECRET|DATABASE_URL|postgresql:\/\//i);
});

test("landing page uses real internal-alpha auth copy without public signup or demo language", () => {
  const html = renderLandingPage();

  assert.match(html, /Swooshz Platform internal access/);
  assert.match(html, /approved provider-backed account/);
  assert.match(html, /Continue with Google|Continue with approved provider/);
  assert.match(html, /Use the approved Google account for your workspace/);
  assert.match(html, /No public signup is available/);
  assert.match(html, /href="\/app"/);
  assert.doesNotMatch(html, /INTERNAL PLATFORM SHELL/);
  assert.doesNotMatch(html, /fake|demo|sample|create public account|public signup available/i);
});

test("app shell references only existing browser JSON APIs", () => {
  const html = renderAppShellPage();

  assert.match(html, /\/api\/platform\/session\/context/);
  assert.match(html, /\/api\/platform\/session\/csrf/);
  assert.match(html, /\/api\/platform\/apps\/launch\/open/);
  assert.match(html, /\/api\/platform\/logout/);
  assert.match(html, /adminLink\.href = adminWorkspaces\.length === 1\s*\?\s*"\/app\/admin"/);
  assert.match(html, /"\/app\/admin\?workspace=" \+ encodeURIComponent\(adminWorkspace\.workspaceSlug\)/);
  assert.doesNotMatch(html, /"\/app\/admin\?workspaceId="/);
  assert.match(html, /id="adminLink"[^>]*hidden/);
});

test("app shell keeps secret and raw-auth material out of static HTML", () => {
  const html = renderAppShellPage();

  assert.doesNotMatch(html, /swooshz_session=session_|session-secret/i);
  assert.doesNotMatch(html, /CSRF_TOKEN_HASH_SECRET|csrf-secret/i);
  assert.doesNotMatch(html, /app-launch:v1:hmac-sha256/i);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /DATABASE_URL|postgresql:\/\/|private\.example/i);
});

test("app shell does not persist launch tokens in browser storage or URLs", () => {
  const html = renderAppShellPage();

  assert.doesNotMatch(html, /localStorage|sessionStorage/);
  assert.doesNotMatch(html, /launchToken|token-box|clipboard/i);
  assert.doesNotMatch(html, /launchToken=.*location|location.*launchToken/s);
  assert.doesNotMatch(html, /URLSearchParams\([^)]*launchToken/s);
});

test("admin shell references protected admin APIs and CSRF-protected actions", () => {
  const html = renderAdminShellPage();

  assert.match(html, /\/api\/platform\/session\/context/);
  assert.match(html, /\/api\/platform\/session\/csrf/);
  assert.match(html, /\/api\/platform\/workspaces\//);
  assert.match(html, /\/members/);
  assert.match(html, /\/add\?email=/);
  assert.match(html, /\/member-approvals/);
  assert.match(html, /\/revoke/);
  assert.match(html, /\/role\?role=/);
  assert.match(html, /\/disable/);
  assert.match(html, /\/reactivate/);
  assert.match(html, /\/app-entitlements/);
  assert.match(html, /\/audit-events\?limit=50/);
  assert.match(html, /\/kqag\/status\?status=/);
  assert.match(html, /\/api\/platform\/logout/);
  assert.match(html, /method: "POST"/);
  assert.match(html, /"x-csrf-token": csrfToken/);
});

test("admin shell includes add-existing-user form with allowed non-owner roles", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="addMemberForm"/);
  assert.match(html, /id="addMemberResult"/);
  assert.match(html, /name="email"/);
  assert.match(html, /name="role"/);
  assert.match(
    html,
    /<select name="role" required>\s*<option value="admin">admin<\/option>\s*<option value="member" selected>member<\/option>\s*<option value="viewer">viewer<\/option>/,
  );
  assert.doesNotMatch(html, /value="owner"/);
  assert.match(html, /addExistingMember/);
  assert.match(html, /Pending approval created\./);
  assert.match(html, /Existing user added to workspace\./);
  assert.match(html, /setAddMemberResult/);
  assert.match(html, /safeAdminActionMessage/);
  assert.match(html, /payload\.message/);
  assert.match(html, /Workspace admin action could not be completed\./);
});

test("admin shell renders pending approvals with revoke controls", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="pendingApprovals"/);
  assert.match(html, /sectionHeading\("Pending Approvals"\)/);
  assert.match(html, /renderPendingApprovals/);
  assert.match(html, /adminApprovalsUrl/);
  assert.match(html, /approvalActionsCell/);
  assert.match(html, /revokeApproval/);
  assert.match(html, /"Approval revoked\."/);
  assert.match(html, /Pending approvals/);
  assert.doesNotMatch(html, /owner approval/i);
});

test("admin shell documents owner transfer as unavailable in internal alpha", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="ownerTransfer"/);
  assert.match(html, /Owner transfer is not available in internal alpha yet\./);
  assert.match(html, /reviewed operator process before hosted execution/);
  assert.doesNotMatch(html, /transferOwner|owner-transfer-confirmation|\/owner-transfer/);
});

test("admin shell includes Activity section for safe audit browsing", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="activity"/);
  assert.match(html, /sectionHeading\("Activity"\)/);
  assert.match(html, /renderActivity/);
  assert.match(html, /adminAuditEventsUrl/);
  assert.match(html, /activityLabel/);
  assert.match(html, /metadataRows/);
  assert.match(html, /KQAG access enabled/);
  assert.match(html, /KQAG access disabled/);
  assert.match(html, /Member role changed/);
  assert.match(html, /Membership approval created/);
  assert.match(html, /Membership approval revoked/);
  assert.match(html, /Member reactivated/);
  assert.match(html, /Action/);
  assert.match(html, /Subject/);
  assert.match(html, /Actor/);
  assert.match(html, /Time/);
  assert.match(html, /Details/);
  assert.match(html, /activityPageSize: 10/);
  assert.match(html, /function activityPager/);
  assert.match(html, /Older/);
  assert.match(html, /Newer/);
  assert.match(html, /Previous role/);
  assert.match(html, /New status/);
  assert.match(html, /normalizeAppKeyMetadata/);
  assert.match(html, /value: "KQAG"/);
  assert.match(html, /Platform user/);
  assert.match(html, /System/);
  assert.match(html, /title = raw/);
});

test("admin shell Activity metadata uses an explicit friendly allowlist", () => {
  const html = renderAdminShellPage();

  assert.match(html, /allowedMetadataRows/);
  assert.match(html, /case "previousRole":\s*return \{ label: "Previous role", value: String\(value\) \}/);
  assert.match(html, /case "newRole":\s*return \{ label: "New role", value: String\(value\) \}/);
  assert.match(
    html,
    /case "previousStatus":\s*return \{ label: "Previous status", value: String\(value\) \}/,
  );
  assert.match(html, /case "newStatus":\s*return \{ label: "New status", value: String\(value\) \}/);
  assert.match(html, /case "appKey":\s*return normalizeAppKeyMetadata\(value\)/);
  assert.match(html, /label: "App", value: "KQAG"/);
  assert.doesNotMatch(html, /return key\.replace/);
  assert.doesNotMatch(html, /metadataLabel\(key\)/);
  assert.doesNotMatch(html, /metadataValue\(key, value\)/);
  assert.match(html, /default:\s*return null;/);
  assert.doesNotMatch(html, /case "targetUserId"/);
  assert.doesNotMatch(html, /case "appId"/);
  assert.doesNotMatch(html, /case "membershipId"/);
  assert.doesNotMatch(html, /case "workspaceId"/);
  assert.doesNotMatch(html, /case "entitlementId"/);
  assert.doesNotMatch(html, /case "source"/);
  assert.doesNotMatch(html, /endsWith\("Id"\)/);
});

test("platform shells explain logout scope and show signed-out Google account note", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();
  const landingHtml = renderLandingPage();

  for (const html of [appHtml, adminHtml]) {
    assert.match(html, /Sign out of Swooshz Platform/);
    assert.match(html, /window\.location\.assign\("\/\?signedOut=1"\)/);
  }

  assert.match(
    landingHtml,
    /You are signed out of Swooshz Platform\.\s+Your Google account may\s+still be signed in\./,
  );
  assert.match(landingHtml, /URLSearchParams\(window\.location\.search\)/);
});

test("admin shell limits usable controls to owner/admin workspace context", () => {
  const html = renderAdminShellPage();

  assert.match(html, /membershipRole === "owner" \|\| workspace\.membershipRole === "admin"/);
  assert.match(html, /params\.get\("workspace"\)/);
  assert.match(html, /workspace\.workspaceSlug === requestedSlug/);
  assert.match(html, /Workspace slug/);
  assert.doesNotMatch(html, /Workspace ID/);
  assert.match(html, /Workspace admin is available to workspace owners and admins only\./);
  assert.match(html, /actorIsOwner = state\.workspace\?\.membershipRole === "owner"/);
  assert.match(html, /option\.disabled = role === "owner" && !actorIsOwner/);
  assert.match(html, /member\.role === "owner" && !actorIsOwner/);
  assert.match(html, /button\.textContent = member\.status === "disabled" \? "Reactivate" : "Disable"/);
  assert.match(html, /button\.disabled = !canAct \|\| !\["active", "disabled"\]\.includes\(member\.status\)/);
  assert.match(html, /isProtectedOwner = member\.role === "owner"/);
  assert.match(html, /"Member disabled\."/);
  assert.match(html, /"Member reactivated\."/);
  assert.doesNotMatch(html, /button\.disabled = isSelf \|\| member\.status !== "active"/);
});

test("admin shell keeps secret raw-auth and KQAG quote material out of static HTML", () => {
  const html = renderAdminShellPage();

  assert.doesNotMatch(html, /swooshz_session=session_|session-secret/i);
  assert.doesNotMatch(html, /CSRF_TOKEN_HASH_SECRET|csrf-secret/i);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /DATABASE_URL|postgresql:\/\/|private\.example/i);
  assert.doesNotMatch(html, /quote export|pricing|xlsx|quote session/i);
  assert.doesNotMatch(html, /localStorage|sessionStorage|clipboard/);
});

test("auth error page renders safe retry actions", () => {
  const html = renderAuthErrorPage();

  assert.match(html, /Access not approved/);
  assert.match(html, /not approved for Swooshz Platform/);
  assert.match(html, /href="\/api\/platform\/auth\/start"/);
  assert.match(html, /Try another Google account/);
  assert.match(html, /href="\/"/);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /cookie|DATABASE_URL|postgresql:\/\//i);
});

test("platform shell module does not import frontend frameworks provider SDKs DB KQAG or migrations", async () => {
  const contents = await readFile("src/http/platform-shell.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:kqag|clerk|auth0|supabase|stripe)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /node:http|src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});
