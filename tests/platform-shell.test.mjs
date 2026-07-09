import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  renderAuthErrorPage,
  renderAdminShellPage,
  renderAppShellPage,
  renderAboutPage,
  renderContactPage,
  renderLandingPage,
  renderLoginPage,
  renderResourceArticlePage,
  renderResourcesPage,
  renderRequestAccessPage,
  renderSolutionsPage,
} from "../dist/index.js";

const forbiddenFrontendCopy = [
  /upgrade your plan/i,
  /\bbilling\b/i,
  /\bpayment\b/i,
  /Split-Pane Auto Generator/i,
  /Structured Query/i,
  /data lake/i,
  /\bvector\b/i,
  /\b2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\b/,
];
const fakeDateCopy =
  /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?|20\d{2})\b/;

function withoutSharedStyle(html) {
  return html.replace(/<style>[\s\S]*?<\/style>/g, "");
}

test("landing page renders the public Stitch parity homepage with canonical product copy", () => {
  const html = renderLandingPage();

  assert.match(html, /Swooshz Platform/);
  assert.match(html, /workspace platform for launching trusted business apps/i);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate app launched from\s+Platform/i);
  assert.match(html, /SEO \/ GEO \/ Seozilla/);
  assert.match(html, /Vendor workflow pending|Coming soon|Unavailable until confirmed/i);
  assert.match(html, /href="\/solutions"/);
  assert.match(html, /href="\/login"/);
  assert.match(html, /href="\/request-access"/);
  assert.doesNotMatch(html, /SESSION_SECRET|DATABASE_URL|postgresql:\/\//i);
});

test("login page preserves provider-backed auth start without public signup or password auth", () => {
  const html = renderLoginPage();

  assert.match(html, /Secure Access Portal/);
  assert.match(html, /approved provider-backed account/);
  assert.match(html, /href="\/api\/platform\/auth\/start"/);
  assert.match(html, /Continue with Google|Continue with approved provider/);
  assert.match(html, /Use the approved Google account for your workspace/);
  assert.match(html, /No public signup is available/);
  assert.match(html, /href="\/app"/);
  assert.doesNotMatch(html, /<form/i);
  assert.doesNotMatch(html, /type="password"|Forgot\?|Sign In/i);
  assert.match(html, /href="\/request-access"/);
  assert.doesNotMatch(html, /INTERNAL PLATFORM SHELL/);
  assert.doesNotMatch(html, /fake|demo|sample|create public account|public signup available/i);
});

test("solutions page separates Platform SQAG and unavailable vendor-pending products", () => {
  const html = renderSolutionsPage();

  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate product app launched from Platform/i);
  assert.match(html, /Access Management/);
  assert.match(html, /Workspace Entitlements/);
  assert.match(html, /Owner/);
  assert.match(html, /Admin/);
  assert.match(html, /Member/);
  assert.match(html, /Pending/);
  assert.match(html, /SEO \/ GEO \/ Seozilla/);
  assert.match(html, /Vendor workflow pending/);
  assert.match(html, /Unavailable until confirmed/);
  assert.doesNotMatch(html, /SKR/);
});

test("about page renders safe public company and platform boundary copy", () => {
  const html = renderAboutPage();

  assert.match(html, /About Swooshz/);
  assert.match(html, /workspace access/i);
  assert.match(html, /provider-backed\s+accounts/i);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate app launched\s+from Platform/i);
  assert.match(html, /SEO \/ GEO \/ Seozilla/);
  assert.match(html, /Vendor workflow pending|Unavailable until confirmed/i);
  assert.match(html, /href="\/contact"/);
  assert.match(html, /href="\/request-access"/);
  assert.doesNotMatch(html, /founder|team member|case study|founded in|headquarters/i);
  assert.doesNotMatch(html, /SKR/);
});

test("contact page renders safe access enquiry copy without fake intake flow", () => {
  const html = renderContactPage();

  assert.match(html, /Contact/);
  assert.match(html, /Access enquiry/);
  assert.match(html, /Use your existing Swooshz or workspace sponsor channel/i);
  assert.match(html, /Do not send secrets/i);
  assert.match(html, /href="\/request-access"/);
  assert.doesNotMatch(html, /<form|<input|<textarea|Submit Inquiry|send message/i);
  assert.doesNotMatch(html, /@gmail\.com|@outlook\.com|@example\.com|\+\d|street|avenue|road/i);
  assert.doesNotMatch(html, /ticket|CRM|automated|workflow created|we will email/i);
});

test("request access page is a public information state without signup or delivery claims", () => {
  const html = renderRequestAccessPage();

  assert.match(html, /Request Access/);
  assert.match(html, /approved workspace/i);
  assert.match(html, /provider-backed account/i);
  assert.match(html, /This page does not create an account/i);
  assert.match(html, /No public signup is available/i);
  assert.match(html, /href="\/login"/);
  assert.match(html, /href="\/contact"/);
  assert.doesNotMatch(html, /<form|<input|<textarea|Submit Request|Select an option/i);
  assert.doesNotMatch(html, /free email providers? (?:will be )?automatically rejected/i);
  assert.doesNotMatch(html, /invite sent|email invitation|confirmation email|support ticket|CRM/i);
});

test("resources page renders safe placeholder listing content", () => {
  const html = withoutSharedStyle(renderResourcesPage());

  assert.match(html, /Insights & Resources|Resources/);
  assert.match(html, /Content pending editorial review/i);
  assert.match(html, /How Swooshz Platform launches workspace apps safely/);
  assert.match(html, /Provider-backed access matters/);
  assert.match(html, /Keeping product workflow data outside Platform/);
  assert.match(html, /Swooshz Quote Auto\s+Generator/);
  assert.match(html, /separate app launched from\s+Platform/i);
  assert.match(html, /href="\/resources\/platform-launch-boundaries"/);
  assert.doesNotMatch(html, /<form|<input|<textarea|newsletter|subscribe|email capture/i);
  assert.doesNotMatch(html, /by\s+[A-Z][a-z]+|author|team member|workspace member/i);
  assert.doesNotMatch(html, fakeDateCopy);
  assert.doesNotMatch(html, /case study|testimonial|customer story|\bROI\b|\d+%/i);
  assert.doesNotMatch(html, /CMS|content admin|editor dashboard|publish workflow/i);
  assert.doesNotMatch(html, /SKR|\bSQAG\b|Split-Pane|Structured Query|data lake|vector/i);
});

test("resource article page renders safe article template without fake metadata", () => {
  const html = withoutSharedStyle(renderResourceArticlePage());

  assert.match(html, /How Swooshz Platform launches workspace apps safely/);
  assert.match(html, /Article template pending editorial approval/i);
  assert.match(html, /Provider-backed access/);
  assert.match(html, /Swooshz Quote Auto\s+Generator/);
  assert.match(html, /separate app launched from\s+Platform/i);
  assert.match(html, /product workflow data stays outside Platform/i);
  assert.match(html, /SEO \/ GEO \/ Seozilla/);
  assert.match(html, /unavailable until confirmed|vendor workflow pending/i);
  assert.match(html, /href="\/resources"/);
  assert.doesNotMatch(html, /<form|<input|<textarea|newsletter|subscribe|email capture/i);
  assert.doesNotMatch(html, /by\s+[A-Z][a-z]+|author|team member|workspace member/i);
  assert.doesNotMatch(html, fakeDateCopy);
  assert.doesNotMatch(html, /case study|testimonial|customer story|\bROI\b|\d+%|performance metric/i);
  assert.doesNotMatch(html, /<pre|<code|curl|api key|Authorization:/i);
  assert.doesNotMatch(html, /CMS|content admin|editor dashboard|publish workflow/i);
  assert.doesNotMatch(html, /SKR|\bSQAG\b|Split-Pane|Structured Query|data lake|vector/i);
});

test("public navigation links implemented pages and resources route", () => {
  const html =
    renderLandingPage() +
    renderAboutPage() +
    renderContactPage() +
    renderRequestAccessPage() +
    renderResourcesPage() +
    renderResourceArticlePage();

  assert.match(html, /href="\/about"/);
  assert.match(html, /href="\/contact"/);
  assert.match(html, /href="\/resources"/);
  assert.match(html, /href="\/request-access"/);
  assert.doesNotMatch(html, /<span aria-disabled="true">(?:Blog|Resources)<\/span>/);
});

test("implemented frontend slice excludes forbidden copy and unapproved business flows", () => {
  const pages = [
    renderLandingPage(),
    renderSolutionsPage(),
    renderResourcesPage(),
    renderResourceArticlePage(),
    renderAboutPage(),
    renderContactPage(),
    renderRequestAccessPage(),
    renderLoginPage(),
    renderAppShellPage(),
    renderAdminShellPage(),
    renderAuthErrorPage(),
  ];

  for (const html of pages) {
    for (const forbidden of forbiddenFrontendCopy) {
      assert.doesNotMatch(html, forbidden);
    }

    assert.doesNotMatch(html, /checkout|pricing file|quote history|quote session|case study/i);
    assert.doesNotMatch(html, /newsletter|subscribe|email capture|CMS|content admin/i);
    assert.doesNotMatch(html, /(?:\d{1,3}\.){3}\d{1,3}/);
    assert.doesNotMatch(html, /[a-f0-9]{40}/i);
  }
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

test("app shell shows a clear no-workspace-access state for authenticated users", () => {
  const html = renderAppShellPage();

  assert.match(html, /No workspace access is available for this account\./);
  assert.doesNotMatch(html, /No active workspaces are available\./);
});

test("app shell renders portal launcher and fail-closed entitlement states with safe copy", () => {
  const html = renderAppShellPage();

  assert.match(html, /App Launcher/);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /Launch Apps/);
  assert.match(html, /Contact workspace admin/);
  assert.match(html, /Return to apps/);
  assert.match(html, /Product unavailable/);
  assert.match(html, /Access unavailable/);
  assert.match(html, /app\.access\?\.allowed === true/);
  assert.doesNotMatch(html, /upgrade your plan|billing|payment/i);
});

test("portal and admin shells format workspace roles without prominent Viewer copy", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();

  assert.match(appHtml, /textBlock\("Role", displayWorkspaceRole\(workspace\.membershipRole\)\)/);
  assert.match(appHtml, /function displayWorkspaceRole\(role\)/);
  assert.match(adminHtml, /textBlock\("Role", displayRole\(workspace\.membershipRole\)\)/);
  assert.match(adminHtml, /tableCell\(displayStatus\(member\.status \|\| ""\), "Status"\)/);
  assert.match(adminHtml, /tableCell\(displayRole\(approval\.role\), "Role"\)/);
  assert.match(adminHtml, /tableCell\(displayStatus\(approval\.status\), "Status"\)/);
  assert.doesNotMatch(appHtml + adminHtml, /textBlock\("Role", workspace\.membershipRole\)/);
  assert.doesNotMatch(appHtml + adminHtml, /\bViewer\b/);
});

test("app shell normalizes SQAG display copy without changing app keys or launch endpoint", () => {
  const html = renderAppShellPage();

  assert.match(html, /displayAppName\(app\)/);
  assert.match(html, /"&appKey=" \+ encodeURIComponent\(appKey\)/);
  assert.match(html, /return "Swooshz Quote Auto Generator"/);
  assert.match(html, /endpoints\.launch \+/);
  assert.doesNotMatch(html, /Split-Pane Auto Generator|Structured Query/i);
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
  assert.match(html, /\/add/);
  assert.match(html, /body: \{ email, role \}/);
  assert.match(html, /\/member-approvals/);
  assert.match(html, /\/revoke/);
  assert.match(html, /\/role\?role=/);
  assert.match(html, /\/disable/);
  assert.match(html, /\/reactivate/);
  assert.match(html, /\/remove/);
  assert.match(html, /\/app-entitlements/);
  assert.match(html, /\/audit-events\?limit=50/);
  assert.match(html, /\/sqag\/status\?status=/);
  assert.match(html, /\/api\/platform\/logout/);
  assert.match(html, /method: "POST"/);
  assert.match(html, /"x-csrf-token": csrfToken/);
});

test("admin shell includes add-existing-user form with allowed non-owner roles", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="addMemberForm"/);
  assert.match(html, /id="addMemberModal"/);
  assert.match(html, /id="openAddMemberButton"/);
  assert.match(html, /id="addMemberResult"/);
  assert.match(html, /name="email"/);
  assert.match(html, /name="role"/);
  assert.match(html, /Create a pending workspace access approval/);
  assert.match(html, /provider-backed sign-in flow/);
  assert.match(html, /button[^>]*type="submit"[^>]*>\s*Add member\s*<\/button>/);
  assert.match(html, /<option value="admin">Admin<\/option>/);
  assert.match(html, /<option value="member" selected>Member<\/option>/);
  assert.doesNotMatch(html, /value="owner"/);
  assert.doesNotMatch(html, /value="viewer"|>viewer<|>Viewer</);
  assert.doesNotMatch(html, /email invitation|send invite|Invite a new member/i);
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
  assert.match(html, /Review pending workspace access approvals/);
  assert.match(html, /No email delivery is implied/);
  assert.match(html, /renderPendingApprovals/);
  assert.match(html, /adminApprovalsUrl/);
  assert.match(html, /approvalActionsCell/);
  assert.match(html, /revokeApproval/);
  assert.match(html, /"Approval revoked\."/);
  assert.match(html, /Pending Approvals/);
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
  assert.match(html, /sectionHeading\("Audit Log"\)/);
  assert.match(html, /renderActivity/);
  assert.match(html, /adminAuditEventsUrl/);
  assert.match(html, /activityLabel/);
  assert.match(html, /metadataRows/);
  assert.match(html, /App launch allowed/);
  assert.match(html, /App launch denied/);
  assert.match(html, /Role changed/);
  assert.match(html, /Member removed/);
  assert.match(html, /Login blocked for unapproved user/);
  assert.doesNotMatch(html, /SQAG access enabled|SQAG access disabled|Membership approval/i);
  assert.match(html, /Action/);
  assert.match(html, /Subject/);
  assert.match(html, /Actor/);
  assert.match(html, /Time/);
  assert.match(html, /Details/);
  assert.match(html, /activityPageSize: 10/);
  assert.match(html, /function activityPager/);
  assert.match(html, /Older/);
  assert.match(html, /Newer/);
  assert.match(html, /event\.targetLabel/);
  assert.match(html, /Unknown user/);
  assert.match(html, /Previous role/);
  assert.match(html, /New status/);
  assert.match(html, /normalizeAppKeyMetadata/);
  assert.match(html, /value: "Swooshz Quote Auto Generator"/);
  assert.match(html, /Platform user/);
  assert.match(html, /System/);
  assert.doesNotMatch(html, /title = raw/);
});

test("admin shell Activity metadata uses an explicit friendly allowlist", () => {
  const html = renderAdminShellPage();

  assert.match(html, /allowedMetadataRows/);
  assert.match(html, /case "previousRole":\s*return \{ label: "Previous role", value: displayRole\(value\) \}/);
  assert.match(html, /case "newRole":\s*return \{ label: "New role", value: displayRole\(value\) \}/);
  assert.match(
    html,
    /case "previousStatus":\s*return \{ label: "Previous status", value: displayStatus\(value\) \}/,
  );
  assert.match(html, /case "newStatus":\s*return \{ label: "New status", value: displayStatus\(value\) \}/);
  assert.match(html, /case "appKey":\s*return normalizeAppKeyMetadata\(value\)/);
  assert.match(html, /label: "App", value: "Swooshz Quote Auto Generator"/);
  assert.match(html, /case "app_entitlement":\s*return "Swooshz Quote Auto Generator access";/);
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

test("admin shell Activity subject identifies affected users and pending emails safely", () => {
  const html = renderAdminShellPage();

  assert.match(html, /function subjectLabel\(event\)/);
  assert.match(html, /event\.targetLabel \|\| "Unknown user"/);
  assert.match(html, /case "membership":\s*return event\.targetLabel \|\| "Unknown user";/);
  assert.match(
    html,
    /case "membership_approval":\s*return event\.targetLabel \|\| "Unknown user";/,
  );
  assert.doesNotMatch(html, /targetUserId.*textContent/s);
  assert.doesNotMatch(html, /providerSubject|rawClaims|oauthCode|rawProvider/i);
});

test("platform shells explain logout scope and show signed-out Google account note", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();
  const loginHtml = renderLoginPage();

  for (const html of [appHtml, adminHtml]) {
    assert.match(html, /Sign out of Swooshz Platform/);
    assert.match(html, /window\.location\.assign\("\/login\?signedOut=1"\)/);
  }

  assert.match(
    loginHtml,
    /You are signed out of Swooshz Platform\.\s+Your Google account may\s+still be signed in\./,
  );
  assert.match(loginHtml, /URLSearchParams\(window\.location\.search\)/);
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
  assert.match(html, /isProtectedOwner = member\.role === "owner"/);
  assert.match(html, /"Member disabled\."/);
  assert.match(html, /"Member reactivated\."/);
  assert.match(html, /"Member removed\."/);
  assert.doesNotMatch(html, /\bviewer\b/i);
  assert.doesNotMatch(html, /button\.disabled = isSelf \|\| member\.status !== "active"/);
});

test("admin shell renders member row actions as a compact Actions menu with internal action modal", () => {
  const html = renderAdminShellPage();

  assert.match(html, /function memberActionsCell\(member, activeOwnerCount, label\)/);
  assert.match(html, /menuButton\.textContent = "Actions"/);
  assert.match(html, /closeAllActionMenus/);
  assert.match(html, /actionButton\("Disable Access"/);
  assert.match(html, /actionButton\("Reactivate"/);
  assert.match(html, /actionButton\("Remove from Workspace"/);
  assert.match(html, /removeMember\(member\.membershipId\)/);
  assert.match(html, /id="adminActionModal"/);
  assert.match(html, /Remove member\?/);
  assert.match(
    html,
    /This removes workspace access for this member\. Their platform account is not deleted\./,
  );
  assert.match(html, /Remove member/);
  assert.match(html, /Cancel/);
  assert.match(html, /Removing member\.\.\./);
  assert.match(html, /modalConfirmButton\.disabled = true/);
  assert.match(html, /modalCancelButton\.disabled = true/);
  assert.doesNotMatch(html, /Permanent action|associated projects and data|data loss|product records/i);
  assert.doesNotMatch(html, /window\.confirm/);
  assert.match(html, /member\.status === "active"/);
  assert.match(html, /member\.status === "disabled"/);
  assert.match(html, /menuButton\.disabled = !canAct \|\| !\["active", "disabled"\]\.includes\(member\.status\)/);
  assert.match(html, /adminMemberUrl\(state\.workspace\.workspaceId, membershipId\) \+ "\/remove"/);
  assert.match(html, /case "workspace\.membership\.removed":\s*return "Member removed";/);
  assert.doesNotMatch(html, /button\.textContent = member\.status === "disabled" \? "Reactivate" : "Disable"/);
});

test("admin shell uses Stitch portal layout for workspace management surfaces", () => {
  const html = renderAdminShellPage();

  assert.match(html, /class="portal-layout admin-layout"/);
  assert.match(html, /class="portal-sidebar"/);
  assert.match(html, /Workspace Members/);
  assert.match(html, /Manage access and roles for your workspace/);
  assert.match(html, /Members/);
  assert.match(html, /Activity/);
  assert.match(html, /Add Member/);
  assert.match(html, /data-admin-section="members"/);
  assert.match(html, /data-admin-section="pending-approvals"/);
  assert.match(html, /data-admin-section="activity"/);
});

test("admin shell does not render an enabled no-op workspace search control", () => {
  const html = renderAdminShellPage();
  const enabledSearchInput = /<input\b(?=[^>]*\btype="search"\b)(?![^>]*\bdisabled\b)[^>]*>/i;

  assert.doesNotMatch(html, enabledSearchInput);
  assert.doesNotMatch(html, /Search workspace/);
});

test("platform topbar decorative icons are hidden non-controls without placeholder text", () => {
  const appTopbar = extractTopbarActions(renderAppShellPage());
  const adminTopbar = extractTopbarActions(renderAdminShellPage());

  for (const topbar of [appTopbar, adminTopbar]) {
    assert.match(topbar, /aria-hidden="true"/);
    assert.match(topbar, /class="topbar-icon/);
    assert.doesNotMatch(topbar, /<a\b|<button\b|role="button"/i);
    assert.doesNotMatch(topbar, />\s*(bell|history|account)\s*</i);
  }
});

test("future-only navigation controls render disabled instead of clickable links", () => {
  const html = renderAdminShellPage() + renderLandingPage() + renderSolutionsPage();

  assert.match(html, /<span aria-disabled="true">Help<\/span>/);
  assert.match(html, /<span aria-disabled="true">Settings<\/span>/);
  assert.match(html, /\.portal-nav span\[aria-disabled="true"\]/);
  assert.match(html, /pointer-events: none/);
  assert.match(html, /<a class="" href="\/about">About<\/a>/);
  assert.match(html, /<a class="" href="\/resources">Resources<\/a>/);
  assert.doesNotMatch(html, /<a\b[^>]*>\s*(?:Help|Settings)\s*<\/a>/i);
});

test("admin shell modals support keyboard and backdrop dismissal with visible focus states", () => {
  const html = renderAdminShellPage();

  assert.match(html, /document\.addEventListener\("keydown"/);
  assert.match(html, /event\.key === "Escape"/);
  assert.match(html, /closeAddMemberModal\(\)/);
  assert.match(html, /closeActionModal\(\)/);
  assert.match(html, /addMember\.addEventListener\("click"/);
  assert.match(html, /event\.target === addMember/);
  assert.match(html, /adminActionModal\.addEventListener\("click"/);
  assert.match(html, /event\.target === adminActionModal/);
  assert.match(html, /:focus-visible/);
});

test("admin shell app access surface avoids raw implementation identifiers", () => {
  const html = renderAdminShellPage();

  assert.match(html, /sectionHeading\("App Access"\)/);
  assert.match(html, /Workspace app availability and launch access controls\./);
  assert.match(html, /displayEntitlementAppName/);
  assert.match(html, /textBlock\("Workspace access"/);
  assert.match(html, /Disable access/);
  assert.match(html, /Allow launch/);
  assert.doesNotMatch(html, /textBlock\("App key"/);
  assert.doesNotMatch(html, /textBlock\("Granted by"/);
  assert.doesNotMatch(html, /textBlock\("Entitlement"/);
  assert.doesNotMatch(html, /grantedByUserId/);
});

test("admin shell mobile tables expose row labels without horizontal overflow", () => {
  const html = renderAdminShellPage();

  assert.match(html, /setCellLabel\(cell, label\)/);
  assert.match(html, /memberIdentityCell\(member, "Member"\)/);
  assert.match(html, /roleCell\(member, "Role"\)/);
  assert.match(html, /metadataCell\(event\.metadata, "Details"\)/);
  assert.match(html, /min-width: 220px/);
  assert.match(html, /table-layout: auto/);
  assert.doesNotMatch(html, /table-layout: fixed/);
  assert.match(html, /\.admin-layout \.portal-sidebar/);
  assert.match(html, /height: auto/);
  assert.match(html, /td::before/);
  assert.match(html, /content: attr\(data-label\)/);
  assert.match(html, /overflow-wrap: anywhere/);
});

test("admin shell activity actors avoid raw ids and private actor emails", () => {
  const html = renderAdminShellPage();

  assert.match(html, /function actorLabel\(event\)/);
  assert.match(html, /event\.actorDisplayName \|\|/);
  assert.match(html, /"Platform user"/);
  assert.match(html, /"System"/);
  assert.doesNotMatch(html, /actorEmail/);
});

test("admin shell shows loading feedback for state-changing admin actions", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="adminActionStatus"/);
  assert.match(html, /class="spinner"/);
  assert.match(html, /Saving workspace admin change\.\.\./);
  assert.match(html, /Disabling member\.\.\./);
  assert.match(html, /Reactivating member\.\.\./);
  assert.match(html, /Revoking approval\.\.\./);
  assert.match(html, /Updating app access\.\.\./);
  assert.match(html, /Adding workspace member\.\.\./);
  assert.match(html, /showActionStatus\(loadingMessage, true\)/);
});

test("admin shell keeps secret raw-auth and SQAG quote material out of static HTML", () => {
  const html = renderAdminShellPage();

  assert.doesNotMatch(html, /swooshz_session=session_|session-secret/i);
  assert.doesNotMatch(html, /CSRF_TOKEN_HASH_SECRET|csrf-secret/i);
  assert.doesNotMatch(html, /auth-code|raw-state|raw-nonce|provider-token|raw-claim/i);
  assert.doesNotMatch(html, /DATABASE_URL|postgresql:\/\/|private\.example/i);
  assert.doesNotMatch(html, /quote export|pricing|xlsx|quote session|raw id|commit hash/i);
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

test("platform shell module does not import frontend frameworks provider SDKs DB SQAG or migrations", async () => {
  const contents = await readFile("src/http/platform-shell.ts", "utf8");

  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:react|next|vite|express|fastify|hono)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:sqag|clerk|auth0|supabase|stripe)/i);
  assert.doesNotMatch(contents, /from\s+["'][^"']*(?:db|drizzle|pg|migrations?)/i);
  assert.doesNotMatch(contents, /node:http|src\/db|\.{1,2}\/db|\.{1,2}\/\.{1,2}\/db/i);
});

function extractTopbarActions(html) {
  const match = html.match(/<div class="portal-topbar-actions" aria-hidden="true">[\s\S]*?<\/div>/);
  assert.ok(match, "expected portal topbar actions container");
  return match[0];
}
