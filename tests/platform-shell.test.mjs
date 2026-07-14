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
  assert.match(html, /trusted entry point for your approved workspace/i);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate app launched from\s+Platform/i);
  assert.doesNotMatch(html, /SEO \/ GEO \/ Seozilla/i);
  assert.doesNotMatch(html, /Vendor workflow pending|Coming soon|Unavailable until confirmed/i);
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

test("solutions page presents one approved product and no abandoned product chapter", () => {
  const html = renderSolutionsPage();

  assert.match(html, /One focused product, reached through one trusted place\./);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate product app launched from Platform/i);
  assert.match(html, /Platform owns the entry/);
  assert.match(html, /Owner/);
  assert.match(html, /Admin/);
  assert.match(html, /Member/);
  assert.match(html, /Pending/);
  assert.equal((html.match(/product-chapter-number/g) ?? []).length, 1);
  assert.doesNotMatch(html, /SEO \/ GEO \/ Seozilla|Vendor workflow pending|Unavailable until confirmed|SKR/i);
});

test("about page renders safe public company and platform boundary copy", () => {
  const html = renderAboutPage();

  assert.match(html, /About Swooshz/);
  assert.match(html, /workspace access/i);
  assert.match(html, /provider-backed\s+accounts/i);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /separate app launched\s+from Platform/i);
  assert.doesNotMatch(html, /SEO \/ GEO \/ Seozilla/i);
  assert.doesNotMatch(html, /Vendor workflow pending|Unavailable until confirmed/i);
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
  assert.match(html, /How Swooshz Platform launches its workspace product safely/);
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

  assert.match(html, /How Swooshz Platform launches its workspace product safely/);
  assert.match(html, /Article template pending editorial approval/i);
  assert.match(html, /Provider-backed access/);
  assert.match(html, /Swooshz Quote Auto\s+Generator/);
  assert.match(html, /separate app launched from\s+Platform/i);
  assert.match(html, /product workflow data stays outside Platform/i);
  assert.doesNotMatch(html, /SEO \/ GEO \/ Seozilla/i);
  assert.doesNotMatch(html, /unavailable until confirmed|vendor workflow pending/i);
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
  assert.match(html, /adminLink\.href = "\/app\/admin\?workspace=" \+ encodeURIComponent\(workspace\.workspaceSlug\)/);
  assert.doesNotMatch(html, /"\/app\/admin\?workspaceId="/);
  assert.match(html, /id="adminLink"[^>]*hidden/);
});

test("app shell shows a clear no-workspace-access state for authenticated users", () => {
  const html = renderAppShellPage();

  assert.match(html, /No workspace access is available for this account\./);
  assert.doesNotMatch(html, /No active workspaces are available\./);
});

test("app shell renders the approved compact launcher and fail-closed product states", () => {
  const html = renderAppShellPage();

  assert.match(html, /class="authenticated-shell launcher-shell"/);
  assert.match(html, /Your product/);
  assert.match(html, /Available to your workspace\./);
  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /Create professional quotations using your approved workspace\./);
  assert.match(html, /Ready to launch/);
  assert.match(html, /Open product/);
  assert.match(html, /Product access unavailable/);
  assert.match(html, /Your workspace does not currently have access to this product\./);
  assert.match(html, /We could not open the product\. Try again\./);
  assert.match(html, /Retry/);
  assert.match(html, /state\.app\?\.access\?\.allowed === true/);
  assert.doesNotMatch(html, /<aside[^>]*sidebar|upgrade your plan|billing|payment/i);
  assert.match(html, /@media \(max-width: 350px\)[\s\S]*\.auth-account-context \{ width: calc\(100% \+ 23px\);[\s\S]*64px 52px 55px/);
  assert.match(html, /\.auth-header-link, \.auth-header-button \{ min-width: 0; \}/);
});

test("launcher and admin shells format workspace roles without unsupported role copy", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();

  assert.match(appHtml, /workspaceRole\.textContent = displayWorkspaceRole\(workspace\.membershipRole\)/);
  assert.match(appHtml, /function displayWorkspaceRole\(role\)/);
  assert.match(adminHtml, /headerWorkspaceRole\.textContent = displayRole\(workspace\.membershipRole\)/);
  assert.match(adminHtml, /tableCell\(displayStatus\(member\.status \|\| ""\), "Status"\)/);
  assert.match(adminHtml, /tableCell\(displayRole\(approval\.role\), "Role"\)/);
  assert.doesNotMatch(appHtml + adminHtml, /\bViewer\b/);
});

test("app shell presents the approved product name while preserving the internal app key contract", () => {
  const html = renderAppShellPage();

  assert.match(html, /Swooshz Quote Auto Generator/);
  assert.match(html, /String\(app\.appKey \|\| ""\)\.toLowerCase\(\) === "sqag"/);
  assert.match(html, /"&appKey=" \+ encodeURIComponent\(state\.app\.appKey\)/);
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

test("admin shell includes an accessible add-member flow with allowed non-owner roles", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="addMemberForm"/);
  assert.match(html, /id="addMemberModal"/);
  assert.match(html, /role="dialog" aria-modal="true"/);
  assert.match(html, /Add an existing Swooshz account to this workspace\./);
  assert.match(html, /id="addMemberSubmitButton"[^>]*type="submit">Add member<\/button>/);
  assert.match(html, /<option value="member" selected>Member<\/option><option value="admin">Admin<\/option>/);
  assert.doesNotMatch(html, /value="owner"|value="viewer"|email invitation|send invite/i);
  assert.match(html, /addExistingMember/);
  assert.match(html, /Pending approval created\./);
  assert.match(html, /Existing user added to workspace\./);
  assert.match(html, /addMemberSubmitButton\.disabled = true/);
  assert.match(html, /addMemberSubmitButton\.textContent = "Adding member\.\.\."/);
  assert.match(html, /safeAdminActionMessage/);
  assert.match(html, /Workspace admin action could not be completed\./);
});

test("admin shell renders pending approvals with revoke controls", () => {
  const html = renderAdminShellPage();

  assert.match(html, /data-admin-nav="pending-approvals"/);
  assert.match(html, /sectionHeading\("Pending approvals"\)/);
  assert.match(html, /Review access waiting for an administrator\./);
  assert.match(html, /renderPendingApprovals/);
  assert.match(html, /adminApprovalsUrl/);
  assert.match(html, /approvalActionsCell/);
  assert.match(html, /revokeApproval/);
  assert.match(html, /"Approval revoked\."/);
  assert.doesNotMatch(html, /owner approval|email delivery is implied/i);
});

test("admin shell protects owners without exposing an unfinished owner-transfer surface", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="ownerTransfer" hidden/);
  assert.match(html, /isProtectedOwner = member\.role === "owner"/);
  assert.match(html, /"Protected owner"/);
  assert.doesNotMatch(html, /Owner transfer is not available|transferOwner|owner-transfer-confirmation|\/owner-transfer/);
});

test("admin shell includes an Audit activity section for safe audit browsing", () => {
  const html = renderAdminShellPage();

  assert.match(html, /data-admin-nav="activity"[^>]*>Audit activity<\/button>/);
  assert.match(html, /sectionHeading\("Audit activity"\)/);
  assert.match(html, /renderActivity/);
  assert.match(html, /adminAuditEventsUrl/);
  assert.match(html, /activityLabel/);
  assert.match(html, /metadataRows/);
  assert.match(html, /App launch allowed|App launch denied|Role changed|Member removed/);
  assert.match(html, /Action|Subject|Actor|Time|Details/);
  assert.match(html, /activityPageSize: 10/);
  assert.match(html, /function activityPager/);
  assert.match(html, /Older|Newer/);
  assert.match(html, /normalizeAppKeyMetadata/);
  assert.match(html, /value: "Swooshz Quote Auto Generator"/);
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

test("platform shells use CSRF-protected logout and preserve the signed-out account note", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();
  const loginHtml = renderLoginPage();

  for (const html of [appHtml, adminHtml]) {
    assert.match(html, />Log out<\/button>/);
    assert.match(html, /fetch\(endpoints\.logout/);
    assert.match(html, /"x-csrf-token": csrfToken/);
    assert.match(html, /window\.location\.assign\("\/login\?signedOut=1"\)/);
  }
  assert.match(loginHtml, /You are signed out of Swooshz Platform\.\s+Your Google account may\s+still be signed in\./);
  assert.match(loginHtml, /URLSearchParams\(window\.location\.search\)/);
});

test("admin shell limits usable controls to owner/admin workspace context", () => {
  const html = renderAdminShellPage();

  assert.match(html, /workspace\.membershipRole === "owner" \|\| workspace\.membershipRole === "admin"/);
  assert.match(html, /params\.get\("workspace"\)/);
  assert.match(html, /workspace\.workspaceSlug === requestedSlug/);
  assert.match(html, /Workspace admin is available to workspace owners and admins only\./);
  assert.match(html, /actorIsOwner = state\.workspace\?\.membershipRole === "owner"/);
  assert.match(html, /option\.disabled = role === "owner" && !actorIsOwner/);
  assert.match(html, /isProtectedOwner = member\.role === "owner"/);
  assert.match(html, /"Member disabled\."|"Member reactivated\."|"Member removed\."/);
  assert.doesNotMatch(html, /\bviewer\b/i);
});

test("admin shell renders compact accessible member actions with confirmations", () => {
  const html = renderAdminShellPage();

  assert.match(html, /function memberActionsCell\(member, activeOwnerCount, label\)/);
  assert.match(html, /menuButton\.textContent = "Manage"/);
  assert.match(html, /aria-haspopup", "menu"/);
  assert.match(html, /aria-expanded", "false"/);
  assert.match(html, /closeAllActionMenus/);
  assert.match(html, /actionButton\("Disable member"/);
  assert.match(html, /actionButton\("Reactivate member"/);
  assert.match(html, /actionButton\("Remove member"/);
  assert.match(html, /id="adminActionModal"/);
  assert.match(html, /role="alertdialog" aria-modal="true"/);
  assert.match(html, /This removes workspace access for this member\. Their platform account is not deleted\./);
  assert.match(html, /modalConfirmButton\.disabled = true/);
  assert.match(html, /restoreModalFocus/);
  assert.match(html, /trapModalFocus/);
  assert.doesNotMatch(html, /window\.confirm|Permanent action|associated projects and data|data loss/i);
});

test("admin shell uses the approved compact four-section workspace administration surface", () => {
  const html = renderAdminShellPage();

  assert.match(html, /class="authenticated-shell admin-shell"/);
  assert.match(html, /class="admin-section-nav"/);
  assert.match(html, /data-admin-nav="members"/);
  assert.match(html, /data-admin-nav="pending-approvals"/);
  assert.match(html, /data-admin-nav="app-access"/);
  assert.match(html, /data-admin-nav="activity"/);
  assert.match(html, />Members<\/button>/);
  assert.match(html, />Pending approvals<\/button>/);
  assert.match(html, />Product access<\/button>/);
  assert.match(html, />Audit activity<\/button>/);
  assert.doesNotMatch(withoutSharedStyle(html), /portal-sidebar|Dashboard|Billing|Settings|Security|Reports|Integrations/);
});

test("admin shell does not render an enabled no-op workspace search control", () => {
  const html = renderAdminShellPage();
  const enabledSearchInput = /<input\b(?=[^>]*\btype="search"\b)(?![^>]*\bdisabled\b)[^>]*>/i;

  assert.doesNotMatch(html, enabledSearchInput);
  assert.doesNotMatch(html, /Search workspace/);
});

test("authenticated headers expose only working account, workspace, role, admin, product, and logout controls", () => {
  const appHtml = renderAppShellPage();
  const adminHtml = renderAdminShellPage();

  for (const html of [appHtml, adminHtml]) {
    assert.match(html, /class="auth-app-bar"/);
    assert.match(html, /Signed in as/);
    assert.match(html, /Workspace/);
    assert.match(html, /Role/);
    assert.match(html, />Log out<\/button>/);
  }
  assert.match(appHtml, />Administration<\/a>/);
  assert.match(adminHtml, />Your product<\/a>/);
});

test("authenticated navigation omits future-only and abandoned destinations", () => {
  const html = renderAppShellPage() + renderAdminShellPage();

  assert.doesNotMatch(html, />Help<|>Settings<|Dashboard|Billing|Security|Reports|Integrations/);
  assert.doesNotMatch(html, /SEO \/ GEO \/ Seozilla|Vendor workflow pending/i);
  assert.match(html, /href="\/app"/);
  assert.match(html, /href="\/app\/admin"/);
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

test("admin shell product access surface shows one customer-facing product and no raw identifiers", () => {
  const html = renderAdminShellPage();

  assert.match(html, /sectionHeading\("Product access"\)/);
  assert.match(html, /Control whether this workspace can use its current product\./);
  assert.match(html, /displayEntitlementAppName/);
  assert.match(html, /Members with access can create professional quotations for this workspace\./);
  assert.match(html, /Enable product access/);
  assert.match(html, /Disable product access/);
  assert.match(html, /Disabling product access prevents new launches and does not change member records\./);
  assert.match(html, /String\(entitlement\.appKey \|\| ""\)\.toLowerCase\(\) === "sqag"/);
  assert.doesNotMatch(html, /textBlock\("App key"|textBlock\("Granted by"|grantedByUserId/);
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

test("admin shell shows busy feedback for state-changing admin actions", () => {
  const html = renderAdminShellPage();

  assert.match(html, /id="adminActionStatus"/);
  assert.match(html, /class="spinner"/);
  assert.match(html, /Saving workspace admin change\.\.\./);
  assert.match(html, /Disabling member\.\.\./);
  assert.match(html, /Reactivating member\.\.\./);
  assert.match(html, /Revoking approval\.\.\./);
  assert.match(html, /Updating product access\.\.\./);
  assert.match(html, /Adding member\.\.\./);
  assert.match(html, /showActionStatus\(loadingMessage, true\)/);
  assert.match(html, /setModalBusy\(true, action\.loadingMessage\)/);
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
