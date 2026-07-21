import { publicAssetUrl } from "./public-asset-manifest.js";

export function renderAppShellPage(): string {
  return htmlDocument({
    title: "Swooshz Platform",
    body: `
      <div class="authenticated-shell launcher-shell">
        <a class="auth-skip-link" href="#main-content">Skip to main content</a>
        <header class="auth-app-bar" aria-label="Application header">
          <div class="auth-bar-inner">
            <a class="auth-brand" href="/app" aria-label="Swooshz Platform home">
              <img src="${publicAssetUrl("/public-assets/swooshz-mark.png")}" width="34" height="34" alt="">
              <span>Swooshz Platform</span>
            </a>
            <div id="accountContext" class="auth-account-context" hidden>
              <label id="workspaceControl" class="auth-context-control" hidden>
                <span>Workspace</span>
                <select id="workspaceSelect" aria-label="Current workspace"></select>
              </label>
              <div id="singleWorkspaceContext" class="auth-context-value">
                <span>Workspace</span>
                <strong id="workspaceName"></strong>
              </div>
              <div class="auth-context-value auth-role-context">
                <span>Role</span>
                <strong id="workspaceRole"></strong>
              </div>
              <div class="auth-account-copy">
                <span>Signed in as</span>
                <strong id="accountName"></strong>
                <small id="accountEmail"></small>
              </div>
              <a id="adminLink" class="auth-header-link" href="/app/admin" hidden>Administration</a>
              <button id="logoutButton" class="auth-header-button" type="button">Log out</button>
            </div>
          </div>
        </header>

        <main id="main-content" class="auth-main launcher-main">
          <section class="launcher-page" aria-labelledby="launcherTitle">
            <header class="auth-page-heading">
              <h1 id="launcherTitle">Your product</h1>
              <p>Available to your workspace.</p>
            </header>

            <section id="status" class="auth-status" role="status" aria-live="polite">Loading your workspace...</section>
            <section id="noWorkspace" class="auth-empty-state" hidden>
              <h2>No workspace available</h2>
              <p>No workspace access is available for this account.</p>
            </section>

            <article id="launchUnit" class="launch-unit" aria-labelledby="productTitle" hidden>
              <div class="product-summary">
                <div class="product-mark" aria-hidden="true">
                  <svg class="quote-document-icon" viewBox="0 0 64 64">
                    <path class="icon-sheet" d="M17 7h21l11 11v39H17z"></path>
                    <path class="icon-fold" d="M38 7v12h11"></path>
                    <path class="icon-line" d="M23 28h21M23 36h21M23 44h21"></path>
                    <path class="icon-column" d="M36 28v16"></path>
                    <path class="icon-total" d="M23 51h21"></path>
                  </svg>
                </div>
                <div class="product-copy">
                  <p class="product-label">Quotations</p>
                  <h2 id="productTitle">Swooshz Quote Auto Generator</h2>
                  <p class="product-description">Create professional quotations using your approved workspace.</p>
                </div>
              </div>

              <div id="launchReadiness" class="launch-readiness">
                <div class="readiness-status">
                  <span id="launchStatusDot" class="auth-status-dot" aria-hidden="true"></span>
                  <span>
                    <span class="readiness-label">Product status</span>
                    <strong id="launchStatus">Ready to launch</strong>
                  </span>
                </div>
                <button id="launchButton" class="auth-primary-button launch-button" type="button">Open product</button>
                <div id="launchFeedback" class="launch-feedback" role="alert" hidden>
                  <strong>We could not open the product. Try again.</strong>
                  <button id="retryLaunchButton" type="button">Retry</button>
                </div>
              </div>

              <footer class="launch-note">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5h14v14H5zM8 9h8M8 13h5"></path></svg>
                <span><strong>Ready when you are.</strong> Your workspace and role stay the same when the product opens.</span>
              </footer>
            </article>
          </section>
        </main>
      </div>
      <script>
        (() => {
          const endpoints = {
            context: "/api/platform/session/context",
            csrf: "/api/platform/session/csrf",
            launch: "/api/platform/apps/launch/open",
            logout: "/api/platform/logout"
          };
          const state = {
            context: null,
            csrfToken: null,
            workspace: null,
            app: null,
            launchBusy: false
          };

          const status = document.getElementById("status");
          const noWorkspace = document.getElementById("noWorkspace");
          const launchUnit = document.getElementById("launchUnit");
          const launchReadiness = document.getElementById("launchReadiness");
          const launchStatus = document.getElementById("launchStatus");
          const launchStatusDot = document.getElementById("launchStatusDot");
          const launchButton = document.getElementById("launchButton");
          const retryLaunchButton = document.getElementById("retryLaunchButton");
          const launchFeedback = document.getElementById("launchFeedback");
          const accountContext = document.getElementById("accountContext");
          const accountName = document.getElementById("accountName");
          const accountEmail = document.getElementById("accountEmail");
          const workspaceControl = document.getElementById("workspaceControl");
          const workspaceSelect = document.getElementById("workspaceSelect");
          const singleWorkspaceContext = document.getElementById("singleWorkspaceContext");
          const workspaceName = document.getElementById("workspaceName");
          const workspaceRole = document.getElementById("workspaceRole");
          const adminLink = document.getElementById("adminLink");
          const logoutButton = document.getElementById("logoutButton");

          workspaceSelect.addEventListener("change", () => {
            const workspace = state.context?.workspaces?.find((candidate) =>
              candidate.workspaceId === workspaceSelect.value
            );
            if (workspace) renderWorkspace(workspace);
          });
          launchButton.addEventListener("click", () => { void launchProduct(); });
          retryLaunchButton.addEventListener("click", () => { void launchProduct(); });
          logoutButton.addEventListener("click", () => { void logout(); });

          void loadContext();

          async function loadContext() {
            setStatus("Loading your workspace...");
            try {
              const response = await fetch(endpoints.context, {
                credentials: "same-origin",
                cache: "no-store"
              });
              const context = await readJson(response);
              if (!response.ok || context.outcome !== "authenticated") {
                renderUnauthenticated();
                return;
              }
              renderAuthenticated(context);
            } catch {
              setStatus("We could not load your workspace. Try again by refreshing the page.");
            }
          }

          function renderUnauthenticated() {
            accountContext.hidden = true;
            launchUnit.hidden = true;
            noWorkspace.hidden = true;
            status.replaceChildren();
            const message = document.createElement("span");
            message.textContent = "You are not signed in. ";
            const link = document.createElement("a");
            link.href = "/api/platform/auth/start";
            link.textContent = "Continue with Google";
            status.append(message, link);
            status.hidden = false;
          }

          function renderAuthenticated(context) {
            state.context = context;
            accountContext.hidden = false;
            accountName.textContent = context.user.displayName || context.user.email;
            accountEmail.textContent = context.user.email || "";
            const workspaces = Array.isArray(context.workspaces) ? context.workspaces : [];
            workspaceSelect.replaceChildren();
            for (const workspace of workspaces) {
              const option = document.createElement("option");
              option.value = workspace.workspaceId;
              option.textContent = workspace.workspaceName || workspace.workspaceId;
              workspaceSelect.append(option);
            }
            workspaceControl.hidden = workspaces.length < 2;
            singleWorkspaceContext.hidden = workspaces.length > 1;
            if (workspaces.length === 0) {
              state.workspace = null;
              state.app = null;
              status.hidden = true;
              launchUnit.hidden = true;
              noWorkspace.hidden = false;
              adminLink.hidden = true;
              return;
            }
            renderWorkspace(workspaces[0]);
          }

          function renderWorkspace(workspace) {
            state.workspace = workspace;
            workspaceSelect.value = workspace.workspaceId;
            workspaceName.textContent = workspace.workspaceName || workspace.workspaceId;
            workspaceRole.textContent = displayWorkspaceRole(workspace.membershipRole);
            noWorkspace.hidden = true;
            const canAdmin = workspace.membershipRole === "owner" || workspace.membershipRole === "admin";
            adminLink.hidden = !canAdmin;
            if (canAdmin) {
              adminLink.href = "/app/admin?workspace=" + encodeURIComponent(workspace.workspaceSlug);
            }
            const apps = Array.isArray(workspace.apps) ? workspace.apps : [];
            state.app = apps.find((app) => String(app.appKey || "").toLowerCase() === "sqag") || null;
            launchUnit.hidden = false;
            renderLaunchState(state.app?.access?.allowed === true ? "ready" : "unavailable");
            status.hidden = true;
          }

          function renderLaunchState(nextState) {
            launchReadiness.classList.remove("is-loading", "is-unavailable");
            launchFeedback.hidden = true;
            launchButton.disabled = false;
            launchButton.textContent = "Open product";
            launchStatusDot.classList.remove("is-disabled");
            if (nextState === "loading") {
              launchReadiness.classList.add("is-loading");
              launchButton.disabled = true;
              launchButton.textContent = "Opening product...";
              launchStatus.textContent = "Opening product";
              return;
            }
            if (nextState === "failure") {
              launchStatus.textContent = "Could not open";
              launchFeedback.hidden = false;
              return;
            }
            if (nextState === "unavailable") {
              launchReadiness.classList.add("is-unavailable");
              launchStatusDot.classList.add("is-disabled");
              launchStatus.textContent = "Product access unavailable";
              launchButton.disabled = true;
              launchFeedback.replaceChildren();
              const heading = document.createElement("strong");
              heading.textContent = "Product access unavailable";
              const copy = document.createElement("span");
              copy.textContent = "Your workspace does not currently have access to this product.";
              launchFeedback.append(heading, copy);
              launchFeedback.hidden = false;
              return;
            }
            launchStatus.textContent = "Ready to launch";
          }

          async function launchProduct() {
            if (state.launchBusy || !state.workspace || !state.app || state.app.access?.allowed !== true) return;
            state.launchBusy = true;
            renderLaunchState("loading");
            try {
              const csrfToken = await getCsrfToken();
              const response = await fetch(
                endpoints.launch +
                  "?workspaceId=" + encodeURIComponent(state.workspace.workspaceId) +
                  "&appKey=" + encodeURIComponent(state.app.appKey),
                {
                  method: "POST",
                  credentials: "same-origin",
                  cache: "no-store",
                  headers: { "x-csrf-token": csrfToken }
                }
              );
              const payload = await readJson(response);
              let finalizationHandle = response.headers.get("x-sqag-finalization-handle");
              if (!response.ok || payload.outcome !== "launch_opened" || !payload.launchUrl || !payload.finalizationUrl || !finalizationHandle) {
                renderLaunchState("failure");
                return;
              }
              const launchUrl = new URL(payload.launchUrl);
              const finalizationUrl = new URL(payload.finalizationUrl);
              if (launchUrl.protocol !== "https:" || finalizationUrl.protocol !== "https:" || launchUrl.origin !== finalizationUrl.origin || launchUrl.origin === window.location.origin) {
                finalizationHandle = null;
                renderLaunchState("failure");
                return;
              }
              const finalizeResponse = await fetch(finalizationUrl.toString(), {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: { "x-sqag-finalization-handle": finalizationHandle }
              });
              finalizationHandle = null;
              if (!finalizeResponse.ok) {
                renderLaunchState("failure");
                return;
              }
              window.location.assign(launchUrl.toString());
            } catch {
              renderLaunchState("failure");
            } finally {
              state.launchBusy = false;
            }
          }

          async function getCsrfToken() {
            if (state.csrfToken) return state.csrfToken;
            const response = await fetch(endpoints.csrf, {
              credentials: "same-origin",
              cache: "no-store"
            });
            const payload = await readJson(response);
            if (!response.ok || payload.outcome !== "issued" || !payload.csrfToken) {
              throw new Error("CSRF token unavailable.");
            }
            state.csrfToken = payload.csrfToken;
            return state.csrfToken;
          }

          async function logout() {
            setStatus("Signing out...");
            try {
              const csrfToken = await getCsrfToken();
              await fetch(endpoints.logout, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: { "x-csrf-token": csrfToken }
              });
            } finally {
              window.location.assign("/login?signedOut=1");
            }
          }

          function displayWorkspaceRole(role) {
            if (role === "owner") return "Owner";
            if (role === "admin") return "Admin";
            return "Member";
          }

          async function readJson(response) {
            try { return await response.json(); } catch { return {}; }
          }

          function setStatus(message) {
            status.textContent = message;
            status.hidden = false;
          }
        })();
      </script>
    `,
  });
}
export function renderAdminShellPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Administration",
    body: `
      <div id="adminShell" class="authenticated-shell admin-shell" data-active-section="members">
        <a class="auth-skip-link" href="#main-content">Skip to main content</a>
        <header class="auth-app-bar" aria-label="Application header">
          <div class="auth-bar-inner">
            <a class="auth-brand" href="/app" aria-label="Swooshz Platform home">
              <img src="${publicAssetUrl("/public-assets/swooshz-mark.png")}" width="34" height="34" alt="">
              <span>Swooshz Platform</span>
            </a>
            <div id="accountContext" class="auth-account-context" hidden>
              <label id="workspaceControl" class="auth-context-control" hidden>
                <span>Workspace</span>
                <select id="workspaceSelect" aria-label="Current workspace"></select>
              </label>
              <div id="singleWorkspaceContext" class="auth-context-value">
                <span>Workspace</span>
                <strong id="headerWorkspaceName"></strong>
              </div>
              <div class="auth-context-value auth-role-context">
                <span>Role</span>
                <strong id="headerWorkspaceRole"></strong>
              </div>
              <div class="auth-account-copy">
                <span>Signed in as</span>
                <strong id="headerAccountName"></strong>
                <small id="headerAccountEmail"></small>
              </div>
              <a class="auth-header-link" href="/app">Your product</a>
              <button id="logoutButton" class="auth-header-button" type="button">Log out</button>
            </div>
          </div>
        </header>

        <nav class="admin-section-nav" aria-label="Administration sections">
          <div class="admin-nav-inner">
            <button type="button" data-admin-nav="members" aria-current="page">Members</button>
            <button type="button" data-admin-nav="pending-approvals">Pending approvals</button>
            <button type="button" data-admin-nav="app-access">Product access</button>
            <button type="button" data-admin-nav="activity">Audit activity</button>
          </div>
        </nav>

        <main id="main-content" class="auth-main admin-main">
          <label class="mobile-admin-selector">
            <span>Administration section</span>
            <select id="adminSectionSelect">
              <option value="members">Members</option>
              <option value="pending-approvals">Pending approvals</option>
              <option value="app-access">Product access</option>
              <option value="activity">Audit activity</option>
            </select>
          </label>
          <header class="admin-page-header">
            <div class="auth-page-heading">
              <h1 id="adminPageTitle">Members</h1>
              <p id="adminPageDescription">Manage who can access this workspace and what they are allowed to do.</p>
            </div>
            <button id="openAddMemberButton" class="auth-primary-button" type="button" hidden>Add member</button>
          </header>
          <section id="status" class="auth-status" role="status" aria-live="polite">Loading your workspace...</section>
          <section id="adminActionStatus" class="auth-action-status" role="status" aria-live="polite" hidden>
            <span class="spinner" aria-hidden="true"></span>
            <span id="adminActionStatusText"></span>
          </section>
          <section id="identity" hidden></section>
          <section id="workspaceSummary" hidden></section>
          <section id="ownerTransfer" hidden></section>
          <section id="members" class="admin-panel" data-admin-section="members" hidden></section>
          <section id="pendingApprovals" class="admin-panel" data-admin-section="pending-approvals" hidden></section>
          <section id="entitlements" class="admin-panel" data-admin-section="app-access" hidden></section>
          <section id="activity" class="admin-panel" data-admin-section="activity" hidden></section>
        </main>
      </div>

      <div id="addMemberModal" class="modal-backdrop auth-modal-backdrop" hidden>
        <section class="action-modal add-member-modal" role="dialog" aria-modal="true" aria-labelledby="addMemberModalTitle" aria-describedby="addMemberModalBody">
          <div class="modal-header">
            <div><p class="modal-kicker">Members</p><h2 id="addMemberModalTitle">Add member</h2></div>
            <button id="closeAddMemberModalButton" class="modal-close" type="button" aria-label="Close add member form">&times;</button>
          </div>
          <div class="modal-body">
            <p id="addMemberModalBody">Add a teammate by email. Existing Swooshz accounts are added immediately. Otherwise, access activates after the same email signs in with Google. No invitation email is sent.</p>
            <p id="addMemberResult" class="inline-feedback" role="status" aria-live="polite" hidden></p>
            <form id="addMemberForm" class="field-stack">
              <label><strong>Email address</strong><input name="email" type="email" autocomplete="email" placeholder="name@example.com" required></label>
              <label><strong>Role</strong><select name="role" required><option value="member" selected>Member</option><option value="admin">Admin</option></select></label>
              <div class="modal-actions">
                <button id="cancelAddMemberModalButton" class="auth-secondary-button" type="button">Cancel</button>
                <button id="addMemberSubmitButton" class="auth-primary-button" type="submit">Add member</button>
              </div>
            </form>
          </div>
        </section>
      </div>

      <div id="adminActionModal" class="modal-backdrop auth-modal-backdrop" hidden>
        <section class="action-modal member-action-modal" role="alertdialog" aria-modal="true" aria-labelledby="adminActionModalTitle" aria-describedby="adminActionModalBody">
          <div class="modal-header">
            <div><p class="modal-kicker">Confirm change</p><h2 id="adminActionModalTitle">Remove member?</h2></div>
            <button id="adminActionModalCancel" class="modal-close" type="button" aria-label="Cancel administrative action">&times;</button>
          </div>
          <div class="modal-body">
            <p id="adminActionModalBody">This removes workspace access for this member. Their platform account is not deleted.</p>
            <p id="adminActionModalLoading" class="modal-loading" role="status" hidden><span class="spinner" aria-hidden="true"></span><span id="adminActionModalLoadingText">Removing member...</span></p>
            <p id="adminActionModalError" class="modal-error" role="alert" hidden></p>
          </div>
          <div class="modal-actions modal-footer">
            <button id="adminActionModalDismiss" class="auth-secondary-button" type="button">Cancel</button>
            <button id="adminActionModalConfirm" class="auth-danger-button" type="button">Remove member</button>
          </div>
        </section>
      </div>
      <script>
        (() => {
          const endpoints = {
            context: "/api/platform/session/context",
            csrf: "/api/platform/session/csrf",
            logout: "/api/platform/logout"
          };

          const state = {
            context: null,
            csrfToken: null,
            workspace: null,
            activityEvents: [],
            activityPage: 0,
            activityPageSize: 10,
            modalAction: null,
            modalRestoreFocus: null,
            lastActionMenuButton: null,
            activeSection: "members",
            adminReady: false
          };

          const adminShell = document.getElementById("adminShell");
          const accountContext = document.getElementById("accountContext");
          const workspaceControl = document.getElementById("workspaceControl");
          const workspaceSelect = document.getElementById("workspaceSelect");
          const singleWorkspaceContext = document.getElementById("singleWorkspaceContext");
          const headerWorkspaceName = document.getElementById("headerWorkspaceName");
          const headerWorkspaceRole = document.getElementById("headerWorkspaceRole");
          const headerAccountName = document.getElementById("headerAccountName");
          const headerAccountEmail = document.getElementById("headerAccountEmail");
          const adminPageTitle = document.getElementById("adminPageTitle");
          const adminPageDescription = document.getElementById("adminPageDescription");
          const adminSectionSelect = document.getElementById("adminSectionSelect");
          const adminNavButtons = document.querySelectorAll("[data-admin-nav]");
          const status = document.getElementById("status");
          const adminActionStatus = document.getElementById("adminActionStatus");
          const adminActionStatusText = document.getElementById("adminActionStatusText");
          const identity = document.getElementById("identity");
          const workspaceSummary = document.getElementById("workspaceSummary");
          const addMember = document.getElementById("addMemberModal");
          const openAddMemberButton = document.getElementById("openAddMemberButton");
          const closeAddMemberModalButton = document.getElementById("closeAddMemberModalButton");
          const cancelAddMemberModalButton = document.getElementById("cancelAddMemberModalButton");
          const addMemberResult = document.getElementById("addMemberResult");
          const addMemberForm = document.getElementById("addMemberForm");
          const addMemberSubmitButton = document.getElementById("addMemberSubmitButton");
          const ownerTransfer = document.getElementById("ownerTransfer");
          const pendingApprovals = document.getElementById("pendingApprovals");
          const members = document.getElementById("members");
          const entitlements = document.getElementById("entitlements");
          const activity = document.getElementById("activity");
          const logoutButton = document.getElementById("logoutButton");
          const adminActionModal = document.getElementById("adminActionModal");
          const modalTitle = document.getElementById("adminActionModalTitle");
          const modalBody = document.getElementById("adminActionModalBody");
          const modalLoading = document.getElementById("adminActionModalLoading");
          const modalLoadingText = document.getElementById("adminActionModalLoadingText");
          const modalError = document.getElementById("adminActionModalError");
          const modalCancelButton = document.getElementById("adminActionModalCancel");
          const modalDismissButton = document.getElementById("adminActionModalDismiss");
          const modalConfirmButton = document.getElementById("adminActionModalConfirm");

          logoutButton.addEventListener("click", () => {
            void logout();
          });
          workspaceSelect.addEventListener("change", () => {
            const workspace = state.context?.workspaces?.find((candidate) =>
              candidate.workspaceId === workspaceSelect.value &&
              (candidate.membershipRole === "owner" || candidate.membershipRole === "admin")
            );
            if (!workspace) return;
            state.workspace = workspace;
            const nextUrl = new URL(window.location.href);
            nextUrl.searchParams.set("workspace", workspace.workspaceSlug);
            window.history.replaceState({}, "", nextUrl);
            renderWorkspaceSummary(workspace);
            void loadAdminData();
          });
          for (const button of adminNavButtons) {
            button.addEventListener("click", () => setAdminSection(button.dataset.adminNav));
          }
          adminSectionSelect.addEventListener("change", () => setAdminSection(adminSectionSelect.value));
          addMemberForm.addEventListener("submit", (event) => {
            void addExistingMember(event);
          });
          openAddMemberButton.addEventListener("click", () => {
            openAddMemberModal();
          });
          closeAddMemberModalButton.addEventListener("click", () => {
            closeAddMemberModal();
          });
          cancelAddMemberModalButton.addEventListener("click", () => {
            closeAddMemberModal();
          });
          modalCancelButton.addEventListener("click", () => {
            closeActionModal();
          });
          modalDismissButton.addEventListener("click", () => {
            closeActionModal();
          });
          modalConfirmButton.addEventListener("click", () => {
            void runModalAction();
          });
          addMember.addEventListener("click", (event) => {
            if (event.target === addMember) {
              closeAddMemberModal();
            }
          });
          adminActionModal.addEventListener("click", (event) => {
            if (event.target === adminActionModal) {
              closeActionModal();
            }
          });
          document.addEventListener("keydown", (event) => {
            if (event.key === "Tab" && (!addMember.hidden || !adminActionModal.hidden)) {
              trapModalFocus(event);
            }
            if (event.key === "Escape") {
              closeAllActionMenus(true);
              if (!addMember.hidden) closeAddMemberModal();
              if (!adminActionModal.hidden) closeActionModal();
            }
          });
          document.addEventListener("click", (event) => {
            if (!event.target.closest(".action-menu")) {
              const focusWasInsidePanel = document.activeElement?.closest?.(".action-menu-panel") !== null;
              closeAllActionMenus(focusWasInsidePanel);
            }
          });

          const requestedSection = new URLSearchParams(window.location.search).get("section");
          setAdminSection(requestedSection || "members");
          void loadContext();

          async function loadContext() {
            setStatus("Loading platform session...");
            hideAdminSections();

            try {
              const response = await fetch(endpoints.context, {
                credentials: "same-origin",
                cache: "no-store"
              });
              const context = await readJson(response);

              if (!response.ok || context.outcome !== "authenticated") {
                renderUnauthenticated();
                return;
              }

              state.context = context;
              logoutButton.hidden = false;
              renderIdentity(context);

              const workspace = chooseWorkspace(context);
              if (!workspace) {
                renderForbidden();
                return;
              }

              state.workspace = workspace;
              await loadAdminData();
            } catch {
              setStatus("Workspace admin could not be loaded.");
            }
          }

          async function loadAdminData() {
            setStatus("Loading workspace admin...");
            const workspaceId = state.workspace.workspaceId;

            try {
              const [
                membersResponse,
                approvalsResponse,
                entitlementsResponse,
                activityResponse
              ] = await Promise.all([
                fetch(adminMembersUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminApprovalsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminEntitlementsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminAuditEventsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                })
              ]);
              const membersPayload = await readJson(membersResponse);
              const approvalsPayload = await readJson(approvalsResponse);
              const entitlementsPayload = await readJson(entitlementsResponse);
              const activityPayload = await readJson(activityResponse);

              if (
                !membersResponse.ok ||
                !approvalsResponse.ok ||
                !entitlementsResponse.ok ||
                !activityResponse.ok ||
                membersPayload.outcome !== "listed" ||
                approvalsPayload.outcome !== "listed" ||
                entitlementsPayload.outcome !== "listed" ||
                activityPayload.outcome !== "listed"
              ) {
                renderForbidden();
                return;
              }

              renderWorkspaceSummary(state.workspace);
              renderPendingApprovals(approvalsPayload.approvals);
              renderMembers(membersPayload.members);
              renderEntitlements(entitlementsPayload.entitlements);
              renderActivity(activityPayload.events);
              state.adminReady = true;
              setAdminSection(state.activeSection);
              setStatus("Workspace administration ready.");
            } catch {
              setStatus("Workspace admin could not be loaded.");
              hideAdminSections();
            }
          }

          function chooseWorkspace(context) {
            const params = new URLSearchParams(window.location.search);
            const requestedSlug = params.get("workspace");
            const requested = params.get("workspaceId");
            const adminWorkspaces = Array.isArray(context.workspaces)
              ? context.workspaces.filter((workspace) =>
                  workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
                )
              : [];

            if (requestedSlug) {
              return adminWorkspaces.find((workspace) => workspace.workspaceSlug === requestedSlug) ?? null;
            }

            if (requested) {
              return adminWorkspaces.find((workspace) => workspace.workspaceId === requested) ?? null;
            }

            return adminWorkspaces[0] ?? null;
          }

          function renderUnauthenticated() {
            accountContext.hidden = true;
            logoutButton.hidden = true;
            hideAdminSections();
            status.replaceChildren();
            const message = document.createElement("span");
            message.textContent = "No active platform session. ";
            const link = document.createElement("a");
            link.href = "/api/platform/auth/start";
            link.textContent = "Continue with Google";
            status.append(message, link);
          }

          function renderForbidden() {
            hideAdminSections();
            setStatus("Workspace admin is available to workspace owners and admins only.");
          }

          function renderIdentity(context) {
            identity.hidden = true;
            accountContext.hidden = false;
            headerAccountName.textContent = context.user.displayName || context.user.email;
            headerAccountEmail.textContent = context.user.email || "";
            const adminWorkspaces = Array.isArray(context.workspaces)
              ? context.workspaces.filter((workspace) =>
                  workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
                )
              : [];
            workspaceSelect.replaceChildren();
            for (const workspace of adminWorkspaces) {
              const option = document.createElement("option");
              option.value = workspace.workspaceId;
              option.textContent = workspace.workspaceName || workspace.workspaceId;
              workspaceSelect.append(option);
            }
            workspaceControl.hidden = adminWorkspaces.length < 2;
            singleWorkspaceContext.hidden = adminWorkspaces.length > 1;
          }

          function renderWorkspaceSummary(workspace) {
            workspaceSummary.hidden = true;
            headerWorkspaceName.textContent = workspace.workspaceName || workspace.workspaceId;
            headerWorkspaceRole.textContent = displayRole(workspace.membershipRole);
            workspaceSelect.value = workspace.workspaceId;
          }
          function renderMembers(memberList) {
            members.hidden = false;
            members.replaceChildren(
              sectionHeading("Members"),
              sectionDescription("Manage who can access this workspace and what they are allowed to do.")
            );

            if (!Array.isArray(memberList) || memberList.length === 0) {
              members.append(emptyMessage("No workspace members are available."));
              return;
            }

            const table = document.createElement("table");
            table.append(tableHead(["Member", "Role", "Status", "Last active", "Actions"]));
            const body = document.createElement("tbody");
            const activeOwnerCount = memberList.filter((member) =>
              member.role === "owner" && member.status === "active"
            ).length;

            for (const [memberIndex, member] of memberList.entries()) {
              const row = document.createElement("tr");
              row.append(
                memberIdentityCell(member, "Member"),
                roleCell(member, "Role"),
                tableCell(displayStatus(member.status || ""), "Status"),
                timeCell(member.user?.lastLoginAt, "Last active"),
                memberActionsCell(member, activeOwnerCount, "Actions", memberIndex)
              );
              body.append(row);
            }

            table.append(body);
            members.append(table);
          }

          function renderPendingApprovals(approvalList) {
            pendingApprovals.hidden = false;
            pendingApprovals.replaceChildren(
              sectionHeading("Pending approvals"),
              sectionDescription("Review access waiting for an administrator.")
            );

            if (!Array.isArray(approvalList) || approvalList.length === 0) {
              pendingApprovals.append(emptyMessage("No pending approvals are available."));
              return;
            }

            const table = document.createElement("table");
            table.append(tableHead(["Requester", "Role", "Status", "Created", "Actions"]));
            const body = document.createElement("tbody");

            for (const approval of approvalList) {
              const row = document.createElement("tr");
              row.append(
                tableCell(approval.email || "", "Requester"),
                tableCell(displayRole(approval.role), "Role"),
                tableCell(displayStatus(approval.status), "Status"),
                timeCell(approval.createdAt, "Created"),
                approvalActionsCell(approval, "Actions")
              );
              body.append(row);
            }

            table.append(body);
            pendingApprovals.append(table);
          }

          function renderEntitlements(entitlementList) {
            entitlements.hidden = false;
            entitlements.replaceChildren(
              sectionHeading("Product access"),
              sectionDescription("Control whether this workspace can use its current product.")
            );
            const productAccess = Array.isArray(entitlementList)
              ? entitlementList.filter((entitlement) =>
                  String(entitlement.appKey || "").toLowerCase() === "sqag"
                )
              : [];
            if (productAccess.length === 0) {
              entitlements.append(emptyMessage("Product access has not been configured for this workspace."));
              return;
            }
            for (const entitlement of productAccess) {
              const row = document.createElement("article");
              row.className = "product-access-row";
              const detail = document.createElement("div");
              detail.className = "product-access-product";
              const copy = document.createElement("div");
              const heading = document.createElement("h3");
              const description = document.createElement("p");
              heading.textContent = displayEntitlementAppName(entitlement);
              description.textContent = "Members with access can create professional quotations for this workspace.";
              copy.append(heading, description);
              detail.append(productSymbol(), copy);
              const accessState = document.createElement("div");
              accessState.className = "product-access-state";
              const accessLabel = document.createElement("span");
              const accessValue = document.createElement("strong");
              accessLabel.textContent = "Product access";
              accessValue.textContent = displayAccessStatus(entitlement.status);
              accessValue.dataset.status = entitlement.status === "enabled" ? "enabled" : "disabled";
              accessState.append(accessLabel, accessValue);
              const button = document.createElement("button");
              button.type = "button";
              button.className = "auth-secondary-button";
              const nextStatus = entitlement.status === "enabled" ? "disabled" : "enabled";
              button.textContent = nextStatus === "enabled" ? "Enable product access" : "Disable product access";
              button.addEventListener("click", () => updateEntitlement(nextStatus));
              row.append(detail, accessState, button);
              entitlements.append(row);
            }
            const note = document.createElement("p");
            note.className = "surface-note";
            note.textContent = "Disabling product access prevents new launches and does not change member records.";
            entitlements.append(note);
          }
          function renderActivity(eventList) {
            activity.hidden = false;
            state.activityEvents = Array.isArray(eventList) ? eventList : [];
            state.activityPage = 0;
            renderActivityPage();
          }

          function renderActivityPage() {
            activity.replaceChildren(
              sectionHeading("Audit activity"),
              sectionDescription("Review recent administrative changes for this workspace.")
            );

            const eventList = state.activityEvents;
            if (eventList.length === 0) {
              activity.append(emptyMessage("No recent workspace activity is available."));
              return;
            }

            const start = state.activityPage * state.activityPageSize;
            const visibleEvents = eventList.slice(start, start + state.activityPageSize);
            const table = document.createElement("table");
            table.append(tableHead(["Action", "Subject", "Actor", "Time", "Details"]));
            const body = document.createElement("tbody");

            for (const event of visibleEvents) {
              const row = document.createElement("tr");
              row.append(
                tableCell(activityLabel(event), "Action"),
                tableCell(subjectLabel(event), "Subject"),
                tableCell(actorLabel(event), "Actor"),
                timeCell(event.createdAt, "Time"),
                metadataCell(event.metadata, "Details")
              );
              body.append(row);
            }

            table.append(body);
            activity.append(table);
            activity.append(activityPager(start, visibleEvents.length, eventList.length));
          }

          function activityPager(start, visibleCount, totalCount) {
            const pager = document.createElement("div");
            pager.className = "pager";
            const summary = document.createElement("p");
            summary.className = "empty";
            summary.textContent =
              "Showing " + String(start + 1) + "-" + String(start + visibleCount) +
              " of " + String(totalCount) + " recent events";

            const newer = document.createElement("button");
            newer.type = "button";
            newer.className = "secondary-action compact";
            newer.textContent = "Newer";
            newer.disabled = state.activityPage === 0;
            newer.addEventListener("click", () => {
              state.activityPage = Math.max(0, state.activityPage - 1);
              renderActivityPage();
            });

            const older = document.createElement("button");
            older.type = "button";
            older.className = "secondary-action compact";
            older.textContent = "Older";
            older.disabled = start + visibleCount >= totalCount;
            older.addEventListener("click", () => {
              state.activityPage += 1;
              renderActivityPage();
            });

            pager.append(summary, newer, older);
            return pager;
          }

          function roleCell(member, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            const select = document.createElement("select");
            const roles = ["owner", "admin", "member"];
            const isSelf = member.user?.id === state.context?.user?.userId;
            const actorIsOwner = state.workspace?.membershipRole === "owner";

            for (const role of roles) {
              const option = document.createElement("option");
              option.value = role;
              option.textContent = displayRole(role);
              option.selected = member.role === role || (!roles.includes(member.role) && role === "member");
              option.disabled = role === "owner" && !actorIsOwner;
              select.append(option);
            }

            select.disabled =
              isSelf || member.status !== "active" || (member.role === "owner" && !actorIsOwner);
            select.addEventListener("change", () => {
              const nextRole = select.value;
              select.value = member.role;
              changeMemberRole(member.membershipId, nextRole);
            });
            cell.append(select);
            return cell;
          }

          function memberActionsCell(member, activeOwnerCount, label, memberIndex) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            const isSelf = member.user?.id === state.context?.user?.userId;
            const isProtectedOwner = member.role === "owner";
            const isLastActiveOwner =
              member.role === "owner" && member.status === "active" && activeOwnerCount <= 1;
            const canAct = !isSelf && !isProtectedOwner && !isLastActiveOwner;

            if (!canAct) {
              const protectedLabel = document.createElement("span");
              protectedLabel.className = "protected-label";
              protectedLabel.textContent = isProtectedOwner || isLastActiveOwner
                ? "Protected owner"
                : "Your account";
              protectedLabel.title = isProtectedOwner || isLastActiveOwner
                ? "The workspace owner cannot be removed."
                : "Use another administrator for changes to your own access.";
              cell.append(protectedLabel);
              return cell;
            }

            const menu = document.createElement("div");
            const menuButton = document.createElement("button");
            const menuPanel = document.createElement("div");
            menu.className = "action-menu";
            menuButton.type = "button";
            menuButton.className = "auth-secondary-button compact";
            menuButton.textContent = "Manage";
            menuButton.disabled = !["active", "disabled"].includes(member.status);
            const actionIdSuffix = String(member.membershipId || memberIndex).replace(/[^a-zA-Z0-9_-]/g, "-");
            menuButton.id = "member-actions-trigger-" + String(memberIndex) + "-" + actionIdSuffix;
            menuPanel.id = "member-actions-panel-" + String(memberIndex) + "-" + actionIdSuffix;
            menuButton.setAttribute("aria-controls", menuPanel.id);
            menuButton.setAttribute("aria-expanded", "false");
            menuButton.addEventListener("click", () => {
              const shouldOpen = menuPanel.hidden;
              closeAllActionMenus(false);
              menuPanel.hidden = !shouldOpen;
              menuButton.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
              if (shouldOpen) {
                state.lastActionMenuButton = menuButton;
                menuPanel.querySelector("button")?.focus();
              }
            });

            menuPanel.className = "action-menu-panel";
            menuPanel.hidden = true;
            if (member.status === "active") {
              menuPanel.append(actionButton("Disable member", () => {
                closeAllActionMenus(false, true);
                disableMember(member.membershipId);
              }));
            }
            if (member.status === "disabled") {
              menuPanel.append(actionButton("Reactivate member", () => {
                closeAllActionMenus(false, true);
                reactivateMember(member.membershipId);
              }));
            }
            if (["active", "disabled"].includes(member.status)) {
              menuPanel.append(actionButton("Remove member", () => {
                closeAllActionMenus(false, true);
                removeMember(member.membershipId);
              }));
            }
            menu.append(menuButton, menuPanel);
            cell.append(menu);
            return cell;
          }

          function closeAllActionMenus(restoreFocus = false, preserveTrigger = false) {
            const restoreTarget = state.lastActionMenuButton;
            for (const panel of document.querySelectorAll(".action-menu-panel")) panel.hidden = true;
            for (const button of document.querySelectorAll(".action-menu > button[aria-controls]")) {
              button.setAttribute("aria-expanded", "false");
            }
            if (!preserveTrigger) state.lastActionMenuButton = null;
            if (restoreFocus) restoreTarget?.focus();
          }
          function actionButton(label, onClick) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "secondary-action compact";
            button.textContent = label;
            button.addEventListener("click", onClick);
            return button;
          }

          function approvalActionsCell(approval, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            const button = document.createElement("button");
            button.type = "button";
            button.className = "secondary-action compact";
            button.textContent = "Revoke";
            button.disabled = approval.status !== "pending";
            button.addEventListener("click", () => {
              void revokeApproval(approval.approvalId);
            });
            cell.append(button);
            return cell;
          }

          function changeMemberRole(membershipId, role) {
            openActionModal({
              title: "Change role?",
              body: "Confirm that you want to change this member's role.",
              confirmLabel: "Change role",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) +
                "/role?role=" + encodeURIComponent(role),
              successMessage: "Member role updated.",
              loadingMessage: "Changing member role..."
            });
          }

          async function disableMember(membershipId) {
            openActionModal({
              title: "Disable member?",
              body: "This disables workspace access for this member. Their platform account is not deleted.",
              confirmLabel: "Disable member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/disable",
              successMessage: "Member disabled.",
              loadingMessage: "Disabling member..."
            });
          }

          async function reactivateMember(membershipId) {
            openActionModal({
              title: "Reactivate member?",
              body: "This restores workspace access for this member.",
              confirmLabel: "Reactivate member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/reactivate",
              successMessage: "Member reactivated.",
              loadingMessage: "Reactivating member..."
            });
          }

          async function removeMember(membershipId) {
            openActionModal({
              title: "Remove member?",
              body: "This removes workspace access for this member. Their platform account is not deleted.",
              confirmLabel: "Remove member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/remove",
              successMessage: "Member removed.",
              loadingMessage: "Removing member..."
            });
          }

          async function revokeApproval(approvalId) {
            openActionModal({
              title: "Revoke approval?",
              body: "This removes the pending workspace access approval for this email.",
              confirmLabel: "Revoke approval",
              url: adminApprovalUrl(state.workspace.workspaceId, approvalId) + "/revoke",
              successMessage: "Approval revoked.",
              loadingMessage: "Revoking approval..."
            });
          }

          function updateEntitlement(nextStatus) {
            const disabling = nextStatus === "disabled";
            openActionModal({
              title: disabling ? "Disable product access?" : "Enable product access?",
              body: disabling
                ? "Members will be unable to launch this product until access is enabled again."
                : "Members with access will be able to launch this product.",
              confirmLabel: disabling ? "Disable product access" : "Enable product access",
              url: adminEntitlementsUrl(state.workspace.workspaceId) +
                "/sqag/status?status=" + encodeURIComponent(nextStatus),
              successMessage: disabling ? "Product access disabled." : "Product access enabled.",
              loadingMessage: "Updating product access..."
            });
          }

          async function addExistingMember(event) {
            event.preventDefault();
            const formData = new FormData(addMemberForm);
            const email = String(formData.get("email") || "");
            const role = String(formData.get("role") || "member");
            if (!email.trim()) {
              setAddMemberResult("We could not add this member. Check the email address and try again.");
              return;
            }
            addMemberSubmitButton.disabled = true;
            addMemberSubmitButton.textContent = "Adding member...";
            const result = await postAdminAction(
              addMemberUrl(state.workspace.workspaceId),
              null,
              { body: { email, role }, loadingMessage: "Adding member..." }
            );
            addMemberSubmitButton.disabled = false;
            addMemberSubmitButton.textContent = "Add member";
            if (result) {
              addMemberForm.reset();
              closeAddMemberModal();
            }
          }
          function openActionModal(action) {
            state.modalRestoreFocus = state.lastActionMenuButton || document.activeElement;
            state.lastActionMenuButton = null;
            state.modalAction = action;
            modalTitle.textContent = action.title;
            modalBody.textContent = action.body;
            modalConfirmButton.textContent = action.confirmLabel;
            modalError.hidden = true;
            modalError.textContent = "";
            setModalBusy(false, action.loadingMessage);
            adminActionModal.hidden = false;
            modalCancelButton.focus();
          }

          function openAddMemberModal() {
            state.modalRestoreFocus = openAddMemberButton;
            setAddMemberResult("");
            addMember.hidden = false;
            addMemberForm.querySelector("input[name='email']").focus();
          }

          function closeAddMemberModal() {
            if (addMemberSubmitButton.disabled) return;
            addMember.hidden = true;
            setAddMemberResult("");
            restoreModalFocus();
          }

          function closeActionModal() {
            if (modalConfirmButton.disabled) {
              return;
            }

            state.modalAction = null;
            adminActionModal.hidden = true;
            modalError.hidden = true;
            modalError.textContent = "";
            setModalBusy(false, "");
            restoreModalFocus();
          }

          async function runModalAction() {
            const action = state.modalAction;

            if (!action) {
              return;
            }

            setModalBusy(true, action.loadingMessage);
            const success = await postAdminAction(action.url, action.successMessage, {
              loadingMessage: action.loadingMessage
            });

            if (success) {
              setModalBusy(false, "");
              closeActionModal();
              return;
            }

            setModalBusy(false, action.loadingMessage);
            modalError.textContent = "Workspace admin action could not be completed.";
            modalError.hidden = false;
          }

          function setModalBusy(isBusy, message) {
            if (isBusy) {
              modalConfirmButton.disabled = true;
              modalCancelButton.disabled = true;
              modalDismissButton.disabled = true;
            } else {
              modalConfirmButton.disabled = false;
              modalCancelButton.disabled = false;
              modalDismissButton.disabled = false;
            }
            modalLoading.hidden = !isBusy;
            modalLoadingText.textContent = message || "";
          }

          async function postAdminAction(
            url,
            successMessage = "Workspace admin change saved.",
            options = {}
          ) {
            const loadingMessage = options.loadingMessage || "Saving workspace admin change...";
            setStatus(loadingMessage);
            showActionStatus(loadingMessage, true);
            setAddMemberResult("");

            try {
              const csrfToken = await getCsrfToken();
              const response = await fetch(url, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                  ...(options.body ? { "content-type": "application/json" } : {}),
                  "x-csrf-token": csrfToken
                },
                body: options.body ? JSON.stringify(options.body) : undefined
              });
              const payload = await readJson(response);

              if (!response.ok) {
                const message = safeAdminActionMessage(payload);
                setStatus(message);
                showActionStatus(message, false);
                setAddMemberResult(message);
                await loadAdminData();
                return false;
              }

              await loadAdminData();
              const message = successMessage || adminActionSuccessMessage(payload);
              setStatus(message);
              showActionStatus(message, false);
              setAddMemberResult(message);
              return true;
            } catch {
              const message = "Workspace admin action could not be completed.";
              setStatus(message);
              showActionStatus(message, false);
              setAddMemberResult(message);
              return false;
            }
          }

          function adminActionSuccessMessage(payload) {
            if (payload?.outcome === "pending_approval_created") {
              return "Pending approval created.";
            }

            if (payload?.outcome === "created") {
              return "Existing user added to workspace.";
            }

            if (payload?.outcome === "revoked") {
              return "Approval revoked.";
            }

            return "Workspace admin change saved.";
          }

          function safeAdminActionMessage(payload) {
            if (payload && typeof payload.message === "string" && payload.message.trim()) {
              return payload.message;
            }

            return "Workspace admin action could not be completed.";
          }

          function setAddMemberResult(message) {
            if (!message) {
              addMemberResult.hidden = true;
              addMemberResult.textContent = "";
              return;
            }

            addMemberResult.textContent = message;
            addMemberResult.hidden = false;
          }

          function showActionStatus(message, busy) {
            if (!message) {
              adminActionStatus.hidden = true;
              adminActionStatusText.textContent = "";
              adminActionStatus.querySelector(".spinner").hidden = true;
              return;
            }

            adminActionStatus.hidden = false;
            adminActionStatusText.textContent = message;
            adminActionStatus.querySelector(".spinner").hidden = !busy;
          }

          async function getCsrfToken() {
            if (state.csrfToken) {
              return state.csrfToken;
            }

            const response = await fetch(endpoints.csrf, {
              credentials: "same-origin",
              cache: "no-store"
            });
            const payload = await readJson(response);

            if (!response.ok || payload.outcome !== "issued" || !payload.csrfToken) {
              throw new Error("CSRF token unavailable.");
            }

            state.csrfToken = payload.csrfToken;
            return state.csrfToken;
          }

          async function logout() {
            setStatus("Signing out...");

            try {
              const csrfToken = await getCsrfToken();
              await fetch(endpoints.logout, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                  "x-csrf-token": csrfToken
                }
              });
            } finally {
              window.location.assign("/login?signedOut=1");
            }
          }

          async function readJson(response) {
            try {
              return await response.json();
            } catch {
              return {};
            }
          }

          function adminMembersUrl(workspaceId) {
            return "/api/platform/workspaces/" + encodeURIComponent(workspaceId) + "/members";
          }

          function addMemberUrl(workspaceId) {
            return adminMembersUrl(workspaceId) + "/add";
          }

          function adminMemberUrl(workspaceId, membershipId) {
            return adminMembersUrl(workspaceId) + "/" + encodeURIComponent(membershipId);
          }

          function adminApprovalsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/member-approvals";
          }

          function adminApprovalUrl(workspaceId, approvalId) {
            return adminApprovalsUrl(workspaceId) + "/" + encodeURIComponent(approvalId);
          }

          function adminEntitlementsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/app-entitlements";
          }

          function adminAuditEventsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/audit-events?limit=50";
          }

          function activityLabel(event) {
            switch (event.eventType) {
              case "workspace.app_entitlement.enabled":
                return "App launch allowed";
              case "workspace.app_entitlement.disabled":
                return "App launch denied";
              case "workspace.membership.added":
                return "Member added";
              case "workspace.membership.disabled":
                return "Member removed";
              case "workspace.membership.reactivated":
                return "Member added";
              case "workspace.membership.removed":
                return "Member removed";
              case "workspace.membership.role_changed":
                return "Role changed";
              case "workspace.membership_approval.created":
                return "Login blocked for unapproved user";
              case "workspace.membership_approval.revoked":
                return "Login blocked for unapproved user";
              case "workspace.membership_approval.accepted":
                return "Member added";
              default:
                return "Workspace activity";
            }
          }

          function subjectLabel(event) {
            switch (event.targetType) {
              case "app_entitlement":
                return "Swooshz Quote Auto Generator access";
              case "membership":
                return event.targetLabel || "Unknown user";
              case "membership_approval":
                return event.targetLabel || "Unknown user";
              default:
                return "Workspace item";
            }
          }

          function actorLabel(event) {
            return event.actorDisplayName ||
              (event.actorUserId ? "Platform user" : "System");
          }

          function metadataCell(metadata, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            const rows = metadataRows(metadata);

            if (rows.length === 0) {
              cell.textContent = "No details";
              return cell;
            }

            const list = document.createElement("dl");
            list.className = "metadata-list";

            for (const row of rows) {
              const term = document.createElement("dt");
              const detail = document.createElement("dd");
              term.textContent = row.label;
              detail.textContent = row.value;
              list.append(term, detail);
            }

            cell.append(list);
            return cell;
          }

          function metadataRows(metadata) {
            if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
              return [];
            }

            const rows = [];

            for (const [key, value] of Object.entries(metadata)) {
              const row = allowedMetadataRows(key, value);
              if (row) {
                rows.push(row);
              }
            }

            return rows;
          }

          function allowedMetadataRows(key, value) {
            if (!isSafeMetadataValue(value)) {
              return null;
            }

            switch (key) {
              case "previousRole":
                return { label: "Previous role", value: displayRole(value) };
              case "newRole":
                return { label: "New role", value: displayRole(value) };
              case "previousStatus":
                return { label: "Previous status", value: displayStatus(value) };
              case "newStatus":
                return { label: "New status", value: displayStatus(value) };
              case "appKey":
                return normalizeAppKeyMetadata(value);
              default:
                return null;
            }
          }

          function normalizeAppKeyMetadata(value) {
            if (String(value).toLowerCase() !== "sqag") {
              return null;
            }

            return { label: "App", value: "Swooshz Quote Auto Generator" };
          }

          function isSafeMetadataValue(value) {
            return value === null ||
              typeof value === "string" ||
              typeof value === "number" ||
              typeof value === "boolean";
          }

          function hideAdminSections() {
            state.adminReady = false;
            identity.hidden = true;
            adminActionStatus.hidden = true;
            adminActionStatusText.textContent = "";
            workspaceSummary.hidden = true;
            openAddMemberButton.hidden = true;
            addMember.hidden = true;
            addMemberResult.hidden = true;
            addMemberResult.textContent = "";
            ownerTransfer.hidden = true;
            pendingApprovals.hidden = true;
            members.hidden = true;
            entitlements.hidden = true;
            activity.hidden = true;
            workspaceSummary.replaceChildren();
            addMemberForm.reset();
            pendingApprovals.replaceChildren();
            members.replaceChildren();
            entitlements.replaceChildren();
            activity.replaceChildren();
          }

          function setAdminSection(requestedSection) {
            const sectionContent = {
              members: ["Members", "Manage who can access this workspace and what they are allowed to do."],
              "pending-approvals": ["Pending approvals", "Review access waiting for an administrator."],
              "app-access": ["Product access", "Control whether this workspace can use its current product."],
              activity: ["Audit activity", "Review recent administrative changes for this workspace."]
            };
            const section = sectionContent[requestedSection] ? requestedSection : "members";
            state.activeSection = section;
            adminShell.dataset.activeSection = section;
            adminPageTitle.textContent = sectionContent[section][0];
            adminPageDescription.textContent = sectionContent[section][1];
            adminSectionSelect.value = section;
            for (const button of adminNavButtons) {
              const active = button.dataset.adminNav === section;
              if (active) {
                button.setAttribute("aria-current", "page");
              } else {
                button.removeAttribute("aria-current");
              }
            }
            for (const panel of document.querySelectorAll("[data-admin-section]")) {
              panel.hidden = panel.dataset.adminSection !== section;
            }
            openAddMemberButton.hidden = !state.adminReady || section !== "members";
          }

          function restoreModalFocus() {
            const target = state.modalRestoreFocus;
            state.modalRestoreFocus = null;
            target?.focus?.();
          }

          function trapModalFocus(event) {
            const backdrop = !addMember.hidden ? addMember : adminActionModal;
            const focusable = [...backdrop.querySelectorAll(
              'button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'
            )];
            if (focusable.length === 0) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) {
              event.preventDefault();
              last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
              event.preventDefault();
              first.focus();
            }
          }

          function productSymbol() {
            const namespace = "http://www.w3.org/2000/svg";
            const mark = document.createElement("span");
            const svg = document.createElementNS(namespace, "svg");
            mark.className = "product-mark compact";
            mark.setAttribute("aria-hidden", "true");
            svg.setAttribute("class", "quote-document-icon");
            svg.setAttribute("viewBox", "0 0 64 64");
            const paths = [
              ["icon-sheet", "M17 7h21l11 11v39H17z"],
              ["icon-fold", "M38 7v12h11"],
              ["icon-line", "M23 28h21M23 36h21M23 44h21"],
              ["icon-column", "M36 28v16"],
              ["icon-total", "M23 51h21"]
            ];
            for (const [className, data] of paths) {
              const path = document.createElementNS(namespace, "path");
              path.setAttribute("class", className);
              path.setAttribute("d", data);
              svg.append(path);
            }
            mark.append(svg);
            return mark;
          }

          function setStatus(message) {
            status.textContent = message;
            status.hidden = message === "Workspace administration ready.";
          }

          function sectionHeading(value) {
            const heading = document.createElement("h2");
            heading.textContent = value;
            return heading;
          }

          function sectionDescription(value) {
            const description = document.createElement("p");
            description.className = "empty section-description";
            description.textContent = value;
            return description;
          }

          function memberIdentityCell(member, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            const block = document.createElement("div");
            block.className = "member-identity";
            const avatar = document.createElement("span");
            avatar.className = "member-avatar";
            avatar.textContent = initials(member.user?.displayName || member.user?.email || "Member");
            const copy = document.createElement("span");
            const name = document.createElement("strong");
            const email = document.createElement("span");
            name.textContent = member.user?.displayName || "Workspace member";
            email.textContent = member.user?.email || "";
            copy.append(name, email);
            block.append(avatar, copy);
            cell.append(block);
            return cell;
          }

          function initials(value) {
            return String(value || "M")
              .trim()
              .split(/\\s+/)
              .slice(0, 2)
              .map((part) => part[0] || "")
              .join("")
              .toUpperCase() || "M";
          }

          function displayRole(role) {
            switch (role) {
              case "owner":
                return "Owner";
              case "admin":
                return "Admin";
              default:
                return "Member";
            }
          }

          function displayStatus(status) {
            switch (status) {
              case "active":
                return "Active";
              case "disabled":
                return "Disabled";
              case "pending":
                return "Pending";
              case "enabled":
                return "Enabled";
              default:
                return status ? String(status) : "Not available";
            }
          }

          function displayEntitlementAppName(entitlement) {
            const key = String(entitlement.appKey || "").toLowerCase();
            const name = String(entitlement.appName || "");

            if (key === "sqag" || name.toLowerCase() === "sqag") {
              return "Swooshz Quote Auto Generator";
            }

            return name || "Workspace app";
          }

          function displayEntitlementStatus(status) {
            if (status === "active") {
              return "Available";
            }

            if (!status) {
              return "Not available";
            }

            return String(status);
          }

          function displayAccessStatus(status) {
            return status === "enabled" ? "Enabled" : "Disabled";
          }

          function textBlock(label, value) {
            const block = document.createElement("p");
            const strong = document.createElement("strong");
            strong.textContent = label;
            const span = document.createElement("span");
            span.textContent = value ?? "";
            block.append(strong, span);
            return block;
          }

          function tableHead(labels) {
            const head = document.createElement("thead");
            const row = document.createElement("tr");
            for (const label of labels) {
              const cell = document.createElement("th");
              cell.scope = "col";
              cell.textContent = label;
              row.append(cell);
            }
            head.append(row);
            return head;
          }

          function tableCell(value, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            cell.textContent = value ?? "";
            return cell;
          }

          function timeCell(value, label) {
            const cell = document.createElement("td");
            setCellLabel(cell, label);
            cell.textContent = formatDate(value);
            return cell;
          }

          function setCellLabel(cell, label) {
            if (label) {
              cell.setAttribute("data-label", label);
            }
          }

          function formatDate(value) {
            if (!value) {
              return "Not available";
            }

            const date = new Date(value);
            if (Number.isNaN(date.getTime())) {
              return String(value);
            }

            return date.toLocaleString(undefined, {
              year: "numeric",
              month: "short",
              day: "2-digit",
              hour: "2-digit",
              minute: "2-digit"
            });
          }

          function emptyMessage(message) {
            const node = document.createElement("p");
            node.className = "empty";
            node.textContent = message;
            return node;
          }
        })();
      </script>
    `,
  });
}

export function renderAuthErrorPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Access Not Approved",
    body: `
      <main class="landing">
        <section class="panel">
          <p class="eyebrow">Swooshz Platform internal access</p>
          <h1>Access not approved</h1>
          <p class="lede">
            This account is not approved for Swooshz Platform. Use an approved
            account or contact your workspace admin.
          </p>
          <div class="login-actions">
            <a class="primary-action" href="/api/platform/auth/start">Try another Google account</a>
            <a class="secondary-action" href="/">Back to sign in</a>
          </div>
        </section>
      </main>
    `,
  });
}

function htmlDocument({
  title,
  body,
}: {
  title: string;
  body: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --surface: #ffffff;
      --ink: #18212b;
      --muted: #5d6b78;
      --line: #d7dde3;
      --primary: #000000;
      --secondary: #0051d5;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --danger-soft: #fef3c7;
      --surface-container-low: #f2f4f6;
      --surface-container-high: #e6e8ea;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }

    a,
    button {
      font: inherit;
    }

    a:focus-visible,
    button:focus-visible,
    input:focus-visible,
    select:focus-visible {
      outline: 3px solid rgb(0 81 213 / 42%);
      outline-offset: 2px;
    }

    .public-nav,
    .public-footer {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 20px 28px;
      border-color: var(--line);
      background: var(--surface);
    }

    .public-nav {
      min-height: 72px;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .public-brand,
    .public-footer strong {
      color: var(--primary);
      font-size: 24px;
      font-weight: 700;
      text-decoration: none;
      letter-spacing: 0;
    }

    .public-nav nav,
    .public-actions,
    .public-footer nav,
    .button-row {
      display: flex;
      align-items: center;
      gap: 20px;
    }

    .public-nav nav a,
    .public-nav nav span,
    .text-action,
    .public-footer a,
    .public-footer span,
    .public-footer p {
      color: var(--ink);
      font-size: 15px;
      text-decoration: none;
    }

    .public-nav nav span,
    .public-footer a,
    .public-footer span,
    .public-footer p {
      color: var(--muted);
    }

    .public-footer a:hover {
      color: var(--secondary);
    }

    .public-nav nav a.active {
      color: var(--secondary);
      border-bottom: 2px solid var(--secondary);
      padding-bottom: 8px;
      font-weight: 700;
    }

    .public-page {
      background: var(--bg);
    }

    .public-hero,
    .solutions-hero,
    .public-band,
    .process-section {
      width: min(1280px, calc(100% - 48px));
      margin: 0 auto;
    }

    .public-hero,
    .solutions-hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(360px, 0.92fr);
      gap: 56px;
      align-items: center;
      min-height: 520px;
      padding: 64px 0;
    }

    .public-hero-centered {
      min-height: 500px;
    }

    .solutions-hero {
      border-bottom: 1px solid var(--line);
      background-image: radial-gradient(circle at 2px 2px, #dfe4e8 1px, transparent 0);
      background-size: 32px 32px;
    }

    .hero-copy {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 20px;
    }

    .hero-copy h1 {
      max-width: 640px;
      margin: 0;
      color: var(--primary);
      font-size: 48px;
      line-height: 1.12;
      letter-spacing: 0;
    }

    .utility-label {
      margin: 0;
      color: var(--secondary);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .architecture-card,
    .product-preview {
      min-height: 360px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 12px 28px rgb(24 33 43 / 8%);
    }

    .architecture-bar,
    .preview-window-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .architecture-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
      padding-top: 24px;
    }

    .architecture-grid-stacked {
      grid-template-columns: 1fr;
    }

    .architecture-grid span,
    .mini-workflow span,
    .role-rail span {
      min-height: 42px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--bg);
      color: var(--ink);
      font-size: 13px;
      text-align: center;
    }

    .preview-empty {
      min-height: 280px;
      display: grid;
      place-items: center;
      align-content: center;
      gap: 16px;
      margin-top: 16px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-container-low, #f2f4f6);
      text-align: center;
    }

    .preview-empty p {
      max-width: 360px;
      margin: 0;
      color: var(--muted);
      font-size: 18px;
    }

    .public-band,
    .process-section {
      padding: 64px 0;
      border-top: 1px solid var(--line);
    }

    .resources-page,
    .article-page {
      background: var(--bg);
    }

    .resources-hero,
    .resources-band,
    .article-shell {
      width: min(1280px, calc(100% - 48px));
      margin: 0 auto;
    }

    .resources-hero {
      display: grid;
      grid-template-columns: minmax(0, 1.3fr) minmax(280px, 0.55fr);
      gap: 48px;
      align-items: end;
      padding: 72px 0 54px;
      border-bottom: 1px solid var(--line);
    }

    .resources-hero h1,
    .article-hero h1 {
      margin: 0;
      color: var(--primary);
      font-size: 54px;
      line-height: 1.08;
      letter-spacing: 0;
    }

    .resource-note {
      display: grid;
      gap: 10px;
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .resource-note h2,
    .resource-note p {
      margin: 0;
    }

    .resource-note h2 {
      color: var(--primary);
      font-size: 20px;
    }

    .resource-note p {
      color: var(--muted);
    }

    .resources-band {
      padding: 36px 0;
      border-bottom: 1px solid var(--line);
    }

    .topic-rail {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .topic-rail span {
      display: inline-flex;
      align-items: center;
      min-height: 38px;
      padding: 0 16px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--surface);
      color: var(--ink);
      font-size: 13px;
      font-weight: 700;
    }

    .topic-rail span[aria-current="true"] {
      border-color: var(--primary);
      background: var(--primary);
      color: #ffffff;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 24px;
    }

    .resource-card {
      display: grid;
      grid-template-rows: 220px 1fr;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      overflow: hidden;
    }

    .resource-card-featured {
      grid-column: span 2;
    }

    .resource-visual,
    .article-visual {
      position: relative;
      display: grid;
      place-items: center;
      min-height: 220px;
      border-bottom: 1px solid var(--line);
      background:
        linear-gradient(135deg, rgb(255 255 255 / 72%), rgb(230 232 234 / 70%)),
        repeating-linear-gradient(135deg, transparent 0 18px, rgb(0 98 255 / 10%) 18px 19px),
        repeating-linear-gradient(45deg, transparent 0 30px, rgb(24 33 43 / 8%) 30px 31px);
    }

    .resource-visual-primary {
      background:
        linear-gradient(135deg, rgb(255 255 255 / 76%), rgb(230 232 234 / 76%)),
        linear-gradient(90deg, rgb(0 98 255 / 20%), transparent),
        repeating-linear-gradient(135deg, transparent 0 18px, rgb(0 98 255 / 10%) 18px 19px),
        repeating-linear-gradient(45deg, transparent 0 30px, rgb(24 33 43 / 8%) 30px 31px);
    }

    .resource-visual span,
    .article-visual span {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgb(255 255 255 / 84%);
      color: var(--primary);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .resource-card-body {
      display: grid;
      gap: 12px;
      align-content: start;
      padding: 24px;
    }

    .resource-kicker {
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-card h3,
    .resource-card p {
      margin: 0;
    }

    .resource-card h3,
    .resource-card h3 a {
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
      text-decoration: none;
    }

    .resource-card p {
      color: var(--muted);
      font-size: 16px;
    }

    .text-link {
      color: var(--primary);
      font-weight: 700;
      text-decoration: none;
    }

    .text-link::after {
      content: " ->";
    }

    .article-shell {
      padding: 56px 0 72px;
    }

    .article-hero {
      width: min(760px, 100%);
      display: grid;
      gap: 18px;
      margin: 0 auto;
      padding-bottom: 28px;
      border-bottom: 1px solid var(--line);
    }

    .article-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .article-meta span {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--surface);
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    .article-visual {
      width: min(900px, 100%);
      min-height: 300px;
      margin: 32px auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }

    .article-visual div {
      width: min(620px, calc(100% - 48px));
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .article-layout {
      width: min(980px, 100%);
      display: grid;
      grid-template-columns: minmax(0, 1fr) 280px;
      gap: 44px;
      margin: 0 auto;
      align-items: start;
    }

    .article-body {
      display: grid;
      gap: 28px;
    }

    .article-body section,
    .article-callout,
    .article-sidebar {
      display: grid;
      gap: 12px;
    }

    .article-body h2,
    .article-sidebar h2 {
      margin: 0;
      color: var(--primary);
      font-size: 28px;
      line-height: 1.2;
    }

    .article-body p,
    .article-sidebar li {
      margin: 0;
      color: var(--ink);
      font-size: 17px;
      line-height: 1.7;
    }

    .article-callout,
    .article-sidebar {
      padding: 22px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .article-callout {
      border-left: 4px solid var(--accent);
    }

    .article-callout strong {
      color: var(--primary);
      font-size: 14px;
    }

    .article-sidebar {
      position: sticky;
      top: 96px;
    }

    .article-sidebar ul {
      display: grid;
      gap: 10px;
      margin: 0;
      padding-left: 20px;
    }

    .public-split-page,
    .access-state-panel {
      width: min(1280px, calc(100% - 48px));
      margin: 0 auto;
      padding: 80px 0;
    }

    .public-split-page {
      display: grid;
      grid-template-columns: minmax(0, 0.95fr) minmax(320px, 0.78fr);
      gap: 64px;
      align-items: stretch;
      min-height: calc(100vh - 158px);
    }

    .public-info-panel,
    .access-state-panel {
      display: grid;
      gap: 22px;
      align-content: start;
      padding: 42px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .public-info-panel h1,
    .access-state-panel h1 {
      margin: 0;
      color: var(--primary);
      font-size: 48px;
      line-height: 1.12;
      letter-spacing: 0;
    }

    .public-info-panel h2,
    .access-state-panel h2 {
      margin: 0;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
      letter-spacing: 0;
    }

    .muted-panel {
      background:
        linear-gradient(135deg, rgb(255 255 255 / 92%), rgb(242 244 246 / 88%)),
        radial-gradient(circle at 2px 2px, #dfe4e8 1px, transparent 0);
      background-size: auto, 28px 28px;
    }

    .guidance-list {
      display: grid;
      gap: 18px;
      color: var(--muted);
      font-size: 16px;
    }

    .guidance-list p,
    .notice-card p,
    .access-requirement-grid p {
      margin: 0;
      color: var(--muted);
    }

    .request-access-page {
      min-height: calc(100vh - 158px);
      display: grid;
      align-items: start;
      background-image: radial-gradient(circle at 1px 1px, #dfe4e8 1px, transparent 0);
      background-size: 24px 24px;
    }

    .access-state-panel {
      width: min(920px, calc(100% - 48px));
      justify-items: center;
      text-align: center;
    }

    .access-state-panel .lede {
      max-width: 720px;
    }

    .access-requirement-grid {
      width: 100%;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      text-align: left;
    }

    .access-requirement-grid article,
    .notice-card {
      display: grid;
      gap: 10px;
      padding: 20px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfd;
    }

    .access-requirement-grid span {
      color: var(--secondary);
      font-size: 13px;
      font-weight: 700;
    }

    .notice-card {
      width: 100%;
      text-align: left;
      border-color: var(--secondary);
      background: #f7faff;
    }

    .centered-actions {
      justify-content: center;
    }

    .section-heading {
      display: grid;
      gap: 8px;
      margin-bottom: 28px;
    }

    .section-heading.centered {
      justify-items: center;
      text-align: center;
    }

    .section-heading h2 {
      margin: 0;
      color: var(--primary);
      font-size: 32px;
      line-height: 1.25;
      letter-spacing: 0;
    }

    .section-heading p,
    .module-card p,
    .process-grid p {
      color: var(--muted);
    }

    .module-grid,
    .capability-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
    }

    .capability-grid {
      grid-template-columns: 2fr 1fr;
    }

    .three-up-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .module-card {
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-height: 220px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .module-card h3 {
      margin: 0;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .module-card p {
      margin: 0;
      font-size: 16px;
    }

    .module-card-wide {
      grid-column: span 1;
    }

    .module-stack {
      display: grid;
      gap: 16px;
    }

    .muted-card,
    .unavailable-card {
      background: #fbfcfd;
    }

    .unavailable-card {
      grid-column: 1 / -1;
      align-items: center;
      min-height: 210px;
      text-align: center;
    }

    .card-title-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: max-content;
      min-height: 28px;
      padding: 4px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-container-high, #e6e8ea);
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .mini-workflow,
    .role-rail,
    .process-grid {
      display: grid;
      gap: 14px;
    }

    .mini-workflow {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: auto;
    }

    .role-rail {
      grid-template-columns: repeat(4, minmax(0, 1fr));
      margin-top: auto;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--bg);
    }

    .process-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: 36px;
      text-align: center;
    }

    .process-grid article {
      display: grid;
      justify-items: center;
      gap: 12px;
    }

    .process-grid span {
      display: grid;
      place-items: center;
      width: 58px;
      height: 58px;
      border: 1px solid var(--ink);
      border-radius: 6px;
      background: var(--surface);
      color: var(--primary);
      font-size: 24px;
      font-weight: 700;
    }

    .process-grid article:last-child span {
      background: var(--primary);
      color: #ffffff;
    }

    .public-footer {
      border-top: 1px solid var(--line);
    }

    .public-footer p {
      margin: 0;
      text-align: right;
    }

    .login-canvas {
      position: relative;
      min-height: calc(100vh - 76px);
      display: grid;
      place-items: center;
      padding: 40px 24px;
      overflow: hidden;
    }

    .access-panel {
      position: relative;
      z-index: 1;
      width: min(560px, 100%);
      display: grid;
      gap: 20px;
      padding: 48px 42px;
      border: 1px solid var(--line);
      background: var(--surface);
      text-align: center;
    }

    .access-heading {
      display: grid;
      gap: 8px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--line);
    }

    .access-heading h1,
    .access-heading p {
      margin: 0;
    }

    .login-lines::before,
    .login-lines::after {
      content: "";
      position: fixed;
      width: 52vw;
      height: 52vh;
      border: 1px solid var(--line);
      opacity: 0.36;
      transform: rotate(10deg);
    }

    .login-lines::before {
      top: -18vh;
      right: 4vw;
    }

    .login-lines::after {
      left: -12vw;
      bottom: -16vh;
    }

    .portal-layout {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      background: var(--bg);
    }

    .portal-sidebar {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      gap: 24px;
      padding: 28px 20px;
      border-right: 1px solid var(--line);
      background: var(--surface);
    }

    .portal-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .portal-brand h1,
    .portal-brand p,
    .portal-topbar p,
    .portal-heading h2,
    .portal-heading p {
      margin: 0;
    }

    .portal-brand h1 {
      color: var(--primary);
      font-size: 26px;
      line-height: 1.15;
    }

    .portal-brand p {
      color: var(--ink);
      font-size: 13px;
      letter-spacing: 0;
    }

    .brand-mark,
    .icon-mark {
      display: inline-grid;
      place-items: center;
      min-width: 42px;
      min-height: 42px;
      border-radius: 6px;
      background: var(--primary);
      color: #ffffff;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .icon-mark {
      border: 1px solid var(--line);
      background: var(--surface-container-high, #e6e8ea);
      color: var(--primary);
    }

    .icon-mark.large {
      min-width: 58px;
      min-height: 58px;
    }

    .sidebar-launch {
      width: 100%;
    }

    .portal-nav {
      display: grid;
      gap: 8px;
    }

    .portal-nav a,
    .portal-nav span,
    .sidebar-logout {
      min-height: 44px;
      display: flex;
      align-items: center;
      padding: 0 18px;
      border: 0;
      border-radius: 4px;
      background: transparent;
      color: var(--ink);
      font-weight: 700;
      text-decoration: none;
    }

    .portal-nav span {
      color: var(--muted);
    }

    .portal-nav span[aria-disabled="true"] {
      cursor: default;
      opacity: 0.62;
      pointer-events: none;
    }

    .portal-nav .portal-nav-active {
      border-right: 4px solid var(--primary);
      background: var(--secondary);
      color: #ffffff;
    }

    .sidebar-logout {
      margin-top: auto;
      border-top: 1px solid var(--line);
      border-radius: 0;
      cursor: pointer;
    }

    .portal-main {
      min-width: 0;
      display: flex;
      flex-direction: column;
    }

    .portal-topbar {
      min-height: 80px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 0 32px;
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }

    .portal-topbar p {
      color: var(--primary);
      font-size: 24px;
    }

    .portal-topbar-actions {
      display: flex;
      gap: 18px;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }

    .portal-canvas {
      width: min(1180px, calc(100% - 64px));
      display: grid;
      gap: 20px;
      margin: 0 auto;
      padding: 44px 0 56px;
    }

    .portal-heading h2 {
      color: var(--primary);
      font-size: 40px;
      line-height: 1.15;
      letter-spacing: 0;
    }

    .portal-heading p {
      color: var(--muted);
      font-size: 18px;
    }

    .unavailable-state {
      display: grid;
      gap: 8px;
      min-width: min(420px, 100%);
      color: var(--ink);
    }

    .unavailable-state strong {
      color: var(--muted);
    }

    .unavailable-state span {
      overflow-wrap: anywhere;
    }

    .unavailable-actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin-top: 2px;
    }

    .contact-admin {
      color: var(--ink);
      font-size: 14px;
    }

    .landing,
    .shell {
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
    }

    .landing {
      min-height: 100vh;
      display: grid;
      place-items: center;
    }

    .panel,
    .workspace,
    .handoff {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
    }

    .panel {
      width: min(520px, 100%);
      padding: 40px;
    }

    .shell {
      padding: 32px 0 48px;
    }

    .topbar,
    .workspace-header,
    .app-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    .topbar {
      margin-bottom: 20px;
    }

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .eyebrow {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    h1,
    h2,
    p {
      margin-top: 0;
    }

    h1 {
      margin-bottom: 12px;
      font-size: 42px;
      line-height: 1;
      letter-spacing: 0;
    }

    h2 {
      font-size: 18px;
    }

    .lede,
    .status,
    .empty,
    .helper {
      color: var(--muted);
    }

    .status,
    .identity {
      margin-bottom: 16px;
    }

    .signed-out {
      margin-bottom: 16px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--danger-soft);
    }

    .login-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
    }

    .identity {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
    }

    .identity p,
    .workspace p,
    .handoff p {
      margin: 0;
    }

    strong,
    span {
      display: block;
    }

    strong {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .workspace-list {
      display: grid;
      gap: 16px;
    }

    .workspace,
    .handoff {
      padding: 20px;
    }

    .workspace + .workspace {
      margin-top: 16px;
    }

    .workspace-header {
      align-items: flex-start;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--line);
    }

    .apps {
      display: grid;
      gap: 10px;
      padding-top: 16px;
    }

    .app-row {
      min-height: 76px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfaf7;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: auto;
    }

    th,
    td {
      padding: 12px 10px;
      border-top: 1px solid var(--line);
      text-align: left;
      vertical-align: middle;
      overflow-wrap: anywhere;
    }

    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    select {
      width: 100%;
      min-height: 40px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      font: inherit;
    }

    input {
      width: 100%;
      min-height: 40px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      font: inherit;
    }

    .inline-form {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(140px, 180px) auto;
      gap: 12px;
      align-items: end;
    }

    .metadata-list {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 4px 10px;
      margin: 0;
    }

    .metadata-list dt {
      color: var(--muted);
      font-weight: 700;
    }

    .metadata-list dd {
      margin: 0;
    }

    .pager {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 14px;
    }

    .pager .empty {
      margin-right: auto;
    }

    .action-menu {
      position: relative;
      display: inline-flex;
    }

    .action-menu-panel {
      position: absolute;
      right: 0;
      top: calc(100% + 6px);
      z-index: 2;
      display: grid;
      gap: 6px;
      min-width: 132px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      box-shadow: 0 12px 24px rgb(0 0 0 / 12%);
    }

    .action-menu-panel[hidden] {
      display: none;
    }

    .action-menu-panel .secondary-action {
      width: 100%;
      min-height: 38px;
    }

    .action-status,
    .modal-loading {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .action-status {
      min-height: 44px;
      margin-bottom: 16px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--muted);
    }

    .admin-layout .portal-sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
    }

    .admin-layout .portal-topbar {
      justify-content: flex-end;
    }

    .admin-canvas {
      width: min(1240px, calc(100% - 64px));
      gap: 18px;
    }

    .admin-page-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 4px;
    }

    .topbar-icon {
      display: inline-block;
      width: 22px;
      height: 22px;
      border: 2px solid var(--primary);
      border-radius: 999px;
      vertical-align: middle;
    }

    .topbar-icon-history {
      border-style: dashed;
    }

    .topbar-icon-account {
      position: relative;
    }

    .topbar-icon-account::after {
      position: absolute;
      left: 4px;
      right: 4px;
      bottom: 3px;
      height: 6px;
      border-top: 2px solid var(--primary);
      border-radius: 999px 999px 0 0;
      content: "";
    }

    .admin-summary-grid {
      margin-bottom: 0;
    }

    .admin-summary,
    .admin-surface {
      padding: 22px;
    }

    .admin-surface h2,
    .admin-summary h2 {
      margin: 0 0 6px;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .section-description {
      margin-bottom: 18px;
    }

    .member-identity {
      display: flex;
      align-items: center;
      gap: 14px;
      min-width: 220px;
    }

    .member-identity strong {
      color: var(--primary);
      font-size: 15px;
      text-transform: none;
    }

    .member-avatar {
      display: grid;
      place-items: center;
      width: 44px;
      height: 44px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--secondary);
      color: #ffffff;
      font-weight: 700;
    }

    .spinner {
      width: 14px;
      height: 14px;
      border: 2px solid var(--line);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      flex: 0 0 auto;
    }

    .spinner[hidden] {
      display: none;
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 10;
      display: grid;
      place-items: center;
      padding: 24px;
      background: rgb(24 33 43 / 42%);
    }

    .action-modal {
      width: min(420px, 100%);
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 18px 46px rgb(0 0 0 / 18%);
      overflow: hidden;
    }

    .add-member-modal {
      width: min(560px, 100%);
    }

    .modal-header,
    .modal-body,
    .modal-footer {
      padding: 20px 24px;
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      border-bottom: 1px solid var(--line);
    }

    .modal-header h2 {
      margin: 0;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .modal-body {
      display: grid;
      gap: 16px;
    }

    .modal-close {
      width: 36px;
      min-height: 36px;
      border: 0;
      background: transparent;
      color: var(--ink);
      cursor: pointer;
      font-size: 20px;
    }

    .field-stack {
      display: grid;
      gap: 16px;
    }

    .field-stack label {
      display: grid;
      gap: 8px;
    }

    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }

    .modal-footer {
      border-top: 1px solid var(--line);
      background: var(--surface-container-low);
    }

    .modal-error {
      margin-top: 12px;
      color: #991b1b;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    button:disabled,
    select:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    .primary-action,
    .secondary-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 18px;
      border-radius: 6px;
      border: 1px solid transparent;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
    }

    .primary-action {
      background: var(--primary);
      color: #ffffff;
    }

    .primary-action:hover {
      background: var(--secondary);
    }

    .landing .primary-action {
      display: flex;
      width: max-content;
      margin-left: auto;
    }

    .secondary-action {
      background: var(--surface);
      border-color: var(--line);
      color: var(--ink);
    }

    .compact {
      min-width: 104px;
    }

    .handoff {
      margin-top: 18px;
      background: var(--danger-soft);
    }

    [hidden] {
      display: none !important;
    }

    @media (max-width: 640px) {
      .public-nav,
      .public-footer {
        align-items: stretch;
        flex-direction: column;
        padding: 18px 20px;
      }

      .public-nav {
        position: static;
      }

      .public-nav nav,
      .public-actions,
      .public-footer nav,
      .button-row {
        flex-wrap: wrap;
        gap: 12px;
      }

      .public-hero,
      .solutions-hero,
      .public-band,
      .process-section,
      .resources-hero,
      .resources-band,
      .article-shell,
      .public-split-page,
      .access-state-panel {
        width: min(100% - 32px, 1280px);
      }

      .public-hero,
      .solutions-hero,
      .resources-hero,
      .public-split-page {
        grid-template-columns: 1fr;
        min-height: auto;
        padding: 36px 0;
      }

      .public-split-page {
        gap: 18px;
      }

      .public-info-panel,
      .access-state-panel {
        padding: 28px 22px;
      }

      .public-info-panel h1,
      .access-state-panel h1 {
        font-size: 36px;
        line-height: 1.16;
      }

      .hero-copy h1 {
        font-size: 36px;
        line-height: 1.16;
      }

      .resources-hero h1,
      .article-hero h1 {
        font-size: 38px;
        line-height: 1.12;
      }

      .resources-band,
      .article-shell {
        padding: 32px 0;
      }

      .topic-rail {
        flex-wrap: nowrap;
        overflow-x: auto;
        padding-bottom: 2px;
      }

      .topic-rail span {
        flex: 0 0 auto;
      }

      .resource-grid,
      .article-layout,
      .article-visual div {
        grid-template-columns: 1fr;
      }

      .resource-card,
      .resource-card-featured {
        grid-column: auto;
      }

      .resource-card {
        grid-template-rows: 180px 1fr;
      }

      .resource-visual {
        min-height: 180px;
      }

      .article-visual {
        min-height: 240px;
      }

      .article-sidebar {
        position: static;
      }

      .architecture-card,
      .product-preview {
        min-height: auto;
      }

      .architecture-grid,
      .module-grid,
      .capability-grid,
      .three-up-grid,
      .access-requirement-grid,
      .mini-workflow,
      .role-rail,
      .process-grid {
        grid-template-columns: 1fr;
      }

      .public-footer p {
        text-align: left;
      }

      .access-panel {
        padding: 32px 24px;
      }

      .portal-layout {
        display: block;
      }

      .portal-sidebar {
        position: static;
        min-height: auto;
        height: auto;
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }

      .admin-layout .portal-sidebar {
        position: static;
        min-height: auto;
        height: auto;
      }

      .portal-nav {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .portal-main,
      .portal-canvas {
        width: 100%;
      }

      .portal-topbar {
        min-height: 64px;
        padding: 0 20px;
      }

      .portal-topbar-actions {
        display: none;
      }

      .portal-canvas {
        padding: 28px 16px 40px;
        overflow: hidden;
      }

      .admin-canvas {
        width: 100%;
      }

      .admin-page-header {
        display: grid;
        gap: 16px;
      }

      .admin-summary,
      .admin-surface {
        padding: 18px;
      }

      .member-identity {
        align-items: flex-start;
      }

      .portal-heading h2 {
        font-size: 34px;
      }

      .identity {
        grid-template-columns: 1fr;
      }

      .workspace,
      .workspace-list,
      .apps,
      .app-row,
      .app-row > div,
      .unavailable-state {
        min-width: 0;
        width: 100%;
      }

      .app-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
      }

      .workspace span,
      .app-row span {
        max-width: calc(100vw - 104px);
        overflow-wrap: anywhere;
        white-space: normal;
      }

      .unavailable-actions {
        display: grid;
        width: 100%;
      }

      .topbar,
      .topbar-actions,
      .workspace-header,
      .app-row {
        align-items: stretch;
        flex-direction: column;
      }

      table,
      thead,
      tbody,
      tr,
      th,
      td,
      .pager,
      .inline-form {
        display: block;
        width: 100%;
      }

      th {
        display: none;
      }

      td {
        min-height: 56px;
        padding: 12px 0;
      }

      td::before {
        display: block;
        margin-bottom: 4px;
        color: var(--muted);
        content: attr(data-label);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
      }

      .action-menu,
      .action-menu-panel {
        position: static;
        width: 100%;
      }

      .action-menu-panel {
        margin-top: 8px;
      }

      .panel {
        padding: 28px;
      }

      h1 {
        font-size: 34px;
      }

      .primary-action,
      .secondary-action {
        width: 100%;
      }

      .modal-actions {
        display: grid;
      }

      .modal-header,
      .modal-body,
      .modal-footer {
        padding: 18px;
      }
    }

    @font-face {
      font-family: "Auth Manrope";
      src: url("${publicAssetUrl("/public-assets/fonts/manrope-latin-variable.woff2")}") format("woff2");
      font-style: normal;
      font-weight: 200 800;
      font-display: swap;
    }

    .authenticated-shell,
    .auth-modal-backdrop {
      --auth-paper: #f0f1ed;
      --auth-surface: #fffefa;
      --auth-surface-soft: #f3f6f4;
      --auth-ink: #0f1a2a;
      --auth-ink-secondary: #364b63;
      --auth-muted: #637184;
      --auth-line: #ccd5d4;
      --auth-line-strong: #9eafb2;
      --auth-line-subtle: #e1e7e5;
      --auth-teal: #0b756d;
      --auth-teal-dark: #064f4c;
      --auth-teal-soft: #e0f1ec;
      --auth-success: #188657;
      --auth-disabled: #7b8490;
      --auth-danger: #9b463f;
      --auth-focus: 0 0 0 3px rgb(29 119 146 / 28%);
      color: var(--auth-ink);
      font-family: "Auth Manrope", ui-sans-serif, system-ui, sans-serif;
      font-size: 16px;
      line-height: 1.5;
    }

    .authenticated-shell {
      min-width: 320px;
      min-height: 100vh;
      background: linear-gradient(180deg, rgb(255 254 250 / 56%), transparent 280px), var(--auth-paper);
    }

    .authenticated-shell *,
    .auth-modal-backdrop * { box-sizing: border-box; }
    .authenticated-shell span,
    .authenticated-shell strong,
    .auth-modal-backdrop span,
    .auth-modal-backdrop strong {
      color: inherit;
      font-size: inherit;
      font-weight: inherit;
      letter-spacing: normal;
      text-transform: none;
    }
    .authenticated-shell button,
    .authenticated-shell input,
    .authenticated-shell select,
    .auth-modal-backdrop button,
    .auth-modal-backdrop input,
    .auth-modal-backdrop select { font: inherit; }
    .authenticated-shell svg,
    .auth-modal-backdrop svg {
      fill: none;
      stroke: currentColor;
      stroke-linecap: round;
      stroke-linejoin: round;
      stroke-width: 1.8;
    }
    .authenticated-shell :focus-visible,
    .auth-modal-backdrop :focus-visible {
      outline: 2px solid #116a82;
      outline-offset: 2px;
      box-shadow: var(--auth-focus);
    }

    .auth-skip-link {
      position: fixed;
      top: 8px;
      left: 8px;
      z-index: 100;
      transform: translateY(-160%);
      padding: 10px 14px;
      border-radius: 8px;
      background: var(--auth-ink);
      color: #fff;
    }
    .auth-skip-link:focus { transform: translateY(0); }

    .auth-app-bar {
      position: relative;
      min-height: 66px;
      border-bottom: 1px solid var(--auth-line);
      background: rgb(255 254 250 / 98%);
    }
    .auth-app-bar::before {
      display: block;
      height: 3px;
      background: linear-gradient(90deg, var(--auth-teal) 0 9%, var(--auth-ink) 9% 100%);
      content: "";
    }
    .auth-bar-inner,
    .admin-nav-inner,
    .auth-main {
      width: min(1180px, calc(100% - 48px));
      margin: 0 auto;
    }
    .auth-bar-inner {
      min-height: 63px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }
    .auth-brand {
      display: inline-flex;
      align-items: center;
      gap: 11px;
      flex: 0 0 auto;
      color: var(--auth-ink);
      font-size: 18px;
      font-weight: 780;
      letter-spacing: -.02em;
      text-decoration: none;
    }
    .auth-brand img { width: 34px; height: 34px; object-fit: contain; }
    .auth-account-context {
      min-width: 0;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 20px;
    }
    .auth-context-control,
    .auth-context-value,
    .auth-account-copy {
      display: grid;
      gap: 0;
      min-width: 0;
      color: var(--auth-ink);
      font-size: 14px;
      line-height: 1.25;
    }
    .auth-context-control > span,
    .auth-context-value > span,
    .auth-account-copy > span,
    .auth-account-copy small { color: var(--auth-muted); font-size: 14px; }
    .auth-context-control select {
      width: auto;
      min-width: 150px;
      min-height: 30px;
      margin-left: -4px;
      padding: 1px 26px 1px 3px;
      border: 0;
      background: transparent;
      color: var(--auth-ink);
      font-size: 15px;
      font-weight: 720;
    }
    .auth-context-value strong,
    .auth-account-copy strong { font-size: 15px; font-weight: 720; }
    .auth-account-copy { max-width: 210px; }
    .auth-account-copy strong,
    .auth-account-copy small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .auth-header-link,
    .auth-header-button {
      min-height: 44px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0 10px;
      border: 0;
      background: transparent;
      color: var(--auth-teal-dark);
      font-size: 14px;
      font-weight: 740;
      text-decoration: none;
      white-space: nowrap;
    }
    .auth-header-button { cursor: pointer; }
    .auth-header-link:hover,
    .auth-header-button:hover { background: var(--auth-teal-soft); }

    .auth-main { padding: 58px 0 72px; }
    .launcher-main {
      min-height: calc(100vh - 66px);
      display: grid;
      align-items: center;
      padding-top: 48px;
      padding-bottom: 96px;
    }
    .launcher-page { width: 100%; max-width: 1080px; margin: 0 auto; }
    .auth-page-heading { max-width: 760px; }
    .auth-page-heading h1 {
      margin: 0 0 8px;
      color: var(--auth-ink);
      font-size: 34px;
      font-weight: 740;
      line-height: 1.08;
      letter-spacing: -.035em;
    }
    .auth-page-heading p {
      margin: 0;
      color: var(--auth-ink-secondary);
      font-size: 16px;
    }
    .auth-status,
    .auth-action-status {
      margin: 20px 0 0;
      padding: 12px 14px;
      border: 1px solid var(--auth-line);
      border-radius: 8px;
      background: var(--auth-surface);
      color: var(--auth-ink-secondary);
      font-size: 15px;
    }
    .auth-status a { color: var(--auth-teal-dark); font-weight: 720; }
    .auth-empty-state {
      margin-top: 24px;
      padding: 28px;
      border: 1px dashed var(--auth-line-strong);
      border-left: 3px solid var(--auth-teal);
      border-radius: 12px;
      background: rgb(255 254 250 / 82%);
    }
    .auth-empty-state h2 { margin: 0 0 6px; font-size: 22px; }
    .auth-empty-state p { margin: 0; color: var(--auth-ink-secondary); }

    .authenticated-shell .launch-unit {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1.42fr) minmax(320px, .58fr);
      margin-top: 24px;
      overflow: hidden;
      border: 1px solid var(--auth-line);
      border-radius: 12px;
      background: var(--auth-surface);
      box-shadow: 0 6px 18px rgb(15 26 42 / 7%);
    }
    .authenticated-shell .launch-unit::before {
      position: absolute;
      inset: 0 auto 0 0;
      width: 4px;
      background: linear-gradient(180deg, var(--auth-teal) 0 76%, var(--auth-ink) 76% 100%);
      content: "";
    }
    .authenticated-shell .product-summary {
      display: grid;
      grid-template-columns: 76px minmax(0, 1fr);
      gap: 24px;
      align-items: start;
      padding: 38px 40px 38px 42px;
    }
    .authenticated-shell .product-mark {
      width: 76px;
      height: 76px;
      display: grid;
      place-items: center;
      flex: 0 0 auto;
      border: 1px solid #bfd4cf;
      border-radius: 9px;
      background: #edf6f2;
    }
    .authenticated-shell .quote-document-icon,
    .auth-modal-backdrop .quote-document-icon { width: 52px; height: 52px; }
    .quote-document-icon .icon-sheet { fill: var(--auth-surface); stroke: var(--auth-ink); stroke-width: 2.2; }
    .quote-document-icon .icon-fold { stroke: var(--auth-teal); stroke-width: 2.4; }
    .quote-document-icon .icon-line { stroke: #7c8d96; stroke-width: 2.1; }
    .quote-document-icon .icon-column { stroke: var(--auth-teal); stroke-width: 1.9; }
    .quote-document-icon .icon-total { stroke: var(--auth-teal); stroke-width: 3; }
    .product-label { margin: 0 0 6px; color: var(--auth-teal-dark); font-size: 14px; font-weight: 780; }
    .authenticated-shell .product-summary h2 {
      max-width: 580px;
      margin: 0 0 10px;
      color: var(--auth-ink);
      font-size: 27px;
      font-weight: 740;
      line-height: 1.14;
      letter-spacing: -.025em;
    }
    .product-description { max-width: 620px; margin: 0; color: var(--auth-ink-secondary); font-size: 16px; line-height: 1.56; }
    .launch-readiness {
      display: grid;
      align-content: center;
      gap: 20px;
      padding: 32px;
      border-left: 1px solid var(--auth-line);
      background: #f1f5f3;
    }
    .readiness-status { min-height: 54px; display: flex; align-items: center; gap: 12px; }
    .readiness-status > span:last-child { display: grid; gap: 1px; }
    .readiness-label { color: var(--auth-muted); font-size: 14px; }
    .readiness-status strong { font-size: 16px; font-weight: 760; }
    .auth-status-dot { width: 8px; height: 8px; display: inline-block; border-radius: 50%; background: var(--auth-success); }
    .auth-status-dot.is-disabled { background: var(--auth-disabled); }
    .auth-primary-button,
    .auth-secondary-button,
    .auth-danger-button {
      min-height: 46px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0 18px;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 750;
      text-decoration: none;
      white-space: nowrap;
    }
    .auth-primary-button { border: 1px solid var(--auth-teal-dark); background: var(--auth-teal); color: #fff; }
    .auth-primary-button:hover { background: var(--auth-teal-dark); }
    .auth-secondary-button { border: 1px solid var(--auth-line-strong); background: var(--auth-surface); color: var(--auth-ink); }
    .auth-secondary-button:hover { background: var(--auth-surface-soft); }
    .auth-danger-button { border: 1px solid #883c36; background: var(--auth-danger); color: #fff; }
    .launch-button { width: 100%; }
    .launch-readiness.is-loading .launch-button { cursor: wait; opacity: .72; }
    .launch-readiness.is-unavailable .launch-button { border-color: #9aa3ad; background: #9aa3ad; }
    .launch-feedback {
      padding: 11px 12px;
      border: 1px solid #e2b8b2;
      border-radius: 8px;
      background: #fff3f0;
      color: #7e302a;
      font-size: 14px;
      line-height: 1.45;
    }
    .launch-feedback strong { display: block; color: #68241f; font-weight: 760; }
    .launch-feedback span { display: block; }
    .launch-feedback button { min-height: 44px; padding: 0; border: 0; background: transparent; color: #6d2924; font-weight: 780; text-decoration: underline; }
    .launch-note {
      grid-column: 1 / -1;
      min-height: 58px;
      display: flex;
      align-items: center;
      gap: 11px;
      padding: 11px 32px 11px 42px;
      border-top: 1px solid var(--auth-line-strong);
      background: linear-gradient(90deg, #eef5f1 0 70%, #f8faf7 70% 100%);
      color: var(--auth-ink-secondary);
      font-size: 14px;
    }
    .launch-note svg { width: 20px; height: 20px; flex: 0 0 auto; color: var(--auth-teal); }
    .launch-note strong { color: var(--auth-ink); font-weight: 760; }

    .admin-section-nav { border-bottom: 1px solid var(--auth-line); background: rgb(255 254 250 / 84%); }
    .admin-nav-inner { height: 58px; display: flex; align-items: stretch; gap: 6px; }
    .admin-nav-inner button {
      position: relative;
      min-height: 44px;
      padding: 0 14px;
      border: 0;
      background: transparent;
      color: var(--auth-ink-secondary);
      font-size: 15px;
      font-weight: 650;
    }
    .admin-nav-inner button::after { position: absolute; right: 0; bottom: -1px; left: 0; height: 3px; background: transparent; content: ""; }
    .admin-nav-inner button[aria-current="page"] { color: var(--auth-teal-dark); background: linear-gradient(90deg, var(--auth-teal) 0 3px, var(--auth-teal-soft) 3px 100%); }
    .admin-nav-inner button[aria-current="page"]::after { background: var(--auth-teal); }
    .admin-main { padding-top: 42px; }
    .mobile-admin-selector { display: none; }
    .admin-page-header { display: flex; align-items: end; justify-content: space-between; gap: 32px; margin-bottom: 22px; }
    .admin-page-header .auth-page-heading h1 { font-size: 34px; }
    .auth-action-status { display: flex; align-items: center; gap: 9px; margin-bottom: 18px; }
    .admin-panel { min-width: 0; }
    .admin-panel > h2,
    .admin-panel > .section-description { display: none; }
    .admin-panel table {
      width: 100%;
      overflow: visible;
      border: 1px solid #becac9;
      border-radius: 12px;
      border-collapse: separate;
      border-spacing: 0;
      background: var(--auth-surface);
      box-shadow: 0 6px 18px rgb(15 26 42 / 7%);
      table-layout: auto;
    }
    .admin-panel th,
    .admin-panel td { padding: 12px 16px; border-top: 1px solid var(--auth-line-subtle); color: var(--auth-ink); font-size: 15px; vertical-align: middle; }
    .admin-panel th {
      height: 52px;
      border-top: 0;
      border-bottom: 1px solid var(--auth-line-strong);
      background: #f0f3f1;
      color: var(--auth-ink-secondary);
      font-size: 14px;
      font-weight: 750;
      letter-spacing: .01em;
      text-transform: none;
    }
    .admin-panel th:first-child { border-left: 3px solid var(--auth-teal); background: #e5efec; color: var(--auth-teal-dark); }
    .admin-panel tbody tr:hover,
    .admin-panel tbody tr:focus-within { background: linear-gradient(90deg, #eff7f4 0 38%, #f8faf9 38% 100%); box-shadow: inset 3px 0 0 rgb(11 117 109 / 72%); }
    .admin-panel select,
    .auth-modal-backdrop input,
    .auth-modal-backdrop select {
      min-height: 46px;
      padding: 0 12px;
      border: 1px solid var(--auth-line-strong);
      border-radius: 8px;
      background: #fff;
      color: var(--auth-ink);
      font-size: 15px;
    }
    .admin-panel select { min-width: 110px; }
    .authenticated-shell .member-identity { min-width: 260px; display: flex; align-items: center; gap: 13px; padding-right: 18px; border-right: 1px solid var(--auth-line-subtle); }
    .authenticated-shell .member-avatar { width: 40px; height: 40px; display: grid; place-items: center; flex: 0 0 auto; border: 1px solid #c9dfda; border-radius: 10px; background: var(--auth-teal-soft); color: var(--auth-teal-dark); font-size: 14px; font-weight: 750; }
    .authenticated-shell .member-identity > span:last-child { min-width: 0; }
    .authenticated-shell .member-identity strong { display: block; color: var(--auth-ink); font-size: 16px; font-weight: 770; line-height: 1.35; }
    .authenticated-shell .member-identity strong + span { display: block; overflow-wrap: anywhere; color: var(--auth-muted); font-size: 14px; }
    .protected-label { display: inline-flex; min-height: 44px; align-items: center; color: var(--auth-muted); font-size: 14px; font-weight: 650; }
    .authenticated-shell .action-menu { position: relative; display: inline-flex; }
    .authenticated-shell .action-menu-panel { position: absolute; z-index: 20; top: calc(100% + 6px); right: 0; min-width: 190px; display: grid; gap: 4px; padding: 6px; border: 1px solid var(--auth-line-strong); border-radius: 8px; background: var(--auth-surface); box-shadow: 0 14px 36px rgb(15 26 42 / 16%); }
    .authenticated-shell .action-menu-panel[hidden] { display: none; }
    .authenticated-shell .action-menu-panel button { width: 100%; min-height: 44px; justify-content: flex-start; border: 0; background: transparent; }
    .product-access-row { display: grid; grid-template-columns: minmax(0, 1fr) 170px 220px; gap: 24px; align-items: center; padding: 26px 28px; border: 1px solid var(--auth-line); border-left: 3px solid var(--auth-teal); border-radius: 12px; background: var(--auth-surface); box-shadow: 0 6px 18px rgb(15 26 42 / 7%); }
    .product-access-product { min-width: 0; display: flex; align-items: center; gap: 18px; }
    .authenticated-shell .product-mark.compact { width: 58px; height: 58px; }
    .authenticated-shell .product-mark.compact .quote-document-icon { width: 36px; height: 36px; }
    .product-access-product h3 { margin: 0 0 6px; color: var(--auth-ink); font-size: 22px; line-height: 1.2; }
    .product-access-product p { margin: 0; color: var(--auth-ink-secondary); font-size: 15px; }
    .product-access-state { display: grid; gap: 4px; }
    .product-access-state > span { color: var(--auth-muted); font-size: 14px; }
    .product-access-state strong { display: inline-flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 740; }
    .product-access-state strong::before { width: 8px; height: 8px; border-radius: 50%; background: var(--auth-disabled); content: ""; }
    .product-access-state strong[data-status="enabled"]::before { background: var(--auth-success); }
    .surface-note { margin: 18px 0 0; color: var(--auth-ink-secondary); font-size: 14px; }
    .admin-panel > .empty { padding: 30px; border: 1px dashed var(--auth-line-strong); border-left: 3px solid var(--auth-teal); border-radius: 12px; background: rgb(255 254 250 / 82%); color: var(--auth-ink-secondary); font-size: 15px; }
    .pager { margin-top: 16px; display: flex; align-items: center; justify-content: flex-end; gap: 10px; }
    .pager .empty { margin: 0 auto 0 0; color: var(--auth-muted); font-size: 14px; }

    .auth-modal-backdrop { background: rgb(15 26 42 / 28%); }
    .auth-modal-backdrop .action-modal { width: min(580px, calc(100vw - 48px)); max-height: min(760px, calc(100vh - 48px)); overflow: auto; border: 1px solid #ccd5d8; border-top: 3px solid var(--auth-teal); border-radius: 12px; background: var(--auth-surface); box-shadow: 0 24px 70px rgb(15 26 42 / 24%); }
    .auth-modal-backdrop .member-action-modal { width: min(520px, calc(100vw - 48px)); }
    .auth-modal-backdrop .modal-header { align-items: flex-start; padding: 20px 22px 17px; }
    .auth-modal-backdrop .modal-kicker { margin: 0 0 3px; color: var(--auth-teal-dark); font-size: 14px; font-weight: 780; }
    .auth-modal-backdrop .modal-header h2 { font-size: 22px; }
    .auth-modal-backdrop .modal-close { width: 44px; min-height: 44px; margin: -8px -8px 0 0; font-size: 24px; }
    .auth-modal-backdrop .modal-body { padding: 18px 22px; }
    .auth-modal-backdrop .modal-body > p { margin: 0; color: var(--auth-ink-secondary); font-size: 15px; }
    .auth-modal-backdrop .field-stack label { color: var(--auth-ink); font-size: 14px; font-weight: 750; }
    .auth-modal-backdrop .modal-actions { gap: 10px; }
    .auth-modal-backdrop .modal-footer { padding: 16px 22px 20px; background: var(--auth-surface); }
    .inline-feedback { padding: 10px 12px; border-radius: 8px; background: #eaf7ef; color: #145d3f !important; font-size: 14px !important; }
    .modal-error { color: #7e302a !important; }

    @media (max-width: 980px) {
      .auth-account-copy { display: none; }
      .auth-account-context { gap: 10px; }
      .product-access-row { grid-template-columns: minmax(0, 1fr) 150px; }
      .product-access-row > button { grid-column: 2; }
    }

    @media (max-width: 760px) {
      .authenticated-shell { background: var(--auth-paper); }
      .auth-app-bar { min-height: 58px; }
      .auth-bar-inner,
      .admin-nav-inner,
      .auth-main { width: 100%; }
      .auth-bar-inner { min-height: 55px; flex-wrap: wrap; gap: 0; padding: 0 16px; }
      .auth-brand { min-height: 55px; gap: 8px; font-size: 16px; }
      .auth-brand img { width: 30px; height: 30px; }
      .auth-account-context { order: 2; width: calc(100% + 32px); min-height: 56px; display: grid; grid-template-columns: minmax(0, 1fr) 78px auto auto; gap: 0; margin: 0 -16px; border-top: 1px solid var(--auth-line); background: var(--auth-surface); }
      .auth-account-context > * { min-width: 0; padding: 7px 12px; }
      .auth-account-context > * + * { border-left: 1px solid var(--auth-line); }
      .auth-context-control,
      .auth-context-value { align-content: center; }
      .auth-context-control select { width: 100%; min-width: 0; max-width: 100%; padding-left: 0; overflow: hidden; text-overflow: ellipsis; font-size: 14px; }
      .auth-context-value strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 14px; }
      .auth-context-control > span,
      .auth-context-value > span { font-size: 14px; }
      .auth-account-copy { display: none; }
      .auth-header-link,
      .auth-header-button { min-width: 52px; padding: 0 8px; font-size: 13px; }
      .auth-header-link { font-size: 0; }
      .auth-header-link::after { font-size: 13px; content: "Admin"; }
      .auth-main { padding: 24px 16px 48px; }
      .launcher-main { min-height: 0; display: block; }
      .auth-page-heading h1 { font-size: 28px; line-height: 1.12; }
      .auth-page-heading p { font-size: 15px; }
      .authenticated-shell .launch-unit { grid-template-columns: 1fr; margin-top: 22px; }
      .authenticated-shell .launch-unit::before { width: 3px; }
      .authenticated-shell .product-summary { grid-template-columns: 38px minmax(0, 1fr); gap: 8px 12px; padding: 22px 20px 20px 22px; }
      .authenticated-shell .product-copy { display: contents; }
      .authenticated-shell .product-mark { width: 38px; height: 38px; border: 0; background: transparent; }
      .authenticated-shell .product-mark .quote-document-icon { width: 34px; height: 34px; }
      .product-label { align-self: center; margin: 0; }
      .authenticated-shell .product-summary h2 { grid-column: 1 / -1; margin: 0; font-size: 24px; line-height: 1.16; }
      .product-description { grid-column: 1 / -1; font-size: 15px; line-height: 1.48; }
      .launch-readiness { gap: 14px; padding: 16px 20px 18px 22px; border-top: 1px solid var(--auth-line); border-left: 0; }
      .readiness-status { min-height: 42px; }
      .launch-button { min-height: 48px; }
      .launch-note { min-height: 0; align-items: flex-start; padding: 13px 20px 14px 22px; background: #f3f8f5; line-height: 1.42; }
      .launch-note span { display: grid; gap: 1px; }
      .admin-section-nav { display: none; }
      .admin-main { padding-top: 16px; }
      .mobile-admin-selector { display: grid; gap: 6px; margin-bottom: 22px; color: var(--auth-muted); font-size: 14px; }
      .mobile-admin-selector select { width: 100%; min-height: 48px; padding: 0 14px; border: 1px solid var(--auth-line-strong); border-radius: 8px; background: var(--auth-surface); color: var(--auth-ink); font-size: 15px; font-weight: 720; }
      .admin-page-header { align-items: stretch; flex-direction: column; gap: 16px; margin-bottom: 20px; }
      .admin-page-header .auth-page-heading h1 { font-size: 28px; }
      .admin-page-header .auth-primary-button { width: 100%; min-height: 48px; }
      .admin-panel table,
      .admin-panel thead,
      .admin-panel tbody,
      .admin-panel tr,
      .admin-panel th,
      .admin-panel td { display: block; width: 100%; }
      .admin-panel table { overflow: visible; }
      .admin-panel thead { display: none; }
      .admin-panel tr { padding: 14px 16px; border-bottom: 1px solid var(--auth-line-subtle); }
      .admin-panel tr:last-child { border-bottom: 0; }
      .admin-panel td { min-height: 48px; padding: 9px 0; border: 0; }
      .admin-panel td::before { display: block; margin-bottom: 4px; color: var(--auth-muted); content: attr(data-label); font-size: 14px; font-weight: 720; text-transform: none; }
      .authenticated-shell .member-identity { min-width: 0; align-items: flex-start; padding: 0; border: 0; }
      .authenticated-shell .member-identity strong { font-size: 16px; }
      .admin-panel select { width: 100%; }
      .authenticated-shell .action-menu,
      .authenticated-shell .action-menu-panel { position: static; width: 100%; }
      .authenticated-shell .action-menu-panel { margin-top: 8px; }
      .product-access-row { grid-template-columns: 1fr; gap: 18px; padding: 20px; }
      .product-access-row > button { grid-column: auto; width: 100%; min-height: 48px; }
      .product-access-product { align-items: flex-start; gap: 14px; }
      .authenticated-shell .product-mark.compact { width: 46px; height: 46px; border: 1px solid #bfd4cf; background: #edf6f2; }
      .authenticated-shell .product-mark.compact .quote-document-icon { width: 30px; height: 30px; }
      .product-access-product h3 { font-size: 20px; }
      .product-access-product p { font-size: 14px; }
      .product-access-state { grid-template-columns: 110px 1fr; align-items: center; }
      .pager { align-items: stretch; flex-wrap: wrap; }
      .pager .empty { width: 100%; margin: 0; }
      .pager .auth-secondary-button,
      .pager .secondary-action { flex: 1; }
      .auth-modal-backdrop { align-items: end; padding: 12px; }
      .auth-modal-backdrop .action-modal,
      .auth-modal-backdrop .member-action-modal { width: 100%; max-height: calc(100vh - 24px); border-radius: 12px; }
      .auth-modal-backdrop .modal-actions { display: grid; grid-template-columns: 1fr; }
      .auth-modal-backdrop .modal-actions button { width: 100%; min-height: 48px; }
    }

    @media (max-width: 350px) {
      .auth-bar-inner { padding-right: 12px; padding-left: 12px; }
      .auth-account-context { width: calc(100% + 23px); grid-template-columns: minmax(0, 1fr) 64px 52px 55px; margin-right: -11px; margin-left: -12px; }
      .auth-header-link, .auth-header-button { min-width: 0; }
      .auth-account-context > * { padding-right: 8px; padding-left: 8px; }
      .auth-main { padding-right: 12px; padding-left: 12px; }
      .authenticated-shell .product-summary { grid-template-columns: 42px minmax(0, 1fr); gap: 12px; padding: 19px 16px 18px 18px; }
      .authenticated-shell .product-summary h2 { font-size: 22px; }
      .product-description { font-size: 14px; }
      .launch-readiness { padding: 16px 16px 18px 18px; }
    }

    @media (prefers-reduced-motion: reduce) {
      .authenticated-shell *,
      .authenticated-shell *::before,
      .authenticated-shell *::after,
      .auth-modal-backdrop *,
      .auth-modal-backdrop *::before,
      .auth-modal-backdrop *::after {
        scroll-behavior: auto !important;
        transition-duration: .01ms !important;
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
      }
    }
  </style>
</head>
<body>
${body}
</body>
</html>`;
}
